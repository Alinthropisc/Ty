//! Passive packet sniffers built on libty pcap wrappers.
//!
//! Because `thc_pcap_check` uses a C callback API that is difficult to bridge
//! safely with Rust closures, both sniffers use `spawn_blocking` to run a
//! polling loop on a dedicated OS thread.  The loop calls `thc_pcap_check`
//! with a null callback — this drains the pcap ring and returns the count of
//! matched packets without invoking any Rust code from C context.
//!
//! Parsing the raw packet bytes from within Rust is left as future work.
//! The current implementation reports packet counts and source addresses where
//! the C library exposes them via other helpers.

use std::ffi::CString;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::task;

// ── RouterInfo ────────────────────────────────────────────────────────────────

/// Information about a router advertisement seen on the wire.
#[derive(Clone, Debug)]
pub struct RouterInfo {
    pub src_ip:   String,
    pub src_mac:  String,
    pub prefix:   String,
    pub lifetime: u32,
}

// ── Dhcp6Event ────────────────────────────────────────────────────────────────

/// A DHCPv6 packet event captured on the wire.
#[derive(Clone, Debug)]
pub struct Dhcp6Event {
    pub msg_type:       u8,
    pub src_ip:         String,
    pub transaction_id: String,
}

// ── dump_routers ─────────────────────────────────────────────────────────────

/// Passively sniff Router Advertisement packets for `duration_secs` seconds.
///
/// Opens a pcap handle filtered to ICMPv6 RA (type 134) and polls every 100 ms
/// using `thc_pcap_check`.  Because the C callback API cannot be safely called
/// from Rust closures, this function counts matched packets and reports the
/// total; full per-packet parsing is not performed.
///
/// Returns a `Vec<RouterInfo>` sized by the packet count; the `src_ip` /
/// `src_mac` / `prefix` fields are placeholder strings indicating the capture
/// count rather than real values — a full implementation would require a C
/// helper to extract those fields.
pub async fn dump_routers(
    interface:     String,
    duration_secs: u64,
    json:          bool,
) -> Result<Vec<RouterInfo>> {
    // BPF filter for ICMPv6 Router Advertisements.
    let filter = "ip6 and icmp6 and ip6[40] == 134".to_string();

    let count = run_pcap_loop(interface.clone(), filter, duration_secs).await?;

    eprintln!("  captured {count} router advertisement packet(s) on {interface}");

    // Build placeholder RouterInfo entries — one per captured packet.
    let mut results = Vec::with_capacity(count as usize);
    for i in 0..count {
        let info = RouterInfo {
            src_ip:   format!("unknown-{i}"),
            src_mac:  "unknown".into(),
            prefix:   "unknown".into(),
            lifetime: 0,
        };
        if json {
            println!(
                r#"{{"src_ip": "{}", "src_mac": "{}", "prefix": "{}", "lifetime": {}}}"#,
                info.src_ip, info.src_mac, info.prefix, info.lifetime
            );
        } else {
            println!(
                "RA from {} mac={} prefix={} lifetime={}",
                info.src_ip, info.src_mac, info.prefix, info.lifetime
            );
        }
        results.push(info);
    }
    Ok(results)
}

// ── dump_dhcp6 ───────────────────────────────────────────────────────────────

/// Passively sniff DHCPv6 packets (ports 546/547) for `duration_secs` seconds.
///
/// Uses the same poll-based approach as `dump_routers`.  Returns a
/// `Vec<Dhcp6Event>` with placeholder data sized by the captured packet count.
pub async fn dump_dhcp6(
    interface:     String,
    duration_secs: u64,
    json:          bool,
) -> Result<Vec<Dhcp6Event>> {
    let filter = "ip6 and udp and (dst port 547 or dst port 546)".to_string();

    let count = run_pcap_loop(interface.clone(), filter, duration_secs).await?;

    eprintln!("  captured {count} DHCPv6 packet(s) on {interface}");

    let mut results = Vec::with_capacity(count as usize);
    for i in 0..count {
        let event = Dhcp6Event {
            msg_type:       0,
            src_ip:         format!("unknown-{i}"),
            transaction_id: format!("{i:06x}"),
        };
        if json {
            println!(
                r#"{{"msg_type": {}, "src_ip": "{}", "transaction_id": "{}"}}"#,
                event.msg_type, event.src_ip, event.transaction_id
            );
        } else {
            println!(
                "DHCPv6 type={} from {} txid={}",
                event.msg_type, event.src_ip, event.transaction_id
            );
        }
        results.push(event);
    }
    Ok(results)
}

// ── internal pcap polling loop ────────────────────────────────────────────────

/// Open a pcap capture on `interface` with `filter`, poll for `duration_secs`
/// seconds, then close it and return the total number of matched packets.
///
/// Runs on a dedicated blocking OS thread via `spawn_blocking` so the tokio
/// runtime is not blocked during the capture window.
async fn run_pcap_loop(
    interface:     String,
    filter:        String,
    duration_secs: u64,
) -> Result<u64> {
    task::spawn_blocking(move || -> Result<u64> {
        let iface_cs  = CString::new(interface).context("null in interface")?;
        let filter_cs = CString::new(filter).context("null in filter")?;

        let pcap = unsafe {
            crate::ffi::thc_pcap_init(iface_cs.as_ptr(), filter_cs.as_ptr())
        };
        if pcap.is_null() {
            anyhow::bail!("thc_pcap_init failed — check interface name and privileges");
        }

        let deadline = Instant::now() + Duration::from_secs(duration_secs);
        let poll_interval = Duration::from_millis(100);
        let mut total: u64 = 0;

        while Instant::now() < deadline {
            // Pass null callback and null opt to just drain packets and count.
            let n = unsafe {
                crate::ffi::thc_pcap_check(pcap, std::ptr::null(), std::ptr::null_mut())
            };
            if n > 0 {
                total += n as u64;
            }
            std::thread::sleep(poll_interval);
        }

        unsafe { crate::ffi::thc_pcap_close(pcap) };
        Ok(total)
    })
    .await
    .context("pcap blocking thread panicked")?
}
