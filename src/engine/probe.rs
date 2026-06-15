//! Active probing — TCP port scanning and EUI-64 address enumeration.
//!
//! All operations are pure Rust / tokio — no FFI calls.  The C library is not
//! involved here so these functions work even without a raw socket capable
//! interface.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::engine::discover::ping6_alive;
use crate::engine::stats::Stats;

// ── scan_ports ────────────────────────────────────────────────────────────────

/// Scan `ports` on `target` using async TCP connect with bounded concurrency.
///
/// Returns the list of open ports.  Progress is printed to stdout as ports are
/// discovered; if `json` is true the format is one JSON object per line.
pub async fn scan_ports(
    _interface:   String,
    target:       String,
    ports:        Vec<u16>,
    concurrency:  usize,
    timeout_ms:   u64,
    stats:        Arc<Stats>,
    json:         bool,
) -> Result<Vec<u16>> {
    let sem     = Arc::new(Semaphore::new(concurrency.max(1)));
    let timeout = Duration::from_millis(timeout_ms);
    let mut handles = Vec::with_capacity(ports.len());

    for port in ports {
        let sem2    = Arc::clone(&sem);
        let target2 = target.clone();
        let stats2  = Arc::clone(&stats);

        let handle = tokio::spawn(async move {
            let _permit = sem2.acquire_owned().await.unwrap();
            let addr = format!("[{target2}]:{port}");
            let open = tokio::time::timeout(timeout, TcpStream::connect(&addr))
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
            stats2.inc_sent();
            (port, open)
        });
        handles.push(handle);
    }

    let mut open_ports = Vec::new();
    for h in handles {
        let (port, open) = h.await?;
        if open {
            open_ports.push(port);
            if json {
                println!(r#"{{"port": {port}, "state": "open"}}"#);
            } else {
                println!("port {port}/tcp open");
            }
        }
    }
    open_ports.sort_unstable();
    Ok(open_ports)
}

// ── enum_addrs ────────────────────────────────────────────────────────────────

/// Enumerate live IPv6 addresses under a /64 `prefix` using common EUI-64
/// suffixes and low-value interface identifiers.
///
/// Candidates are probed via ICMPv6 ping6 (see `engine::discover::ping6_alive`).
/// Returns the list of addresses that responded.
pub async fn enum_addrs(
    interface:   String,
    prefix:      String,
    concurrency: usize,
    timeout_ms:  u64,
    stats:       Arc<Stats>,
    json:        bool,
) -> Result<Vec<String>> {
    // Strip trailing colons/slashes that the caller might have included.
    let prefix = prefix.trim_end_matches('/').trim_end_matches(':').to_string();
    // Remove /64 or similar CIDR suffix.
    let prefix = if let Some(p) = prefix.split('/').next() { p.to_string() } else { prefix };

    let mut candidates: Vec<String> = Vec::new();

    // Low sequential interface IDs: ::1 through ::ff and ::1:0 through ::ff:ff.
    for i in 1u32..=0xff {
        candidates.push(format!("{prefix}::{i:x}"));
    }
    for hi in 1u32..=0xff {
        for lo in 0u32..=0xff {
            candidates.push(format!("{prefix}::{hi:x}:{lo:02x}"));
        }
    }

    // Common EUI-64 OUI patterns — the `02:18:xx:ff:fe:xx:xx:xx` form used
    // by many tools, plus real-world Dell/Intel/Cisco OUIs with ff:fe inserted.
    let common_ouis: &[&str] = &[
        // fake OUI used by this toolkit
        "0218",
        // Dell
        "f8bc12", "b083fe",
        // Intel
        "8086f4", "000c29",
        // Cisco
        "001b8f", "001d46",
    ];
    for oui in common_ouis {
        for lo in [0x00u8, 0x01, 0xff] {
            // EUI-64: OUI[0] ^ 0x02 : OUI[1] : OUI[2] : ff : fe : rand : rand : lo
            if oui.len() == 4 {
                // Short fake OUI: treat as 2-byte prefix with random fill
                let b0 = u8::from_str_radix(&oui[0..2], 16).unwrap_or(0x02) ^ 0x02;
                let b1 = u8::from_str_radix(&oui[2..4], 16).unwrap_or(0x18);
                for mid in [0x00u8, 0x11, 0x22, 0xaa, 0xbb] {
                    candidates.push(format!(
                        "{prefix}:{b0:02x}{b1:02x}:ff:fe{mid:02x}:{lo:02x}{lo:02x}"
                    ));
                }
            } else {
                // 6-hex-char (3-byte) OUI.
                let b0 = u8::from_str_radix(&oui[0..2], 16).unwrap_or(0) ^ 0x02;
                let b1 = u8::from_str_radix(&oui[2..4], 16).unwrap_or(0);
                let b2 = u8::from_str_radix(&oui[4..6], 16).unwrap_or(0);
                for mid in [0x00u8, 0x11, 0xaa] {
                    candidates.push(format!(
                        "{prefix}:{b0:02x}{b1:02x}:{b2:02x}ff:fe{mid:02x}:{lo:02x}{lo:02x}"
                    ));
                }
            }
        }
    }

    candidates.dedup();

    let sem      = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(candidates.len());

    for addr in candidates {
        let sem2      = Arc::clone(&sem);
        let iface2    = interface.clone();
        let stats2    = Arc::clone(&stats);

        let handle = tokio::spawn(async move {
            let _permit = sem2.acquire_owned().await.unwrap();
            let alive = ping6_alive(iface2.clone(), addr.clone(), timeout_ms).await.unwrap_or(false);
            stats2.inc_sent();
            (addr, alive)
        });
        handles.push(handle);
    }

    let mut live = Vec::new();
    for h in handles {
        let (addr, alive) = h.await?;
        if alive {
            live.push(addr.clone());
            if json {
                println!(r#"{{"addr": "{addr}"}}"#);
            } else {
                println!("{addr}");
            }
        }
    }
    Ok(live)
}
