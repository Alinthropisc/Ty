//! Active probing — TCP port scanning and EUI-64 address enumeration.
//!
//! Pure Rust / tokio — no FFI.  Uses `FuturesUnordered` so results stream as
//! they arrive rather than waiting for the slowest probe to finish.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use futures::StreamExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::engine::discover::ping6_alive;
use crate::engine::stats::Stats;

// ── scan_ports ────────────────────────────────────────────────────────────────

/// Scan `ports` on `target` using async TCP connect with bounded concurrency.
///
/// Returns the list of open ports sorted ascending.  Results are printed to
/// stdout as each probe completes; `json` switches to JSON-lines format.
pub async fn scan_ports(
    _interface: String,
    target: String,
    ports: Vec<u16>,
    concurrency: usize,
    timeout_ms: u64,
    stats: Arc<Stats>,
    json: bool,
) -> Result<Vec<u16>> {
    let sem = Arc::new(Semaphore::new(concurrency.max(1)));
    let timeout = Duration::from_millis(timeout_ms);

    let mut stream = futures::stream::iter(ports)
        .map(|port| {
            let sem2 = Arc::clone(&sem);
            let target2 = target.clone();
            let stats2 = Arc::clone(&stats);
            async move {
                let _permit = sem2.acquire_owned().await.unwrap();
                let addr = format!("[{target2}]:{port}");
                let open = tokio::time::timeout(timeout, TcpStream::connect(&addr))
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false);
                stats2.inc_sent();
                (port, open)
            }
        })
        .buffer_unordered(concurrency.max(1));

    let mut open_ports = Vec::new();
    while let Some((port, open)) = stream.next().await {
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
/// Returns addresses that responded to ICMPv6 ping6.
pub async fn enum_addrs(
    interface: String,
    prefix: String,
    concurrency: usize,
    timeout_ms: u64,
    stats: Arc<Stats>,
    json: bool,
) -> Result<Vec<String>> {
    let prefix = normalise_prefix(&prefix);
    let candidates = build_candidates(&prefix);

    let sem = Arc::new(Semaphore::new(concurrency.max(1)));

    let mut stream = futures::stream::iter(candidates)
        .map(|addr| {
            let sem2 = Arc::clone(&sem);
            let iface2 = interface.clone();
            let stats2 = Arc::clone(&stats);
            async move {
                let _permit = sem2.acquire_owned().await.unwrap();
                let alive = ping6_alive(iface2, addr.clone(), timeout_ms)
                    .await
                    .unwrap_or(false);
                stats2.inc_sent();
                (addr, alive)
            }
        })
        .buffer_unordered(concurrency.max(1));

    let mut live = Vec::new();
    while let Some((addr, alive)) = stream.next().await {
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

// ── candidate generation ──────────────────────────────────────────────────────

fn normalise_prefix(prefix: &str) -> String {
    // Strip trailing slashes, colons, and CIDR notation (e.g. /64).
    let p = prefix.trim_end_matches('/').trim_end_matches(':');
    match p.split('/').next() {
        Some(s) => s.to_string(),
        None => p.to_string(),
    }
}

fn build_candidates(prefix: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    // Low sequential interface IDs: ::1 through ::ff.
    for i in 1u32..=0xff {
        out.push(format!("{prefix}::{i:x}"));
    }
    // Two-component low IDs: ::1:00 through ::ff:ff.
    for hi in 1u32..=0xff {
        for lo in 0u32..=0xff {
            out.push(format!("{prefix}::{hi:x}:{lo:02x}"));
        }
    }

    // Common EUI-64 OUI patterns — 2-byte short fake OUI or real 3-byte OUI.
    const OUIS: &[&str] = &[
        "0218", // toolkit fake OUI
        "f8bc12", "b083fe", // Dell
        "8086f4", "000c29", // Intel
        "001b8f", "001d46", // Cisco
    ];

    for oui in OUIS {
        for lo in [0x00u8, 0x01, 0xff] {
            if oui.len() == 4 {
                // 2-byte short OUI: build EUI-64 with ff:fe middle bytes.
                let b0 = u8::from_str_radix(&oui[0..2], 16).unwrap_or(0x02) ^ 0x02;
                let b1 = u8::from_str_radix(&oui[2..4], 16).unwrap_or(0x18);
                for mid in [0x00u8, 0x11, 0x22, 0xaa, 0xbb] {
                    out.push(format!(
                        "{prefix}:{b0:02x}{b1:02x}:ff:fe{mid:02x}:{lo:02x}{lo:02x}"
                    ));
                }
            } else {
                // 3-byte real OUI.
                let b0 = u8::from_str_radix(&oui[0..2], 16).unwrap_or(0) ^ 0x02;
                let b1 = u8::from_str_radix(&oui[2..4], 16).unwrap_or(0);
                let b2 = u8::from_str_radix(&oui[4..6], 16).unwrap_or(0);
                for mid in [0x00u8, 0x11, 0xaa] {
                    out.push(format!(
                        "{prefix}:{b0:02x}{b1:02x}:{b2:02x}ff:fe{mid:02x}:{lo:02x}{lo:02x}"
                    ));
                }
            }
        }
    }

    out.dedup();
    out
}
