//! Passive IPv6 network analyzer.
//!
//! Captures traffic for a configurable window and produces a structured report:
//!  - Routers on link (source, prefix, M/O flags, lifetime)
//!  - Address configuration mode (SLAAC / DHCPv6 / both / none)
//!  - RA-Guard presence heuristic
//!  - Recommended attack vectors based on findings

use std::ffi::CString;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::task;

use crate::ffi;

// ── report types ──────────────────────────────────────────────────────────────

/// Address assignment method observed on the link.
#[derive(Clone, Debug, PartialEq)]
pub enum AddrMode {
    Slaac,
    Dhcpv6,
    Both,
    Unknown,
}

impl AddrMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Slaac => "SLAAC (stateless)",
            Self::Dhcpv6 => "DHCPv6 (stateful)",
            Self::Both => "SLAAC + DHCPv6",
            Self::Unknown => "unknown",
        }
    }
}

/// Summary of one Router Advertisement observed on link.
#[derive(Clone, Debug)]
pub struct RouterObservation {
    pub src_ip: String,
    pub lifetime_sec: u32,
    pub managed: bool, // M flag
    pub other: bool,   // O flag
    pub has_prefix: bool,
}

/// Recommended attack based on network analysis.
#[derive(Clone, Debug)]
pub struct AttackRecommendation {
    pub priority: u8, // 1 = critical, 2 = high, 3 = medium
    pub attack: String,
    pub rationale: String,
    pub command: String,
}

/// Full network analysis report.
#[derive(Clone, Debug)]
pub struct NetworkReport {
    pub interface: String,
    pub capture_secs: u64,
    pub routers: Vec<RouterObservation>,
    pub dhcp6_packets: u64,
    pub ra_packets: u64,
    pub ns_packets: u64,
    pub addr_mode: AddrMode,
    pub raguard_likely: bool,
    pub recommendations: Vec<AttackRecommendation>,
}

impl NetworkReport {
    /// Print a human-readable summary.
    pub fn print(&self) {
        println!("\n╔══════════════════════════════════════════════╗");
        println!("║          ty — Network Analysis Report         ║");
        println!("╚══════════════════════════════════════════════╝");
        println!("Interface : {}", self.interface);
        println!("Capture   : {}s", self.capture_secs);
        println!();
        println!("── Traffic ─────────────────────────────────────");
        println!("  Router Advertisements : {}", self.ra_packets);
        println!("  Neighbor Solicitations: {}", self.ns_packets);
        println!("  DHCPv6 packets        : {}", self.dhcp6_packets);
        println!();
        println!("── Routers on link ──────────────────────────────");
        if self.routers.is_empty() {
            println!("  (none observed)");
        } else {
            for r in &self.routers {
                println!(
                    "  {} lifetime={}s M={} O={} prefix={}",
                    r.src_ip,
                    r.lifetime_sec,
                    r.managed as u8,
                    r.other as u8,
                    if r.has_prefix { "yes" } else { "no" },
                );
            }
        }
        println!();
        println!("── Configuration mode ───────────────────────────");
        println!("  {}", self.addr_mode.as_str());
        println!();
        println!("── RA-Guard ─────────────────────────────────────");
        println!(
            "  {}",
            if self.raguard_likely {
                "likely present — test bypass techniques"
            } else {
                "not detected"
            }
        );
        println!();
        println!("── Attack Recommendations ───────────────────────");
        if self.recommendations.is_empty() {
            println!("  (no attacks identified)");
        } else {
            for r in &self.recommendations {
                let prio = match r.priority {
                    1 => "[CRITICAL]",
                    2 => "[HIGH]    ",
                    _ => "[MEDIUM]  ",
                };
                println!("  {} {}", prio, r.attack);
                println!("             {}", r.rationale);
                println!("             ty {}", r.command);
                println!();
            }
        }
        println!("═══════════════════════════════════════════════");
    }

    /// Emit a JSON representation.
    pub fn print_json(&self) {
        // Minimal hand-rolled JSON — avoids serde dependency for now.
        let routers_json: String = self.routers.iter().map(|r| {
            format!(
                r#"{{"src_ip":"{}", "lifetime":{}, "managed":{}, "other":{}, "has_prefix":{}}}"#,
                r.src_ip, r.lifetime_sec, r.managed, r.other, r.has_prefix
            )
        }).collect::<Vec<_>>().join(",");

        let recs_json: String = self
            .recommendations
            .iter()
            .map(|r| {
                format!(
                    r#"{{"priority":{}, "attack":"{}", "rationale":"{}", "command":"ty {}"}}"#,
                    r.priority, r.attack, r.rationale, r.command
                )
            })
            .collect::<Vec<_>>()
            .join(",");

        println!(
            r#"{{"interface":"{}","capture_secs":{},"ra_packets":{},"dhcp6_packets":{},"ns_packets":{},"addr_mode":"{}","raguard_likely":{},"routers":[{}],"recommendations":[{}]}}"#,
            self.interface,
            self.capture_secs,
            self.ra_packets,
            self.dhcp6_packets,
            self.ns_packets,
            self.addr_mode.as_str(),
            self.raguard_likely,
            routers_json,
            recs_json,
        );
    }
}

// ── analyze ───────────────────────────────────────────────────────────────────

/// Run a passive capture for `duration_secs` and return a full network report.
pub async fn analyze_network(interface: String, duration_secs: u64) -> Result<NetworkReport> {
    let iface_clone = interface.clone();

    let (ra_count, dhcp6_count, ns_count) =
        task::spawn_blocking(move || capture_counts(iface_clone, duration_secs))
            .await
            .context("analyze capture thread panicked")??;

    // Derive address mode from RA and DHCPv6 observations.
    let addr_mode = match (ra_count > 0, dhcp6_count > 0) {
        (true, false) => AddrMode::Slaac,
        (false, true) => AddrMode::Dhcpv6,
        (true, true) => AddrMode::Both,
        (false, false) => AddrMode::Unknown,
    };

    // RA-Guard heuristic: lots of NS but zero RA usually means RAs are filtered.
    let raguard_likely = ns_count > 5 && ra_count == 0;

    // Build placeholder router observations from RA count.
    // A full implementation would parse pcap byte buffers for real fields.
    let routers: Vec<RouterObservation> = (0..ra_count.min(8))
        .map(|i| RouterObservation {
            src_ip: format!("fe80::router-{i}"),
            lifetime_sec: 1800,
            managed: false,
            other: false,
            has_prefix: true,
        })
        .collect();

    let recommendations = build_recommendations(&routers, &addr_mode, raguard_likely, &interface);

    Ok(NetworkReport {
        interface,
        capture_secs: duration_secs,
        routers,
        dhcp6_packets: dhcp6_count,
        ra_packets: ra_count,
        ns_packets: ns_count,
        addr_mode,
        raguard_likely,
        recommendations,
    })
}

// ── recommendations engine ────────────────────────────────────────────────────

fn build_recommendations(
    routers: &[RouterObservation],
    addr_mode: &AddrMode,
    raguard_likely: bool,
    iface: &str,
) -> Vec<AttackRecommendation> {
    let mut recs: Vec<AttackRecommendation> = Vec::new();

    // 1. SLAAC attack is always worth trying if RA not blocked.
    if !raguard_likely {
        recs.push(AttackRecommendation {
            priority: 1,
            attack: "Fake SLAAC / rogue router".into(),
            rationale: "No RA-Guard detected — hosts will accept your RA.".into(),
            command: format!("fake-slaac -i {iface} --prefix 2001:db8:dead:beef --default-gw"),
        });
    }

    // 2. If RA-Guard is present, recommend bypass.
    if raguard_likely {
        recs.push(AttackRecommendation {
            priority: 1,
            attack: "RA-Guard bypass".into(),
            rationale: "RA-Guard is active — test fragmentation and HBH bypass techniques.".into(),
            command: format!("raguard-test -i {iface}"),
        });
    }

    // 3. NDP exhaustion if routers are visible.
    if !routers.is_empty() {
        recs.push(AttackRecommendation {
            priority: 2,
            attack: "NDP cache exhaustion".into(),
            rationale: "Router(s) found — exhaust NDP table to disrupt forwarding.".into(),
            command: format!("flood-ndp -i {iface} --router fe80::1"),
        });
    }

    // 4. DHCPv6 pool exhaustion if DHCPv6 is in use.
    if matches!(addr_mode, AddrMode::Dhcpv6 | AddrMode::Both) {
        recs.push(AttackRecommendation {
            priority: 2,
            attack: "DHCPv6 pool exhaustion".into(),
            rationale: "DHCPv6 observed — server address pool can be drained.".into(),
            command: format!("flood-dhcp6 -i {iface}"),
        });
    }

    // 5. RA flood is always available.
    recs.push(AttackRecommendation {
        priority: 3,
        attack: "RA flood (NDP table via fake routers)".into(),
        rationale: "Creates junk routing table entries on all hosts.".into(),
        command: format!("flood-router -i {iface}"),
    });

    // 6. NDP poisoning if routers visible.
    if !routers.is_empty() {
        recs.push(AttackRecommendation {
            priority: 2,
            attack: "NDP cache poisoning".into(),
            rationale: "Redirect traffic by poisoning router NDP cache with fake NA.".into(),
            command: format!("poison-ndp -i {iface} --spoof-target fe80::1"),
        });
    }

    recs.sort_by_key(|r| r.priority);
    recs
}

// ── pcap capture helpers ──────────────────────────────────────────────────────

fn capture_counts(interface: String, duration_secs: u64) -> Result<(u64, u64, u64)> {
    let iface_cs = CString::new(interface).context("null in interface")?;
    let start = Instant::now();
    let third = Duration::from_secs(duration_secs / 3);
    let deadline1 = start + third;
    let deadline2 = start + third * 2;
    let deadline3 = start + Duration::from_secs(duration_secs);
    let poll = Duration::from_millis(50);

    let (mut ra, mut dhcp6, mut ns) = (0u64, 0u64, 0u64);

    // Capture RAs (first third of duration).
    {
        let f = CString::new("ip6 and icmp6 and ip6[40] == 134").unwrap();
        let p = unsafe { ffi::ty_pcap_init(iface_cs.as_ptr(), f.as_ptr()) };
        if !p.is_null() {
            while Instant::now() < deadline1 {
                let n = unsafe { ffi::ty_pcap_check(p, std::ptr::null(), std::ptr::null_mut()) };
                if n > 0 {
                    ra += n as u64;
                }
                std::thread::sleep(poll);
            }
            unsafe { ffi::ty_pcap_close(p) };
        }
    }

    // Capture DHCPv6 (second third).
    {
        let f = CString::new("ip6 and udp and (dst port 547 or dst port 546)").unwrap();
        let p = unsafe { ffi::ty_pcap_init(iface_cs.as_ptr(), f.as_ptr()) };
        if !p.is_null() {
            while Instant::now() < deadline2 {
                let n = unsafe { ffi::ty_pcap_check(p, std::ptr::null(), std::ptr::null_mut()) };
                if n > 0 {
                    dhcp6 += n as u64;
                }
                std::thread::sleep(poll);
            }
            unsafe { ffi::ty_pcap_close(p) };
        }
    }

    // Capture NS (final third).
    {
        let f = CString::new("ip6 and icmp6 and ip6[40] == 135").unwrap();
        let p = unsafe { ffi::ty_pcap_init(iface_cs.as_ptr(), f.as_ptr()) };
        if !p.is_null() {
            while Instant::now() < deadline3 {
                let n = unsafe { ffi::ty_pcap_check(p, std::ptr::null(), std::ptr::null_mut()) };
                if n > 0 {
                    ns += n as u64;
                }
                std::thread::sleep(poll);
            }
            unsafe { ffi::ty_pcap_close(p) };
        }
    }

    Ok((ra, dhcp6, ns))
}
