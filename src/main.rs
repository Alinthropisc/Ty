//! ty — IPv6 Attack Toolkit, 2026 edition.
//!
//! Rust async frontend over the classic C core library (libty).
//! C tools in attack/ fake/ fuzz/ are still built separately via Makefile.

mod engine;
mod ffi;
mod tests;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use engine::discover::alive_scan;
use engine::probe::{enum_addrs, scan_ports};
use engine::sender::{
    AdvertiseConfig, Dhcp6Config, FloodConfig, MldConfig, RsConfig, SolicitateConfig,
    TooBigConfig, flood_advertise, flood_dhcp6, flood_mld, flood_router, flood_rs,
    flood_solicitate, flood_toobig,
};
use engine::sniff::{dump_dhcp6, dump_routers};
use engine::stats::Stats;

#[derive(Parser)]
#[command(
    name    = "ty",
    version = "0.1.0",
    about   = "IPv6 Attack Toolkit — 2026 edition",
)]
struct Cli {
    /// Enable debug output (-v = debug, -vv = trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Stop flood after N seconds (0 = no limit; applies to flood subcommands)
    #[arg(long, global = true, default_value_t = 0)]
    stop_after_secs: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Flood the network with Router Advertisements (async Rust engine)
    FloodRouter {
        /// Network interface (e.g. eth0)
        #[arg(short = 'i', long)]
        interface: String,

        /// Packets per second (0 = unlimited)
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,

        /// Stop after N packets (0 = forever)
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,

        /// Add hop-by-hop header (bypasses some RA guard)
        #[arg(short = 'H', long)]
        hop: bool,

        /// Add N fragmentation headers
        #[arg(short = 'F', long, default_value_t = 0)]
        frag: u32,

        /// Add destination header
        #[arg(short = 'D', long)]
        dst: bool,
    },

    /// Flood network with Neighbor Solicitations
    FloodSolicitate {
        #[arg(short = 'i', long)]
        interface: String,
        #[arg(short = 'r', long, default_value_t = 0)]
        rate: u64,
        #[arg(short = 'n', long, default_value_t = 0)]
        count: u64,
        /// Target IPv6 address (random per-packet if not set)
        #[arg(short = 't', long)]
        target: Option<String>,
        /// Add hop-by-hop router alert option
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
        /// Target IPv6 address (random per-packet if not set)
        #[arg(short = 't', long)]
        target: Option<String>,
    },

    /// Check which IPv6 addresses respond to ping6
    AliveCheck {
        #[arg(short = 'i', long)]
        interface: String,
        /// Target addresses (space-separated or repeat -t)
        #[arg(short = 't', long, required = true, num_args = 1..)]
        targets: Vec<String>,
        /// Parallel pings
        #[arg(short = 'c', long, default_value_t = 8)]
        concurrency: usize,
        /// Timeout per ping in ms
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
    },

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
        /// Target IPv6 address
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

    /// TCP port scan against an IPv6 target
    ScanPorts {
        #[arg(short = 'i', long)]
        interface: String,
        /// Target IPv6 address
        #[arg(short = 't', long)]
        target: String,
        /// Ports to scan (repeat or space-separated)
        #[arg(short = 'p', long, required = true, num_args = 1..)]
        ports: Vec<u16>,
        /// Parallel connection attempts
        #[arg(short = 'c', long, default_value_t = 64)]
        concurrency: usize,
        /// Connect timeout in ms
        #[arg(long, default_value_t = 2000)]
        timeout_ms: u64,
        /// Print results as JSON lines
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// EUI-64 address enumeration under a /64 prefix
    EnumAddrs {
        #[arg(short = 'i', long)]
        interface: String,
        /// IPv6 /64 prefix (e.g. 2001:db8:1:2)
        #[arg(short = 'p', long)]
        prefix: String,
        /// Parallel probes
        #[arg(short = 'c', long, default_value_t = 16)]
        concurrency: usize,
        /// Timeout per probe in ms
        #[arg(long, default_value_t = 1000)]
        timeout_ms: u64,
        /// Print results as JSON lines
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Passively capture Router Advertisements and display router info
    DumpRouters {
        #[arg(short = 'i', long)]
        interface: String,
        /// Capture duration in seconds
        #[arg(short = 'd', long, default_value_t = 30)]
        duration: u64,
        /// Print results as JSON lines
        #[arg(short = 'j', long)]
        json: bool,
    },

    /// Passively capture DHCPv6 traffic
    DumpDhcp6 {
        #[arg(short = 'i', long)]
        interface: String,
        /// Capture duration in seconds
        #[arg(short = 'd', long, default_value_t = 30)]
        duration: u64,
        /// Print results as JSON lines
        #[arg(short = 'j', long)]
        json: bool,
    },
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Spawn a 1-second interval background stats printer and return its handle.
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

/// Run a flood future, honouring the optional `stop_after_secs` time limit.
macro_rules! run_flood {
    ($fut:expr, $stop:expr) => {{
        if $stop > 0 {
            tokio::select! {
                r = $fut => r,
                _ = tokio::time::sleep(Duration::from_secs($stop)) => Ok(()),
            }
        } else {
            $fut.await
        }
    }};
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
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(level)),
        )
        .init();

    let stop = cli.stop_after_secs;

    match cli.command {
        Commands::FloodRouter { interface, rate, count, hop, frag, dst } => {
            let cfg = FloodConfig {
                interface,
                rate_pps:    rate,
                max_packets: count,
                do_hop:      hop,
                do_frag:     frag,
                do_dst:      dst,
            };
            let stats   = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting RA flood (Press Ctrl-C to stop)...");
            let result = run_flood!(flood_router(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodSolicitate { interface, rate, count, target, alert } => {
            let cfg = SolicitateConfig {
                interface,
                rate_pps:    rate,
                max_packets: count,
                target,
                do_alert:    alert,
            };
            let stats   = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting NS flood (Press Ctrl-C to stop)...");
            let result = run_flood!(flood_solicitate(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodAdvertise { interface, rate, count, target } => {
            let cfg = AdvertiseConfig {
                interface,
                rate_pps:    rate,
                max_packets: count,
                target,
            };
            let stats   = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting NA flood (Press Ctrl-C to stop)...");
            let result = run_flood!(flood_advertise(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::AliveCheck { interface, targets, concurrency, timeout_ms } => {
            let stats = Stats::new();
            let alive = alive_scan(interface, targets, concurrency, timeout_ms, Arc::clone(&stats)).await?;
            for host in &alive {
                println!("{host}");
            }
            let (sent, errors, _) = stats.snapshot();
            eprintln!("Done: probed={sent} errors={errors} alive={}", alive.len());
        }

        Commands::FloodMld { interface, rate, count } => {
            let cfg = MldConfig { interface, rate_pps: rate, max_packets: count };
            let stats   = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting MLD flood (Press Ctrl-C to stop)...");
            let result = run_flood!(flood_mld(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodDhcp6 { interface, rate, count } => {
            let cfg = Dhcp6Config { interface, rate_pps: rate, max_packets: count };
            let stats   = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting DHCPv6 Solicit flood (Press Ctrl-C to stop)...");
            let result = run_flood!(flood_dhcp6(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodTooBig { interface, rate, count, target } => {
            let cfg = TooBigConfig { interface, rate_pps: rate, max_packets: count, target };
            let stats   = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting Packet Too Big flood (Press Ctrl-C to stop)...");
            let result = run_flood!(flood_toobig(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::FloodRs { interface, rate, count } => {
            let cfg = RsConfig { interface, rate_pps: rate, max_packets: count };
            let stats   = Stats::new();
            let printer = spawn_printer(Arc::clone(&stats));
            eprintln!("Starting RS flood (Press Ctrl-C to stop)...");
            let result = run_flood!(flood_rs(cfg, Arc::clone(&stats)), stop);
            printer.abort();
            eprintln!();
            print_summary(&stats);
            result?;
        }

        Commands::ScanPorts { interface, target, ports, concurrency, timeout_ms, json } => {
            let stats = Stats::new();
            eprintln!("Scanning {} port(s) on {target}...", ports.len());
            let open = scan_ports(interface, target, ports, concurrency, timeout_ms, Arc::clone(&stats), json).await?;
            let (sent, errors, elapsed) = stats.snapshot();
            eprintln!("Done: probed={sent} errors={errors} open={} elapsed={elapsed:.1}s", open.len());
        }

        Commands::EnumAddrs { interface, prefix, concurrency, timeout_ms, json } => {
            let stats = Stats::new();
            eprintln!("Enumerating addresses under {prefix}...");
            let live = enum_addrs(interface, prefix, concurrency, timeout_ms, Arc::clone(&stats), json).await?;
            let (sent, errors, elapsed) = stats.snapshot();
            eprintln!("Done: probed={sent} errors={errors} live={} elapsed={elapsed:.1}s", live.len());
        }

        Commands::DumpRouters { interface, duration, json } => {
            eprintln!("Sniffing router advertisements on {interface} for {duration}s...");
            let routers = dump_routers(interface, duration, json).await?;
            eprintln!("Done: {} router(s) observed.", routers.len());
        }

        Commands::DumpDhcp6 { interface, duration, json } => {
            eprintln!("Sniffing DHCPv6 traffic on {interface} for {duration}s...");
            let events = dump_dhcp6(interface, duration, json).await?;
            eprintln!("Done: {} DHCPv6 packet(s) observed.", events.len());
        }
    }

    Ok(())
}

fn print_summary(stats: &Stats) {
    let (sent, errors, elapsed) = stats.snapshot();
    eprintln!(
        "Done: sent={sent} errors={errors} elapsed={elapsed:.1}s avg={:.0} pps",
        if elapsed > 0.0 { sent as f64 / elapsed } else { 0.0 }
    );
}
