# ty — IPv6 Attack Toolkit 2026

> A modern revival of the classic IPv6 penetration testing toolkit.
> Rust async frontend over a battle-tested C core library.

[![Build](https://github.com/Alinthropisc/Ty/actions/workflows/ci.yml/badge.svg)](https://github.com/Alinthropisc/Ty/actions/workflows/ci.yml)
[![Tests](https://github.com/Alinthropisc/Ty/actions/workflows/tests.yml/badge.svg)](https://github.com/Alinthropisc/Ty/actions/workflows/tests.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)

---

## What is ty?

**ty** is an IPv6 security research and penetration testing toolkit.
It combines a proven C library (`libty`) with a modern Rust async engine that
adds rate-limiting, concurrency control, JSON output, and time-bounded
operations — without touching the existing C tool behaviour.

**Supported platforms:** Linux 2.6+ with Ethernet interfaces.

---

## Features

| Category | Subcommand | Description |
|----------|-----------|-------------|
| Flood | `flood-router` | Router Advertisement flood with optional hop/frag/dst headers |
| Flood | `flood-solicitate` | Neighbor Solicitation flood (NDP exhaustion) |
| Flood | `flood-advertise` | Neighbor Advertisement flood (Override flag) |
| Flood | `flood-mld` | MLDv1 Report flood (random multicast groups) |
| Flood | `flood-dhcp6` | DHCPv6 Solicit flood (address pool exhaustion) |
| Flood | `flood-toobig` | ICMPv6 Packet Too Big flood (MTU reduction) |
| Flood | `flood-rs` | Router Solicitation flood (triggers unsolicited RAs) |
| Scan | `alive-check` | Async ICMPv6 ping sweep with bounded concurrency |
| Scan | `scan-ports` | Async TCP port scanner for IPv6 targets |
| Enum | `enum-addrs` | EUI-64 address enumeration under a /64 prefix |
| Sniff | `dump-routers` | Passive Router Advertisement capture |
| Sniff | `dump-dhcp6` | Passive DHCPv6 traffic capture |

**Global flags:**
- `-v / -vv` — debug / trace logging
- `--stop-after-secs N` — time-limit any flood
- `-j / --json` — JSON-lines output on scan and sniff commands

---

## Dependencies

```bash
# Debian / Ubuntu / Kali
sudo apt-get install libpcap-dev libssl-dev libnetfilter-queue-dev

# Rust toolchain (1.77+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

---

## Building

```bash
# Build everything (C tools + Rust frontend)
make all

# Build only the Rust binary
cargo build --release

# Install system-wide
sudo make install
```

The Rust binary is placed at `target/release/ty`.
C tools are placed in the project root (or `/usr/local/bin` after `make install`).

---

## Quick Start

```bash
# Flood RA on eth0 at 1000 pps, stop after 30 seconds
ty flood-router -i eth0 -r 1000 --stop-after-secs 30

# Neighbor Solicitation flood with a specific target
ty flood-solicitate -i eth0 -t fe80::1 -r 500

# Alive scan — which of these respond to ping6?
ty alive-check -i eth0 -t 2001:db8::1 2001:db8::2 2001:db8::3

# TCP port scan
ty scan-ports -i eth0 -t 2001:db8::1 -p 22 80 443 8080 --json

# EUI-64 enumeration under a /64 prefix
ty enum-addrs -i eth0 -p 2001:db8:1:2 --json

# Passive RA sniff for 60 seconds
ty dump-routers -i eth0 -d 60 --json

# DHCPv6 Solicit flood, 5 minutes
ty flood-dhcp6 -i eth0 --stop-after-secs 300
```

---

## C Tools

All original C tools are still available and unmodified in behaviour.
After `make all` or `make install`:

```
parasite6         — ICMPv6 neighbor spoofing (man-in-the-middle)
alive6            — Effective alive scanning
dnsdict6          — Parallelised DNS IPv6 dictionary bruteforcer
fake_router6      — Announce yourself as highest-priority router
redir6            — Intelligent ICMPv6 redirect spoofer
toobig6           — MTU decreaser
detect-new-ip6    — Detect new IPv6 devices joining the network
dos-new-ip6       — DOS new devices via DAD collision
trace6            — Fast traceroute with ICMPv6 and TCP-SYN
flood_router6     — C-native RA flood
flood_advertise6  — C-native NA flood
fuzz_ip6          — IPv6 fuzzer
implementation6   — Implementation checks
fake_mld6         — Fake MLD announcements
smurf6 / rsmurf6  — ICMPv6 smurf attacks
exploit6          — Known IPv6 vulnerability tests
denial6           — Denial-of-service test collection
sendpees6         — CGA-based CPU exhaustion
```

Run any tool without arguments for usage.

---

## Architecture

```
ty/
├── src/
│   ├── main.rs              # CLI (clap), subcommand dispatch, flood macro
│   ├── ffi/mod.rs           # unsafe FFI bindings to libty
│   ├── engine/
│   │   ├── discover.rs      # alive_scan, ping6_alive
│   │   ├── probe.rs         # scan_ports, enum_addrs
│   │   ├── sender.rs        # all flood_* functions + Config structs
│   │   ├── sniff.rs         # dump_routers, dump_dhcp6
│   │   └── stats.rs         # AtomicU64 stats (sent, errors, pps)
│   └── tests.rs             # offline unit tests
├── libty/
│   └── thc-ipv6-lib.c       # C core library (libty)
├── attack/                  # C attack tools
├── fake/                    # C fake announcement tools
├── fuzz/                    # C fuzz tools
├── scripts/                 # Helper shell scripts
│   └── ty.sh                # Build / install / test helper
├── ty.bat                   # Windows build helper
├── build.rs                 # Compiles libty into Rust binary
├── Cargo.toml
└── Makefile
```

**Design principles:**
- C code handles raw socket operations and packet construction
- Rust engine adds async I/O, rate control, bounded concurrency, and JSON output
- `spawn_blocking` wraps all C FFI calls — the tokio runtime is never blocked
- `AtomicU64` stats shared across tasks via `Arc<Stats>` — no mutexes on the hot path
- `tokio::select!` in `run_flood!` macro provides clean time-bounded stops

---

## Scripts

```bash
./scripts/ty.sh build        # Build everything
./scripts/ty.sh test         # Run Rust tests
./scripts/ty.sh install      # Install to /usr/local/bin
./scripts/ty.sh check-deps   # Check dependencies
./scripts/ty.sh clean        # Clean build artifacts
```

---

## Development

```bash
cargo clippy -- -D warnings  # Lint
cargo fmt                    # Format
cargo test --lib             # Tests (offline, no network, no C calls)
cargo llvm-cov --lib         # Coverage (requires cargo-llvm-cov)
```

---

## Detection

Most tools produce detectable packet signatures by design — this makes rogue
usage easier to detect with an IDS. If you need covert operation, modify the
source code accordingly.

---

## License

AGPLv3 — see [LICENSE](LICENSE).

---

## Contributing

Pull requests welcome. Please:
1. Keep C comments in English
2. Add tests for all new Rust code (`src/tests.rs`)
3. Run `cargo fmt` and `cargo clippy` before submitting
4. Do not break existing C tool behaviour

GitHub: [https://github.com/Alinthropisc/Ty](https://github.com/Alinthropisc/Ty)
