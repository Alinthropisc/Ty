#!/usr/bin/env bash
# ty — build / install / test helper
set -euo pipefail

BINARY="ty"
INSTALL_DIR="/usr/local/bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> [args]

Commands:
  build        Build Rust frontend + C tools (release)
  build-debug  Build Rust frontend in debug mode
  test         Run Rust unit tests (offline, no C calls)
  coverage     Generate test coverage report (requires cargo-llvm-cov)
  install      Install ty binary and C tools to $INSTALL_DIR
  uninstall    Remove ty binary from $INSTALL_DIR
  clean        Remove build artefacts
  check-deps   Check required system libraries
  lint         Run clippy + rustfmt check
  c-tools      Build only the C tools via make
  help         Show this help

Flood shortcuts (require root / CAP_NET_RAW):
  flood-router    <iface> [rate_pps] [secs]
  flood-sol       <iface> [rate_pps] [secs]
  flood-adv       <iface> [rate_pps] [secs]
  flood-mld       <iface> [rate_pps] [secs]
  flood-dhcp6     <iface> [rate_pps] [secs]
  flood-rs        <iface> [rate_pps] [secs]

Examples:
  $(basename "$0") build
  $(basename "$0") test
  $(basename "$0") flood-router eth0 1000 30
EOF
}

check_deps() {
    local ok=1
    echo "Checking dependencies..."
    for lib in libpcap libssl; do
        if pkg-config --exists "$lib" 2>/dev/null; then
            echo "  [OK]  $lib"
        else
            echo "  [MISSING] $lib — install with: sudo apt-get install ${lib}-dev"
            ok=0
        fi
    done
    if command -v cargo &>/dev/null; then
        echo "  [OK]  cargo ($(cargo --version))"
    else
        echo "  [MISSING] cargo — install Rust: https://rustup.rs"
        ok=0
    fi
    if command -v cc &>/dev/null; then
        echo "  [OK]  C compiler ($(cc --version | head -1))"
    else
        echo "  [MISSING] C compiler — install build-essential"
        ok=0
    fi
    [[ $ok -eq 1 ]] && echo "All dependencies satisfied." || exit 1
}

build_release() {
    cd "$PROJECT_DIR"
    echo "Building Rust frontend (release)..."
    cargo build --release
    echo "Building C tools..."
    make all
    echo "Build complete: target/release/$BINARY"
}

build_debug() {
    cd "$PROJECT_DIR"
    echo "Building Rust frontend (debug)..."
    cargo build
    echo "Debug build: target/debug/$BINARY"
}

run_tests() {
    cd "$PROJECT_DIR"
    echo "Running unit tests..."
    cargo test --lib -- --test-threads=4
}

run_coverage() {
    cd "$PROJECT_DIR"
    if ! command -v cargo-llvm-cov &>/dev/null; then
        echo "cargo-llvm-cov not installed. Run: cargo install cargo-llvm-cov"
        exit 1
    fi
    cargo llvm-cov --lib --html --output-dir llvm-cov-report
    echo "Coverage report: llvm-cov-report/index.html"
}

run_lint() {
    cd "$PROJECT_DIR"
    echo "Running clippy..."
    cargo clippy --all-targets -- -D warnings
    echo "Running rustfmt check..."
    cargo fmt --check
    echo "Lint passed."
}

do_install() {
    cd "$PROJECT_DIR"
    build_release
    echo "Installing $BINARY to $INSTALL_DIR..."
    sudo install -m 0755 "target/release/$BINARY" "$INSTALL_DIR/$BINARY"
    sudo make install
    echo "Installed."
}

do_uninstall() {
    echo "Removing $INSTALL_DIR/$BINARY..."
    sudo rm -f "$INSTALL_DIR/$BINARY"
    echo "Uninstalled."
}

do_clean() {
    cd "$PROJECT_DIR"
    echo "Cleaning..."
    cargo clean
    make clean 2>/dev/null || true
    echo "Clean."
}

flood_shortcut() {
    local cmd="$1" iface="${2:-eth0}" rate="${3:-0}" secs="${4:-0}"
    local ty_bin="$PROJECT_DIR/target/release/$BINARY"
    [[ -x "$ty_bin" ]] || { echo "Binary not found — run: $(basename "$0") build"; exit 1; }
    local stop_arg=""
    [[ "$secs" -gt 0 ]] && stop_arg="--stop-after-secs $secs"
    # shellcheck disable=SC2086
    exec "$ty_bin" $stop_arg "$cmd" -i "$iface" -r "$rate"
}

case "${1:-help}" in
    build)       build_release ;;
    build-debug) build_debug ;;
    test)        run_tests ;;
    coverage)    run_coverage ;;
    install)     do_install ;;
    uninstall)   do_uninstall ;;
    clean)       do_clean ;;
    check-deps)  check_deps ;;
    lint)        run_lint ;;
    c-tools)
        cd "$PROJECT_DIR"
        make all
        ;;
    flood-router)  flood_shortcut flood-router  "${2:-}" "${3:-0}" "${4:-0}" ;;
    flood-sol)     flood_shortcut flood-solicitate "${2:-}" "${3:-0}" "${4:-0}" ;;
    flood-adv)     flood_shortcut flood-advertise  "${2:-}" "${3:-0}" "${4:-0}" ;;
    flood-mld)     flood_shortcut flood-mld        "${2:-}" "${3:-0}" "${4:-0}" ;;
    flood-dhcp6)   flood_shortcut flood-dhcp6      "${2:-}" "${3:-0}" "${4:-0}" ;;
    flood-rs)      flood_shortcut flood-rs         "${2:-}" "${3:-0}" "${4:-0}" ;;
    help|--help|-h) usage ;;
    *)
        echo "Unknown command: $1"
        usage
        exit 1
        ;;
esac
