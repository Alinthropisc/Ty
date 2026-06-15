//! Raw FFI bindings to libty (the C packet engine).
//!
//! C symbols keep their original `thc_*` names; Rust callers use the `ty_*`
//! aliases declared here via `#[link_name]`.  All functions are `unsafe`.
#![allow(dead_code)]

use libc::{c_char, c_int, c_uchar, c_uint};

unsafe extern "C" {
    // ── address / interface helpers ──────────────────────────────────────────

    #[link_name = "thc_resolve6"]
    pub fn ty_resolve6(target: *const c_char) -> *mut c_uchar;

    #[link_name = "thc_get_own_mac"]
    pub fn ty_get_own_mac(iface: *const c_char) -> *mut c_uchar;

    #[link_name = "thc_get_own_ipv6"]
    pub fn ty_get_own_ipv6(
        iface:  *const c_char,
        dst:    *mut c_uchar,
        prefer: c_int,
    ) -> *mut c_uchar;

    #[link_name = "thc_get_multicast_mac"]
    pub fn ty_get_multicast_mac(dst: *mut c_uchar) -> *mut c_uchar;

    #[link_name = "thc_get_mac"]
    pub fn ty_get_mac(
        iface: *const c_char,
        src:   *mut c_uchar,
        dst:   *mut c_uchar,
    ) -> *mut c_uchar;

    #[link_name = "thc_get_mtu"]
    pub fn ty_get_mtu(iface: *const c_char) -> c_int;

    #[link_name = "thc_ipv6_rawmode"]
    pub fn ty_ipv6_rawmode(mode: c_int);

    // ── packet construction ──────────────────────────────────────────────────

    #[link_name = "thc_create_ipv6_extended"]
    pub fn ty_create_ipv6(
        iface:   *const c_char,
        prefer:  c_int,
        pkt_len: *mut c_int,
        src:     *mut c_uchar,
        dst:     *mut c_uchar,
        ttl:     c_int,
        length:  c_int,
        label:   c_int,
        class:   c_int,
        version: c_int,
    ) -> *mut c_uchar;

    #[link_name = "thc_add_hdr_hopbyhop"]
    pub fn ty_add_hdr_hopbyhop(
        pkt:     *mut c_uchar,
        pkt_len: *mut c_int,
        buf:     *mut c_uchar,
        buflen:  c_int,
    ) -> c_int;

    #[link_name = "thc_add_hdr_fragment"]
    pub fn ty_add_hdr_fragment(
        pkt:        *mut c_uchar,
        pkt_len:    *mut c_int,
        offset:     c_int,
        more_frags: c_int,
        id:         c_uint,
    ) -> c_int;

    #[link_name = "thc_add_hdr_dst"]
    pub fn ty_add_hdr_dst(
        pkt:     *mut c_uchar,
        pkt_len: *mut c_int,
        buf:     *mut c_uchar,
        buflen:  c_int,
    ) -> c_int;

    #[link_name = "thc_add_icmp6"]
    pub fn ty_add_icmp6(
        pkt:      *mut c_uchar,
        pkt_len:  *mut c_int,
        type_:    c_int,
        code:     c_int,
        flags:    c_uint,
        data:     *mut c_uchar,
        data_len: c_int,
        checksum: c_int,
    ) -> c_int;

    #[link_name = "thc_add_udp"]
    pub fn ty_add_udp(
        pkt:      *mut c_uchar,
        pkt_len:  *mut c_int,
        src_port: c_int,
        dst_port: c_int,
        checksum: c_int,
        data:     *mut c_uchar,
        data_len: c_int,
    ) -> c_int;

    // ── packet send / generate ───────────────────────────────────────────────

    #[link_name = "thc_generate_and_send_pkt"]
    pub fn ty_send_pkt(
        iface:   *const c_char,
        srcmac:  *mut c_uchar,
        dstmac:  *mut c_uchar,
        pkt:     *mut c_uchar,
        pkt_len: *mut c_int,
    ) -> c_int;

    #[link_name = "thc_generate_pkt"]
    pub fn ty_generate_pkt(
        iface:   *const c_char,
        srcmac:  *mut c_uchar,
        dstmac:  *mut c_uchar,
        pkt:     *mut c_uchar,
        pkt_len: *mut c_int,
    ) -> c_int;

    #[link_name = "thc_send_pkt"]
    pub fn ty_send_raw_pkt(
        iface:   *const c_char,
        pkt:     *mut c_uchar,
        pkt_len: *mut c_int,
    ) -> c_int;

    #[link_name = "thc_send_as_fragment6"]
    pub fn ty_send_as_fragment6(
        iface:    *const c_char,
        src:      *mut c_uchar,
        dst:      *mut c_uchar,
        type_:    c_uchar,
        data:     *mut c_uchar,
        data_len: c_int,
        frag_len: c_int,
    ) -> c_int;

    #[link_name = "thc_send_raguard_bypass6"]
    pub fn ty_send_raguard_bypass6(
        iface:    *const c_char,
        src:      *mut c_uchar,
        dst:      *mut c_uchar,
        srcmac:   *mut c_uchar,
        dstmac:   *mut c_uchar,
        type_:    c_uchar,
        data:     *mut c_uchar,
        data_len: c_int,
        mtu:      c_int,
    ) -> c_int;

    #[link_name = "thc_destroy_packet"]
    pub fn ty_destroy_packet(pkt: *mut c_uchar) -> *mut c_uchar;

    // ── misc / pcap ──────────────────────────────────────────────────────────

    #[link_name = "thc_ipv62notation"]
    pub fn ty_ipv6_to_str(ipv6: *mut c_uchar) -> *mut c_char;

    #[link_name = "thc_parse_mac"]
    pub fn ty_parse_mac(text: *const c_char, mac: *mut c_uchar) -> c_int;

    #[link_name = "thc_routeradv6"]
    pub fn ty_routeradv6(
        iface:       *const c_char,
        src:         *mut c_uchar,
        dst:         *mut c_uchar,
        srcmac:      *mut c_uchar,
        default_ttl: c_uchar,
        managed:     c_int,
        prefix:      *mut c_uchar,
        prefixlen:   c_int,
        mtu:         c_int,
        lifetime:    c_uint,
    ) -> c_int;

    #[link_name = "thc_ping26"]
    pub fn ty_ping6(
        iface:  *const c_char,
        srcmac: *mut c_uchar,
        dstmac: *mut c_uchar,
        src:    *mut c_uchar,
        dst:    *mut c_uchar,
        size:   c_int,
        count:  c_int,
    ) -> c_int;

    #[link_name = "thc_pcap_init"]
    pub fn ty_pcap_init(iface: *const c_char, capture: *const c_char) -> *mut libc::c_void;

    #[link_name = "thc_pcap_check"]
    pub fn ty_pcap_check(
        p:    *mut libc::c_void,
        func: *const c_char,
        opt:  *mut c_char,
    ) -> c_int;

    #[link_name = "thc_pcap_close"]
    pub fn ty_pcap_close(p: *mut libc::c_void) -> *mut c_char;

    #[link_name = "checksum_pseudo_header"]
    pub fn ty_checksum_pseudo_header(
        src:    *mut c_uchar,
        dst:    *mut c_uchar,
        type_:  c_uchar,
        data:   *mut c_uchar,
        length: c_int,
    ) -> c_int;

    pub static mut debug: c_int;
    pub static mut _thc_ipv6_showerrors: c_int;
    pub static mut do_hdr_size: c_int;
}

// ── PREFER_* constants (mirror thc-ipv6.h) ──────────────────────────────────
pub const PREFER_LINK:   c_int = 32;
pub const PREFER_GLOBAL: c_int = 0;

// ── IPv6 extension header next-header numbers ────────────────────────────────
pub const NXT_HBH:   c_int = 0;   // Hop-by-Hop Options
pub const NXT_FRAG:  c_int = 44;  // Fragment
pub const NXT_DST:   c_int = 60;  // Destination Options
pub const NXT_ICMP6: c_int = 58;  // ICMPv6
pub const NXT_UDP:   c_int = 17;
pub const NXT_TCP:   c_int = 6;

// ── ICMPv6 type constants ─────────────────────────────────────────────────────
pub const ICMP6_ECHO_REQUEST: c_int = 128;
pub const ICMP6_ECHO_REPLY:   c_int = 129;
pub const ICMP6_MLD_QUERY:    c_int = 130;
pub const ICMP6_MLD_REPORT:   c_int = 131;
pub const ICMP6_MLD_DONE:     c_int = 132;
pub const ICMP6_ROUTERSOL:    c_int = 133;
pub const ICMP6_ROUTERADV:    c_int = 134;
pub const ICMP6_NEIGHBORSOL:  c_int = 135;
pub const ICMP6_NEIGHBORADV:  c_int = 136;
pub const ICMP6_REDIRECT:     c_int = 137;
pub const ICMP6_MLD2_REPORT:  c_int = 143;
pub const ICMP6_TOOBIG:       c_int = 2;
pub const ICMP6_UNREACHABLE:  c_int = 1;
pub const ICMP6_TIME_EXCEEDED: c_int = 3;
pub const ICMP6_PARAM_PROBLEM: c_int = 4;
