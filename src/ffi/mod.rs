//! Raw FFI bindings to libty (thc-ipv6-lib.c).
#![allow(dead_code)]
//!
//! All functions are `unsafe` — callers must ensure the interface string is
//! valid and that returned pointers are freed via the corresponding
//! `thc_destroy_*` helpers.

use libc::{c_char, c_int, c_uchar, c_uint};

unsafe extern "C" {
    // ── address / interface helpers ──────────────────────────────────────────
    pub fn thc_resolve6(target: *const c_char) -> *mut c_uchar;
    pub fn thc_get_own_mac(iface: *const c_char) -> *mut c_uchar;
    pub fn thc_get_own_ipv6(
        iface: *const c_char,
        dst: *mut c_uchar,
        prefer: c_int,
    ) -> *mut c_uchar;
    pub fn thc_get_multicast_mac(dst: *mut c_uchar) -> *mut c_uchar;
    pub fn thc_get_mac(
        iface: *const c_char,
        src: *mut c_uchar,
        dst: *mut c_uchar,
    ) -> *mut c_uchar;
    pub fn thc_get_mtu(iface: *const c_char) -> c_int;
    pub fn thc_ipv6_rawmode(mode: c_int);

    // ── packet construction ──────────────────────────────────────────────────
    pub fn thc_create_ipv6_extended(
        iface: *const c_char,
        prefer: c_int,
        pkt_len: *mut c_int,
        src: *mut c_uchar,
        dst: *mut c_uchar,
        ttl: c_int,
        length: c_int,
        label: c_int,
        class: c_int,
        version: c_int,
    ) -> *mut c_uchar;

    pub fn thc_add_hdr_hopbyhop(
        pkt: *mut c_uchar,
        pkt_len: *mut c_int,
        buf: *mut c_uchar,
        buflen: c_int,
    ) -> c_int;

    pub fn thc_add_hdr_oneshotfragment(
        pkt: *mut c_uchar,
        pkt_len: *mut c_int,
        id: c_uint,
    ) -> c_int;

    pub fn thc_add_hdr_dst(
        pkt: *mut c_uchar,
        pkt_len: *mut c_int,
        buf: *mut c_uchar,
        buflen: c_int,
    ) -> c_int;

    pub fn thc_add_icmp6(
        pkt: *mut c_uchar,
        pkt_len: *mut c_int,
        type_: c_int,
        code: c_int,
        flags: c_uint,
        data: *mut c_uchar,
        data_len: c_int,
        checksum: c_int,
    ) -> c_int;

    // ── packet send / generate ───────────────────────────────────────────────
    pub fn thc_generate_and_send_pkt(
        iface: *const c_char,
        srcmac: *mut c_uchar,
        dstmac: *mut c_uchar,
        pkt: *mut c_uchar,
        pkt_len: *mut c_int,
    ) -> c_int;

    pub fn thc_generate_pkt(
        iface: *const c_char,
        srcmac: *mut c_uchar,
        dstmac: *mut c_uchar,
        pkt: *mut c_uchar,
        pkt_len: *mut c_int,
    ) -> c_int;

    pub fn thc_send_pkt(
        iface: *const c_char,
        pkt: *mut c_uchar,
        pkt_len: *mut c_int,
    ) -> c_int;

    pub fn thc_send_as_fragment6(
        iface: *const c_char,
        src: *mut c_uchar,
        dst: *mut c_uchar,
        type_: c_uchar,
        data: *mut c_uchar,
        data_len: c_int,
        frag_len: c_int,
    ) -> c_int;

    pub fn thc_send_raguard_bypass6(
        iface: *const c_char,
        src: *mut c_uchar,
        dst: *mut c_uchar,
        srcmac: *mut c_uchar,
        dstmac: *mut c_uchar,
        type_: c_uchar,
        data: *mut c_uchar,
        data_len: c_int,
        mtu: c_int,
    ) -> c_int;

    pub fn thc_destroy_packet(pkt: *mut c_uchar) -> *mut c_uchar;

    // ── misc ─────────────────────────────────────────────────────────────────
    pub fn thc_ipv62notation(ipv6: *mut c_uchar) -> *mut c_char;
    pub fn thc_parse_mac(text: *const c_char, mac: *mut c_uchar) -> c_int;
    pub fn thc_routeradv6(
        iface: *const c_char,
        src: *mut c_uchar,
        dst: *mut c_uchar,
        srcmac: *mut c_uchar,
        default_ttl: c_uchar,
        managed: c_int,
        prefix: *mut c_uchar,
        prefixlen: c_int,
        mtu: c_int,
        lifetime: c_uint,
    ) -> c_int;

    pub fn thc_ping26(
        iface: *const c_char,
        srcmac: *mut c_uchar,
        dstmac: *mut c_uchar,
        src: *mut c_uchar,
        dst: *mut c_uchar,
        size: c_int,
        count: c_int,
    ) -> c_int;

    pub fn thc_pcap_init(iface: *const c_char, capture: *const c_char) -> *mut libc::c_void;
    pub fn thc_pcap_check(p: *mut libc::c_void, func: *const c_char, opt: *mut c_char) -> c_int;
    pub fn thc_pcap_close(p: *mut libc::c_void) -> *mut c_char;

    pub fn checksum_pseudo_header(
        src: *mut c_uchar,
        dst: *mut c_uchar,
        type_: c_uchar,
        data: *mut c_uchar,
        length: c_int,
    ) -> c_int;

    /// Append a UDP header to a packet under construction.
    ///
    /// `src_port` / `dst_port` are host-byte-order.  Pass `checksum = 0` to
    /// have libty compute the checksum automatically.
    pub fn thc_add_udp(
        pkt:      *mut c_uchar,
        pkt_len:  *mut c_int,
        src_port: c_int,
        dst_port: c_int,
        checksum: c_int,
        data:     *mut c_uchar,
        data_len: c_int,
    ) -> c_int;

    pub static mut debug: c_int;
    pub static mut _thc_ipv6_showerrors: c_int;
    pub static mut do_hdr_size: c_int;
}

// ── PREFER_* constants (mirror thc-ipv6.h) ──────────────────────────────────
pub const PREFER_LINK: c_int   = 32;
pub const PREFER_GLOBAL: c_int = 0;

// ── NXT_* next-header constants ───────────────────────────────────────────────
pub const NXT_ICMP6: c_int = 58;
pub const NXT_HBH: c_int   = 0;
pub const NXT_FRAG: c_int  = 44;
pub const NXT_DST: c_int   = 60;

// ── NXT_* next-header — additional protocol numbers ──────────────────────────
pub const NXT_UDP: c_int = 17;

// ── ICMP6 type constants ─────────────────────────────────────────────────────
pub const ICMP6_ROUTERADV:   c_int = 134;
pub const ICMP6_ROUTERSOL:   c_int = 133;
pub const ICMP6_NEIGHBORSOL: c_int = 135;
pub const ICMP6_NEIGHBORADV: c_int = 136;
pub const ICMP6_MLD_REPORT:  c_int = 131;
pub const ICMP6_TOOBIG:      c_int = 2;
