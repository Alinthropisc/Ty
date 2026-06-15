/*
 * ty — IPv6 Attack Toolkit, 2026 edition.
 *
 * Core library header (C23 / -std=c2x).
 *
 * License: AGPL v3.0 (see LICENSE file)
 */

#ifndef _TY_IPV6_H
#define _TY_IPV6_H

/* ── C23 feature detection ───────────────────────────────────────────────── */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#  define TY_C23 1
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201710L
#  define TY_C17 1
#endif

/* Standard attributes — available with -std=c2x in GCC ≥ 9.            */
/* [[nodiscard]] : warn when caller ignores returned pointer/value.       */
/* [[deprecated]]: mark legacy thc_* aliases.                             */
/* [[maybe_unused]]: silence unused-parameter warnings on C side.         */
#if defined(__GNUC__) || defined(__clang__)
#  define TY_NODISCARD     __attribute__((warn_unused_result))
#  define TY_DEPRECATED(m) __attribute__((deprecated(m)))
#  define TY_UNUSED        __attribute__((unused))
#  define TY_NORETURN      __attribute__((noreturn))
#  define TY_NONNULL(...)  __attribute__((nonnull(__VA_ARGS__)))
#  define TY_RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#  define TY_NODISCARD
#  define TY_DEPRECATED(m)
#  define TY_UNUSED
#  define TY_NORETURN
#  define TY_NONNULL(...)
#  define TY_RETURNS_NONNULL
#endif

#include <pcap.h>
#include <endian.h>
#include <stdint.h>
#include <stdbool.h>  /* bool, true, false — keyword in C23, macro in C99-C17 */

#ifdef _HAVE_SSL
#  include <openssl/evp.h>
#  include <openssl/rsa.h>
#  if OPENSSL_VERSION_NUMBER >= 0x30000000L
#    define TY_USE_OPENSSL_3_API 1
#  endif
#endif

/* ── Version / branding ──────────────────────────────────────────────────── */
#define VERSION  "4.0"
#define AUTHOR   "ty contributors"
#define RESOURCE "https://github.com/Alinthropisc/Ty"

/* ── Configuration ───────────────────────────────────────────────────────── */
#define TY_SPLITCONNECT_PORT      64446
#define TY_SPLITCONNECT_FROM_BYTE 0xff
#define TY_SPLITCONNECT_TO_BYTE   0xee

/* Legacy macros kept for binary compatibility with C tools. */
#define THC_SPLITCONNECT_PORT      TY_SPLITCONNECT_PORT
#define THC_SPLITCONNECT_FROM_BYTE TY_SPLITCONNECT_FROM_BYTE
#define THC_SPLITCONNECT_TO_BYTE   TY_SPLITCONNECT_TO_BYTE

#define SHOW_LIBRARY_ERRORS 1

/* ── ICMPv6 type constants ───────────────────────────────────────────────── */
#define ICMP6_UNREACH              1
#define ICMP6_TOOBIG               2
#define ICMP6_TTLEXEED             3
#define ICMP6_PARAMPROB            4
#define ICMP6_PING                 128
#define ICMP6_PONG                 129
#define ICMP6_PINGREQUEST          128
#define ICMP6_PINGREPLY            129
#define ICMP6_ECHOREQUEST          128
#define ICMP6_ECHOREPLY            129
#define ICMP6_MLD_QUERY            130
#define ICMP6_MLD_REPORT           131
#define ICMP6_MLD_DONE             132
#define ICMP6_ROUTERSOL            133
#define ICMP6_ROUTERADV            134
#define ICMP6_NEIGHBORSOL          135
#define ICMP6_NEIGHBORADV          136
#define ICMP6_REDIR                137
#define ICMP6_INFOREQUEST          139
#define ICMP6_NODEQUERY            139
#define ICMP6_INFOREPLY            140
#define ICMP6_NODEREPLY            140
#define ICMP6_INVNEIGHBORSOL       141
#define ICMP6_INVNEIGHBORADV       142
#define ICMP6_MLD2_REPORT          143
#define ICMP6_MOBILE_PREFIXSOL     146
#define ICMP6_MOBILE_PREFIXADV     147
#define ICMP6_CERTPATHSOL          148
#define ICMP6_CERTPATHADV          149
#define ICMP6_MLD_ROUTERADV        151
#define ICMP6_MLD_ROUTERSOL        152
#define ICMP6_MLD_ROUTERTERMINATION 153
#define ICMP6_ROUTERPROXYSOL       154
#define ICMP6_ROUTERPROXYADV       155

/* Neighbor Advertisement flag bits (big-endian u32 field). */
#define ICMP6_NEIGHBORADV_ROUTER    0x080000000u
#define ICMP6_NEIGHBORADV_SOLICIT   0x040000000u
#define ICMP6_NEIGHBORADV_OVERRIDE  0x020000000u

/* ── Address preference constants ────────────────────────────────────────── */
#define PREFER_HOST   16
#define PREFER_LINK   32
#define PREFER_GLOBAL  0

/* ── Byte-order helpers ──────────────────────────────────────────────────── */
#if __BYTE_ORDER == __LITTLE_ENDIAN
#  define _TAKE4 0
#  define _TAKE3 0
#  define _TAKE2 0
#elif __BYTE_ORDER == __BIG_ENDIAN
#  define _TAKE4 (sizeof(void *) - 4)
#  define _TAKE3 (sizeof(void *) - 3)
#  define _TAKE2 (sizeof(void *) - 2)
#else
#  error "Unknown byte order"
#endif

/* ── Next-header (protocol number) constants ─────────────────────────────── */
#define NXT_IP6              41
#define NXT_IPV6             41
#define NXT_INVALID         128
#define NXT_IGNORE           31
#define NXT_HDR               0
#define NXT_HOP               0
#define NXT_HBH               0
#define NXT_ROUTE            43
#define NXT_FRAG             44
#define NXT_NONXT            59
#define NXT_OPTS             60
#define NXT_DST              60
#define NXT_ESP              50
#define NXT_AH               51
#define NXT_MIPV6           135
#define NXT_MOBILITY        135
#define NXT_PIM             103
#define NXT_ICMP6            58
#define NXT_TCP               6
#define NXT_UDP              17
#define NXT_DATA            255
#define NXT_HOSTID          139
#define NXT_HOSTIDENTIFICATION 139
#define NXT_SHIM            140
#define NXT_SHIM6           140
#define NXT_IP4               4
#define NXT_IPV4              4
#define NXT_IP4_RUDIMENTARY  0xf4
#define NXT_IPV4_RUDIMENTARY 0xf4
#define NXT_IPIP              4
#define NXT_ICMP4             1

/* ── Ethernet / TCP constants ────────────────────────────────────────────── */
#define IPV6_FRAME_TYPE 0x86ddu

#define TCP_CWR 128u
#define TCP_ECN  64u
#define TCP_URG  32u
#define TCP_ACK  16u
#define TCP_PSH   8u
#define TCP_RST   4u
#define TCP_SYN   2u
#define TCP_FIN   1u

#define DO_CHECKSUM 0xfaf4u

/* ── Packet structure types ──────────────────────────────────────────────── */

typedef struct {
  unsigned char dst[6];
  unsigned char src[6];
  unsigned int  type : 16;
} ty_ethernet_t;

typedef struct {
  unsigned char *pkt;
  int            pkt_len;
  char          *next_segment;
  char          *final;
  int            final_type;
  unsigned int   version;
  unsigned char  class;
  unsigned int   label;
  unsigned int   length;
  unsigned char  next;
  unsigned char  ttl;
  unsigned char  src[16];
  unsigned char  dst[16];
  unsigned char *final_dst;
  unsigned char *original_src;
} ty_ipv6_hdr;

typedef struct {
  char          *next_segment;
  unsigned char  next;
  unsigned char  length;
  unsigned char *data;
  int            data_len;
} ty_ipv6_ext_hdr;

typedef struct {
  unsigned char  type;
  unsigned char  code;
  unsigned int   checksum : 16;
  unsigned int   flags;
  unsigned char *data;
  int            data_len;
} ty_icmp6_hdr;

typedef struct {
  uint16_t       sport;
  uint16_t       dport;
  uint32_t       sequence;
  uint32_t       ack;
  unsigned char  length;
  unsigned char  flags;
  uint16_t       window;
  uint16_t       checksum;
  uint16_t       urgent;
  unsigned char *option;
  int            option_len;
  unsigned char *data;
  int            data_len;
} ty_tcp_hdr;

typedef struct {
  uint16_t       sport;
  uint16_t       dport;
  uint16_t       length;
  uint16_t       checksum;
  unsigned char *data;
  int            data_len;
} ty_udp_hdr;

typedef struct {
  unsigned char  ver_hlen;
  unsigned char  tos;
  uint16_t       size;
  uint16_t       id;
  uint16_t       frag;
  unsigned char  ttl;
  unsigned char  proto;
  uint16_t       checksum;
  uint32_t       src;
  uint32_t       dst;
} ty_ipv4_hdr;

typedef struct {
  char *next_segment;
  char  dummy[8];
} ty_dummy_hdr;

/* ── Legacy typedef aliases (for existing C tools) ───────────────────────── */
typedef ty_ethernet_t  thc_ethernet;
typedef ty_ipv6_hdr    thc_ipv6_hdr;
typedef ty_ipv6_ext_hdr thc_ipv6_ext_hdr;
typedef ty_icmp6_hdr   thc_icmp6_hdr;
typedef ty_tcp_hdr     thc_tcp_hdr;
typedef ty_udp_hdr     thc_udp_hdr;
typedef ty_ipv4_hdr    thc_ipv4_hdr;
typedef ty_dummy_hdr   thc_dummy_hdr;

/* ── Global state ────────────────────────────────────────────────────────── */
extern int debug;
extern int _thc_ipv6_showerrors;
extern int do_hdr_size;

/* ── Function declarations with C23 / GCC attributes ────────────────────── */

/* pcap / capture */
extern void    thc_ipv6_show_errors(int mode);
extern int     thc_pcap_function(char *interface, char *capture,
                                 char *function, int promisc, char *opt);
TY_NODISCARD
extern pcap_t *thc_pcap_init(char *interface, char *capture);
TY_NODISCARD
extern pcap_t *thc_pcap_init_promisc(char *interface, unsigned char *capture);
TY_NODISCARD
extern unsigned char *thc_pcap_get_data(const struct pcap_pkthdr *header,
                                        const unsigned char *data,
                                        int offset, int *len);
extern void  thc_ipv6_rawmode(int mode);
extern int   thc_pcap_check(pcap_t *p, char *function, char *opt);
extern char *thc_pcap_close(pcap_t *p);

/* address / interface helpers */
extern int thc_parse_mac(const char *text, unsigned char *mac);
TY_NODISCARD
extern unsigned char *thc_resolve6(char *target);
TY_NODISCARD
extern unsigned char *thc_lookup_ipv6_mac(char *interface, unsigned char *dst);
TY_NODISCARD
extern unsigned char *thc_get_own_mac(char *interface);
extern int            thc_get_mtu(char *interface);
TY_NODISCARD
extern unsigned char *thc_get_own_ipv6(char *interface, unsigned char *dst,
                                        int prefer);
TY_NODISCARD
extern unsigned char *thc_get_multicast_mac(unsigned char *dst);
TY_NODISCARD
extern unsigned char *thc_get_mac(char *interface, unsigned char *src,
                                   unsigned char *dst);
TY_NODISCARD
extern unsigned char *thc_inverse_packet(unsigned char *pkt, int pkt_len);

/* high-level send helpers */
extern int thc_ping6(char *interface, unsigned char *src, unsigned char *dst,
                     int size, int count);
extern int thc_ping26(char *interface, unsigned char *srcmac,
                      unsigned char *dstmac, unsigned char *src,
                      unsigned char *dst, int size, int count);
extern int thc_neighboradv6(char *interface, unsigned char *src,
                             unsigned char *dst, unsigned char *srcmac,
                             unsigned char *dstmac, unsigned int flags,
                             unsigned char *target);
extern int thc_neighborsol6(char *interface, unsigned char *src,
                             unsigned char *dst, unsigned char *target,
                             unsigned char *srcmac, unsigned char *dstmac);
extern int thc_routeradv6(char *interface, unsigned char *src,
                           unsigned char *dst, unsigned char *srcmac,
                           unsigned char default_ttl, int managed,
                           unsigned char *prefix, int prefixlen,
                           int mtu, unsigned int lifetime);
extern int thc_routersol6(char *interface, unsigned char *src,
                           unsigned char *dst, unsigned char *srcmac,
                           unsigned char *dstmac);
extern int thc_toobig6(char *interface, unsigned char *src,
                        unsigned char *srcmac, unsigned char *dstmac,
                        unsigned int mtu, unsigned char *pkt, int pkt_len);
extern int thc_paramprob6(char *interface, unsigned char *src,
                           unsigned char *srcmac, unsigned char *dstmac,
                           unsigned char code, unsigned int pointer,
                           unsigned char *pkt, int pkt_len);
extern int thc_unreach6(char *interface, unsigned char *src,
                         unsigned char *srcmac, unsigned char *dstmac,
                         unsigned char code, unsigned char *pkt, int pkt_len);
extern int thc_redir6(char *interface, unsigned char *src,
                       unsigned char *srcmac, unsigned char *dstmac,
                       unsigned char *newrouter, unsigned char *newroutermac,
                       unsigned char *pkt, int pkt_len);
extern int thc_send_as_fragment6(char *interface, unsigned char *src,
                                  unsigned char *dst, unsigned char type,
                                  unsigned char *data, int data_len,
                                  int frag_len);
extern int thc_send_raguard_bypass6(char *interface, unsigned char *src,
                                     unsigned char *dst, unsigned char *srcmac,
                                     unsigned char *dstmac, unsigned char type,
                                     unsigned char *data, int data_len, int mtu);
extern int thc_send_as_overlapping_first_fragment6(
    char *interface, unsigned char *src, unsigned char *dst,
    unsigned char type, unsigned char *data, int data_len,
    int frag_len, int overlap_spoof_type);
extern int thc_send_as_overlapping_last_fragment6(
    char *interface, unsigned char *src, unsigned char *dst,
    unsigned char type, unsigned char *data, int data_len,
    int frag_len, int overlap_spoof_type);

/* packet construction */
TY_NODISCARD
extern unsigned char *thc_create_ipv6(char *interface, int *pkt_len,
                                       unsigned char *src, unsigned char *dst);
TY_NODISCARD
extern unsigned char *thc_create_ipv6_extended(char *interface, int prefer,
                                                int *pkt_len,
                                                unsigned char *src,
                                                unsigned char *dst,
                                                int ttl, int length,
                                                int label, int class,
                                                int version);
extern int thc_add_hdr_misc(unsigned char *pkt, int *pkt_len,
                             unsigned char type, int len,
                             unsigned char *buf, int buflen);
extern int thc_add_hdr_route(unsigned char *pkt, int *pkt_len,
                              unsigned char **routers,
                              unsigned char routerptr);
extern int thc_add_hdr_mobileroute(unsigned char *pkt, int *pkt_len,
                                    unsigned char *dst);
extern int thc_add_hdr_oneshotfragment(unsigned char *pkt, int *pkt_len,
                                        unsigned int id);
extern int thc_add_hdr_fragment(unsigned char *pkt, int *pkt_len,
                                 int offset, char more_frags,
                                 unsigned int id);
extern int thc_add_hdr_dst(unsigned char *pkt, int *pkt_len,
                            unsigned char *buf, int buflen);
extern int thc_add_hdr_hopbyhop(unsigned char *pkt, int *pkt_len,
                                  unsigned char *buf, int buflen);
extern int thc_add_hdr_nonxt(unsigned char *pkt, int *pkt_len, int hdropt);
extern int thc_add_icmp6(unsigned char *pkt, int *pkt_len,
                          int type, int code, unsigned int flags,
                          unsigned char *data, int data_len, int checksum);
extern int thc_add_pim(unsigned char *pkt, int *pkt_len,
                        unsigned char type,
                        unsigned char *data, int data_len);
extern int thc_add_tcp(unsigned char *pkt, int *pkt_len,
                        uint16_t sport, uint16_t dport,
                        uint32_t sequence, uint32_t ack,
                        unsigned char flags, uint16_t window,
                        uint16_t urgent, char *option, int option_len,
                        char *data, int data_len);
extern int thc_add_udp(unsigned char *pkt, int *pkt_len,
                        uint16_t sport, uint16_t dport,
                        unsigned int checksum, char *data, int data_len);
extern int thc_add_ipv4(unsigned char *pkt, int *pkt_len, int src, int dst);
extern int thc_add_ipv4_extended(unsigned char *pkt, int *pkt_len,
                                  int src, int dst,
                                  unsigned char tos, int id,
                                  unsigned char ttl);
extern int thc_add_ipv4_rudimentary(unsigned char *pkt, int *pkt_len,
                                     int src, int dst, int sport, int port);
extern int thc_add_data6(unsigned char *pkt, int *pkt_len,
                          unsigned char type,
                          unsigned char *data, int data_len);

/* packet send / generate */
extern int thc_generate_and_send_pkt(char *interface, unsigned char *srcmac,
                                      unsigned char *dstmac,
                                      unsigned char *pkt, int *pkt_len);
extern int thc_generate_pkt(char *interface, unsigned char *srcmac,
                             unsigned char *dstmac,
                             unsigned char *pkt, int *pkt_len);
extern int thc_send_pkt(char *interface, unsigned char *pkt, int *pkt_len);
TY_NODISCARD
extern unsigned char *thc_destroy_packet(unsigned char *pkt);

/* misc */
extern int   thc_open_ipv6(char *interface);
extern int   thc_is_dst_local(char *interface, unsigned char *dst);
extern int   checksum_pseudo_header(unsigned char *src, unsigned char *dst,
                                     unsigned char type, unsigned char *data,
                                     int length);
extern int   calculate_checksum(unsigned char *data, int data_len);
extern void  thc_dump_data(unsigned char *buf, int len, char *text);
TY_NODISCARD
extern unsigned char *thc_ipv62string(unsigned char *ipv6);
TY_NODISCARD
extern unsigned char *thc_string2ipv6(unsigned char *string);
TY_NODISCARD
extern unsigned char *thc_string2notation(unsigned char *string);
TY_NODISCARD
extern unsigned char *thc_ipv62notation(unsigned char *string);
TY_NODISCARD
extern unsigned char *thc_memstr(char *haystack, char *needle,
                                  int haystack_length, int needle_length);
extern void  thc_notation2beauty(unsigned char *ipv6);
extern int   thc_bind_udp_port(int port);
extern int   thc_bind_multicast_to_socket(int s, char *interface, char *src);
extern char *warlord_checkFingerprint(char *buffer, int len);

/* ── SSL / CGA support ───────────────────────────────────────────────────── */
#ifdef _HAVE_SSL

typedef struct {
  unsigned char  type;
  unsigned char  len;
  unsigned char  pad_len;
  unsigned char  resv;
  unsigned char  modifier[16];
  unsigned char  prefix[8];
  unsigned char  collision_cnt;
  unsigned char  coll2;
  unsigned char *pub_key;
  unsigned char *exts;
  unsigned char *pad;
} ty_cga_hdr;

typedef struct {
  unsigned char      type;
  unsigned char      len;
  unsigned char      resv[6];
  unsigned long long timeval;
} ty_timestamp_hdr;

typedef struct {
  unsigned char type;
  unsigned char len;
  char          nonce[6];
} ty_nonce_hdr;

typedef struct {
  unsigned char  type;
  unsigned char  len;
  short int      resv;
  unsigned char  key_hash[16];
  char          *sign;
  char          *pad;
} ty_rsa_hdr;

typedef struct {
#ifdef TY_USE_OPENSSL_3_API
  EVP_PKEY *pkey;
#else
  RSA *rsa;
#endif
  int len;
} ty_key_t;

typedef struct {
  unsigned char *data;
  int            len;
} ty_opt_t;

/* Legacy aliases */
typedef ty_cga_hdr       thc_cga_hdr;
typedef ty_timestamp_hdr thc_timestamp_hdr;
typedef ty_nonce_hdr     thc_nonce_hdr;
typedef ty_rsa_hdr       thc_rsa_hdr;
typedef ty_key_t         thc_key_t;
typedef ty_opt_t         opt_t;

TY_NODISCARD
extern ty_key_t    *thc_generate_key(int key_len);
TY_NODISCARD
extern ty_cga_hdr  *thc_generate_cga(unsigned char *prefix, ty_key_t *key,
                                      unsigned char **cga);
extern int          thc_add_send(unsigned char *pkt, int *pkt_len,
                                  int type, int code, unsigned int flags,
                                  unsigned char *data, int data_len,
                                  ty_cga_hdr *cga_hdr, ty_key_t *key,
                                  unsigned char *tag, int checksum);
#endif /* _HAVE_SSL */

/* ── C23 static assertions ───────────────────────────────────────────────── */
static_assert(sizeof(unsigned char) == 1, "unsigned char must be 1 byte");
static_assert(sizeof(uint16_t)      == 2, "uint16_t must be 2 bytes");
static_assert(sizeof(uint32_t)      == 4, "uint32_t must be 4 bytes");

#endif /* _TY_IPV6_H */
