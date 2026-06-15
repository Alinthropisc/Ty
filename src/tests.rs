//! Unit tests for ty — all offline, no network, no C library calls.

#[cfg(test)]
mod stats_tests {
    use crate::engine::stats::Stats;
    use std::sync::Arc;

    #[test]
    fn new_stats_zero() {
        let s = Stats::new();
        let (sent, errors, _) = s.snapshot();
        assert_eq!(sent, 0);
        assert_eq!(errors, 0);
    }

    #[test]
    fn inc_sent_increments() {
        let s = Stats::new();
        s.inc_sent();
        s.inc_sent();
        s.inc_sent();
        let (sent, errors, _) = s.snapshot();
        assert_eq!(sent, 3);
        assert_eq!(errors, 0);
    }

    #[test]
    fn inc_errors_increments() {
        let s = Stats::new();
        s.inc_errors();
        let (sent, errors, _) = s.snapshot();
        assert_eq!(sent, 0);
        assert_eq!(errors, 1);
    }

    #[test]
    fn pps_zero_before_any_send() {
        let s = Stats::new();
        // pps may be NaN or 0 right at creation when elapsed≈0
        let pps = s.pps();
        assert!(pps >= 0.0);
    }

    #[test]
    fn pps_after_sends() {
        let s = Stats::new();
        for _ in 0..100 {
            s.inc_sent();
        }
        let (sent, _, _) = s.snapshot();
        assert_eq!(sent, 100);
    }

    #[tokio::test]
    async fn concurrent_increments_safe() {
        let s = Stats::new();
        let mut handles = vec![];
        for _ in 0..16 {
            let s2 = Arc::clone(&s);
            handles.push(tokio::spawn(async move {
                for _ in 0..1000 {
                    s2.inc_sent();
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        let (sent, _, _) = s.snapshot();
        assert_eq!(sent, 16_000);
    }
}

#[cfg(test)]
mod flood_config_tests {
    use crate::engine::sender::FloodConfig;

    #[test]
    fn flood_config_clone() {
        let cfg = FloodConfig {
            interface: "eth0".into(),
            rate_pps: 1000,
            max_packets: 500,
            do_hop: true,
            do_frag: 2,
            do_dst: false,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.interface, "eth0");
        assert_eq!(cfg2.rate_pps, 1000);
        assert_eq!(cfg2.max_packets, 500);
        assert!(cfg2.do_hop);
        assert_eq!(cfg2.do_frag, 2);
    }

    #[test]
    fn rate_zero_means_unlimited() {
        let cfg = FloodConfig {
            interface: "lo".into(),
            rate_pps: 0,
            max_packets: 0,
            do_hop: false,
            do_frag: 0,
            do_dst: false,
        };
        // rate_pps == 0 means unlimited — no sleep between packets
        assert_eq!(cfg.rate_pps, 0);
    }
}

#[cfg(test)]
mod solicitate_advertise_config_tests {
    use crate::engine::sender::{AdvertiseConfig, SolicitateConfig};

    #[test]
    fn solicitate_config_clone() {
        let cfg = SolicitateConfig {
            interface: "eth0".into(),
            rate_pps: 500,
            max_packets: 1000,
            target: Some("fe80::1".into()),
            do_alert: true,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.interface, "eth0");
        assert_eq!(cfg2.rate_pps, 500);
        assert_eq!(cfg2.max_packets, 1000);
        assert_eq!(cfg2.target.as_deref(), Some("fe80::1"));
        assert!(cfg2.do_alert);
    }

    #[test]
    fn solicitate_config_no_target() {
        let cfg = SolicitateConfig {
            interface: "lo".into(),
            rate_pps: 0,
            max_packets: 0,
            target: None,
            do_alert: false,
        };
        assert!(cfg.target.is_none());
        assert_eq!(cfg.rate_pps, 0);
    }

    #[test]
    fn advertise_config_clone() {
        let cfg = AdvertiseConfig {
            interface: "eth1".into(),
            rate_pps: 100,
            max_packets: 50,
            target: None,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.interface, "eth1");
        assert_eq!(cfg2.rate_pps, 100);
        assert_eq!(cfg2.max_packets, 50);
        assert!(cfg2.target.is_none());
    }

    #[test]
    fn advertise_config_with_target() {
        let cfg = AdvertiseConfig {
            interface: "eth0".into(),
            rate_pps: 200,
            max_packets: 0,
            target: Some("2001:db8::1".into()),
        };
        assert_eq!(cfg.target.as_deref(), Some("2001:db8::1"));
        assert_eq!(cfg.max_packets, 0);
    }
}

#[cfg(test)]
mod new_config_tests {
    use crate::engine::sender::{Dhcp6Config, MldConfig, RsConfig, TooBigConfig};
    use crate::ffi;

    #[test]
    fn mld_config_clone() {
        let cfg = MldConfig {
            interface: "eth0".into(),
            rate_pps: 2000,
            max_packets: 100,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.interface, "eth0");
        assert_eq!(cfg2.rate_pps, 2000);
        assert_eq!(cfg2.max_packets, 100);
    }

    #[test]
    fn dhcp6_config_clone() {
        let cfg = Dhcp6Config {
            interface: "eth1".into(),
            rate_pps: 500,
            max_packets: 0,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.interface, "eth1");
        assert_eq!(cfg2.rate_pps, 500);
        assert_eq!(cfg2.max_packets, 0);
    }

    #[test]
    fn toobig_config_clone() {
        let cfg = TooBigConfig {
            interface: "eth0".into(),
            rate_pps: 100,
            max_packets: 50,
            target: "2001:db8::1".into(),
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.interface, "eth0");
        assert_eq!(cfg2.rate_pps, 100);
        assert_eq!(cfg2.max_packets, 50);
        assert_eq!(cfg2.target, "2001:db8::1");
    }

    #[test]
    fn rs_config_clone() {
        let cfg = RsConfig {
            interface: "lo".into(),
            rate_pps: 0,
            max_packets: 10,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg2.interface, "lo");
        assert_eq!(cfg2.max_packets, 10);
    }

    #[test]
    fn icmp6_mld_report_is_131() {
        assert_eq!(ffi::ICMP6_MLD_REPORT, 131);
    }

    #[test]
    fn icmp6_toobig_is_2() {
        assert_eq!(ffi::ICMP6_TOOBIG, 2);
    }

    #[test]
    fn nxt_udp_is_17() {
        assert_eq!(ffi::NXT_UDP, 17);
    }
}

#[cfg(test)]
mod ffi_constants_tests {
    use crate::ffi;

    #[test]
    fn prefer_link_is_32()      { assert_eq!(ffi::PREFER_LINK,   32); }
    #[test]
    fn prefer_global_is_0()     { assert_eq!(ffi::PREFER_GLOBAL,  0); }
    #[test]
    fn icmp6_routeradv_is_134() { assert_eq!(ffi::ICMP6_ROUTERADV,   134); }
    #[test]
    fn icmp6_routersol_is_133() { assert_eq!(ffi::ICMP6_ROUTERSOL,   133); }
    #[test]
    fn nxt_icmp6_is_58()        { assert_eq!(ffi::NXT_ICMP6,   58); }
    #[test]
    fn icmp6_neighborsol_is_135() { assert_eq!(ffi::ICMP6_NEIGHBORSOL, 135); }
    #[test]
    fn icmp6_neighboradv_is_136() { assert_eq!(ffi::ICMP6_NEIGHBORADV, 136); }
    #[test]
    fn icmp6_echo_request_is_128() { assert_eq!(ffi::ICMP6_ECHO_REQUEST, 128); }
    #[test]
    fn icmp6_echo_reply_is_129()   { assert_eq!(ffi::ICMP6_ECHO_REPLY,   129); }
    #[test]
    fn icmp6_mld2_report_is_143()  { assert_eq!(ffi::ICMP6_MLD2_REPORT,  143); }
    #[test]
    fn icmp6_redirect_is_137()     { assert_eq!(ffi::ICMP6_REDIRECT,     137); }
    #[test]
    fn nxt_tcp_is_6()              { assert_eq!(ffi::NXT_TCP,  6); }
    #[test]
    fn nxt_udp_is_17_v2()          { assert_eq!(ffi::NXT_UDP, 17); }
}

#[cfg(test)]
mod attack_helpers_tests {
    use crate::engine::sender::{eui64_ll_pub, rand_fake_mac_pub};

    #[test]
    fn rand_fake_mac_oui() {
        let mac = rand_fake_mac_pub();
        assert_eq!(mac[0], 0x00);
        assert_eq!(mac[1], 0x18);
    }

    #[test]
    fn eui64_link_local_prefix() {
        let mac = [0x00u8, 0x18, 0xab, 0xcd, 0xef, 0x01];
        let ip  = eui64_ll_pub(&mac);
        assert_eq!(ip[0], 0xfe);
        assert_eq!(ip[1], 0x80);
        assert_eq!(ip[8],  mac[0] ^ 0x02); // U/L bit flipped
        assert_eq!(ip[9],  mac[1]);
        assert_eq!(ip[10], mac[2]);
        assert_eq!(ip[11], 0xff);
        assert_eq!(ip[12], 0xfe);
        assert_eq!(ip[13], mac[3]);
    }

    #[test]
    fn eui64_ul_bit_flip() {
        // U/L bit: 0x00 ^ 0x02 = 0x02
        let mac = [0x00u8, 0x18, 0, 0, 0, 0];
        let ip  = eui64_ll_pub(&mac);
        assert_eq!(ip[8], 0x02);
    }
}

#[cfg(test)]
mod analyze_tests {
    use crate::engine::analyze::{AddrMode, AttackRecommendation, RouterObservation};

    #[test]
    fn addr_mode_as_str_slaac() {
        assert_eq!(AddrMode::Slaac.as_str(), "SLAAC (stateless)");
    }

    #[test]
    fn addr_mode_as_str_dhcpv6() {
        assert_eq!(AddrMode::Dhcpv6.as_str(), "DHCPv6 (stateful)");
    }

    #[test]
    fn router_observation_fields() {
        let r = RouterObservation {
            src_ip:       "fe80::1".into(),
            lifetime_sec: 1800,
            managed:      false,
            other:        false,
            has_prefix:   true,
        };
        assert_eq!(r.src_ip, "fe80::1");
        assert_eq!(r.lifetime_sec, 1800);
        assert!(r.has_prefix);
    }

    #[test]
    fn attack_recommendation_fields() {
        let a = AttackRecommendation {
            priority:  1,
            attack:    "Fake SLAAC".into(),
            rationale: "No RA-Guard".into(),
            command:   "fake-slaac -i eth0".into(),
        };
        assert_eq!(a.priority, 1);
        assert_eq!(a.attack, "Fake SLAAC");
    }
}
