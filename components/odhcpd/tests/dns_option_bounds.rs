use owrt_odhcpd::{
    config::Config,
    dhcpv6::{Dhcpv6, RequestContext},
    model::{Clock, Link},
};

#[test]
fn configured_dns_must_fit_option_and_udp_lengths() {
    let mut oversized = Vec::new();
    for count in [1, 4093, 4094, 4095, 4096] {
        let text = format!(
            "config dhcp 'lan'\n option dhcpv6 'server'\n{}",
            " list dns 'fd00::1'\n".repeat(count)
        );
        let mut context = owrt_uci::Context::new();
        let index =
            owrt_uci::parse::import(&mut context, &mut text.as_bytes(), Some("dhcp"), None, true)
                .unwrap()
                .unwrap();
        let config = Config::from_packages(&context.root.remove(index), None, None).unwrap();
        assert_eq!(config.pools[0].dns.len(), count);
        let link = Link {
            name: "lan".into(),
            index: 7,
            flags: 0x41,
            mtu: 1500,
            mac: [2, 0, 0, 0, 0, 1],
            addresses: vec![],
        };
        let outcome = Dhcpv6::default().handle(
            &[11, 1, 2, 3],
            RequestContext {
                source: "[fe80::2%7]:546".parse().unwrap(),
                destination: "ff02::1:2".parse().unwrap(),
                link: &link,
                pool: &config.pools[0],
                config: &config,
                clock: Clock {
                    monotonic_ms: 100000,
                    unix_seconds: 2000000000,
                },
            },
            &mut |_, _| panic!("Information Request cannot change routes"),
        );
        assert!(!outcome.write_state);
        if count >= 4094 {
            if let Some(reply) = outcome.reply {
                oversized.push((
                    count,
                    reply.len(),
                    u16::from_be_bytes([reply[28], reply[29]]),
                ));
            }
            continue;
        }
        let reply = outcome.reply.expect("valid DNS response");
        assert!(reply.len() <= 65527);
        assert_eq!(&reply[..4], &[7, 1, 2, 3]);
        let mut options = &reply[4..];
        let mut dns_count = 0;
        while !options.is_empty() {
            assert!(options.len() >= 4);
            let code = u16::from_be_bytes(options[..2].try_into().unwrap());
            let length = u16::from_be_bytes(options[2..4].try_into().unwrap()) as usize;
            assert!(length <= options.len() - 4);
            if code == 23 {
                assert_eq!(length, count * 16);
                for address in options[4..4 + length].as_chunks::<16>().0 {
                    assert_eq!(
                        *address,
                        "fd00::1".parse::<std::net::Ipv6Addr>().unwrap().octets()
                    );
                }
                dns_count += 1;
            }
            options = &options[4 + length..];
        }
        assert_eq!(dns_count, 1);
    }
    assert!(
        oversized.is_empty(),
        "oversized replies (DNS count, packet bytes, wire length): {oversized:?}"
    );
}
