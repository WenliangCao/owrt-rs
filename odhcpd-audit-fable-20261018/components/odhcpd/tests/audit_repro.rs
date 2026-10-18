//! Independent audit reproductions (not part of the product test suite).
use owrt_odhcpd::config::{Config, NetworkInterface};
use owrt_ubus::json;

fn package(name: &str, text: &str) -> owrt_uci::Package {
    let mut ctx = owrt_uci::Context::new();
    let idx = owrt_uci::parse::import(&mut ctx, &mut text.as_bytes(), Some(name), None, true)
        .unwrap()
        .unwrap();
    ctx.root.remove(idx)
}

const DHCP: &str = "config odhcpd 'odhcpd'\n option maindhcp '0'\nconfig dhcp 'lan'\n option interface 'lan'\n option dhcpv6 'server'\n option ra 'server'\n";

/// netifd dump `data` of a DHCPv4 client interface carries `leasetime` as an
/// integer (device intake: wan data = {dhcpserver: str, leasetime: int}).
/// C parses it with blobmsg_parse and ignores the type mismatch. If the
/// interface has no `config dhcp` section, odhcpd-rs apply_network() errors,
/// and main.rs propagates that error out of run() -> exit 4 -> procd respawn.
#[test]
fn dhcp_client_interface_without_uci_section_is_tolerated() {
    let mut config = Config::from_packages(&package("dhcp", DHCP), None, None).unwrap();
    let data = json::parse("{\"dhcpserver\":\"192.0.2.1\",\"leasetime\":60}").unwrap();
    let result = config.apply_network(&[NetworkInterface {
        name: "wwan".into(),
        device: Some("eth1".into()),
        up: true,
        data,
    }]);
    assert!(result.is_ok(), "apply_network rejected a DHCP client interface dump: {result:?}");
}

/// A single malformed static host (odd-length DUID) makes the whole
/// configuration unloadable; C skips the host and keeps serving.
#[test]
fn malformed_static_host_does_not_take_down_the_configuration() {
    let text = format!("{DHCP}config host\n option name 'printer'\n option duid '0001000123456'\n");
    let result = Config::from_packages(&package("dhcp", &text), None, None);
    assert!(result.is_ok(), "one bad host entry rejected the configuration: {result:?}");
}
