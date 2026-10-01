use dnsmasq_rs::config::{
    dhcp::DhcpConfig,
    dns::DnsConfig,
    loader::{self, Action},
    Error, ScalarConfig,
};
use dnsmasq_rs::dhcp::{
    daemon::LocalProvider,
    runtime::OutcomeProvider,
    service::{dispatch, Ingress, Listener},
};
use dnsmasq_rs::ubus_service::{DhcpEventFields, DhcpEventKind, DhcpLogging};
use std::io::{self, BufRead};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

fn hex(value: Option<&[u8]>) -> String {
    match value {
        None => "-".into(),
        Some([]) => "_".into(),
        Some(value) => value.iter().map(|byte| format!("{byte:02x}")).collect(),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut config = DhcpConfig::default();
    let mut dns = DnsConfig::default();
    let mut scalar = ScalarConfig::default();
    assert_eq!(
        loader::load(&args, Path::new("/etc/dnsmasq.conf"), |directive, _| {
            if config.apply(directive)? || dns.apply(directive)? || scalar.apply(directive)? {
                Ok(())
            } else {
                Err(Error("unsupported event probe option"))
            }
        })?,
        Action::Run
    );
    let mut provider = LocalProvider::new(
        config,
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
        scalar.dns_port,
        || false,
    )?;
    provider.set_dns_config(&dns)?;
    for line in io::stdin().lock().lines() {
        let line = line?;
        let columns: Vec<_> = line.split_whitespace().collect();
        assert_eq!(columns[0], "P");
        let source = columns[3].as_bytes();
        let packet: Vec<u8> = source
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let mut sink = |kind: DhcpEventKind, fields: DhcpEventFields<'_>, _logging: DhcpLogging| {
            let kind = match kind {
                DhcpEventKind::Ack => b"dhcp.ack".as_slice(),
                DhcpEventKind::Release => b"dhcp.release",
            };
            println!(
                "EVENT {} {} {} {} {}",
                hex(Some(kind)),
                hex(fields.mac),
                hex(fields.ip),
                hex(fields.name),
                hex(fields.interface)
            );
        };
        if let Ok(dispatch) = dispatch(
            &packet,
            Ingress {
                listener: Listener::Dhcp,
                interface_index: 1,
                unicast_destination: columns[2] == "1",
            },
            &[],
        ) {
            provider
                .with_event_sink(&mut sink)
                .resolve_on_interface(&dispatch, Some(b"fixture0"))
                .map_err(|error| format!("{error:?}"))?;
        }
        println!("P done");
    }
    Ok(())
}
