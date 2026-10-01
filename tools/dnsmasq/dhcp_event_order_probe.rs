// C dhcp.c:373-377 orders log_packet callback, file, DNS, then socket send.
use dnsmasq_rs::config::{dhcp::DhcpConfig, lex_line};
use dnsmasq_rs::dhcp::{
    daemon::LocalProvider,
    persistence::{DnsLeaseRecord, DnsPublisher},
    runtime::{process_with_random, DatagramSender, Destination, RuntimeError},
    service::{dispatch, Ingress, Listener},
};
use dnsmasq_rs::ubus_service::{DhcpEventFields, DhcpEventKind, DhcpLogging};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

type Trace = Arc<Mutex<Vec<&'static str>>>;
struct Publisher {
    trace: Trace,
    path: PathBuf,
}
impl DnsPublisher for Publisher {
    fn replace(&mut self, records: &[DnsLeaseRecord<'_>]) -> io::Result<()> {
        let mut trace = self.trace.lock().unwrap();
        if trace.is_empty() {
            assert!(records.is_empty());
            return Ok(());
        }
        let before = *trace.last().unwrap();
        let data = std::fs::read(&self.path)?;
        if records.is_empty() {
            assert_eq!(before, "release");
            assert!(data.is_empty());
        } else {
            assert_eq!(before, "ack");
            assert!(data.windows(10).any(|part| part == b"192.0.2.10"));
        }
        trace.push("dns");
        Ok(())
    }
}
struct Sender {
    trace: Trace,
}
impl DatagramSender for Sender {
    fn interface_name(&mut self, _: u32) -> io::Result<Option<[u8; 16]>> {
        let mut name = [0; 16];
        name[..8].copy_from_slice(b"fixture0");
        Ok(Some(name))
    }
    fn send(&mut self, _: &[u8], _: &Destination) -> io::Result<()> {
        let mut trace = self.trace.lock().unwrap();
        assert_eq!(trace.as_slice(), ["ack", "dns"]);
        trace.push("send");
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
}
fn packet(kind: u8) -> Vec<u8> {
    let mut bytes = vec![0; 240];
    bytes[..3].copy_from_slice(&[1, 1, 6]);
    bytes[10] = 0x80;
    bytes[28..34].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    bytes[236..].copy_from_slice(&[99, 130, 83, 99]);
    if kind == 7 {
        bytes[12..16].copy_from_slice(&[192, 0, 2, 10]);
    }
    bytes.extend_from_slice(&[53, 1, kind, 54, 4, 192, 0, 2, 1]);
    if kind == 3 {
        bytes.extend_from_slice(&[
            50, 4, 192, 0, 2, 10, 12, 7, b'c', b'l', b'i', b'e', b'n', b't', b'1',
        ]);
    }
    bytes.push(255);
    bytes
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(std::env::var("DNSMASQ_TEST_ISOLATED").as_deref(), Ok("1"));
    let folder = PathBuf::from(std::env::args_os().nth(1).expect("private output path"));
    assert!(folder
        .components()
        .any(|part| part.as_os_str() == "private"));
    std::fs::create_dir(&folder)?;
    let path = folder.join("leases");
    let mut config = DhcpConfig {
        lease_file: Some(path.as_os_str().as_encoded_bytes().to_vec()),
        no_ping: true,
        ..DhcpConfig::default()
    };
    for line in [
        b"dhcp-authoritative".as_slice(),
        b"dhcp-range=192.0.2.10,192.0.2.20,255.255.255.0,600s",
    ] {
        config.apply(&lex_line(line)?.unwrap())?;
    }
    let trace = Arc::new(Mutex::new(Vec::new()));
    let mut provider = LocalProvider::new(
        config,
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
        53,
        || false,
    )?;
    provider.set_dns_publisher(Box::new(Publisher {
        trace: Arc::clone(&trace),
        path: path.clone(),
    }));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs() as i64;
    provider.initialize(now);
    for kind in [3, 7] {
        let bytes = packet(kind);
        let mut sink = |kind: DhcpEventKind, fields: DhcpEventFields<'_>, _: DhcpLogging| {
            assert_eq!(fields.interface, Some(&b"fixture0"[..]));
            let data = std::fs::read(&path).unwrap();
            let mut trace = trace.lock().unwrap();
            match kind {
                DhcpEventKind::Ack => {
                    assert!(data.is_empty());
                    assert_eq!(fields.name, Some(&b"client1"[..]));
                    trace.push("ack");
                }
                DhcpEventKind::Release => {
                    assert!(data.windows(10).any(|part| part == b"192.0.2.10"));
                    assert!(fields.name.is_none());
                    trace.push("release");
                }
            }
        };
        let dispatch = dispatch(
            &bytes,
            Ingress {
                listener: Listener::Dhcp,
                interface_index: 1,
                unicast_destination: true,
            },
            &[],
        )
        .unwrap();
        let result = process_with_random(
            dispatch,
            SocketAddr::from(([192, 0, 2, 100], 68)),
            &mut provider.with_event_sink(&mut sink),
            &mut Sender {
                trace: Arc::clone(&trace),
            },
            &[],
            &mut [0; 4096],
            || Ok(0),
        );
        if kind == 3 {
            assert!(matches!(result.unwrap_err().error, RuntimeError::Send(_)));
        } else {
            assert!(result.is_ok());
        }
    }
    assert_eq!(
        trace.lock().unwrap().as_slice(),
        ["ack", "dns", "send", "release", "dns"]
    );
    assert!(std::fs::read(&path)?.is_empty());
    std::fs::write(folder.join("result.json"),b"{\"passed\":true,\"trace\":[\"ack\",\"dns\",\"send-failure\",\"release\",\"dns\"],\"lease_file_empty\":true}\n")?;
    println!("source callback -> lease file -> DNS -> failing send; RELEASE callback -> lease file -> DNS: passed");
    Ok(())
}
