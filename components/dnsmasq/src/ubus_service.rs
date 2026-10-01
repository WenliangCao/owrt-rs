//! OpenWrt dnsmasq 2.93 ubus objects and DHCP notification boundary.
//!
//! The caller supplies its live metrics and owns connection/retry scheduling.
//! On any transport error it must drop this service before reconnecting; object
//! and type IDs are connection-local. Product-daemon integration is separate.

use crate::metrics::Metrics;
use owrt_ubus::{blob, status, BlobBuf, Connection, Incoming};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

/// Exact OpenWrt patch 200's per-record synchronous notification budget.
pub const DNS_NOTIFY_TIMEOUT: Duration = Duration::from_millis(100);

/// C retries an absent transport after a main-loop wakeup; registration errors
/// disable the integration. Keep those two failure boundaries distinguishable.
#[derive(Debug)]
pub enum ConnectError {
    Transport(io::Error),
    Registration(io::Error),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(error) => write!(output, "ubus connection: {error}"),
            Self::Registration(error) => write!(output, "ubus object registration: {error}"),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Transport(error) | Self::Registration(error) => error,
        })
    }
}

pub struct UbusService {
    connection: Connection,
    main_id: u32,
    dns_id: u32,
    main_subscribed: bool,
    dns_subscribed: bool,
    buffer: BlobBuf,
}

impl UbusService {
    /// Register `name` with only `metrics`, then `name.dns` with no methods.
    /// A failed second registration drops the whole connection and first object.
    /// No object/type ID or subscriber state is retained across reconnection.
    pub fn connect(socket: Option<&str>, name: &str) -> Result<Self, ConnectError> {
        let mut connection = Connection::connect(socket).map_err(ConnectError::Transport)?;
        connection.set_server_io_timeout(Duration::from_millis(100));
        let main_id = connection
            .add_object(name, &[("metrics", &[])], 1000)
            .map_err(ConnectError::Registration)?;
        let dns_id = connection
            .add_object(&format!("{name}.dns"), &[], 1000)
            .map_err(ConnectError::Registration)?;
        Ok(Self {
            connection,
            main_id,
            dns_id,
            main_subscribed: false,
            dns_subscribed: false,
            buffer: BlobBuf::new(),
        })
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.connection.as_raw_fd()
    }

    pub fn has_pending(&self) -> bool {
        self.connection.has_pending()
    }

    pub fn dns_has_subscribers(&self) -> bool {
        self.dns_subscribed
    }

    /// Process one already-started message; return false if the socket is idle.
    /// A started partial frame is bounded by the transport's 100 ms deadline.
    /// The borrowed counters come from the caller's engine, never a placeholder
    /// created for the ubus method. Unknown methods retain C's status code 3.
    pub fn process_one(&mut self, metrics: &Metrics) -> io::Result<bool> {
        let Some(incoming) = self.connection.incoming_if_started()? else {
            return Ok(false);
        };
        match incoming {
            Incoming::Invoke(request) => {
                let result = if request.objid != self.main_id && request.objid != self.dns_id {
                    self.connection
                        .reply_status(&request, status::NOT_FOUND, None)
                } else if request.objid == self.main_id && request.method == "metrics" {
                    metrics.write_ubus(&mut self.buffer);
                    self.connection
                        .reply_data_status(&request, self.buffer.payload(), status::OK)
                } else {
                    self.connection
                        .reply_status(&request, status::METHOD_NOT_FOUND, None)
                };
                self.connection.recycle_request(request);
                result?;
            }
            Incoming::SubscribeState { objid, active } => {
                if objid == self.main_id {
                    self.main_subscribed = active;
                } else if objid == self.dns_id {
                    self.dns_subscribed = active;
                }
            }
            Incoming::Other(_) => {}
        }
        Ok(true)
    }

    /// Match rfc2131.c log_packet -> ubus_event_bcast, including quiet-dhcp's
    /// early return. Unsubscribed events are not queued for future subscribers.
    pub fn notify_dhcp(
        &mut self,
        kind: DhcpEventKind,
        fields: DhcpEventFields<'_>,
        logging: DhcpLogging,
    ) -> io::Result<bool> {
        if !self.main_subscribed || logging.suppresses_event() {
            return Ok(false);
        }
        fields.write(&mut self.buffer);
        self.connection
            .notify(self.main_id, kind.method(), self.buffer.payload())?;
        Ok(true)
    }

    /// Synchronous OpenWrt UDP DNS doctor hook. The owner must drain pending
    /// ubus messages before calling, and again after return. Never call this in
    /// the TCP path: the C child drops its ubus connection before DNS processing.
    /// Some(address) means replace the address and clear AA, even if unchanged.
    /// A clean 100 ms timeout still uses DATA received before the deadline.
    /// Transport/cancellation errors require dropping this service; the DNS
    /// owner retains its original answer. This method never changes DNS/cache.
    pub fn doctor_dns(
        &mut self,
        result: &DnsResult<'_>,
        cancelled: Option<fn() -> bool>,
    ) -> io::Result<Option<IpAddr>> {
        if !self.dns_subscribed {
            return Ok(None);
        }
        let deadline = Instant::now() + DNS_NOTIFY_TIMEOUT;
        result.write(&mut self.buffer);
        let mut selected = None;
        self.connection.notify_with_data_until(
            self.dns_id,
            "dns_result",
            self.buffer.payload(),
            deadline,
            cancelled,
            |fields| {
                if let Some(bytes) = first_address(fields) {
                    // Last applicable DATA wins, including an invalid string
                    // which cancels an earlier valid replacement.
                    selected = std::str::from_utf8(bytes)
                        .ok()
                        .and_then(|text| text.parse::<IpAddr>().ok())
                        .filter(|address| address.is_ipv4() == result.address.is_ipv4());
                }
            },
        )?;
        Ok(selected)
    }
}

/// libubox blobmsg_parse selects the first matching typed field. Invalid fields
/// terminate parsing, including unrelated fields before the selected address.
/// Fields after the first match cannot clear it even if validation then fails:
/// the C dnsmasq callback ignores the parser status and reads its retained slot.
fn first_address(fields: &[u8]) -> Option<&[u8]> {
    for attribute in blob::iter(fields) {
        let (name, data) = if attribute.extended {
            let length = u16::from_be_bytes(attribute.payload.get(..2)?.try_into().ok()?) as usize;
            let header = blob::pad4(2 + length + 1);
            if attribute.payload.get(2 + length) != Some(&0) {
                return None;
            }
            (
                Some(attribute.payload.get(2..2 + length)?),
                attribute.payload.get(header..)?,
            )
        } else {
            (None, attribute.payload)
        };
        let valid = match attribute.id {
            0..=2 => true,
            3 => data.last() == Some(&0),
            4 => data.len() == 8,
            5 => data.len() == 4,
            6 => data.len() == 2,
            7 => data.len() == 1,
            8 => data.len() >= 8,
            _ => false,
        };
        if !valid {
            return None;
        }
        if attribute.id == 3 && name == Some(b"address".as_slice()) {
            return Some(c_string(data));
        }
    }
    None
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DhcpEventKind {
    Ack,
    Release,
}

impl DhcpEventKind {
    fn method(self) -> &'static str {
        match self {
            Self::Ack => "dhcp.ack",
            Self::Release => "dhcp.release",
        }
    }
}

/// Values passed by C's log_packet call, not inferred from a lease snapshot.
/// RELEASE supplies no name; an absent MAC is an empty string at that caller.
#[derive(Clone, Copy, Debug, Default)]
pub struct DhcpEventFields<'a> {
    pub mac: Option<&'a [u8]>,
    pub ip: Option<&'a [u8]>,
    pub name: Option<&'a [u8]>,
    pub interface: Option<&'a [u8]>,
}

impl DhcpEventFields<'_> {
    pub fn write(self, buffer: &mut BlobBuf) {
        buffer.reset();
        for (key, value) in [
            ("mac", self.mac),
            ("ip", self.ip),
            ("name", self.name),
            ("interface", self.interface),
        ] {
            if let Some(value) = value {
                buffer.msg_string_bytes(key, c_string(value));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DhcpLogging {
    pub quiet_dhcp: bool,
    pub log_options: bool,
    pub has_error: bool,
}

impl DhcpLogging {
    pub fn suppresses_event(self) -> bool {
        self.quiet_dhcp && !self.log_options && !self.has_error
    }
}

/// The outgoing record payload for a synchronous DNS notification.
pub struct DnsResult<'a> {
    /// C's extracted, possibly escaped name bytes, without UTF-8 conversion.
    pub name: &'a [u8],
    pub ttl: u32,
    pub address: IpAddr,
}

impl DnsResult<'_> {
    pub fn write(&self, buffer: &mut BlobBuf) {
        buffer.reset();
        buffer.msg_string_bytes("name", c_string(self.name));
        buffer.msg_u32("ttl", self.ttl);
        buffer.msg_string("type", if self.address.is_ipv4() { "A" } else { "AAAA" });
        buffer.msg_string("address", &notification_address(self.address));
    }
}

fn c_string(value: &[u8]) -> &[u8] {
    &value[..value
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(value.len())]
}

fn notification_address(address: IpAddr) -> String {
    if let IpAddr::V6(value) = address {
        let segments = value.segments();
        // inet_ntop uses a dotted tail for IPv4-compatible addresses when
        // its leading zero run is exactly six words. Rust Display uses hex.
        // Leave ::, ::1 and other seven-word zero runs in hexadecimal.
        if segments[..6] == [0; 6] && segments[6] != 0 {
            let bytes = value.octets();
            return format!(
                "::{}",
                Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])
            );
        }
    }
    address.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use owrt_ubus::blob;

    #[test]
    fn doctor_policy_keeps_first_match_and_stops_at_invalid_preceding_fields() {
        let mut buffer = BlobBuf::new();
        buffer.msg_string("address", "192.0.2.9");
        buffer.msg_string("address", "invalid");
        assert_eq!(
            first_address(buffer.payload()),
            Some(b"192.0.2.9".as_slice())
        );
        buffer.reset();
        buffer.msg_field(5, "other", &[1, 2, 3]);
        buffer.msg_string("address", "192.0.2.9");
        assert_eq!(first_address(buffer.payload()), None);
        buffer.reset();
        buffer.msg_string("address", "192.0.2.9");
        buffer.msg_field(5, "other", &[1, 2, 3]);
        assert_eq!(
            first_address(buffer.payload()),
            Some(b"192.0.2.9".as_slice())
        );
        buffer.reset();
        buffer.msg_string("address", "192.0.2.9");
        let bytes = buffer.payload();
        for length in 0..bytes.len() {
            assert_eq!(first_address(&bytes[..length]), None);
        }
        let mut bad_name = bytes.to_vec();
        bad_name[4 + 2 + "address".len()] = b'X';
        assert_eq!(first_address(&bad_name), None);
        let mut bad_value = bytes.to_vec();
        let raw_length = (u32::from_be_bytes(bytes[..4].try_into().unwrap()) & 0xffffff) as usize;
        bad_value[raw_length - 1] = b'X';
        assert_eq!(first_address(&bad_value), None);
    }

    #[test]
    fn dhcp_omission_order_and_quiet_logging_follow_callsite() {
        let mut buffer = BlobBuf::new();
        DhcpEventFields {
            mac: Some(b""),
            ip: Some(b"192.0.2.1"),
            name: None,
            interface: Some(b"fixture"),
        }
        .write(&mut buffer);
        let fields: Vec<_> = blob::fields(buffer.payload()).collect();
        assert_eq!(
            fields.iter().map(|field| field.name).collect::<Vec<_>>(),
            ["mac", "ip", "interface"]
        );
        assert_eq!(fields[0].as_str(), Some(""));
        for quiet in [false, true] {
            for log_options in [false, true] {
                for has_error in [false, true] {
                    let logging = DhcpLogging {
                        quiet_dhcp: quiet,
                        log_options,
                        has_error,
                    };
                    assert_eq!(
                        logging.suppresses_event(),
                        quiet && !log_options && !has_error
                    );
                }
            }
        }
    }

    #[test]
    fn names_keep_non_utf8_bytes_and_c_string_termination() {
        let mut buffer = BlobBuf::new();
        for name in [b"a\xffb".as_slice(), b"a\\000b", b"a\0ignored"] {
            DnsResult {
                name,
                ttl: 1,
                address: "192.0.2.1".parse().unwrap(),
            }
            .write(&mut buffer);
            let field = blob::fields(buffer.payload()).next().unwrap();
            assert_eq!(
                field.as_bytes(),
                Some(if name == b"a\0ignored" { b"a" } else { name })
            );
        }
    }

    #[test]
    fn dns_payload_keeps_ttl_width_order_and_record_family() {
        for address in [
            "192.0.2.1",
            "2001:db8::1",
            "::192.0.2.1",
            "::ffff:192.0.2.1",
            "::1",
            "::101",
        ] {
            let result = DnsResult {
                name: b"fixture.invalid",
                ttl: u32::MAX,
                address: address.parse().unwrap(),
            };
            let mut buffer = BlobBuf::new();
            result.write(&mut buffer);
            let fields: Vec<_> = blob::fields(buffer.payload()).collect();
            assert_eq!(
                fields.iter().map(|field| field.name).collect::<Vec<_>>(),
                ["name", "ttl", "type", "address"]
            );
            assert_eq!(fields[1].as_u32(), Some(u32::MAX));
            assert_eq!(
                fields[2].as_str(),
                Some(if result.address.is_ipv4() {
                    "A"
                } else {
                    "AAAA"
                })
            );
            assert_eq!(fields[3].as_str(), Some(address));
        }
    }
}
