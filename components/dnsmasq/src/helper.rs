//! Fixed-command lease/ARP/TFTP helper. Only the forked helper waits for scripts;
//! the single service owner exchanges bounded frames through nonblocking pipes.
//! Reference: helper.c:79-134,180-688,773-942; dnsmasq.c:718,1177-1194,1711-1728.

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

#[cfg(target_os = "linux")]
#[path = "helper/process.rs"]
mod process;
#[path = "helper/wire.rs"]
mod wire;
#[cfg(target_os = "linux")]
pub use process::Helper;

#[derive(Clone, Debug)]
pub struct Config {
    /// This command is fixed before fork, never supplied through event IPC.
    pub script: PathBuf,
    pub script_user: Option<Vec<u8>>,
    pub debug: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseAction {
    Add,
    Old,
    Delete,
    OldHostname,
}

/// Transient data from the most recent DHCP packet, in helper.c field order.
/// These values are not stored permanently per lease after its event is sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtraData {
    pub vendor_class: Vec<u8>,
    pub supplied_hostname: Vec<u8>,
    pub cpewan_oui: Vec<u8>,
    pub cpewan_serial: Vec<u8>,
    pub cpewan_class: Vec<u8>,
    pub circuit_id: Vec<u8>,
    pub subscriber_id: Vec<u8>,
    pub remote_id: Vec<u8>,
    /// Comma-separated decimal requested option codes, as produced by C.
    pub requested_options: Vec<u8>,
    pub mud_url: Vec<u8>,
    /// Space-separated, C-ordered, duplicate-filtered DHCP tags.
    pub tags: Vec<u8>,
    pub user_classes: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseEvent {
    pub action: LeaseAction,
    pub hardware_type: u32,
    pub hardware_address: Vec<u8>,
    pub address: Ipv4Addr,
    pub hostname: Option<Vec<u8>>,
    pub client_id: Vec<u8>,
    pub interface: Vec<u8>,
    /// The C zero sentinel represents an infinite lease.
    pub expires: i64,
    pub now: i64,
    pub relay_address: Option<Ipv4Addr>,
    /// None is a restored/deleted lease without packet extradata.
    pub extra: Option<ExtraData>,
    pub log_dhcp: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Lease(LeaseEvent),
    Arp {
        added: bool,
        hardware_address: Vec<u8>,
        address: IpAddr,
    },
    Tftp {
        size: u64,
        address: IpAddr,
        filename: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    Ready,
    /// Merged stdout/stderr bytes; only non-debug scripts are captured by C.
    Output(Vec<u8>),
    ScriptExit(i32),
    ScriptSignal(i32),
    ExecError(i32),
    /// Helper setup/IPC failure (errno, or EINVAL for malformed IPC).
    Error(i32),
    /// The helper itself has been reaped. Raw wait status, zero on EOF success.
    Reaped(i32),
}

#[derive(Debug)]
pub struct StartError {
    pub code: i32,
    pub message: String,
}
impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for StartError {}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid helper event")
}

/// Values here have fixed environment names. An IPC sender cannot choose an
/// executable or set loader variables such as LD_PRELOAD in the privileged child.
#[derive(Debug, PartialEq, Eq)]
struct Invocation {
    args: Vec<Vec<u8>>,
    env: Vec<(String, Option<Vec<u8>>)>,
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(3));
    for (i, &byte) in bytes.iter().enumerate() {
        if i != 0 {
            out.push(b':');
        }
        out.push(DIGITS[(byte >> 4) as usize]);
        out.push(DIGITS[(byte & 15) as usize]);
    }
    out
}

fn hardware(kind: u32, bytes: &[u8]) -> Vec<u8> {
    let mut out = if kind != 1 || bytes.is_empty() {
        format!("{kind:02x}-").into_bytes()
    } else {
        Vec::new()
    };
    out.extend(hex(bytes));
    out
}

// util.c legal_hostname/check_name for the image no-IDN variant. Validation
// mutates a final dot away before splitting the hostname from its domain.
fn hostname(value: &[u8]) -> Option<Vec<u8>> {
    if value.is_empty() {
        return None;
    }
    let trailing_dot = value.last() == Some(&b'.');
    let name = if trailing_dot {
        &value[..value.len() - 1]
    } else {
        value
    };
    if name.len() + 2 > 255 || name.iter().any(|v| !v.is_ascii() || v.is_ascii_control()) {
        return None;
    }
    if !trailing_dot && name.iter().all(|&v| v == b' ') {
        return None;
    }
    if name.split(|&v| v == b'.').any(|label| label.len() > 63) {
        return None;
    }
    if name
        .split(|&v| v == b'.')
        .next()
        .unwrap_or_default()
        .iter()
        .enumerate()
        .any(|(i, v)| !v.is_ascii_alphanumeric() && !(i != 0 && matches!(v, b'-' | b'_')))
    {
        return None;
    }
    Some(name.to_vec())
}

fn invocation(event: &Event) -> io::Result<Invocation> {
    let mut env = Vec::new();
    let args = match event {
        Event::Lease(lease) => {
            if lease.hardware_address.len() > 16 || lease.interface.len() >= 16 {
                return Err(invalid());
            }
            let name = lease.hostname.as_deref().and_then(hostname);
            let (short, domain) = match name.as_deref() {
                Some(name) => match name.iter().position(|&v| v == b'.') {
                    Some(i) => (Some(name[..i].to_vec()), Some(name[i + 1..].to_vec())),
                    None => (Some(name.to_vec()), None),
                },
                None => (None, None),
            };
            let mut add = |key: &str, value: Option<Vec<u8>>| {
                env.push((format!("DNSMASQ_{key}"), value));
            };
            let client = if lease.client_id.is_empty() {
                None
            } else {
                // C limits to 100 bytes but retains the separator when truncating.
                let mut value = hex(&lease.client_id[..lease.client_id.len().min(100)]);
                if lease.client_id.len() > 100 {
                    value.push(b':');
                }
                Some(value)
            };
            add("CLIENT_ID", client);
            add(
                "INTERFACE",
                (!lease.interface.is_empty()).then(|| lease.interface.clone()),
            );
            add(
                "LEASE_EXPIRES",
                Some((lease.expires as u64).to_string().into_bytes()),
            );
            add("DOMAIN", domain);
            if lease.extra.is_none() {
                add("DATA_MISSING", Some(b"1".to_vec()));
            }
            let empty = ExtraData::default();
            let extra = lease.extra.as_ref().unwrap_or(&empty);
            for (key, value) in [
                ("VENDOR_CLASS", &extra.vendor_class),
                ("SUPPLIED_HOSTNAME", &extra.supplied_hostname),
                ("CPEWAN_OUI", &extra.cpewan_oui),
                ("CPEWAN_SERIAL", &extra.cpewan_serial),
                ("CPEWAN_CLASS", &extra.cpewan_class),
                ("CIRCUIT_ID", &extra.circuit_id),
                ("SUBSCRIBER_ID", &extra.subscriber_id),
                ("REMOTE_ID", &extra.remote_id),
                ("REQUESTED_OPTIONS", &extra.requested_options),
                ("MUD_URL", &extra.mud_url),
                ("TAGS", &extra.tags),
            ] {
                add(key, extra_value(value));
            }
            add(
                "RELAY_ADDRESS",
                lease
                    .relay_address
                    .filter(|v| !v.is_unspecified())
                    .map(|v| v.to_string().into_bytes()),
            );
            // grab_extradata also unsets the first absent numbered user class.
            for (i, value) in extra.user_classes.iter().enumerate() {
                add(&format!("USER_CLASS{i}"), extra_value(value));
            }
            add(&format!("USER_CLASS{}", extra.user_classes.len()), None);
            let remaining = if lease.expires == 0 {
                0
            } else {
                lease.expires.wrapping_sub(lease.now) as u32
            };
            add(
                "TIME_REMAINING",
                (lease.action != LeaseAction::Delete && remaining != 0)
                    .then(|| remaining.to_string().into_bytes()),
            );
            add(
                "OLD_HOSTNAME",
                (lease.action == LeaseAction::OldHostname)
                    .then(|| short.clone())
                    .flatten(),
            );
            add("LOG_DHCP", lease.log_dhcp.then(|| b"1".to_vec()));
            let action = match lease.action {
                LeaseAction::Add => b"add".as_slice(),
                LeaseAction::Delete => b"del".as_slice(),
                LeaseAction::Old | LeaseAction::OldHostname => b"old".as_slice(),
            };
            let mut args = vec![
                action.to_vec(),
                hardware(lease.hardware_type, &lease.hardware_address),
                lease.address.to_string().into_bytes(),
            ];
            if lease.action != LeaseAction::OldHostname {
                if let Some(short) = short {
                    args.push(short);
                }
            }
            args
        }
        Event::Arp {
            added,
            hardware_address,
            address,
        } => {
            if hardware_address.len() > 16 {
                return Err(invalid());
            }
            vec![
                if *added {
                    b"arp-add".to_vec()
                } else {
                    b"arp-del".to_vec()
                },
                hardware(1, hardware_address),
                address.to_string().into_bytes(),
            ]
        }
        Event::Tftp {
            size,
            address,
            filename,
        } => {
            vec![
                b"tftp".to_vec(),
                size.to_string().into_bytes(),
                address.to_string().into_bytes(),
                filename.clone(),
            ]
        }
    };
    if args.iter().any(|value| value.contains(&0))
        || env
            .iter()
            .any(|(_, value)| value.as_ref().is_some_and(|value| value.contains(&0)))
    {
        return Err(invalid());
    }
    Ok(Invocation { args, env })
}

fn extra_value(value: &[u8]) -> Option<Vec<u8>> {
    // lease_add_extradata stops at NUL; helper grab_extradata truncates '='.
    let value = value.split(|&v| v == 0).next().unwrap_or_default();
    (!value.is_empty()).then(|| {
        value
            .split(|&v| v == b'=')
            .next()
            .unwrap_or_default()
            .to_vec()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn lease() -> LeaseEvent {
        LeaseEvent {
            action: LeaseAction::Add,
            hardware_type: 1,
            hardware_address: vec![2, 0, 0, 0, 0, 1],
            address: Ipv4Addr::new(192, 0, 2, 10),
            hostname: Some(b"client.lan".to_vec()),
            client_id: vec![1, 2],
            interface: b"br-lan".to_vec(),
            expires: 400,
            now: 100,
            relay_address: None,
            extra: Some(ExtraData::default()),
            log_dhcp: false,
        }
    }
    #[test]
    fn lease_args_and_fixed_environment_match_helper_source() {
        let call = invocation(&Event::Lease(lease())).unwrap();
        assert_eq!(
            call.args,
            [
                b"add".to_vec(),
                b"02:00:00:00:00:01".to_vec(),
                b"192.0.2.10".to_vec(),
                b"client".to_vec()
            ]
        );
        assert!(call
            .env
            .contains(&("DNSMASQ_DOMAIN".into(), Some(b"lan".to_vec()))));
        assert!(call
            .env
            .contains(&("DNSMASQ_TIME_REMAINING".into(), Some(b"300".to_vec()))));
        assert!(!call.env.iter().any(|(k, _)| k == "DNSMASQ_DATA_MISSING"));
        assert!(call.env.iter().all(|(key, _)| key.starts_with("DNSMASQ_")));
    }
    #[test]
    fn old_hostname_delete_infinite_and_restored_data() {
        let mut value = lease();
        value.action = LeaseAction::OldHostname;
        value.extra = None;
        value.expires = 0;
        let call = invocation(&Event::Lease(value.clone())).unwrap();
        assert_eq!(call.args.len(), 3);
        assert!(call
            .env
            .contains(&("DNSMASQ_OLD_HOSTNAME".into(), Some(b"client".to_vec()))));
        assert!(call
            .env
            .contains(&("DNSMASQ_DATA_MISSING".into(), Some(b"1".to_vec()))));
        assert!(call.env.contains(&("DNSMASQ_TIME_REMAINING".into(), None)));
        value.action = LeaseAction::Delete;
        value.expires = 400;
        assert!(invocation(&Event::Lease(value))
            .unwrap()
            .env
            .contains(&("DNSMASQ_TIME_REMAINING".into(), None)));
    }
    #[test]
    fn extra_data_c_truncation_and_client_identifier_limit() {
        assert_eq!(extra_value(b"abc=def"), Some(b"abc".to_vec()));
        assert_eq!(extra_value(b"=def"), Some(Vec::new()));
        assert_eq!(extra_value(b"\0ignore"), None);
        let mut value = lease();
        value.client_id = vec![1; 101];
        let call = invocation(&Event::Lease(value)).unwrap();
        let id = call
            .env
            .iter()
            .find(|(k, _)| k == "DNSMASQ_CLIENT_ID")
            .unwrap()
            .1
            .as_ref()
            .unwrap();
        assert_eq!(id.len(), 300);
        assert_eq!(id.last(), Some(&b':'));
    }
    #[test]
    fn valid_first_label_and_no_idn_hostname_rules() {
        assert_eq!(
            hostname(b"client.other text."),
            Some(b"client.other text".to_vec())
        );
        assert_eq!(hostname(b"-client.lan"), None);
        assert_eq!(hostname(b"client.\xff"), None);
        assert_eq!(hostname(b"client.\n"), None);
        assert_eq!(hostname(&vec![b'a'; 64]), None);
        assert_eq!(hostname(b"."), Some(Vec::new()));
    }
    #[test]
    fn nonlease_events_do_not_modify_inherited_environment() {
        for event in [
            Event::Arp {
                added: false,
                hardware_address: vec![2; 6],
                address: "2001:db8::1".parse().unwrap(),
            },
            Event::Tftp {
                size: 41,
                address: "192.0.2.2".parse().unwrap(),
                filename: b"/srv/a b".to_vec(),
            },
        ] {
            assert!(invocation(&event).unwrap().env.is_empty());
            assert_eq!(wire::decode(&wire::encode(&event).unwrap()).unwrap(), event);
        }
    }
}
