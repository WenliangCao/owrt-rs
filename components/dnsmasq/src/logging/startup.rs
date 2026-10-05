//! Startup messages from dhcp-common.c:950-1025 and dnsmasq.c:1038-1049.
use super::{LogEvent, Priority, Service};
use crate::config::dhcp::RangeConfig;
use crate::config::dns::RuleTarget;
use crate::config::tftp::TftpConfig;
use crate::dhcp::allocation::RangeKind;
use crate::dns::files::SourcedRule;
use crate::dns::forward::ServerId;

/// Call in Config.ranges order: option.c and the parser both prepend ranges.
pub fn dhcp_range(range: &RangeConfig) -> LogEvent {
    let message = match range.kind {
        RangeKind::Dynamic => format!(
            "DHCP, IP range {} -- {}, lease time {}",
            range.start,
            range.end,
            lease_duration(range.lease_time)
        ),
        RangeKind::Static => format!(
            "DHCP, static leases only on {}, lease time {}",
            range.end,
            lease_duration(range.lease_time)
        ),
        RangeKind::Proxy => format!("DHCP, proxy on subnet {}", range.end),
    };
    LogEvent::new(Service::Dhcp, Priority::Info, message.into_bytes())
}

/// Keep the two independent optional flag columns, including their spaces.
pub fn tftp(config: &TftpConfig) -> Option<LogEvent> {
    if !config.enabled {
        return None;
    }
    let mut message = b"TFTP ".to_vec();
    if let Some(root) = &config.root {
        message.extend_from_slice(b"root is ");
        message.extend_from_slice(root);
    } else {
        message.extend_from_slice(b"enabled");
    }
    message.push(b' ');
    if config.secure {
        message.extend_from_slice(b"secure mode");
    }
    message.push(b' ');
    if config.single_port {
        message.extend_from_slice(b"single port mode");
    }
    Some(LogEvent::new(Service::Tftp, Priority::Info, message))
}

/// dnsmasq.c:1050-1055 keeps different global and interface-prefix wording.
pub fn tftp_root_warning(warning: &crate::config::tftp::RootWarning) -> LogEvent {
    let mut message = if warning.interface {
        b"warning: TFTP directory ".to_vec()
    } else {
        b"warning: ".to_vec()
    };
    message.extend_from_slice(&warning.path);
    message.extend_from_slice(b" inaccessible");
    LogEvent::new(Service::Tftp, Priority::Warning, message)
}

/// dnsmasq.c:980-983 uses the source wildcard-prefix name matching rule.
pub fn missing_interfaces(
    config: &crate::config::dns::DnsConfig,
    interfaces: &[crate::interfaces::DnsInterface],
) -> Vec<LogEvent> {
    if config.bind_interfaces || config.bind_dynamic {
        return Vec::new();
    }
    config
        .interfaces
        .iter()
        .flatten()
        .filter(|pattern| {
            !interfaces.iter().any(|interface| {
                match pattern.iter().position(|byte| *byte == b'*') {
                    Some(at) => {
                        interface.name.len() > at && interface.name.starts_with(&pattern[..at])
                    }
                    None => *pattern == &interface.name,
                }
            })
        })
        .map(|name| {
            let mut message = b"warning: interface ".to_vec();
            message.extend_from_slice(name);
            message.extend_from_slice(b" does not currently exist");
            LogEvent::new(Service::Dns, Priority::Warning, message)
        })
        .collect()
}

/// network.c:1627-1677 consumes the live post-check_servers rows. Upstreams
/// retain insertion order; local_domains is a separately prepended C chain.
pub fn server_messages(
    rows: &[SourcedRule],
    is_looped: impl Fn(ServerId) -> bool,
) -> Vec<LogEvent> {
    let mut events = Vec::new();
    let mut count = 0;
    for row in rows.iter().filter(|row| row.server.is_some()) {
        let RuleTarget::Upstream(endpoint) = &row.value.rule.target else {
            continue;
        };
        let Some(address) = row
            .value
            .address
            .or_else(|| crate::dns::routing::validate_endpoint(endpoint).ok())
        else {
            continue;
        };
        if count == 30 {
            events.push(LogEvent::new(
                Service::Dns,
                Priority::Info,
                b"more servers are defined but not logged".to_vec(),
            ));
        }
        count += 1;
        if count > 30 {
            continue;
        }
        let domain = &row.value.rule.domain;
        let mut message =
            if domain.suffix.is_empty() && !domain.dotless && is_looped(row.server.unwrap()) {
                b"NOT using nameserver ".to_vec()
            } else {
                b"using nameserver ".to_vec()
            };
        message.extend_from_slice(&super::address_text(address));
        message.extend_from_slice(format!("#{}", address.port()).as_bytes());
        if domain.dotless {
            message.extend_from_slice(b" for unqualified names ");
        } else if !domain.suffix.is_empty() {
            message.extend_from_slice(b" for domain ");
            if domain.wildcard {
                message.push(b'*');
            }
            message.extend_from_slice(&domain.suffix);
            message.push(b' ');
        } else if is_looped(row.server.unwrap()) {
            message.extend_from_slice(b" - query loop detected");
        } else if let Some(interface) = endpoint
            .source
            .as_ref()
            .and_then(|source| source.interface.as_ref())
            .filter(|name| !name.is_empty())
        {
            message.extend_from_slice(b"(via ");
            message.extend_from_slice(interface);
            message.push(b')');
        }
        events.push(LogEvent::new(Service::Dns, Priority::Info, message));
    }
    let mut count: usize = 0;
    let mut locals = 0;
    for row in rows.iter().rev().filter(|row| row.server.is_none()) {
        count += 1;
        if count > 30 {
            continue;
        }
        let rule = &row.value.rule;
        let prefix = match &rule.target {
            RuleTarget::LocalOnly if !rule.domain.suffix.is_empty() => {
                count -= 1;
                locals += 1;
                if locals > 8 {
                    continue;
                }
                b"using only locally-known addresses for ".as_slice()
            }
            RuleTarget::DefaultResolvers if !rule.domain.suffix.is_empty() => {
                b"using standard nameservers for ".as_slice()
            }
            _ => continue,
        };
        let mut message = prefix.to_vec();
        message.extend_from_slice(&rule.domain.suffix);
        events.push(LogEvent::new(Service::Dns, Priority::Info, message));
    }
    if locals > 8 {
        events.push(LogEvent::new(
            Service::Dns,
            Priority::Info,
            format!("using {} more local addresses", locals - 8).into_bytes(),
        ));
    }
    // Keep C's count-1 boundary for its local_domains list, even when this
    // yields a smaller count than the number of deliberately omitted rows.
    if count > 31 {
        events.push(LogEvent::new(
            Service::Dns,
            Priority::Info,
            format!("using {} more nameservers", count - 31).into_bytes(),
        ));
    }
    events
}

/// util.c:590-607: infinity is special; zero produces an empty duration.
fn lease_duration(seconds: u32) -> String {
    if seconds == u32::MAX {
        return "infinite".into();
    }
    let mut result = String::new();
    for (count, unit) in [
        (seconds / 86400, 'd'),
        ((seconds / 3600) % 24, 'h'),
        ((seconds / 60) % 60, 'm'),
        (seconds % 60, 's'),
    ] {
        if count != 0 {
            result.push_str(&format!("{count}{unit}"));
        }
    }
    result
}
