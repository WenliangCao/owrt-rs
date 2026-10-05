//! Startup messages from dhcp-common.c:950-1025 and dnsmasq.c:1038-1049.
use super::{LogEvent, Priority, Service};
use crate::config::dhcp::RangeConfig;
use crate::config::tftp::TftpConfig;
use crate::dhcp::allocation::RangeKind;

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
