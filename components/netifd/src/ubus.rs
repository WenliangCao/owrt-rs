//! The ubus surface: `network`, `network.device`, `network.interface` and one
//! `network.interface.<name>` per interface.
//!
//! The registered signature is part of the interface — `ubus -v list` prints
//! it, and callers parse it — so the method names, their order and their
//! argument policies match ubus.c's tables exactly, including the methods this
//! build does not implement. An unimplemented method registers with its real
//! signature and returns `NOT_SUPPORTED`, which is a caller-visible refusal
//! rather than a silent success.

use std::io;

use owrt_ubus::blob::{BlobBuf, MsgType};
use owrt_ubus::conn::{Connection, Request};
use owrt_ubus::msg::status;

use crate::logging;

// blobmsg has no distinct BOOL type: a bool is INT8, and that is the type
// `ubus -v list` prints for these arguments.
const BOOL: MsgType = MsgType::Int8;

/// `main_object_methods`, in order. `restart`, `reload` and
/// `get_proto_handlers` take no policy in the C either.
pub const NETWORK_METHODS: &[(&str, &[(&str, MsgType)])] = &[
    ("restart", &[]),
    ("reload", &[]),
    (
        "add_host_route",
        &[
            ("target", MsgType::String),
            ("v6", BOOL),
            ("interface", MsgType::String),
            ("exclude", BOOL),
        ],
    ),
    ("get_proto_handlers", &[]),
    ("add_dynamic", &[("name", MsgType::String)]),
    ("netns_updown", &[("jail", MsgType::String), ("start", BOOL)]),
];

/// `dev_object_methods`. `hotplug_event` is `#ifdef DUMMY_MODE` and this
/// target is not a dummy build, so it is absent — confirmed on the device.
pub const DEVICE_METHODS: &[(&str, &[(&str, MsgType)])] = &[
    ("status", &[("name", MsgType::String)]),
    ("set_alias", &[("alias", MsgType::Array), ("device", MsgType::String)]),
    (
        "set_state",
        &[
            ("name", MsgType::String),
            ("defer", BOOL),
            ("auth_status", BOOL),
            ("auth_vlans", MsgType::Array),
        ],
    ),
    ("stp_init", &[]),
];

/// `wireless.uc`'s `ubus_obj`, in its key order. Measured from the device:
/// every method takes `device`, and `notify` carries the callback payload the
/// handler scripts send.
pub const WIRELESS_METHODS: &[(&str, &[(&str, MsgType)])] = &[
    ("up", &[("device", MsgType::String)]),
    ("down", &[("device", MsgType::String)]),
    ("retry", &[("device", MsgType::String)]),
    ("reconf", &[("device", MsgType::String)]),
    ("status", &[("device", MsgType::String)]),
    (
        "notify",
        &[
            ("device", MsgType::String),
            ("command", MsgType::Int32),
            ("interface", MsgType::String),
            ("vlan", MsgType::String),
            ("data", MsgType::Table),
        ],
    ),
    ("get_validate", &[("device", MsgType::String)]),
];

/// ucode validates every field before converting the request to an object.
/// Repeated valid strings are legal and the last one wins; a later string
/// cannot hide an earlier invalid type or an unknown argument.
pub fn wireless_read_device(data: &[u8]) -> Result<Option<&[u8]>, i32> {
    let mut device = None;
    let mut remaining = data;
    while remaining.len() >= 4 {
        let word = u32::from_be_bytes(remaining[..4].try_into().unwrap());
        let raw_len = (word & 0x00ff_ffff) as usize;
        let padded = owrt_ubus::blob::pad4(raw_len);
        // libubox stops at an incomplete trailing attribute. A raw length
        // of 1..3 still enters its loop, then fails blobmsg validation.
        if padded < 4 || padded > remaining.len() {
            break;
        }
        let (attr, _) = owrt_ubus::blob::attr_at(remaining, 0)
            .ok_or(status::INVALID_ARGUMENT)?;
        if !attr.extended || attr.id != MsgType::String as u32 || attr.payload.len() < 2 {
            return Err(status::INVALID_ARGUMENT);
        }
        let name_len = u16::from_be_bytes(attr.payload[..2].try_into().unwrap()) as usize;
        let header_len = owrt_ubus::blob::pad4(2 + name_len + 1);
        if attr.payload.len() < header_len || attr.payload[2 + name_len] != 0 {
            return Err(status::INVALID_ARGUMENT);
        }
        let name = &attr.payload[2..2 + name_len];
        if name != b"device" {
            return Err(status::INVALID_ARGUMENT);
        }
        let value = &attr.payload[header_len..];
        if value.last() != Some(&0) {
            return Err(status::INVALID_ARGUMENT);
        }
        // ucode retains arbitrary bytes and internal NULs. It tests the
        // full string length before looking up a C-string object key.
        device = Some(&value[..value.len() - 1]);
        remaining = &remaining[padded..];
    }
    Ok(device)
}

#[cfg(test)]
mod wireless_argument_tests {
    use super::*;

    #[test]
    fn repeated_strings_use_the_last_value() {
        let mut b = BlobBuf::new();
        assert_eq!(wireless_read_device(b.payload()), Ok(None));
        b.msg_string("device", "radio0");
        b.msg_string("device", "radio1");
        assert_eq!(wireless_read_device(b.payload()), Ok(Some(b"radio1".as_slice())));
        b.msg_string("device", "");
        assert_eq!(wireless_read_device(b.payload()), Ok(Some(b"".as_slice())));
    }

    #[test]
    fn invalid_argument_is_not_hidden_by_another_field() {
        for bad_first in [false, true] {
            for unknown_name in [false, true] {
                let mut b = BlobBuf::new();
                for bad in [bad_first, !bad_first] {
                    if !bad {
                        b.msg_string("device", "radio0");
                    } else if unknown_name {
                        b.msg_string("extra", "ignored?");
                    } else {
                        b.msg_bool("device", true);
                    }
                }
                assert_eq!(wireless_read_device(b.payload()), Err(status::INVALID_ARGUMENT));
            }
        }
    }

    #[test]
    fn malformed_attributes_are_rejected_instead_of_skipped() {
        let mut b = BlobBuf::new();
        b.msg_string("device", "radio0");
        let valid = b.payload().to_vec();
        let mut bad_name_nul = valid.clone();
        bad_name_nul[4 + 2 + 6] = b'x';
        let mut bad_name_utf8 = valid.clone();
        bad_name_utf8[4 + 2] = 0xff;
        for bad in [
            vec![3, 0, 0, 4],                 // non-extended
            vec![0x83, 0, 0, 5, 0, 0, 0, 0], // short field header
            vec![0x83, 0, 0, 8, 0xff, 0xff, 0, 0],
            bad_name_nul,
            bad_name_utf8,
        ] {
            for prefix in [false, true] {
                let mut request = if prefix { valid.clone() } else { Vec::new() };
                request.extend_from_slice(&bad);
                assert_eq!(wireless_read_device(&request), Err(status::INVALID_ARGUMENT));
            }
        }
        for value in [b"".as_slice(), b"radio0", b"radio0\0tail"] {
            b.reset();
            b.msg_field(MsgType::String as u32, "device", value);
            assert_eq!(wireless_read_device(b.payload()), Err(status::INVALID_ARGUMENT));
        }
    }

    #[test]
    fn incomplete_tail_follows_libubox_iteration_boundary() {
        let mut b = BlobBuf::new();
        b.msg_string("device", "radio0");
        for tail in [
            vec![0xff], vec![0xff; 3], vec![0x83, 0, 0, 0],
            vec![0x83, 0, 0, 100], vec![0x83, 0, 0, 5, b'x'],
        ] {
            let mut request = b.payload().to_vec();
            request.extend_from_slice(&tail);
            assert_eq!(wireless_read_device(&request), Ok(Some(b"radio0".as_slice())));
        }
        for raw_len in 1..=3 {
            let mut request = b.payload().to_vec();
            request.extend_from_slice(&[0x83, 0, 0, raw_len]);
            assert_eq!(wireless_read_device(&request), Err(status::INVALID_ARGUMENT));
        }
    }

    #[test]
    fn strings_keep_internal_nuls_until_selector_lookup() {
        let mut b = BlobBuf::new();
        for value in [b"radio0\0tail".as_slice(), b"\0tail", b"\xff"] {
            b.reset();
            let mut encoded = value.to_vec();
            encoded.push(0);
            b.msg_field(MsgType::String as u32, "device", &encoded);
            assert_eq!(wireless_read_device(b.payload()), Ok(Some(value)));
        }
        for name in ["device\0suffix", "device\0"] {
            b.reset();
            b.msg_string(name, "radio0");
            assert_eq!(wireless_read_device(b.payload()), Err(status::INVALID_ARGUMENT));
        }
    }
}

/// `iface_object_methods`.
pub const IFACE_METHODS: &[(&str, &[(&str, MsgType)])] = &[
    ("up", &[]),
    ("down", &[]),
    ("renew", &[]),
    ("status", &[]),
    ("prepare", &[]),
    ("dump", &[]),
    (
        "add_device",
        &[("name", MsgType::String), ("link-ext", BOOL), ("vlan", MsgType::Array)],
    ),
    (
        "remove_device",
        &[("name", MsgType::String), ("link-ext", BOOL), ("vlan", MsgType::Array)],
    ),
    ("notify_proto", &[]),
    ("remove", &[]),
    ("set_data", &[]),
];

/// The object ids ubusd handed us.
#[derive(Default)]
pub struct Objects {
    pub network: u32,
    pub device: u32,
    pub interface: u32,
    // The fixed interface object keeps this shared method type alive. A fresh
    // Objects::register on reconnect obtains a new connection-scoped type.
    interface_type: u32,
    pub wireless: u32,
    /// One per interface, in registration order.
    pub per_interface: Vec<(String, u32)>,
}

impl Objects {
    /// Register the three fixed objects. Per-interface objects are added as
    /// interfaces appear, which is also how the C does it — the object list is
    /// not fixed at startup.
    pub fn register(conn: &mut Connection) -> io::Result<Self> {
        let network = conn.add_object("network", NETWORK_METHODS, 5000)?;
        let device = conn.add_object("network.device", DEVICE_METHODS, 5000)?;
        let (interface, interface_type) = conn.add_object_typed("network.interface", IFACE_METHODS, None, 5000)?;
        Ok(Self {
            network,
            device,
            interface,
            interface_type,
            wireless: conn.add_object("network.wireless", WIRELESS_METHODS, 5000)?,
            per_interface: Vec::new(),
        })
    }

    /// `netifd_ubus_remove_interface`.
    pub fn remove_interface(&mut self, conn: &mut Connection, name: &str) -> io::Result<()> {
        let Some(pos) = self.per_interface.iter().position(|(n, _)| n == name) else {
            return Ok(());
        };
        let (_, id) = self.per_interface.remove(pos);
        conn.remove_object(id, 5000)
    }

    pub fn add_interface(&mut self, conn: &mut Connection, name: &str) -> io::Result<u32> {
        let path = format!("network.interface.{name}");
        let (id, _) = conn.add_object_typed(&path, &[], Some(self.interface_type), 5000)?;
        self.per_interface.push((name.to_string(), id));
        Ok(id)
    }

    /// Which object a request landed on.
    pub fn route(&self, objid: u32) -> Target<'_> {
        if objid == self.network {
            return Target::Network;
        }
        if objid == self.device {
            return Target::Device;
        }
        if objid == self.interface {
            return Target::Interface(None);
        }
        if objid == self.wireless {
            return Target::Wireless;
        }
        match self.per_interface.iter().find(|(_, id)| *id == objid) {
            Some((name, _)) => Target::Interface(Some(name)),
            None => Target::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Target<'a> {
    Wireless,
    Network,
    Device,
    /// `None` for the shared object, `Some(name)` for a per-interface one.
    Interface(Option<&'a str>),
    Unknown,
}

/// ubusd's built-in event object. `ubus_send_event` is an invoke of `send` on
/// it, carrying `{id: <event name>, data: <table>}`.
pub const SYSTEM_OBJECT_EVENT: u32 = 1;

/// `ubus_send_event`: a broadcast to whoever registered for the name.
/// A failure is reported rather than swallowed -- hotplug consumers are
/// downstream of this, so a lost event is a lost reconfiguration.
pub fn send_event(conn: &mut Connection, id: &str, fields: &[u8]) -> io::Result<()> {
    let mut b = BlobBuf::new();
    b.msg_string("id", id);
    let t = b.msg_open_table("data");
    b.put_raw_fields(fields);
    b.msg_close(t);
    let payload = b.payload().to_vec();
    conn.invoke(SYSTEM_OBJECT_EVENT, "send", &payload, 5000).map(|_| ())
}

/// `netifd_ubus_interface_event`: the `network.interface` broadcast, with the
/// two field names in the C's order.
pub fn interface_event(conn: &mut Connection, name: &str, up: bool) -> io::Result<()> {
    let mut b = BlobBuf::new();
    b.msg_string("action", if up { "ifup" } else { "ifdown" });
    b.msg_string("interface", name);
    let fields = b.payload().to_vec();
    send_event(conn, "network.interface", &fields)
}

/// A refusal that names the method, so a caller sees which call it was.
pub fn not_supported(conn: &mut Connection, req: &Request, what: &str) -> io::Result<()> {
    logging::log!(Warning, "{what} is not implemented by this build");
    conn.reply_status(req, status::NOT_SUPPORTED, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_method_names_and_order_match_the_c_tables() {
        assert_eq!(
            NETWORK_METHODS.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![
                "restart",
                "reload",
                "add_host_route",
                "get_proto_handlers",
                "add_dynamic",
                "netns_updown"
            ]
        );
        assert_eq!(
            DEVICE_METHODS.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec!["status", "set_alias", "set_state", "stp_init"]
        );
        assert_eq!(
            IFACE_METHODS.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![
                "up",
                "down",
                "renew",
                "status",
                "prepare",
                "dump",
                "add_device",
                "remove_device",
                "notify_proto",
                "remove",
                "set_data"
            ]
        );
    }

    #[test]
    fn hotplug_event_is_not_registered_on_this_target() {
        assert!(!DEVICE_METHODS.iter().any(|(n, _)| *n == "hotplug_event"));
    }

    #[test]
    fn routing_distinguishes_the_shared_and_per_interface_objects() {
        let o = Objects {
            network: 1,
            device: 2,
            interface: 3,
            interface_type: 7,
            wireless: 9,
            per_interface: vec![("lan".into(), 4), ("wan".into(), 5)],
        };
        assert_eq!(o.route(1), Target::Network);
        assert_eq!(o.route(2), Target::Device);
        assert_eq!(o.route(3), Target::Interface(None));
        assert_eq!(o.route(4), Target::Interface(Some("lan")));
        assert_eq!(o.route(5), Target::Interface(Some("wan")));
        assert_eq!(o.route(99), Target::Unknown);
    }
}
