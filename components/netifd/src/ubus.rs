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
    pub wireless: u32,
    /// One per interface, in registration order.
    pub per_interface: Vec<(String, u32)>,
}

impl Objects {
    /// Register the three fixed objects. Per-interface objects are added as
    /// interfaces appear, which is also how the C does it — the object list is
    /// not fixed at startup.
    pub fn register(conn: &mut Connection) -> io::Result<Self> {
        Ok(Self {
            network: conn.add_object("network", NETWORK_METHODS, 5000)?,
            device: conn.add_object("network.device", DEVICE_METHODS, 5000)?,
            interface: conn.add_object("network.interface", IFACE_METHODS, 5000)?,
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
        let id = conn.add_object(&path, IFACE_METHODS, 5000)?;
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

/// The proto handlers this build offers, with the validation table
/// `get_proto_handlers` reports. `static` is built in; the shell handlers are
/// read from `/lib/netifd/proto` at startup by the C, and this build reports
/// only what it can actually run.
pub fn proto_handlers(b: &mut BlobBuf, names: &[(&str, bool)]) {
    for (name, no_proto) in names {
        let t = b.msg_open_table(name);
        if *no_proto {
            b.msg_bool("no_proto", true);
        }
        b.msg_close(t);
    }
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
    eprintln!("netifd-rs: {what} is not implemented by this build");
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
