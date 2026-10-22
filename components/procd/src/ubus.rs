//! The ubus surface: `service`, `system` and `container`.
//!
//! The registered signature is part of the interface -- `ubus -v list` prints
//! it and callers parse it -- so method names, their order and their argument
//! policies match procd's own tables exactly. Sources, at the pinned revision
//! 58eb263d5abe03f8c1280bdfa65a3b052614215d:
//!
//! - `service/service.c:1074` `main_object_methods`
//! - `service/service.c:1155` `container_object_methods`
//! - `system.c` `system_object` methods
//!
//! A method that is registered but not implemented by this build answers
//! `NOT_SUPPORTED`, which is a refusal the caller can see, not a silent
//! success.

use owrt_ubus::blob::MsgType;

// blobmsg has no distinct BOOL type: a bool is INT8, and INT8 is what
// `ubus -v list` prints for these arguments.
const BOOL: MsgType = MsgType::Int8;

/// `service_set_attrs` -- shared by `set` and `add`.
const SET_ATTRS: &[(&str, MsgType)] = &[
    ("name", MsgType::String),
    ("script", MsgType::String),
    ("instances", MsgType::Table),
    ("triggers", MsgType::Array),
    ("validate", MsgType::Array),
    ("autostart", BOOL),
    ("data", MsgType::Table),
];

/// `service_attrs` -- shared by `update_start` and `update_complete`.
const NAME_ONLY: &[(&str, MsgType)] = &[("name", MsgType::String)];

/// `main_object_methods`, in order.
pub const SERVICE_METHODS: &[(&str, &[(&str, MsgType)])] = &[
    ("set", SET_ATTRS),
    ("add", SET_ATTRS),
    ("list", &[("name", MsgType::String), ("verbose", BOOL)]),
    (
        "delete",
        &[("name", MsgType::String), ("instance", MsgType::String)],
    ),
    (
        "signal",
        &[
            ("name", MsgType::String),
            ("instance", MsgType::String),
            ("signal", MsgType::Int32),
        ],
    ),
    ("update_start", NAME_ONLY),
    ("update_complete", NAME_ONLY),
    (
        "event",
        &[("type", MsgType::String), ("data", MsgType::Table)],
    ),
    (
        "validate",
        &[
            ("package", MsgType::String),
            ("type", MsgType::String),
            ("service", MsgType::String),
        ],
    ),
    (
        "get_data",
        &[
            ("name", MsgType::String),
            ("instance", MsgType::String),
            ("type", MsgType::String),
        ],
    ),
    (
        "set_data",
        &[
            ("name", MsgType::String),
            ("instance", MsgType::String),
            ("data", MsgType::Table),
        ],
    ),
    ("state", &[("spawn", BOOL), ("name", MsgType::String)]),
    (
        // Designated initialisers do not reorder the array: the enum does.
        // SERVICE_WATCHDOG_{MODE,TIMEOUT,NAME,INSTANCE} is the order the
        // policy is stored in and therefore the order `ubus -v list` prints,
        // even though the initialiser lists name before timeout.
        "watchdog",
        &[
            ("mode", MsgType::Int32),
            ("timeout", MsgType::Int32),
            ("name", MsgType::String),
            ("instance", MsgType::String),
        ],
    ),
];

/// `container_object_methods`. Registered for signature parity; this build
/// runs no containers on this device (`ubus call service list` shows none),
/// so the container-only methods refuse.
pub const CONTAINER_METHODS: &[(&str, &[(&str, MsgType)])] = &[
    ("set", SET_ATTRS),
    ("add", SET_ATTRS),
    ("list", &[("name", MsgType::String), ("verbose", BOOL)]),
    (
        "delete",
        &[("name", MsgType::String), ("instance", MsgType::String)],
    ),
    ("state", &[("spawn", BOOL), ("name", MsgType::String)]),
    ("get_features", &[]),
    (
        "console_set",
        &[("name", MsgType::String), ("instance", MsgType::String)],
    ),
    (
        "console_attach",
        &[("name", MsgType::String), ("instance", MsgType::String)],
    ),
];

/// Which registered object an incoming invoke belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    Service,
    Container,
    System,
}

/// `system_object` methods, in order (`system.c:845`).
///
/// `sysupgrade` and `validate_firmware_image` are implemented since P4
/// (sysupgrade.rs); a real sysupgrade call validates, stops everything and
/// execs /sbin/upgraded, exactly like the C.
pub const SYSTEM_METHODS: &[(&str, &[(&str, MsgType)])] = &[
    ("board", &[]),
    ("info", &[]),
    ("reboot", &[]),
    (
        "watchdog",
        &[
            ("frequency", MsgType::Int32),
            ("timeout", MsgType::Int32),
            ("magicclose", BOOL),
            ("stop", BOOL),
        ],
    ),
    (
        "signal",
        &[("pid", MsgType::Int32), ("signum", MsgType::Int32)],
    ),
    ("validate_firmware_image", &[("path", MsgType::String)]),
    (
        "sysupgrade",
        &[
            ("path", MsgType::String),
            ("force", BOOL),
            ("backup", MsgType::String),
            ("prefix", MsgType::String),
            ("command", MsgType::String),
            ("options", MsgType::Table),
        ],
    ),
];
