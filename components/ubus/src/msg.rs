//! ubus message header, message types, attribute ids and status codes
//! (mirrors ubusmsg.h of the pinned ubus revision).

use crate::blob::{self, Attr};

pub const UBUS_SOCKET: &str = "/var/run/ubus/ubus.sock";
pub const MAX_MSGLEN: usize = 1_048_576;

pub mod ty {
    pub const HELLO: u8 = 0;
    pub const STATUS: u8 = 1;
    pub const DATA: u8 = 2;
    pub const PING: u8 = 3;
    pub const LOOKUP: u8 = 4;
    pub const INVOKE: u8 = 5;
    pub const ADD_OBJECT: u8 = 6;
    pub const REMOVE_OBJECT: u8 = 7;
    pub const SUBSCRIBE: u8 = 8;
    pub const UNSUBSCRIBE: u8 = 9;
    pub const NOTIFY: u8 = 10;
    pub const MONITOR: u8 = 11;
}

pub mod attr {
    pub const STATUS: u32 = 1;
    pub const OBJPATH: u32 = 2;
    pub const OBJID: u32 = 3;
    pub const METHOD: u32 = 4;
    pub const OBJTYPE: u32 = 5;
    pub const SIGNATURE: u32 = 6;
    pub const DATA: u32 = 7;
    pub const TARGET: u32 = 8;
    pub const ACTIVE: u32 = 9;
    pub const NO_REPLY: u32 = 10;
    pub const SUBSCRIBERS: u32 = 11;
    pub const USER: u32 = 12;
    pub const GROUP: u32 = 13;
    pub const MAX: usize = 14;
}

pub mod status {
    pub const OK: i32 = 0;
    pub const INVALID_COMMAND: i32 = 1;
    pub const INVALID_ARGUMENT: i32 = 2;
    pub const METHOD_NOT_FOUND: i32 = 3;
    pub const NOT_FOUND: i32 = 4;
    pub const NO_DATA: i32 = 5;
    pub const PERMISSION_DENIED: i32 = 6;
    pub const TIMEOUT: i32 = 7;
    pub const NOT_SUPPORTED: i32 = 8;
    pub const UNKNOWN_ERROR: i32 = 9;
    pub const CONNECTION_FAILED: i32 = 10;
    pub const NO_MEMORY: i32 = 11;
    pub const PARSE_ERROR: i32 = 12;
    pub const SYSTEM_ERROR: i32 = 13;

    pub fn name(code: i32) -> String {
        static_name(code)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("Unknown error: {code}"))
    }

    fn static_name(code: i32) -> Option<&'static str> {
        Some(match code {
            OK => "Success",
            INVALID_COMMAND => "Invalid command",
            INVALID_ARGUMENT => "Invalid argument",
            METHOD_NOT_FOUND => "Method not found",
            NOT_FOUND => "Not found",
            NO_DATA => "No response",
            PERMISSION_DENIED => "Permission denied",
            TIMEOUT => "Request timed out",
            NOT_SUPPORTED => "Operation not supported",
            UNKNOWN_ERROR => "Unknown error",
            CONNECTION_FAILED => "Connection failed",
            NO_MEMORY => "Out of memory",
            PARSE_ERROR => "Parsing message data failed",
            SYSTEM_ERROR => "System error",
            _ => return None,
        })
    }
}

/// 8-byte wire header: version, type, seq (be16), peer (be32).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub ty: u8,
    pub seq: u16,
    pub peer: u32,
}

impl Header {
    pub const LEN: usize = 8;

    pub fn encode(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = 0;
        out[1] = self.ty;
        out[2..4].copy_from_slice(&self.seq.to_be_bytes());
        out[4..8].copy_from_slice(&self.peer.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8; 8]) -> Option<Self> {
        if bytes[0] != 0 {
            return None;
        }
        Some(Self {
            ty: bytes[1],
            seq: u16::from_be_bytes([bytes[2], bytes[3]]),
            peer: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }
}

/// A received message: header plus the raw head blob (4-byte attr header and
/// its payload of top-level ubus attributes).
#[derive(Debug)]
pub struct Message {
    pub header: Header,
    pub blob: Vec<u8>,
    pub fd: Option<std::os::fd::OwnedFd>,
}

impl Message {
    /// Top-level attributes indexed by attribute id.
    pub fn attrs(&self) -> [Option<Attr<'_>>; attr::MAX] {
        let mut out: [Option<Attr<'_>>; attr::MAX] = Default::default();
        if self.blob.len() >= 4 {
            for item in blob::iter(&self.blob[4..]) {
                if (item.id as usize) < attr::MAX {
                    out[item.id as usize] = Some(item);
                }
            }
        }
        out
    }

    pub fn status(&self) -> Option<i32> {
        self.attrs()[attr::STATUS as usize].and_then(|a| a.as_u32().map(|v| v as i32))
    }
}
