//! Minimal ubus wire-protocol implementation: blob/blobmsg codec, a blocking
//! connection that can act as client (lookup, invoke, notify) and as object
//! server (add_object, receive invokes, reply with data/status and an optional
//! file descriptor). No libubus, no third-party crates. Linux only.

pub mod blob;
pub mod conn;
pub mod msg;
pub mod sys;

pub use blob::{Attr, BlobBuf, Field, MsgType};
pub use conn::{Connection, Incoming, LookupEntry, Reply, Request};
pub use msg::{attr, status, ty, Header, Message};
