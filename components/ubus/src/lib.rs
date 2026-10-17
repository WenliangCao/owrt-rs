//! Minimal ubus wire-protocol implementation: blob/blobmsg codec, a blocking
//! connection that can act as client (lookup, invoke, notify) and as object
//! server (add_object, receive invokes, reply with data/status and an optional
//! file descriptor). No libubus; rustix supplies ordinary OS calls. Linux only.

#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]
#![forbid(unsafe_code)]

pub mod blob;
mod connect;
pub mod conn;
pub mod convert;
pub mod digest;
pub mod json;
pub mod msg;
pub mod readiness;
pub mod sys;

pub use blob::{Attr, BlobBuf, Field, MsgType};
pub use conn::{Connection, Incoming, LookupEntry, Reply, Request};
pub use msg::{attr, status, ty, Header, Message};
