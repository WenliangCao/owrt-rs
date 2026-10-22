//! DHCPv4 primitives traced to the patched OpenWrt dnsmasq 2.93 source.
//!
//! The Linux-only `service::SocketListener` supplies an isolated,
//! nonblocking AF_INET receive/send boundary and can feed local BOOTP/DHCPv4
//! state through [`runtime::StateProvider`]. This remains a caller-owned
//! service component: interface/context selection, relay/PXE policy, durable
//! lease files, DNS publication and the production event loop are separate
//! contracts and must not be silently omitted.

pub mod allocation;
pub mod context;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod filewatch;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod files_runtime;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod daemon;
// The matcher is shared with the portable relay engine; the policy adapter
// itself has production consumers only in the Linux daemon.
#[cfg_attr(
    not(all(target_os = "linux", target_pointer_width = "64")),
    allow(dead_code)
)]
mod interface_admission;
pub mod lease;
pub mod lease_file;
pub mod lease_query;
pub mod logging;
pub mod message_counters;
pub mod packet;
pub mod persistence;
pub mod probe;
pub mod pxe;
pub mod relay;
pub mod reply;
pub mod request;
pub mod runtime;
pub mod service;
pub mod state;

pub mod reply_delay;
