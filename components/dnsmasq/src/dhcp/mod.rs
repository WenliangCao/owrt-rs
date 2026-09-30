//! DHCPv4 primitives traced to the patched OpenWrt dnsmasq 2.93 source.
//!
//! The Linux-only [`service::SocketListener`] now supplies an isolated,
//! nonblocking AF_INET receive/send boundary and can feed local BOOTP/DHCPv4
//! state through [`runtime::StateProvider`]. This remains a caller-owned
//! service component: interface/context selection, relay/PXE policy, durable
//! lease files, DNS publication and the production event loop are separate
//! contracts and must not be silently omitted.

pub mod allocation;
pub mod lease;
pub mod lease_file;
pub mod lease_query;
pub mod packet;
pub mod pxe;
pub mod reply;
pub mod request;
pub mod runtime;
pub mod service;
pub mod state;
