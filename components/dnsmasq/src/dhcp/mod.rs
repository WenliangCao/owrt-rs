//! DHCPv4 primitives traced to the patched OpenWrt dnsmasq 2.93 source.
//!
//! These modules do not yet constitute a DHCP server. In particular, interface
//! selection, tags, reply options, relay/PXE dispatch and durable integration are
//! separate contracts; callers must not silently omit them.

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
