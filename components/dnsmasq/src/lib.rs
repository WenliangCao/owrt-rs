//! Native Rust implementation under development against dnsmasq 2.93-r1.
//!
//! The source and acceptance ledger lives in `docs/dnsmasq`. Individual tested
//! modules do not yet constitute a service or a compatible package replacement.

pub mod config;
pub mod dhcp;
pub mod dns;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod helper;
pub mod hosts;
pub mod interfaces;
pub mod metrics;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod neighbors;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod net;
#[doc(hidden)]
pub mod sorting;
pub mod tftp;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod tftp_listener;
#[cfg(unix)]
pub mod tftp_runtime;
pub mod tftp_service;
pub mod ubus_service;

pub mod startup;

pub mod listeners;
