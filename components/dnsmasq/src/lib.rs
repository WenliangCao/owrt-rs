//! OpenWrt dnsmasq 2.93 configuration, DNS, DHCPv4 and TFTP contracts.
//!
//! Protocol and state-machine modules expose caller-owned operations. The
//! daemon binary coordinates their sockets, file reloads and process lifetimes;
//! `dnsmasq-platform` owns the Linux ABI boundaries.

#![cfg_attr(target_os = "linux", deny(warnings))]
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[path = "logging/address.rs"]
mod address_logging;

pub mod config;
pub mod dhcp;
pub mod dns;
#[cfg(target_os = "linux")]
pub mod dump;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod helper;
pub mod hosts;
pub mod interfaces;
#[cfg(target_os = "linux")]
pub mod logging;
pub mod metrics;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod neighbors;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod net;
#[path = "logging/query.rs"]
pub mod query_logging;
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
