//! The scoped daemon's protocol/state logic. See docs/contracts/odhcpd-*.md.
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod config;
pub mod control;
pub mod dhcpv6;
pub mod kernel;
pub mod leases;
pub mod model;
pub mod netio;
pub mod router;
