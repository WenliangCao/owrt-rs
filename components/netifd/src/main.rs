//! netifd-rs: network device and interface management.
//!
//! Scope is deliberately this device's: see
//! reports/ax3000t-stock-openwrt-25.12.5/R45_NETIFD_SCOPE.md. Configuration
//! this build cannot honour is reported as an error, never ignored.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod device;
mod ethtool;
mod ethtool_modes;
mod netdev_types;
mod netlink;
mod sys;

fn main() {
    eprintln!("netifd-rs: not yet a daemon");
    std::process::exit(1);
}
