//! Internal Linux ABI boundaries shared by the OpenWrt service components.
//! Keep policy and service state in their business crates; prefer rustix/std
//! there and use this crate only for interfaces those safe APIs cannot express.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

#[cfg(target_os = "linux")]
pub mod procd;
#[cfg(target_os = "linux")]
pub mod netifd;
#[cfg(target_os = "linux")]
pub mod rpcd;

pub mod unix;
#[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "x86_64")))]
pub mod directory;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod ipc;

#[cfg(target_os = "linux")]
pub mod readiness;

#[cfg(target_os = "linux")]
pub mod ubusd;

pub mod text;
#[cfg(target_os = "linux")]
pub mod httpd;
