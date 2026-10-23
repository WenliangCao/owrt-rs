//! Internal Linux ABI boundaries shared by the OpenWrt service components.
//! Keep policy and service state in their business crates; prefer rustix/std
//! there and use this crate only for interfaces those safe APIs cannot express.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

// The hand-written libc layouts below are verified for these deployment and
// CI targets. Refuse other ABIs instead of exposing safe functions backed by
// unverified struct sizes (notably time_t, timeval, ifreq and msghdr).
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
)))]
compile_error!("owrt-platform supports only Linux aarch64 and x86_64 ABIs");

#[cfg(target_os = "linux")]
pub mod netifd;
#[cfg(target_os = "linux")]
pub mod procd;
#[cfg(target_os = "linux")]
pub mod rpcd;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub mod directory;
pub mod unix;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod ipc;

#[cfg(target_os = "linux")]
pub mod readiness;

#[cfg(target_os = "linux")]
pub mod ubusd;

#[cfg(target_os = "linux")]
pub mod httpd;
pub mod text;

#[cfg(target_os = "linux")]
pub mod identity;

#[cfg(target_os = "linux")]
pub mod process_owner;
#[cfg(target_os = "linux")]
pub mod reload_signals;
#[cfg(target_os = "linux")]
pub mod rpcd_signals;
#[cfg(target_os = "linux")]
pub mod ubusd_signals;
