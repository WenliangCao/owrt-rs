//! Offline producer observer; run only in tools/dnsmasq/run_isolated.sh.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
include!("../../../../tools/dnsmasq/dhcp_events_probe.rs");
#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn main() {
    panic!("Linux event producer probe required");
}
