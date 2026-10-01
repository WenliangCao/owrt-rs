//! Source-order observer: isolated Linux namespace required.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
include!("../../../../tools/dnsmasq/dhcp_event_order_probe.rs");
#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
fn main() {
    panic!("Linux event order probe required");
}
