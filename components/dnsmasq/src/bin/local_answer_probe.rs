// Test-only cargo target. Keep the implementation under tools/ so it cannot
// be confused with the installed dnsmasq-rs daemon entrypoint.
include!("../../../../tools/dnsmasq/local_answer_probe.rs");
