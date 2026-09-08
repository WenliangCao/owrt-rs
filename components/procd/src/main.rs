//! procd-rs: service supervision.
//!
//! Stage P3.1: the supervision core, running as an ordinary daemon against an
//! existing ubusd. It is not PID 1 and does not claim to be -- inittab, rcS,
//! hotplug and the watchdog are P3.2, and the on-device PID 1 switch is P3.3.

mod instance;
mod service;
mod ubus;

fn main() {
    eprintln!("procd-rs: P3.1 in progress; no daemon entry point yet");
    std::process::exit(1);
}
