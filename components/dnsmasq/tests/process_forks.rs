//! Run fork contracts on the process main thread, without libtest workers.
fn main() {
    assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
    // SAFETY: this standalone main creates no threads, shared mappings or
    // atfork hooks, and holds no I/O/owner locks while running the fixtures.
    unsafe {
        dnsmasq_rs::helper::run_process_tests();
        dnsmasq_rs::config::dns::lookup::run_process_tests();
        dnsmasq_rs::dns::files::run_process_tests();
    }
}
