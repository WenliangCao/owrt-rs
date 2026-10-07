//! Attribution-only companion to frozen M5 dc1b740d. Feature-off builds omit
//! this module and every counter hook. DNSMASQ_M6B_WAKE_METRICS is the sole
//! runtime switch. Histograms have fixed size; no per-wait arrays are retained.

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::PathBuf;
use std::time::{Duration, Instant};

// Inclusive upper bounds, focused on the hypothesized two-millisecond wait.
const WAIT_UPPER_NS: [u64; 18] = [
    1_000, 10_000, 100_000, 1_000_000, 1_500_000, 1_750_000, 1_900_000,
    2_000_000, 2_050_000, 2_100_000, 2_200_000, 2_500_000, 3_000_000,
    5_000_000, 10_000_000, 100_000_000, 1_000_000_000, u64::MAX,
];

#[derive(Default)]
pub struct Listener {
    pub step_udp_calls: u64,
    pub receive_attempts: u64,
    pub udp_packets: u64,
    pub udp_bytes: u64,
    pub would_block: u64,
    pub empty_receives: u64,
    pub receive_errors: u64,
    pub alloc_count: u64,
    pub alloc_bytes: u64,
}

pub struct Counters {
    path: Option<PathBuf>,
    origin: Instant,
    last_write: Instant,
    loop_rounds: u64,
    loop_packets: u64,
    loop_packet_counts: [u64; 3],
    poll_calls: u64,
    poll_wait_ns: u128,
    poll_ready: u64,
    timeout_zero: u64,
    timeout_two: u64,
    wait_min_ns: u64,
    wait_max_ns: u64,
    wait_histogram: [u64; 18],
    fd_count_max: usize,
    dns_udp_fds_max: usize,
    dns_tcp_fds_max: usize,
    probe_calls: u64,
    probe_wait_ns: u128,
    arp_calls: u64,
    arp_wait_ns: u128,
    listeners: Vec<Listener>,
}

impl Counters {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            path: std::env::var_os("DNSMASQ_M6B_WAKE_METRICS").map(PathBuf::from),
            origin: now, last_write: now, loop_rounds: 0, loop_packets: 0,
            loop_packet_counts: [0; 3], poll_calls: 0, poll_wait_ns: 0,
            poll_ready: 0, timeout_zero: 0, timeout_two: 0,
            wait_min_ns: u64::MAX, wait_max_ns: 0, wait_histogram: [0; 18],
            fd_count_max: 0, dns_udp_fds_max: 0, dns_tcp_fds_max: 0,
            probe_calls: 0, probe_wait_ns: 0, arp_calls: 0, arp_wait_ns: 0,
            listeners: Vec::new(),
        }
    }
    pub fn listener(&mut self, index: usize) -> &mut Listener {
        self.listeners.resize_with(self.listeners.len().max(index + 1), Listener::default);
        &mut self.listeners[index]
    }
    pub fn loop_start(&mut self) {
        self.loop_rounds += 1;
        self.loop_packets = 0;
    }
    pub fn loop_finish(&mut self) {
        self.loop_packet_counts[self.loop_packets.min(2) as usize] += 1;
    }
    pub fn packet(&mut self, index: usize, bytes: usize) {
        self.loop_packets += 1;
        let listener = self.listener(index);
        listener.udp_packets += 1;
        listener.udp_bytes += bytes as u64;
    }
    pub fn wait_files(&mut self, timeout: i32, ready: usize, elapsed: Duration,
        fds: usize, dns_udp_fds: usize, dns_tcp_fds: usize)
    {
        let wait = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        self.poll_calls += 1;
        self.poll_wait_ns += elapsed.as_nanos();
        self.poll_ready += u64::from(ready != 0);
        self.timeout_zero += u64::from(timeout == 0);
        self.timeout_two += u64::from(timeout == 2);
        self.wait_min_ns = self.wait_min_ns.min(wait);
        self.wait_max_ns = self.wait_max_ns.max(wait);
        let bucket = WAIT_UPPER_NS.partition_point(|&upper| upper < wait);
        self.wait_histogram[bucket] += 1;
        self.fd_count_max = self.fd_count_max.max(fds);
        self.dns_udp_fds_max = self.dns_udp_fds_max.max(dns_udp_fds);
        self.dns_tcp_fds_max = self.dns_tcp_fds_max.max(dns_tcp_fds);
    }
    pub fn probe_wait(&mut self, elapsed: Duration) {
        self.probe_calls += 1;
        self.probe_wait_ns += elapsed.as_nanos();
    }
    pub fn arp_wait(&mut self, elapsed: Duration) {
        self.arp_calls += 1;
        self.arp_wait_ns += elapsed.as_nanos();
    }
    pub fn maybe_write(&mut self) -> io::Result<()> {
        if self.path.is_some() && self.last_write.elapsed() >= Duration::from_secs(1) {
            self.write()?;
            self.last_write = Instant::now();
        }
        Ok(())
    }
    fn snapshot(&self) -> String {
        let mut json = String::new();
        write!(json, "{{\"schema\":\"m5-old-loop-v1\",\"monotonic_ns\":{},\"loop_rounds\":{},\"loop_packet_counts_0_1_ge2\":{:?},\"poll_calls\":{},\"poll_wait_ns\":{},\"wait_reasons\":{{\"files_timeout_0\":{},\"files_timeout_2ms\":{},\"ready\":{},\"poll_ready\":{}}},\"ordinary_poll_fd_max\":{{\"all\":{},\"dns_udp\":{},\"dns_tcp\":{}}},\"wait_histogram_upper_ns\":{:?},\"wait_histogram_counts\":{:?},\"wait_min_ns\":{},\"wait_max_ns\":{},\"probe_poll_calls\":{},\"probe_poll_wait_ns\":{},\"arp_poll_calls\":{},\"arp_poll_wait_ns\":{},\"udp_listeners\":[",
            self.origin.elapsed().as_nanos(), self.loop_rounds, self.loop_packet_counts,
            self.poll_calls, self.poll_wait_ns, self.timeout_zero, self.timeout_two,
            self.poll_ready, self.poll_ready, self.fd_count_max, self.dns_udp_fds_max,
            self.dns_tcp_fds_max, WAIT_UPPER_NS, self.wait_histogram,
            if self.poll_calls == 0 { 0 } else { self.wait_min_ns }, self.wait_max_ns,
            self.probe_calls, self.probe_wait_ns, self.arp_calls, self.arp_wait_ns).unwrap();
        for (index, listener) in self.listeners.iter().enumerate() {
            if index != 0 { json.push(','); }
            write!(json, "{{\"step_udp_calls\":{},\"receive_attempts\":{},\"udp_packets\":{},\"udp_bytes\":{},\"would_block\":{},\"empty_receives\":{},\"receive_errors\":{},\"alloc_count\":{},\"alloc_bytes\":{}}}",
                listener.step_udp_calls, listener.receive_attempts, listener.udp_packets,
                listener.udp_bytes, listener.would_block, listener.empty_receives,
                listener.receive_errors, listener.alloc_count, listener.alloc_bytes).unwrap();
        }
        json.push_str("]}\n");
        json
    }
    pub fn write(&self) -> io::Result<()> {
        let Some(path) = &self.path else { return Ok(()); };
        let snapshot = self.snapshot();
        let temporary = path.with_extension("json.tmp");
        File::create(&temporary)?.write_all(snapshot.as_bytes())?;
        std::fs::rename(temporary, path)?;
        // A fixed-size snapshot per second, including cumulative buckets.
        // Historical intervals use bucket deltas, never duplicate wait arrays.
        OpenOptions::new().create(true).append(true).open(path.with_extension("jsonl"))?
            .write_all(snapshot.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cumulative_buckets_cover_zero_boundary_and_very_long_waits() {
        let mut counters = Counters::new();
        for nanoseconds in [0, 2_000_000, 2_000_001, u64::MAX] {
            counters.wait_files(2, 0, Duration::from_nanos(nanoseconds), 3, 0, 0);
        }
        assert_eq!(counters.wait_histogram.iter().sum::<u64>(), 4);
        assert_eq!(counters.wait_histogram[0], 1);
        assert_eq!(counters.wait_histogram[7], 1);
        assert_eq!(counters.wait_histogram[8], 1);
        assert_eq!(counters.wait_histogram[17], 1);
        let json = counters.snapshot();
        assert!(!json.contains("wait_durations_ns"));
        assert!(json.len() < 2_000);
    }
    #[test]
    fn listener_and_source_counters_keep_nested_waits_separate() {
        let mut counters = Counters::new();
        counters.loop_start();
        counters.packet(1, 42);
        counters.loop_finish();
        counters.wait_files(2, 0, Duration::from_millis(2), 4, 0, 0);
        counters.probe_wait(Duration::from_millis(250));
        counters.arp_wait(Duration::ZERO);
        assert_eq!(counters.loop_packet_counts, [0, 1, 0]);
        assert_eq!(counters.listener(1).udp_bytes, 42);
        assert_eq!(counters.poll_calls, 1);
        assert_eq!(counters.poll_wait_ns, 2_000_000);
        assert_eq!((counters.probe_calls, counters.arp_calls), (1, 1));
    }
}
