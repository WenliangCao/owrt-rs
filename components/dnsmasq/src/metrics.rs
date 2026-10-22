//! dnsmasq 2.93 metrics.h/metrics.c and ubus.c:236–252.
//! All fields are u32, including counters retained for uncompiled features.

use owrt_ubus::BlobBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Metric {
    CacheInserted,
    CacheLiveFreed,
    QueriesForwarded,
    AuthAnswered,
    LocalAnswered,
    StaleAnswered,
    Unanswered,
    CryptoHighWater,
    SignatureFailureHighWater,
    WorkHighWater,
    Bootp,
    Pxe,
    DhcpAck,
    DhcpDecline,
    DhcpDiscover,
    DhcpInform,
    DhcpNak,
    DhcpOffer,
    DhcpRelease,
    DhcpRequest,
    NoAnswer,
    LeasesAllocated4,
    LeasesPruned4,
    LeasesAllocated6,
    LeasesPruned6,
    TcpConnections,
    DhcpLeaseQuery,
    DhcpLeaseUnassigned,
    DhcpLeaseActive,
    DhcpLeaseUnknown,
}

pub const NAMES: [&str; 30] = [
    "dns_cache_inserted",
    "dns_cache_live_freed",
    "dns_queries_forwarded",
    "dns_auth_answered",
    "dns_local_answered",
    "dns_stale_answered",
    "dns_unanswered",
    "dnssec_max_crypto_use",
    "dnssec_max_sig_fail",
    "dnssec_max_work",
    "bootp",
    "pxe",
    "dhcp_ack",
    "dhcp_decline",
    "dhcp_discover",
    "dhcp_inform",
    "dhcp_nak",
    "dhcp_offer",
    "dhcp_release",
    "dhcp_request",
    "noanswer",
    "leases_allocated_4",
    "leases_pruned_4",
    "leases_allocated_6",
    "leases_pruned_6",
    "tcp_connections",
    "dhcp_leasequery",
    "dhcp_lease_unassigned",
    "dhcp_lease_actve",
    "dhcp_lease_unknown",
];

#[derive(Clone, Copy, Debug, Default)]
pub struct Metrics {
    values: [u32; 30],
}

impl Metrics {
    pub fn get(&self, metric: Metric) -> u32 {
        self.values[metric as usize]
    }

    pub fn add(&mut self, metric: Metric, value: u32) {
        let counter = &mut self.values[metric as usize];
        *counter = counter.wrapping_add(value);
    }

    /// Publish an engine-owned cumulative counter or gauge without consuming
    /// it. The owner must preserve that engine's own reset/lifecycle boundary.
    pub fn set(&mut self, metric: Metric, value: u32) {
        self.values[metric as usize] = value;
    }

    /// cache_reload resets only these two. A metrics snapshot cannot assume
    /// that their window matches forwarded/local counters after SIGHUP.
    pub fn cache_reloaded(&mut self) {
        self.values[Metric::CacheInserted as usize] = 0;
        self.values[Metric::CacheLiveFreed as usize] = 0;
    }

    pub fn write_ubus(&self, output: &mut BlobBuf) {
        output.reset();
        for (name, value) in NAMES.iter().zip(self.values) {
            output.msg_u32(name, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use owrt_ubus::blob;

    #[test]
    fn reload_preserves_other_windows_and_wire_counter_width() {
        let mut metrics = Metrics::default();
        metrics.add(Metric::CacheInserted, 100);
        metrics.add(Metric::QueriesForwarded, u32::MAX);
        metrics.add(Metric::DhcpLeaseActive, 7);
        metrics.cache_reloaded();
        assert_eq!(metrics.get(Metric::CacheInserted), 0);
        assert_eq!(metrics.get(Metric::QueriesForwarded), u32::MAX);
        metrics.add(Metric::QueriesForwarded, 1);
        assert_eq!(metrics.get(Metric::QueriesForwarded), 0);
        let mut buffer = BlobBuf::new();
        metrics.write_ubus(&mut buffer);
        let fields: Vec<_> = blob::fields(buffer.payload()).collect();
        assert_eq!(fields.len(), 30);
        // The misspelling is the existing public interface, not a new key.
        assert_eq!(fields[28].name, "dhcp_lease_actve");
        assert_eq!(fields[28].as_u32(), Some(7));
    }
}
