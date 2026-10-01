//! Cumulative message events from rfc2131.c, independent of socket delivery.
//! Lease allocations/removals are owned separately by LeaseStore. Neither
//! cache/hosts reload nor file/DNS publication resets these u32 counters.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MessageCounters {
    pub bootp: u32,
    /// Reserved for the PXE runtime producer, which is not yet integrated.
    pub pxe: u32,
    pub ack: u32,
    pub decline: u32,
    pub discover: u32,
    pub inform: u32,
    pub nak: u32,
    pub offer: u32,
    pub release: u32,
    pub request: u32,
    pub no_answer: u32,
}

impl MessageCounters {
    /// metrics.h's contiguous BOOTP..NOANSWER order for independent probes.
    pub fn as_array(self) -> [u32; 11] {
        [
            self.bootp,
            self.pxe,
            self.ack,
            self.decline,
            self.discover,
            self.inform,
            self.nak,
            self.offer,
            self.release,
            self.request,
            self.no_answer,
        ]
    }
}
