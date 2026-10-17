//! One-shot research instrumentation; never part of a shipping candidate.
use std::cell::Cell;
use std::io::Write;

fn emit(line: std::fmt::Arguments<'_>) {
    // Foreground production mode also redirects stderr to /dev/null. The
    // harness supplies a unique private file; all output I/O follows the end
    // counter read, with no change to the daemon's logging or reload policy.
    let Some(path) = std::env::var_os("DNSMASQ_HUP_TIMING") else { return };
    if let Ok(mut output) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(output, "{line}");
    }
}

thread_local! {
    static ACTIVE: Cell<bool> = const { Cell::new(false) };
    static PUBLICATION: Cell<(u64, u64)> = const { Cell::new((0, 0)) };
}

fn ticks() -> u64 {
    let value;
    // Architectural virtual counter: elapsed time, including descheduling.
    unsafe { core::arch::asm!("isb", "mrs {value}, cntvct_el0", value = out(reg) value,
                             options(nostack, preserves_flags)); }
    value
}

fn frequency() -> u64 {
    let value;
    unsafe { core::arch::asm!("mrs {value}, cntfrq_el0", value = out(reg) value,
                             options(nostack, preserves_flags)); }
    value
}

pub(super) struct Publication(Option<u64>);
impl Publication {
    pub(super) fn start() -> Self {
        Self(ACTIVE.get().then(ticks))
    }
}
impl Drop for Publication {
    fn drop(&mut self) {
        if let Some(start) = self.0 {
            let elapsed = ticks().wrapping_sub(start);
            PUBLICATION.set((PUBLICATION.get().0 + elapsed, PUBLICATION.get().1 + 1));
        }
    }
}

pub(super) struct Reload {
    start: u64,
    data_end: Option<u64>,
    data_publication: u64,
    file_turns: usize,
    signaled: bool,
    complete: bool,
}
impl Reload {
    pub(super) fn start(signaled: bool) -> Self {
        PUBLICATION.set((0, 0));
        ACTIVE.set(true);
        Self { start: ticks(), data_end: None, data_publication: 0,
               file_turns: 0, signaled, complete: false }
    }
    pub(super) fn data_done(&mut self) {
        self.data_end = Some(ticks());
        self.data_publication = PUBLICATION.get().0;
    }
    pub(super) fn file_turn(&mut self) { self.file_turns += 1; }
    pub(super) fn complete(&mut self, runnable: bool, hosts_pending: bool) {
        let end = ticks();
        ACTIVE.set(false);
        let (publication, calls) = PUBLICATION.get();
        let data = self.data_end.unwrap_or(end).wrapping_sub(self.start);
        let files = end.wrapping_sub(self.data_end.unwrap_or(end));
        self.complete = true;
        // Emit after the measured interval. Publication nests within the data
        // or file stage; expose both raw and exclusive values, never add twice.
        emit(format_args!("HUP_TIMING {{\"frequency_hz\":{},\"total_ticks\":{},\"data_ticks\":{},\"file_ticks\":{},\"publication_ticks\":{},\"data_exclusive_ticks\":{},\"file_exclusive_ticks\":{},\"publication_calls\":{},\"file_turns\":{},\"signaled\":{},\"runnable_after\":{},\"hosts_pending_after\":{},\"complete\":true}}",
            frequency(), end.wrapping_sub(self.start), data, files, publication,
            data.saturating_sub(self.data_publication),
            files.saturating_sub(publication.saturating_sub(self.data_publication)),
            calls, self.file_turns, self.signaled, runnable, hosts_pending));
    }
}
impl Drop for Reload {
    fn drop(&mut self) {
        ACTIVE.set(false);
        if !self.complete { emit(format_args!("HUP_TIMING {{\"complete\":false}}")); }
    }
}
