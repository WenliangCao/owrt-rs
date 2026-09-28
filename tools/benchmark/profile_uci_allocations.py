#!/usr/bin/env python3
"""Build an allocation-only, private instrumented UCI CLI.

The real CLI entry path is retained; counters stop immediately before exit.
Rust GlobalAlloc counters exclude libc internals and the observer; counts and
peak requested live bytes are attribution,
not CPU timings, RSS, allocator overhead, or standalone performance evidence.
The private copy is required so diagnostic instrumentation never enters release.
"""
import argparse
from pathlib import Path
import shutil
import subprocess

SUPPORT = r"""
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
struct Counter;
const N: usize = 6;
static PHASE: AtomicUsize = AtomicUsize::new(0);
static ENABLED: AtomicBool = AtomicBool::new(true);
static ALLOC: [AtomicUsize; N] = [const { AtomicUsize::new(0) }; N];
static ZERO: [AtomicUsize; N] = [const { AtomicUsize::new(0) }; N];
static REALLOC: [AtomicUsize; N] = [const { AtomicUsize::new(0) }; N];
static FREED: [AtomicUsize; N] = [const { AtomicUsize::new(0) }; N];
static REQUESTED: [AtomicUsize; N] = [const { AtomicUsize::new(0) }; N];
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn allocated(size: usize) {
    REQUESTED[PHASE.load(Relaxed)].fetch_add(size, Relaxed);
    let live = LIVE.fetch_add(size, Relaxed) + size;
    PEAK.fetch_max(live, Relaxed);
}
// SAFETY: every operation delegates the caller's layout/pointer to System.
unsafe impl GlobalAlloc for Counter {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: the caller provided a valid GlobalAlloc layout.
        let p = unsafe { System.alloc(l) };
        if ENABLED.load(Relaxed) && !p.is_null() {
            ALLOC[PHASE.load(Relaxed)].fetch_add(1, Relaxed); allocated(l.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        // SAFETY: the caller provided a valid GlobalAlloc layout.
        let p = unsafe { System.alloc_zeroed(l) };
        if ENABLED.load(Relaxed) && !p.is_null() {
            ZERO[PHASE.load(Relaxed)].fetch_add(1, Relaxed); allocated(l.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if ENABLED.load(Relaxed) {
            FREED[PHASE.load(Relaxed)].fetch_add(1, Relaxed); LIVE.fetch_sub(l.size(), Relaxed);
        }
        // SAFETY: forward the same valid pointer and allocation layout.
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, size: usize) -> *mut u8 {
        // SAFETY: forward the caller's valid pointer/layout and new size.
        let result = unsafe { System.realloc(p, l, size) };
        if ENABLED.load(Relaxed) && !result.is_null() {
            REALLOC[PHASE.load(Relaxed)].fetch_add(1, Relaxed);
            LIVE.fetch_sub(l.size(), Relaxed); allocated(size);
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: Counter = Counter;
pub struct Phase(usize);
pub fn phase(next: usize) -> Phase { Phase(PHASE.swap(next, Relaxed)) }
impl Drop for Phase { fn drop(&mut self) { PHASE.store(self.0, Relaxed); } }
pub fn exit(status: i32) -> ! {
    ENABLED.store(false, Relaxed);
    eprintln!("UCI_ALLOC_BEGIN status={status}");
    eprintln!("phase,alloc,zeroed,realloc,free,requested_bytes");
    for (i, name) in ["argv", "cli_and_other", "read", "parse_excluding_bytes", "export", "bytes"].iter().enumerate() {
        eprintln!("{name},{},{},{},{},{}", ALLOC[i].load(Relaxed), ZERO[i].load(Relaxed), REALLOC[i].load(Relaxed), FREED[i].load(Relaxed), REQUESTED[i].load(Relaxed));
    }
    eprintln!("peak_requested_live_bytes={}", PEAK.load(Relaxed));
    eprintln!("UCI_ALLOC_END");
    std::process::exit(status)
}
"""

def replace_once(path, old, new):
    text = path.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f"instrumentation anchor must occur once: {path}: {old!r}")
    path.write_text(text.replace(old, new))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="repository root")
    parser.add_argument("--work", type=Path, required=True, help="new private directory")
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    crate = args.work / "uci"
    shutil.copytree(args.source / "components/uci", crate, ignore=shutil.ignore_patterns("target"))
    src = crate / "src"
    (src / "allocation_profile.rs").write_text(SUPPORT)
    with (src / "lib.rs").open("a") as f:
        f.write("\npub mod allocation_profile;\n")
    cli = src / "bin/uci-rs.rs"
    replace_once(cli, "fn run(raw: Vec<Arg>) -> ! {", "fn run(raw: Vec<Arg>) -> ! {\n    let _profile = owrt_uci::allocation_profile::phase(1);")
    cli.write_text(cli.read_text().replace("std::process::exit(", "owrt_uci::allocation_profile::exit("))
    replace_once(cli, "                        let mut buf = Vec::with_capacity(export::size_hint(p));", "                        let _profile = owrt_uci::allocation_profile::phase(4);\n                        let mut buf = Vec::with_capacity(export::size_hint(p));")
    path = src / "file.rs"
    anchor = "fn read_into(ctx: &Context, mut reader: impl Read, hint: usize, mut data: Vec<u8>) -> Result<Vec<u8>> {"
    replace_once(path, anchor, anchor + "\n    let _profile = crate::allocation_profile::phase(2);")
    anchor = "pub(crate) fn read_whole(ctx: &Context, mut f: &File) -> Result<Vec<u8>> {"
    replace_once(path, anchor, anchor + "\n    let _profile = crate::allocation_profile::phase(2);")
    path = src / "parse.rs"
    replace_once(path, ") -> Result<Option<usize>> {\n    ctx.cleanup();", ") -> Result<Option<usize>> {\n    let _profile = crate::allocation_profile::phase(3);\n    ctx.cleanup();")
    path = src / "export.rs"
    anchor = "pub fn export_package"
    text = path.read_text()
    start = text.index("{", text.index(anchor)) + 1
    path.write_text(text[:start] + "\n    let _profile = crate::allocation_profile::phase(4);" + text[start:])
    path = src / "model.rs"
    for signature in ["fn from(value: &[u8]) -> Self {", "fn from(value: Vec<u8>) -> Self {"]:
        replace_once(path, signature, signature + "\n        let _profile = crate::allocation_profile::phase(5);")
    subprocess.run([args.cargo, "build", "--release", "--manifest-path", str(crate / "Cargo.toml"), "--target-dir", str(args.work / "target")], check=True)
    print(args.work / "target/release/uci-rs")

if __name__ == "__main__":
    main()
