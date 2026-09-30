#!/usr/bin/env python3
"""Frozen TFTP netascii microbenchmark; native host evidence only.

Requires the correctness gate first. Equal file-read copies, one shared output
buffer and exact C get_block; no network, protocol loop or service claim.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import resource
import subprocess
import time
from tftp_oracle import C_PREFIX, REPO, function

C_MAIN = r'''
int main(int argc, char **argv) {
 if (argc != 4) return 2;
 unsigned size=atoi(argv[1]), pattern=atoi(argv[2]), count=atoi(argv[3]);
 if (size < 1 || size > 8192) return 3;
 for (unsigned i=0; i<size; i++) input[i] = pattern == 2 || (pattern == 1 && i%80 == 79) ? 10 : 'A';
 struct tftp_file file = { .size=size, .posn=0, .fd=-1 };
 struct tftp_transfer transfer = { .block=1, .blocksize=size, .netascii=1, .file=&file };
 uint64_t checksum=0;
 state.packet_buff_sz=sizeof(state.packet);
 for (unsigned i=0; i<count; i++) {
  __asm__ __volatile__("" : : "r"(input), "r"(&transfer) : "memory");
  state.srv_save=NULL; file.posn=0;
  ssize_t len=get_block(&transfer);
  __asm__ __volatile__("" : : "r"(state.packet) : "memory");
  checksum += (unsigned char)state.packet[4] + (unsigned char)state.packet[len-1] + len-4 + transfer.expansion + transfer.carrylf;
 }
 printf("%llu\n", (unsigned long long)checksum);
}
'''
RUST = r'''
#[path = "TFTP_PATH"] mod tftp;
use std::hint::black_box;
fn main() {
 let args: Vec<String> = std::env::args().collect();
 let size: usize=args[1].parse().unwrap(); let pattern: u32=args[2].parse().unwrap();
 let count: usize=args[3].parse().unwrap();
 let mut input = [0u8;8192]; let mut packet = [0u8;8196];
 for (i, value) in input[..size].iter_mut().enumerate() { *value=if pattern==2 || (pattern==1 && i%80==79) { 10 } else { b'A' }; }
 let mut checksum=0u64;
 for _ in 0..count {
  packet[4..size+4].copy_from_slice(black_box(&input[..size]));
  packet[..4].copy_from_slice(&[0,3,0,1]);
  let result=tftp::encode_netascii_in_place(black_box(&mut packet[4..size+4]),size,false).unwrap();
  let packet=black_box(&packet);
  checksum += u64::from(packet[4]) + u64::from(packet[result.len+3]) + result.len as u64 + result.expansion as u64 + u64::from(result.carry_lf);
 }
 println!("{checksum}");
}
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", type=Path, required=True)
    ap.add_argument("--gate", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--rustc", default="rustc")
    ap.add_argument("--screen", action="store_true", help="10k operations, one round; cannot satisfy frozen acceptance")
    args = ap.parse_args()
    gate = json.loads(args.gate.read_text())
    if not gate["complete"] or gate["failures"] or gate["cases"] < 97384:
        ap.error("full netascii correctness gate required")
    source = args.source.read_text()
    if hashlib.sha256(args.source.read_bytes()).hexdigest() != gate["c_source_sha256"]:
        ap.error("source must match correctness gate")
    rust_path = REPO / "components/dnsmasq/src/tftp.rs"
    if hashlib.sha256(rust_path.read_bytes()).hexdigest() != gate["rust_source_sha256"]:
        ap.error("Rust source must match correctness gate")
    out = args.out.resolve()
    if not out.is_relative_to(REPO / "private") or out.exists():
        ap.error("choose a new ignored private/ output")
    out.mkdir(parents=True)
    (out / "c.c").write_text(C_PREFIX + function(source, "static ssize_t get_block(struct tftp_transfer *transfer)") + C_MAIN)
    (out / "rust.rs").write_text(RUST.replace("TFTP_PATH", str(rust_path)))
    subprocess.run(["cc", "-O2", str(out / "c.c"), "-o", str(out / "c")], check=True, capture_output=True)
    subprocess.run([args.rustc, "--edition=2021", "-C", "opt-level=3", "-C", "codegen-units=1", "-C", "lto=true", "-A", "dead_code", str(out / "rust.rs"), "-o", str(out / "rust")], check=True, capture_output=True)
    iterations = 10_000 if args.screen else 1_000_000
    rounds = 1 if args.screen else 5
    identity = {"host": platform.platform(), "scope":"screen only, not acceptance" if args.screen else "native host microbenchmark only", "iterations":iterations,
                "rounds":rounds, "rust_sha256":hashlib.sha256(rust_path.read_bytes()).hexdigest(),
                "c_source_sha256":gate["c_source_sha256"], "clock":"parent getrusage user+system / monotonic wall",
                "buffer_budget":"8192 input bytes + 8196 output bytes in each driver"}
    (out / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    results = []
    # Order is fixed before results: the first of five rounds is C then Rust.
    with (out / "rounds.jsonl").open("w") as log:
        for round_index in range(rounds):
            for size in (512, 1468, 4092):
                for pattern in range(3):
                    checksums = []
                    for implementation in (("c", "rust") if round_index % 2 == 0 else ("rust", "c")):
                        before = resource.getrusage(resource.RUSAGE_CHILDREN)
                        start = time.monotonic_ns()
                        process = subprocess.run([str(out / implementation), str(size), str(pattern), str(iterations)], capture_output=True, text=True)
                        wall = time.monotonic_ns() - start
                        after = resource.getrusage(resource.RUSAGE_CHILDREN)
                        row = {"round":round_index, "size":size, "pattern":pattern, "implementation":implementation,
                               "cpu_seconds":after.ru_utime + after.ru_stime - before.ru_utime - before.ru_stime,
                               "wall_ns":wall, "exit":process.returncode, "checksum":process.stdout.strip(),
                               "stderr":process.stderr}
                        results.append(row)
                        log.write(json.dumps(row) + "\n"); log.flush()
                        if process.returncode:
                            raise SystemExit("benchmark failed; raw window retained")
                        checksums.append(process.stdout)
                    if checksums[0] != checksums[1]:
                        raise SystemExit("checksum mismatch; no performance conclusion")
            print(json.dumps({"completed_round":round_index + 1}), flush=True)
    summary = []
    for size in (512, 1468, 4092):
        for pattern in range(3):
            c = [r["cpu_seconds"] for r in results if r["size"]==size and r["pattern"]==pattern and r["implementation"]=="c"]
            rust = [r["cpu_seconds"] for r in results if r["size"]==size and r["pattern"]==pattern and r["implementation"]=="rust"]
            summary.append({"size":size, "pattern":pattern, "c_cpu_seconds":c, "rust_cpu_seconds":rust,
                            "rust_over_c":[r / v for r, v in zip(rust,c)]})
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
