#!/usr/bin/env python3
"""Compare the no-IDN canonicalise boundary with exact C check_name()."""
import hashlib
import json
from pathlib import Path
import random
import shutil
import subprocess
from tftp_oracle import REPO, function


def main():
    source = REPO / "private/dnsmasq-rewrite/reference/dnsmasq-2.93/src/util.c"
    identity = json.loads((source.parents[2] / "identity.json").read_text())
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if identity["patched_files"]["src/util.c"] != digest:
        raise SystemExit("C source drift")
    out = REPO / "private/dnsmasq-rewrite/hosts-oracle"
    out.mkdir(parents=True, exist_ok=True)
    c = "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#include <ctype.h>\n#define MAXLABEL 63\n#define MAXDNAME 255\n"
    c += function(source.read_text(), "static int check_name(char *in)")
    c += r'''
int main(void) {
 char hex[4097], name[2049];
 while (scanf("%4096s", hex) == 1) {
  size_t n = strcmp(hex,"-") ? strlen(hex)/2 : 0;
  for (size_t i=0; i<n; i++) { unsigned b; if(sscanf(hex+2*i,"%2x",&b)!=1) return 2; name[i]=b; }
  name[n]=0;
  if (!check_name(name)) puts("0");
  else { printf("1 "); if (!*name) printf("-"); for(size_t i=0;name[i];i++) printf("%02x",(unsigned char)name[i]); puts(""); }
 }
}
'''
    (out / "oracle.c").write_text(c)
    rust = r'''
#[path="HOSTS"] mod hosts;
use std::io::{self,BufRead};
fn main() { for line in io::stdin().lock().lines() {
 let line=line.unwrap(); let bytes=if line=="-" {Vec::new()} else {line.as_bytes().chunks_exact(2).map(|p|u8::from_str_radix(std::str::from_utf8(p).unwrap(),16).unwrap()).collect()};
 match hosts::canonicalise(&bytes) { None=>println!("0"),Some(v)=>{print!("1 ");if v.is_empty(){print!("-");}for b in v{print!("{b:02x}");}println!();}}
}}
'''
    (out / "driver.rs").write_text(rust.replace("HOSTS", str(REPO / "components/dnsmasq/src/hosts.rs")))
    subprocess.run(["cc", "-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", str(out / "oracle.c"), "-o", str(out / "oracle")], check=True)
    rustc = shutil.which("rustc") or str(Path.home() / ".rustup/toolchains/1.98.1-aarch64-apple-darwin/bin/rustc")
    subprocess.run([rustc, "--edition=2021", "-A", "dead_code", str(out / "driver.rs"), "-o", str(out / "driver")], check=True)
    cases = [b"", b".", b"..", b"a..b", b" ", b" .", b"A.B.", b"a\0trailing", b"a\x7f", b"\xff"]
    for size in (0,1,62,63,64,252,253,254,255,256,502,503):
        cases += [b"a"*size, (b"a."*size)[:size], b"a"*size+b"."]
    rng = random.Random(0x293001)
    for _ in range(10000):
        cases.append(bytes(rng.choice([ord('a'), ord(' '), ord('.'), rng.randrange(256)]) for _ in range(rng.randrange(600))))
    payload = "".join((data.hex() or "-") + "\n" for data in cases)
    (out / "inputs.txt").write_text(payload)
    outputs = []
    for binary in ("oracle", "driver"):
        result = subprocess.run([str(out / binary)], input=payload, text=True, capture_output=True, check=True)
        (out / (binary + ".txt")).write_text(result.stdout)
        outputs.append(result.stdout.splitlines())
    assert outputs[0][:3] == ["0", "1 -", "1 2e"]
    assert outputs[1][:3] == outputs[0][:3]
    failures = [{"case":i,"c":a,"rust":b} for i,(a,b) in enumerate(zip(*outputs)) if a!=b]
    complete = len(outputs[0]) == len(outputs[1]) == len(cases)
    report = {"cases":len(cases), "failures":failures, "complete":complete, "source_sha256":digest,
              "scope":"no-IDN canonicalise, not hosts-file I/O or DNS response"}
    (out / "result.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report))
    raise SystemExit(bool(failures) or not complete)


if __name__ == "__main__":
    main()
