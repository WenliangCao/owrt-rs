#!/usr/bin/env python3
"""Exact option.c reread_dhcp file-bank oracle; no listener or lease path.

Each implementation gets the same private files and sequence of edits. C's
own loader supplies expectations, including skipped bad rows and file order.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import dhcp_config_diff as base
from dhcp_host_config_diff import C_DRIVER, HASHES

ROOT = base.ROOT
COUNTS = {
    "replace-delete-recreate": [(1, 0), (1, 0), (0, 0), (0, 1), (1, 0)],
    "two-files-order": [(2, 0), (2, 1)],
    "main-preserved": [(2, 1), (2, 0), (1, 1)],
    "rows-errors-quotes": [(3, 2), (2, 0)],
    "directory-order-filter": [(3, 0), (3, 0), (1, 1), (2, 0)],
    "directory-explicit-overlap": [(2, 0), (2, 0)],
    "same-file-twice": [(1, 1), (1, 1)],
}
DUMP = C_DRIVER[C_DRIVER.index("  int index=0;"):C_DRIVER.index("  char context")]
C = r'''
#include "dnsmasq.h"
static unsigned int errors;
void __wrap_my_syslog(int priority, const char *format, ...) {
  (void)format;if((priority & LOG_PRIMASK) <= LOG_ERR)errors++;
}
static void bytes(const unsigned char *p, int n) {
  if (!p) putchar('-'); else for(int i=0;i<n;i++) printf("%02x",p[i]);
}
static void dump(void) {
''' + DUMP + r'''
}
int main(int argc,char **argv) {
  rand_init();read_opts(argc,argv,"dhcp-hostsfile-state");
  char command[32];
  while(fgets(command,sizeof(command),stdin)) {
    errors=0;reread_dhcp();printf("errors=%u\n",errors);dump();puts("END");fflush(stdout);
  }
  return 0;
}
'''
RUST = r'''
use dnsmasq_rs::config::{dhcp::{DhcpConfig,HostFiles},loader};
use std::{io::{self,BufRead,Write},path::Path};
fn hex(bytes:Option<&[u8]>)->String {bytes.map_or_else(||"-".into(),|v|v.iter().map(|b|format!("{b:02x}")).collect())}
fn main() {
 let mut dhcp=DhcpConfig::default();let args:Vec<_>=std::env::args_os().skip(1).collect();
 loader::load(&args,Path::new("/etc/dnsmasq.conf"),|d,_| {if dhcp.apply(d)? {Ok(())} else {Err(dnsmasq_rs::config::Error("unhandled probe option"))}}).unwrap();
 let mut files=HostFiles::new(&dhcp.host_files);
 for _ in io::stdin().lock().lines() {
  let report=files.reload(&dhcp.hosts);println!("errors={}",report.errors.len());
  for (i,c) in report.hosts.iter().enumerate() {
   print!("host={i} addr={} time={} ignore={} noclid={} id={} name={} domain={} hw=",c.address.map_or_else(||"-".into(),|a|a.to_string()),c.lease_time.map_or_else(||"-".into(),|v|v.to_string()),u8::from(c.ignore),u8::from(c.ignore_client_id),hex(c.client_id.as_deref()),hex(c.hostname.as_deref()),hex(c.domain.as_deref()));
   for h in &c.hardware {print!("{}:{};",h.kind,hex(Some(&h.address)));} println!();
  }
  println!("END");io::stdout().flush().unwrap();
 }
}
'''


def host(client, address, name):
    return f"02:00:00:00:00:{client:02x},192.0.2.{address},{name}\n"


def cases():
    # A None content deletes a path. A dict supplies a complete directory tree.
    yield "replace-delete-recreate", ["a"], {}, [
        {"a": host(1, 10, "first")}, {"a": host(1, 11, "changed")},
        {"a": ""}, {"a": None}, {"a": host(2, 12, "recreated")},
    ]
    yield "two-files-order", ["a", "b"], {}, [
        {"a": host(1, 10, "a"), "b": host(1, 11, "b")},
        {"a": host(1, 11, "duplicate") + host(3, 13, "next")},
    ]
    yield "main-preserved", ["a"], {"main_host": host(1, 10, "main")}, [
        {"a": host(2, 10, "duplicate") + host(3, 13, "first")},
        {"a": host(3, 14, "second")}, {"a": None},
    ]
    yield "rows-errors-quotes", ["a"], {}, [
        {"a": "# comment\n\n  " + host(1, 10, "first").strip() + " # trailing\n"
          + "bad:hex,192.0.2.11\n" + 'id:"a=b",192.0.2.12,"quoted.name"\n'
          + '"unterminated\n' + host(2, 13, "last").strip()},
        {"a": b"  \t\r\n" + host(4, 14, "nul").encode().rstrip() + b"\0ignored\n" + host(5, 15, "after").encode()},
    ]
    yield "directory-order-filter", ["dir", "a"], {}, [
        {"a": host(1, 10, "explicit"), "dir": {"20": host(2, 20, "twenty"), "10": host(3, 30, "ten"),
          ".hidden": host(4, 40, "hidden"), "backup~": host(5, 50, "backup"), "#temp#": host(6, 60, "temp"),
          "nested": {"inside": host(7, 70, "nested")}}},
        {"dir": {"15": host(8, 80, "new"), "20": host(2, 21, "changed")}},
        {"dir": None},
        {"dir": {"10": host(9, 90, "again")}},
    ]
    yield "directory-explicit-overlap", ["dir", "dir/10"], {}, [
        {"dir": {"10": host(1, 10, "one"), "20": host(2, 20, "two")}},
        {"dir": {"10": host(1, 11, "updated"), "30": host(3, 30, "three")}},
    ]
    yield "same-file-twice", ["a", "a"], {}, [
        {"a": host(1, 10, "once")}, {"a": host(1, 11, "twice")},
    ]


def write(path, content):
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()
    if content is None:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, dict):
        path.mkdir()
        for name, value in content.items():
            write(path / name, value)
    else:
        path.write_bytes(content.encode() if isinstance(content, str) else content)


def build(args, out):
    objects = args.reference_build.resolve() / "dnsmasq"
    for name, expected in HASHES.items():
        for path in (args.source / "src" / name, objects / name):
            assert base.sha(path) == expected
    (out / "probe.c").write_text(C)
    subprocess.run(["objcopy", "--redefine-sym", "main=reference_main", str(objects / "dnsmasq.o"),
                    str(out / "dnsmasq-without-main.o")], check=True)
    deps = args.reference_build.resolve() / "deps"
    subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror", "-DHAVE_UBUS", "-DHAVE_POLL_H",
                    "-DNO_DHCP6", "-DNO_AUTH", "-DNO_IPSET", "-DNO_ID", "-I" + str(objects),
                    "-I" + str(deps / "include"), str(out / "probe.c"), str(out / "dnsmasq-without-main.o"),
                    *(str(p) for p in sorted(objects.glob("*.o")) if p.name != "dnsmasq.o"),
                    "-Wl,--wrap=my_syslog", "-L" + str(deps / "lib"), "-Wl,-rpath," + str(deps / "lib"),
                    "-lubus", "-lubox", "-o", str(out / "c-probe")], check=True)
    if not args.c_only:
        manifest = ROOT / "components/dnsmasq/Cargo.toml"
        subprocess.run([args.cargo, "build", "--lib", "--manifest-path", str(manifest)], check=True)
        target = manifest.parent / "target/debug"
        (out / "probe.rs").write_text(RUST)
        subprocess.run([args.rustc, "--edition=2021", str(out / "probe.rs"), "--extern",
                        "dnsmasq_rs=" + str(target / "libdnsmasq_rs.rlib"), "-L",
                        "dependency=" + str(target / "deps"), "-o", str(out / "rust-probe")], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--c-only", action="store_true")
    parser.add_argument("--inject-error", action="store_true")
    parser.add_argument("--cargo", default=shutil.which("cargo") or "cargo")
    parser.add_argument("--rustc", default=shutil.which("rustc") or "rustc")
    args = parser.parse_args()
    if args.c_only and args.inject_error:
        parser.error("--inject-error requires a paired run")
    out = args.out.resolve(); assert out.is_relative_to(ROOT / "private")
    out.mkdir(parents=True, exist_ok=False); build(args, out)
    rows = []
    for name, paths, options, phases in cases():
        folder = out / name; folder.mkdir(); data = folder / "data"
        observed = {}
        for implementation in (["c"] if args.c_only else ["c", "rust"]):
            write(data, {})
            config = folder / "dnsmasq.conf"
            config.write_text("".join(f"dhcp-hostsfile={data / path}\n" for path in paths)
                              + ("dhcp-host=" + options["main_host"] if "main_host" in options else ""))
            with (folder / f"{implementation}.stderr").open("wb") as stderr:
                proc = subprocess.Popen([str(out / f"{implementation}-probe"), "-C", str(config)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, text=True)
                values = []
                try:
                    for index, edits in enumerate(phases):
                        for path, content in edits.items():
                            write(data / path, content)
                        snapshot = folder / f"{implementation}-{index:02d}-input"
                        shutil.copytree(data, snapshot)
                        proc.stdin.write("reload\n"); proc.stdin.flush()
                        lines = []
                        while True:
                            line = proc.stdout.readline()
                            if not line: raise AssertionError("oracle ended without phase delimiter")
                            if line == "END\n": break
                            lines.append(line)
                        text = "".join(lines); values.append(text)
                        (folder / f"{implementation}-{index:02d}.stdout").write_text(text)
                    proc.stdin.close(); assert proc.wait(5) == 0
                finally:
                    if proc.poll() is None: proc.kill(); proc.wait()
                observed[implementation] = values
        counts = [(text.count("host="), int(text.splitlines()[0].split("=")[1])) for text in observed["c"]]
        assert counts == COUNTS[name], (name, counts, COUNTS[name])
        if args.inject_error and name == "replace-delete-recreate":
            observed["rust"][0] = observed["rust"][0].replace("192.0.2.10", "192.0.2.11")
        rows.append({"case": name, "c": observed["c"], "rust": observed.get("rust"),
                     "match": observed.get("rust") == observed["c"] if not args.c_only else None})
    assert len(rows) == len(COUNTS)
    failures = [row for row in rows if row["match"] is False]
    result = {"cases": len(rows), "reloads": sum(len(row["c"]) for row in rows),
              "passed": None if args.c_only else len(rows) - len(failures), "failed": len(failures),
              "counts": {row["case"]: [(text.count("host="), int(text.splitlines()[0].split("=")[1])) for text in row["c"]] for row in rows},
              "rows": rows, "source_sha256": HASHES, "c_sha256": base.sha(out / "c-probe"),
              "scope": "exact reread_dhcp configuration banks and file-error counts; no leases/DNS/listeners"}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "rows"}, indent=2))
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
