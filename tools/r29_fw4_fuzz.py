#!/usr/bin/env python3
"""Differential fuzzing of fw4-rs against the upstream ucode fw4.

Both implementations run against the upstream test mocks (tests/mocks) with a
mutated `uci/firewall.json` placed in a per-case override directory, exactly
the way run_tests.sh layers `-- File --` sections over the mocks. Every case
compares stdout, stderr and the exit code of `fw4 print`.

Mutations: option values replaced by malformed / boundary values (ports, IPs,
CIDRs, MACs, protocols, targets, families, booleans, numbers), options and
sections removed or duplicated, unknown options and sections added, strings
turned into lists and back, very long and non-ASCII strings.

Usage: r29_fw4_fuzz.py <firewall4-src-dir> <fw4-rs-binary> [--cases N] [--seed S] [--keep DIR] [--ucode PATH]
Exit code 1 when any case differs. Differing cases are written to --keep.
"""
import copy
import json
import re
import os
import random
import shutil
import subprocess
import sys
import tempfile

TESTCASE = """{%
	include("./root/usr/share/firewall4/main.uc", {
		getenv: function(varname) {
			switch (varname) {
			case 'ACTION':
				return 'print';
			}
		}
	})
%}
"""

WEIRD_STRINGS = ["", " ", "-", "0", "-1", "65536", "70000", "1-2-3", "80-", "-80", "abc", "1e3", "0x50", "999.1.1.1",
                 "10.0.0.0/33", "10.0.0.1/-1", "::g", "fe80::1%eth0", "1.2.3", "1.2.3.4.5", "!10.0.0.1", "! ", "!",
                 "00:11:22:33:44", "00:11:22:33:44:55:66", "zz:11:22:33:44:55", "tcp udp icmp sctp", "foo", "ipv7", "any",
                 "maybe", "yes", "no", "TRUE", "2", "-5", "3.14", "99999999999999999999", "BOGUS", "ACCEPT DROP",
                 "café", "名字", "a" * 300, "'; drop table", "$(id)", "a b", "\t", "\\n", "0.0.0.0/0", "::/0", "0-65535",
                 "1024:2048", "!lan", "*", "@lan", "lan wan", "wan6"]
KNOWN_KEYS = {
    "defaults": ["input", "output", "forward", "drop_invalid", "syn_flood", "synflood_protect", "synflood_rate", "synflood_burst",
                 "tcp_syncookies", "tcp_ecn", "tcp_window_scaling", "accept_redirects", "accept_source_route", "custom_chains",
                 "disable_ipv6", "flow_offloading", "flow_offloading_hw", "auto_helper", "auto_includes"],
    "zone": ["name", "network", "device", "subnet", "input", "output", "forward", "masq", "masq_allow_invalid", "masq_src", "masq_dest",
             "masq6", "mtu_fix", "family", "log", "log_limit", "extra", "extra_src", "extra_dest", "helper", "enabled", "custom_chains"],
    "rule": ["name", "src", "dest", "proto", "src_ip", "src_mac", "src_port", "dest_ip", "dest_port", "icmp_type", "family", "target",
             "enabled", "limit", "limit_burst", "extra", "mark", "set_mark", "set_xmark", "set_helper", "helper", "start_date", "stop_date",
             "start_time", "stop_time", "weekdays", "monthdays", "utc_time", "ipset", "device", "direction"],
    "redirect": ["name", "src", "dest", "proto", "src_ip", "src_dip", "src_port", "src_dport", "dest_ip", "dest_port", "target",
                 "family", "reflection", "reflection_src", "enabled", "mark", "limit", "helper", "ipset"],
    "forwarding": ["src", "dest", "family", "enabled", "ipset"],
    "ipset": ["name", "family", "storage", "match", "entry", "maxelem", "timeout", "counters", "comment", "loadfile", "enabled"],
    "include": ["type", "path", "position", "chain", "fw4_compatible", "enabled", "reload"],
    "nat": ["name", "family", "proto", "src_ip", "src_port", "dest_ip", "dest_port", "snat_ip", "snat_port", "target", "device", "enabled"],
}


def sections(cfg):
    """(type, index or None, dict) for every section in the mock uci document."""
    out = []
    for ty, v in cfg.items():
        if isinstance(v, list):
            for i, s in enumerate(v):
                if isinstance(s, dict):
                    out.append((ty, i, s))
        elif isinstance(v, dict):
            out.append((ty, None, v))
    return out


def mutate(cfg, rng):
    cfg = copy.deepcopy(cfg)
    for _ in range(rng.randint(1, 4)):
        secs = sections(cfg)
        if not secs:
            break
        ty, idx, sec = rng.choice(secs)
        kind = rng.randint(0, 9)
        keys = KNOWN_KEYS.get(ty, list(sec.keys()) or ["name"])
        if kind <= 3:                      # weird value for a known or existing option
            k = rng.choice(keys + list(sec.keys()))
            v = rng.choice(WEIRD_STRINGS)
            sec[k] = [v, rng.choice(WEIRD_STRINGS)] if rng.random() < 0.25 else v
        elif kind == 4 and sec:            # drop an option
            del sec[rng.choice(list(sec.keys()))]
        elif kind == 5:                    # unknown option
            sec["opt_" + rng.choice(["x", "extra", "foo", "名"])] = rng.choice(WEIRD_STRINGS)
        elif kind == 6 and idx is not None:  # duplicate a section
            cfg[ty].insert(idx, copy.deepcopy(sec))
        elif kind == 7 and idx is not None and len(cfg[ty]) > 1:  # remove a section
            del cfg[ty][idx]
        elif kind == 8:                    # list <-> string
            k = rng.choice(list(sec.keys()) or ["name"])
            v = sec.get(k)
            sec[k] = v[0] if isinstance(v, list) and v else [str(v), rng.choice(WEIRD_STRINGS)]
        else:                              # new section of a random type
            nty = rng.choice(list(KNOWN_KEYS.keys()) + ["bogus"])
            ns = {rng.choice(KNOWN_KEYS.get(nty, ["a"])): rng.choice(WEIRD_STRINGS) for _ in range(rng.randint(0, 4))}
            if nty in ("zone", "rule", "redirect", "nat", "ipset", "include", "forwarding"):
                cfg.setdefault(nty, [])
                if isinstance(cfg[nty], dict):
                    cfg[nty] = [cfg[nty]]
                cfg[nty].append(ns)
            else:
                cfg[nty] = ns
    return cfg


# mocklib prints these (in blue) when a mutated path hits an unmocked fs call; the
# Rust mock layer answers "absent" silently. Harness noise, not fw4 behaviour.
FIXTURE_NOTICE = re.compile(r"\x1b\[34;1m\[!\] No stdout fixture defined for .*?\x1b\[0m\n(\x1b\[34;1m\[!\] Provide a mock output through the following text file:\n.*?\x1b\[0m\n)?", re.S)
# an ucode runtime exception (fw4.uc dereferencing a skipped `defaults`/`include`
# section) is an upstream crash, not a fw4 result; fw4-rs deliberately degrades
# to the ucode defaults instead of aborting (DEVIATION, see R09)
UCODE_CRASH = re.compile(r"^(Reference|Type|Syntax) error: .*\nIn ", re.M)


def run_case(src, binary, ucode, files, tmp):
    mocks = os.path.join(src, "tests", "mocks")
    u = subprocess.run([ucode, "-S", "-T,", "-L./tests/lib", "-L./root/usr/share/ucode",
                        "-D", "MOCK_SEARCH_PATH=" + json.dumps([files, mocks]), "-l", "mocklib", "-l", "fw4", "-"],
                       input=TESTCASE, capture_output=True, text=True, errors="replace", cwd=src, timeout=120)
    env = dict(os.environ, FW4_MOCK_DIRS=files + ":" + mocks, FW4_TRACE="")
    r = subprocess.run([binary, "print"], env=env, capture_output=True, text=True, errors="replace", cwd=tmp, timeout=120)
    ustderr = FIXTURE_NOTICE.sub("", u.stderr)
    crashed = u.returncode == 254 and UCODE_CRASH.search(u.stderr) is not None
    return (u.returncode, u.stdout, ustderr), (r.returncode, r.stdout, r.stderr), crashed


def first_diff(a, b):
    k = 0
    while k < min(len(a), len(b)) and a[k] == b[k]:
        k += 1
    lo = max(0, k - 80)
    return a[lo:k + 200], b[lo:k + 200]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    opt = lambda name, default: sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default
    for name in ("--cases", "--seed", "--keep", "--ucode"):
        if name in sys.argv:
            v = sys.argv[sys.argv.index(name) + 1]
            if v in args:
                args.remove(v)
    src, binary = os.path.abspath(args[0]), os.path.abspath(args[1])
    n, seed, keep, ucode = int(opt("--cases", "200")), int(opt("--seed", "1")), opt("--keep", None), opt("--ucode", "ucode")
    rng = random.Random(seed)
    base = json.load(open(os.path.join(src, "tests", "mocks", "uci", "firewall.json")))
    tmp = tempfile.mkdtemp(prefix="r29-")
    bad = crashes = 0
    try:
        for k in range(n):
            cfg = mutate(base, rng)
            files = os.path.join(tmp, "case%04d" % k)
            os.makedirs(os.path.join(files, "uci"))
            with open(os.path.join(files, "uci", "firewall.json"), "w") as f:
                json.dump(cfg, f, indent=1, ensure_ascii=False)
            u, r, crashed = run_case(src, binary, ucode, files, tmp)
            if crashed:
                crashes += 1
                if keep:
                    os.makedirs(keep, exist_ok=True)
                    shutil.copy(os.path.join(files, "uci", "firewall.json"), os.path.join(keep, "crash%04d.json" % k))
                shutil.rmtree(files)
                continue
            if u == r:
                shutil.rmtree(files)
                continue
            bad += 1
            print("DIFF case%04d: exit %d vs %d" % (k, u[0], r[0]))
            for i, what in ((1, "stdout"), (2, "stderr")):
                if u[i] != r[i]:
                    a, b = first_diff(u[i], r[i])
                    print("   %s ucode=%r\n   %s fw4rs=%r" % (what, a, " " * len(what), b))
            if keep:
                os.makedirs(keep, exist_ok=True)
                shutil.copy(os.path.join(files, "uci", "firewall.json"), os.path.join(keep, "case%04d.json" % k))
            shutil.rmtree(files)
        print("cases=%d differing=%d ucode_crashed=%d" % (n, bad, crashes))
        return 1 if bad else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
