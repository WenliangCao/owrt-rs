#!/usr/bin/env python3
"""Argument fuzzing of rpcd-rs against the original rpcd (same sandbox as r17).

Every ubus method of the rpcd objects gets random argument objects: type-correct
and type-wrong values, boundary numbers, odd paths / config / section names,
very long strings, control characters, missing and unknown parameters. Both
sides run the same step list in their own copy of the exact rootfs; rc, stdout
and stderr of every `ubus call` must be identical after r17's normalisation.

Methods that would act on the build host from inside the chroot (reboot,
sysupgrade, init scripts, arbitrary exec/write/remove, clock) are excluded.
Methods whose output is inherently time/process dependent compare rc only.

Usage: r26_rpcd_fuzz.py <rootfs-files> <rpcd-rs-musl-binary> [--cases-per-method N] [--seed S]
Exit code 1 when any step differs.
"""
import json
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import r17_rpcd_core_check as base  # noqa: E402

S, I, B, A, O = "string", "int32", "bool", "array", "object"

METHODS = {
    "session": {
        "login": {"username": S, "password": S, "timeout": I},
        "create": {"timeout": I},
        "list": {"ubus_rpc_session": S},
        "grant": {"ubus_rpc_session": S, "scope": S, "objects": A},
        "revoke": {"ubus_rpc_session": S, "scope": S, "objects": A},
        "access": {"ubus_rpc_session": S, "scope": S, "object": S, "function": S},
        "set": {"ubus_rpc_session": S, "values": O},
        "get": {"ubus_rpc_session": S, "keys": A},
        "unset": {"ubus_rpc_session": S, "keys": A},
        "destroy": {"ubus_rpc_session": S},
    },
    "uci": {
        "configs": {},
        "get": {"config": S, "section": S, "option": S, "type": S, "match": O, "ubus_rpc_session": S},
        "state": {"config": S, "section": S, "option": S, "type": S, "match": O, "ubus_rpc_session": S},
        "set": {"config": S, "section": S, "type": S, "values": O, "ubus_rpc_session": S},
        "add": {"config": S, "type": S, "name": S, "values": O, "ubus_rpc_session": S},
        "delete": {"config": S, "section": S, "type": S, "match": O, "option": S, "options": A, "ubus_rpc_session": S},
        "rename": {"config": S, "section": S, "option": S, "name": S, "ubus_rpc_session": S},
        "order": {"config": S, "sections": A, "ubus_rpc_session": S},
        "changes": {"config": S, "ubus_rpc_session": S},
        "revert": {"config": S, "ubus_rpc_session": S},
        "commit": {"config": S, "ubus_rpc_session": S},
        "reload_config": {},
    },
    "file": {
        "read": {"path": S, "base64": B},
        "list": {"path": S},
        "stat": {"path": S},
        "md5": {"path": S},
    },
    "rc": {"list": {"name": S, "skip": B}},
    "luci": {
        "getVersion": {}, "getInitList": {"name": S}, "getTimezones": {}, "getLEDs": {}, "getUSBDevices": {},
        "getConntrackHelpers": {}, "getFeatures": {}, "getSwconfigFeatures": {"switch": S},
        "getSwconfigPortState": {"switch": S}, "getBlockDevices": {}, "getMountPoints": {},
        "getRealtimeStats": {"mode": S, "device": S}, "getConntrackList": {}, "getProcessList": {}, "getLocaltime": {},
    },
    "luci-rpc": {
        "getNetworkDevices": {}, "getWirelessDevices": {}, "getHostHints": {}, "getDUIDHints": {},
        "getBoardJSON": {}, "getDHCPLeases": {"family": I},
    },
    "rpc-sys": {"packagelist": {"all": B}, "password_set": {"user": S, "password": S}},
    "iwinfo": {
        "devices": {}, "info": {"device": S}, "scan": {"device": S}, "assoclist": {"device": S, "mac": S},
        "freqlist": {"device": S}, "txpowerlist": {"device": S}, "countrylist": {"device": S},
        "survey": {"device": S}, "phyname": {"section": S},
    },
}
# output depends on the moment / process table / mounts: compare the return code only
RC_ONLY = {("luci", "getRealtimeStats"), ("luci", "getConntrackList"), ("luci", "getProcessList"), ("luci", "getLocaltime"),
           ("luci", "getMountPoints"), ("luci", "getBlockDevices"), ("luci", "getUSBDevices"), ("luci", "getLEDs"),
           ("luci-rpc", "getNetworkDevices"), ("luci-rpc", "getHostHints"), ("luci-rpc", "getDUIDHints"), ("luci", "getInitList"),
           ("rc", "list")}

STRINGS = ["", " ", "a", "root", "r17crypt", "system", "fwtest", "dhcptest", "network", "nonexist", "../system", "sys tem",
           "system/", "/etc/config/system", "/etc/passwd", "/etc/shadow", "/etc/config", "/etc/config/", "/nonexistent", "/",
           "//etc//config//system", "/etc/config/../passwd", "relative/path", "/proc/self/status", "/dev/null", "/usr/share/acl.d",
           "@system[0]", "@system[-1]", "@system[99]", "@", "@[0]", "cfg000000", "cfg0", "lan", "wan", "zone", "rule", "hostname",
           "ubus", "uci", "*", "?", "!", "-", "--", "1", "0", "-1", "3.5", "0x10", "x" * 200, "y" * 5000, "\t", "\n", "a\nb",
           "\x00", "", "%s%s%n", "$(id)", "`id`", "'; ls", "\"", "\\", "café", "名字", "😀",
           "phy0-ap0", "phy0", "wlan0", "radio0", "eth0", "br-lan", "lo", "00:11:22:33:44:55", "zz:zz", "ipv4", "ipv6", "all",
           "secret17", "wrong", "unauthenticated", "luci-base", "deadbeefdeadbeefdeadbeefdeadbeef", "00000000000000000000000000000000",
           "@SID@", "@SID@x", "conntrack", "interface", "wireless"]
INTS = [0, 1, -1, 2, 4, 6, 10, 30, 60, 255, 256, 65535, 65536, 2147483647, -2147483648, 4294967295, 9999999999]
BOOLS = [True, False]
ARRAYS = [[], ["a"], ["system", "network"], ["cfg000000", "@system[0]"], ["@SID@"], [1, 2], [None], [{"a": 1}], ["x" * 300],
          ["luci-base", "*"], [["nested"]], ["uci", "file"], list(range(50))]
OBJECTS = [{}, {"a": "b"}, {"hostname": "fuzz"}, {"hostname": ["a", "b"]}, {"hostname": 1}, {"hostname": True}, {"hostname": None},
           {"x" * 100: "y"}, {"": ""}, {"ubus": {"uci": ["get", "set"]}}, {"ubus": {"*": ["*"]}}, {"ubus": "notobject"},
           {"k": {"deep": {"deeper": [1, 2, {"x": None}]}}}, {"a": "b", "c": "d", "e": "f", "g": "h"}, {".type": "system"},
           {"section": "@system[0]"}, {"option": "hostname"}]
POOL = {S: STRINGS, I: INTS, B: BOOLS, A: ARRAYS, O: OBJECTS}
ANY = STRINGS + INTS + BOOLS + ARRAYS + OBJECTS + [None]


def value(rng, ty):
    if rng.random() < 0.75:
        return rng.choice(POOL[ty])
    return rng.choice(ANY)


def cases_for(rng, params, n):
    out = [{}]
    if params:
        out.append({p: rng.choice(ANY) for p in params})              # every parameter, random types
        out.append({p: value(rng, t) for p, t in params.items()})      # every parameter, mostly right types
    for _ in range(n):
        args = {}
        for p, t in params.items():
            if rng.random() < 0.7:
                args[p] = value(rng, t)
        if rng.random() < 0.2:
            args[rng.choice(["extra", "ubus_rpc_session", "path", "config", "x" * 50])] = rng.choice(ANY)
        out.append(args)
    return out


def main():
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    opt = lambda name, default: sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default
    for name in ("--cases-per-method", "--seed"):
        if name in sys.argv:
            v = sys.argv[sys.argv.index(name) + 1]
            if v in argv:
                argv.remove(v)
    rootfs, binary = argv[0], argv[1]
    per, seed = int(opt("--cases-per-method", "8")), int(opt("--seed", "1"))
    rng = random.Random(seed)

    base.STEPS.clear()
    base.SORT_KEYS.clear()
    base.SORT_LINES.clear()
    base.cap("SID", "login0", "session", "login", {"username": "r17crypt", "password": "secret17"})
    rc_only = set()
    k = 0
    for obj, methods in METHODS.items():
        for method, params in methods.items():
            for args in cases_for(rng, params, per):
                sid = "f%04d_%s_%s" % (k, obj.replace("-", ""), method)
                k += 1
                base.req(sid, obj, method, args)
                if (obj, method) in RC_ONLY:
                    rc_only.add(sid)
    # the state both sides should have reached
    base.shx("d_fwtest", "cat /etc/config/fwtest; cat /etc/config/dhcptest; cat /etc/config/system")
    base.shx("d_changes", "ubus call uci changes")
    base.shx("d_sessions", "ubus call session list | grep -c ubus_rpc_session")
    total = len(base.STEPS)
    print("steps: %d (fuzz calls %d)" % (total, k), flush=True)

    orig, osids, ologs = base.run_side(rootfs, "original", binary)
    cand, csids, clogs = base.run_side(rootfs, "candidate", binary)

    def norm(sid, data, sids):
        text = base.normalize(sid, data, sids)
        text = re.sub(r'"(remaining|timeout|expires|time|uptime|localtime|idletime)":\s*-?\d+', r'"\1":<N>', text)
        return text

    bad = 0
    for st in base.STEPS:
        sid = st[0]
        exts = ("rc",) if sid in rc_only else ("rc", "out", "err")
        diffs = []
        for ext in exts:
            k2 = "%s.%s" % (sid, ext)
            a, b = norm(sid, orig.get(k2, b""), osids), norm(sid, cand.get(k2, b""), csids)
            if a != b:
                diffs.append((ext, a, b))
        if not diffs:
            continue
        bad += 1
        args = st[4] if st[1] == "req" else ""
        print("DIFF %s %s" % (sid, args[:160]))
        for ext, a, b in diffs:
            j = 0
            while j < min(len(a), len(b)) and a[j] == b[j]:
                j += 1
            lo = max(0, j - 60)
            print("   %s orig=%r\n   %s cand=%r" % (ext, a[lo:j + 160], " " * len(ext), b[lo:j + 160]))
    for name in ("rpcd-rs.log", "rpcd.log"):
        if clogs.get(name, "").strip():
            print("== candidate %s tail: %r" % (name, clogs[name][-600:]))
    print("steps=%d differing=%d" % (total, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
