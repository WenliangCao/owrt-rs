#!/usr/bin/env python3
"""Build a fw4-rs mock fixture directory from a read-only AX3000T capture.

Usage: r09_device_fixtures.py <capture.txt> <modules.txt> <out-dir>

The capture is the delimited output of the read-only SSH command recorded in
reports/ax3000t-stock-openwrt-25.12.5/R09_FW4.md; the result is consumed with
`FW4_MOCK_DIRS=<out-dir> fw4-rs print` and compared with the captured
`fw4 print` section."""
import json, os, re, sys

def mangle(s):
    return re.sub(r"[^A-Za-z0-9_-]+", "_", s)

def main():
    cap = open(sys.argv[1]).read()
    parts = re.split(r"^===== (\S+)\n", cap, flags=re.M)
    sec = {parts[i]: parts[i + 1] for i in range(1, len(parts), 2)}
    mods = [l.strip() for l in open(sys.argv[2]) if l.startswith("/sys/module/")]
    out = sys.argv[3]

    def w(rel, data):
        p = os.path.join(out, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        open(p, "w").write(data)

    w("uci/firewall", sec["uci_firewall"])
    w("uci/helpers", sec["helpers"])
    w("ubus/network.interface~dump.json", sec["iface_dump"])
    w("ubus/service~get_data~type-firewall.json", sec["service_data"])
    w("ubus/network.device~status.json", sec["devstatus"])
    w("fs/open~_proc_version.txt", sec["proc_version"])
    for line in sec["flags"].strip().splitlines():
        dev, fl = line.split()
        w("fs/open~%s.txt" % mangle("/sys/class/net/%s/flags" % dev), fl + "\n")
        w("fs/open~%s.txt" % mangle("/sys/class/net/%s" % dev), "1\n")
    for mod in mods:
        w("fs/stat~%s.json" % mangle(mod), json.dumps({"type": "directory"}))
    files = [l.strip() for l in sec["nftables_d"].splitlines() if l.startswith("/")]
    for pos in ["ruleset-pre", "ruleset-post", "table-pre", "table-post"]:
        d = "/usr/share/nftables.d/%s" % pos
        lst = sorted(f for f in files if os.path.dirname(f) == d and f.endswith(".nft"))
        w("fs/glob~%s.json" % mangle(d + "/*.nft"), json.dumps(lst))
    for pos in ["chain-pre", "chain-post"]:
        d = "/usr/share/nftables.d/%s" % pos
        chains = sorted({f[len(d) + 1:].split("/")[0] for f in files if f.startswith(d + "/")})
        w("fs/opendir~%s.json" % mangle(d), json.dumps(chains))
        for c in chains:
            lst = sorted(f for f in files if os.path.dirname(f) == d + "/" + c and f.endswith(".nft"))
            w("fs/glob~%s.json" % mangle(d + "/" + c + "/*.nft"), json.dumps(lst))
    for f in files:
        if f.startswith("/usr/share/nftables.d/") and f.endswith(".nft"):
            w("fs/open~%s.txt" % mangle(f), "# x\n")
    w("fs/popen~%s.txt" % mangle("/usr/sbin/nft --terse --json list flowtables inet"), sec["flowtables"])
    open(os.path.join(out, "..", "fw4_print_device.txt"), "w").write(sec["fw4_print"])

if __name__ == "__main__":
    main()
