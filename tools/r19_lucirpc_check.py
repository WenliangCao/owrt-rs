#!/usr/bin/env python3
"""Side-by-side check of rpcd-rs's `luci-rpc` (non-wireless methods) against
the original luci-rpc plugin inside ONE copy of the exact rootfs: rpcd-rs
registers its object under the test name `luci-rpc-rs`
(OWRT_RPCD_LUCI_RPC_NAME), the original rpcd keeps `luci-rpc`, and every
request is sent to both objects back to back, so both read the same host
network state, the same synthetic lease/ethers/uci fixtures and the same fake
PTR server (127.0.0.1:53, needs sudo).

Usage: r19_lucirpc_check.py <rootfs-files> <rpcd-rs-musl-binary> [--report out.json]
"""
import json, os, re, subprocess, sys, tempfile, time

DNS_SERVER = r'''
import socket, struct
PTR = {"20.1.168.192.in-addr.arpa": ["host20.lan"], "40.1.168.192.in-addr.arpa": ["ether40.lan"],
       "0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa": ["v6hundred.lan"],
       "4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa": ["v6four.lan"]}
def name(q):
    out = b""
    for l in q.split("."):
        out += bytes([len(l)]) + l.encode()
    return out + b"\0"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 53))
while True:
    data, peer = s.recvfrom(512)
    if len(data) < 12: continue
    off = 12; labels = []
    while data[off]:
        n = data[off]; labels.append(data[off+1:off+1+n].decode()); off += 1 + n
    off += 1
    q = ".".join(labels)
    qtype = struct.unpack("!H", data[off:off+2])[0]
    names = PTR.get(q, []) if qtype == 12 else []
    hdr = data[:2] + struct.pack("!HHHHH", 0x8180 | (0 if q in PTR else 3), 1, len(names), 0, 0)
    ans = b""
    for n in names:
        rd = name(n); ans += b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 60, len(rd)) + rd
    s.sendto(hdr + data[12:off+4] + ans, peer)
'''

FIXTURES = r"""
set -e
cat > /tmp/dhcp.leases <<'EOF'
1900000000 aa:bb:cc:dd:ee:01 192.168.1.20 host20 01:aa:bb:cc:dd:ee:01
1900000000 aa:bb:cc:dd:ee:02 192.168.1.21 * *
0 aa:bb:cc:dd:ee:03 192.168.1.22 infinite ff:00:00:00:01:00:03:00:01:aa:bb:cc:dd:ee:03
1900000000 aa:bb:cc:dd:ee:04 2001:db8::4 v6host 00030001aabbccddee04
1900000000 aa:bb:cc:dd:ee:05 2001:db8::5 v6b 00:03:00:01:aa:bb:cc:dd:ee:05
1700000000 aa:bb:cc:dd:ee:06 192.168.1.23 expired *
1900000000 * 2001:db8::6 nomac 000100019999999900112233ee06
garbage line
1900000000 notamac 192.168.1.24 x *
1900000000 aa:bb:cc:dd:ee:07 notanip x *
1900000000 aa:bb:cc:dd:ee:0a 192.168.1.26 short
EOF
cat > /tmp/odhcpd.leases <<'EOF'
# lan 000100011234567800112233aabb 6f3a1b2c hostv6 1900000000 12 128 2001:db8::100/128 2001:db8::101
# lan aa:bb:cc:dd:ee:08 ipv4 host8 1900000000 5 32 192.168.1.30
# lan 00030001aabbccddee09 1a2b3c4d - 0 7 0 2001:db8::9
# lan 0001000198765432aabbccddeeff 12345678 dupname 1900000000 1 64 2001:db8::200 2001:db8::201
# lan 0001000198765432aabbccddeeff 12345678 dupname2 1900000000 1 64 2001:db8::202
# wan - x y z
# lan aabbccddee0b ipv4 nohex 1700000000 3 0 192.168.1.31
not a comment line
EOF
printf 'aa:bb:cc:dd:ee:20 192.168.1.40\naa:bb:cc:dd:ee:21 etherhost\nbad line\naa:bb:cc:dd:ee:01 leasehost-overridden\n' > /etc/ethers
cat >> /etc/config/dhcp <<'EOF'

config host
	option name 'static1'
	option mac 'aa:bb:cc:dd:ee:30 aa:bb:cc:dd:ee:31'
	option ip '192.168.1.50'

config host
	option name 'static2'
	list mac 'aa:bb:cc:dd:ee:32'
	list mac 'notamac'
	option ip '192.168.1.51'

config host
	option mac 'aa:bb:cc:dd:ee:02'
	option name 'named-by-uci'
EOF
[ -f /etc/board.json ] || printf '{"model":{"id":"r19","name":"R19 fixture"},"network":{"lan":{"device":"br-lan","protocol":"static"}},"list":[1,2.5,true,null,"x"]}\n' > /etc/board.json
printf 'search lan\nnameserver 127.0.0.1\n' > /etc/resolv.conf
"""

SCENARIO = r"""
set -eu
root=$1
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t sysfs sysfs "$root/sys"
mount -t tmpfs tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
mknod -m 666 "$root/dev/random" c 1 8
trap 'umount "$root/dev" 2>/dev/null || true; umount "$root/sys" 2>/dev/null || true; umount "$root/proc" 2>/dev/null || true' EXIT
chroot "$root" /bin/sh /tmp/steps.sh
"""

PRELUDE = r"""#!/bin/sh
mkdir -p /var/run/ubus /tmp/out/res /var/lock /var/state /var/lib /tmp/.uci
exec 2>/tmp/out/trace.txt
sh /tmp/fixtures.sh
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
ubusd_pid=$!
sleep 1
OWRT_RPCD_LUCI_RPC_NAME=luci-rpc-rs /tmp/rpcd-rs -s /var/run/ubus/ubus.sock -t 30 >/tmp/out/rpcd-rs.log 2>&1 &
rs_pid=$!
for i in 1 2 3 4 5 6 7 8 9 10; do ubus list luci-rpc-rs >/dev/null 2>&1 && break; sleep 1; done
/sbin/rpcd -s /var/run/ubus/ubus.sock -t 30 >/tmp/out/rpcd.log 2>&1 &
rpcd_pid=$!
for i in 1 2 3 4 5 6 7 8 9 10; do ubus list luci-rpc >/dev/null 2>&1 && break; sleep 1; done
pair() {
  id=$1; method=$2; args=$3
  ubus -S -t 60 call luci-rpc "$method" "$args" >/tmp/out/res/$id.o.out 2>/tmp/out/res/$id.o.err; echo $? >/tmp/out/res/$id.o.rc
  ubus -S -t 60 call luci-rpc-rs "$method" "$args" >/tmp/out/res/$id.c.out 2>/tmp/out/res/$id.c.err; echo $? >/tmp/out/res/$id.c.rc
}
ubus -v list luci-rpc > /tmp/out/res/sig.o.out 2>&1; echo $? > /tmp/out/res/sig.o.rc; : > /tmp/out/res/sig.o.err
ubus -v list luci-rpc-rs > /tmp/out/res/sig.c.out 2>&1; echo $? > /tmp/out/res/sig.c.rc; : > /tmp/out/res/sig.c.err
"""

EPILOGUE = r"""
kill $rs_pid $rpcd_pid $ubusd_pid 2>/dev/null || true
sleep 1
"""

PAIRS = [
    ("netdev", "getNetworkDevices", {}),
    ("hosthints", "getHostHints", {}),
    ("duid", "getDUIDHints", {}),
    ("board", "getBoardJSON", {}),
    ("leases", "getDHCPLeases", {}),
    ("leases4", "getDHCPLeases", {"family": 4}),
    ("leases6", "getDHCPLeases", {"family": 6}),
    ("leases_bad", "getDHCPLeases", {"family": 5}),
    ("leases_badtype", "getDHCPLeases", {"family": "4"}),
    ("nomethod", "noSuchMethod", {}),
]
IDS = ["sig"] + [p[0] for p in PAIRS]
# per-run volatile values
from audit_checks import COUNTERS
MASK_KEYS = {"expires", "changes", "up_count", "down_count"}


def build_steps():
    lines = [PRELUDE]
    for sid, method, args in PAIRS:
        lines.append("pair %s %s %s" % (sid, method, shquote(json.dumps(args))))
    lines.append(EPILOGUE)
    return "\n".join(lines) + "\n"


def shquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def sudo(*args, **kw):
    return subprocess.run(["sudo", "-n"] + list(args), check=kw.pop("check", True), **kw)


def normalize(sid, data):
    text = data.decode("utf-8", errors="replace").strip()
    if sid == "sig":
        text = re.sub(r"^'luci-rpc(-rs)?' @[0-9a-f]{8}$", "'luci-rpc' @<typeid>", text, flags=re.M)
        return text
    try:
        v = json.loads(text)
    except Exception:
        return text

    def mask(x, path=()):
        if isinstance(x, dict):
            return {k: ("<masked>" if k in MASK_KEYS or (path and path[-1] == "statistics" and k in COUNTERS)
                        else mask(y, path + (k,))) for k, y in x.items()}
        if isinstance(x, list):
            return [mask(y, path) for y in x]
        return x
    return json.dumps(mask(v))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    report = None
    if "--report" in sys.argv:
        report = sys.argv[sys.argv.index("--report") + 1]
        args.remove(report)
    rootfs, binary = args[0], args[1]
    dns = subprocess.Popen(["sudo", "-n", "python3", "-c", DNS_SERVER])
    time.sleep(0.5)
    tmp = tempfile.mkdtemp(prefix="owrt-r19-")
    root = os.path.join(tmp, "root")
    try:
        sudo("cp", "-a", rootfs, root)
        sudo("chown", "-R", "root:root", os.path.join(root, "etc/config"), os.path.join(root, "usr/share/acl.d"))
        sudo("cp", binary, os.path.join(root, "tmp/rpcd-rs"))
        sudo("chmod", "755", os.path.join(root, "tmp/rpcd-rs"))
        for name, content in (("steps.sh", build_steps()), ("fixtures.sh", FIXTURES)):
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
                f.write(content)
                path = f.name
            sudo("cp", path, os.path.join(root, "tmp", name))
            os.unlink(path)
        sudo("setsid", "-w", "unshare", "--mount", "--fork", "/bin/sh", "-c", SCENARIO, "sh", root, check=False, timeout=900)
        out = {}
        resdir = os.path.join(root, "tmp/out/res")
        for name in sudo("ls", resdir, capture_output=True, text=True, check=False).stdout.split():
            out[name] = sudo("cat", os.path.join(resdir, name), capture_output=True, check=False).stdout
        logs = {n: sudo("cat", os.path.join(root, "tmp/out", n), capture_output=True, check=False).stdout.decode(errors="replace")[-2000:] for n in ("rpcd.log", "rpcd-rs.log", "trace.txt")}
    finally:
        subprocess.run(["sudo", "-n", "pkill", "-f", "socket.bind((\"127.0.0.1\", 53))"], check=False)
        dns.terminate()
        sudo("rm", "-rf", "--", tmp, check=False)
    ndiff = 0
    details = []
    for sid in IDS:
        same = all(normalize(sid, out.get("%s.o.%s" % (sid, e), b"")) == normalize(sid, out.get("%s.c.%s" % (sid, e), b"")) for e in ("rc", "out", "err"))
        if same:
            print("OK   %s" % sid)
            continue
        ndiff += 1
        details.append(sid)
        print("DIFF %s" % sid)
        for e in ("rc", "out", "err"):
            o = normalize(sid, out.get("%s.o.%s" % (sid, e), b""))
            c = normalize(sid, out.get("%s.c.%s" % (sid, e), b""))
            if o != c:
                print("   %s orig: %s" % (e, o[:1500]))
                print("   %s cand: %s" % (e, c[:1500]))
    n = len(IDS)
    print("\n%d pairs: %d identical, %d differ" % (n, n - ndiff, ndiff))
    if ndiff:
        for k, v in logs.items():
            if v.strip():
                print("[%s]\n%s" % (k, v[-1200:]))
    if report:
        samples = {sid: out.get("%s.c.out" % sid, b"").decode("utf-8", errors="replace")[:600] for sid in IDS}
        json.dump({"pairs": n, "identical": n - ndiff, "differ": ndiff, "differing": details, "candidate_samples": samples}, open(report, "w"), indent=2)
    sys.exit(1 if ndiff else 0)


if __name__ == "__main__":
    main()
