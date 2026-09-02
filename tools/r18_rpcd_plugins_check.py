#!/usr/bin/env python3
"""Differential check of the rpcd plugin objects moved into rpcd-rs in stage 8
(`rpc-sys`, `network.rrdns`, later `luci-rpc`) against the original rpcd
plugins, in two disposable copies of the exact rootfs (same sandbox shape as
r17: candidate = rpcd-rs first, then rpcd with file.so/ucode.so removed, whose
core and plugin registrations that rpcd-rs already owns fail silently).

A small PTR-only DNS responder runs on the host at 127.0.0.1:5353 for the
duration of each run (the chroot shares the host network namespace), so
`network.rrdns lookup` gets deterministic answers, NXDOMAIN and a silent
address for the timeout path.

Usage: r18_rpcd_plugins_check.py <rootfs-files> <rpcd-rs-musl-binary> [--report out.json]
"""
import json, os, re, socket, struct, subprocess, sys, tempfile, threading

DNS_PORT = 5353
PTR_MAP = {
    "20.1.168.192.in-addr.arpa": ["host20.lan"],
    "1.1.168.192.in-addr.arpa": ["gw.lan", "gateway.lan"],
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa": ["v6host.lan"],
}
SILENT = {"99.1.168.192.in-addr.arpa"}

def dns_name(qname):
    out = b""
    for label in qname.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"

def parse_qname(msg, off):
    labels = []
    while True:
        n = msg[off]
        if n == 0:
            return ".".join(labels), off + 1
        labels.append(msg[off + 1:off + 1 + n].decode())
        off += 1 + n

def dns_server(stop):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", DNS_PORT))
    s.settimeout(0.5)
    while not stop.is_set():
        try:
            data, peer = s.recvfrom(512)
        except socket.timeout:
            continue
        if len(data) < 12:
            continue
        qname, qend = parse_qname(data, 12)
        qtype, qclass = struct.unpack("!HH", data[qend:qend + 4])
        if qname in SILENT:
            continue
        names = PTR_MAP.get(qname, []) if qtype == 12 else []
        rcode = 0 if qname in PTR_MAP else 3
        hdr = data[:2] + struct.pack("!HHHHH", 0x8180 | rcode, 1, len(names), 0, 0)
        ans = b""
        for n in names:
            rdata = dns_name(n)
            ans += b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 60, len(rdata)) + rdata
        s.sendto(hdr + data[12:qend + 4] + ans, peer)
    s.close()

SCENARIO = r"""
set -eu
root=$1
impl=$2
mount --make-rprivate /
mount -t proc proc "$root/proc"
mount -t tmpfs tmpfs "$root/dev"
mknod -m 666 "$root/dev/null" c 1 3
mknod -m 666 "$root/dev/zero" c 1 5
mknod -m 666 "$root/dev/urandom" c 1 9
mknod -m 666 "$root/dev/random" c 1 8
trap 'umount "$root/dev" 2>/dev/null || true; umount "$root/proc" 2>/dev/null || true' EXIT
chroot "$root" /bin/sh /tmp/steps.sh "$impl"
"""

PRELUDE = r"""#!/bin/sh
impl=$1
mkdir -p /var/run/ubus /tmp/out/res /var/lock /var/state /var/lib /tmp/.uci
exec 2>/tmp/out/trace.txt
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
ubusd_pid=$!
sleep 1
rs_pid=
if [ "$impl" = candidate ]; then
  /tmp/rpcd-rs -s /var/run/ubus/ubus.sock -t 30 >/tmp/out/rpcd-rs.log 2>&1 &
  rs_pid=$!
  for i in 1 2 3 4 5 6 7 8 9 10; do ubus list session >/dev/null 2>&1 && break; sleep 1; done
fi
/sbin/rpcd -s /var/run/ubus/ubus.sock -t 30 >/tmp/out/rpcd.log 2>&1 &
rpcd_pid=$!
for i in 1 2 3 4 5 6 7 8 9 10; do
  ubus list rpc-sys >/dev/null 2>&1 && ubus list network.rrdns >/dev/null 2>&1 && ubus list luci-rpc >/dev/null 2>&1 && break
  sleep 1
done
req() {
  id=$1; obj=$2; method=$3; args=$4
  ubus -S -t 60 call "$obj" "$method" "$args" >/tmp/out/res/$id.out 2>/tmp/out/res/$id.err; echo $? >/tmp/out/res/$id.rc
}
shx() {
  id=$1; shift
  ( eval "$*" ) >/tmp/out/res/$id.out 2>/tmp/out/res/$id.err; echo $? >/tmp/out/res/$id.rc
}
"""

EPILOGUE = r"""
kill $rs_pid $rpcd_pid $ubusd_pid 2>/dev/null || true
sleep 1
"""

STEPS = []
def req(sid, obj, method, args):
    STEPS.append((sid, "req", obj, method, json.dumps(args)))
def shx(sid, cmd):
    STEPS.append((sid, "sh", cmd))

SORT_KEYS = set()

shx("objects", "ubus list | sort")
shx("sig_sys", "ubus -v list rpc-sys")
shx("sig_rrdns", "ubus -v list network.rrdns")

# ---------------------------------------------------------------- rpc-sys
req("sys_pkglist_world", "rpc-sys", "packagelist", {})
req("sys_pkglist_all", "rpc-sys", "packagelist", {"all": True})
req("sys_pkglist_all_false", "rpc-sys", "packagelist", {"all": False})
req("sys_pkglist_badtype", "rpc-sys", "packagelist", {"all": "yes"})
shx("world_prep", "cp /etc/apk/world /tmp/world.bak && printf 'luci\\nrpcd=1\\nlibubox20260213@x\\n' > /etc/apk/world")
req("sys_pkglist_custom_world", "rpc-sys", "packagelist", {})
shx("world_noeol", "printf 'luci' > /etc/apk/world")
req("sys_pkglist_world_noeol", "rpc-sys", "packagelist", {})
shx("world_empty", ": > /etc/apk/world")
req("sys_pkglist_world_empty", "rpc-sys", "packagelist", {})
shx("world_missing", "rm -f /etc/apk/world")
req("sys_pkglist_world_missing", "rpc-sys", "packagelist", {})
shx("world_restore", "cp /tmp/world.bak /etc/apk/world")
shx("db_prep", "cp /lib/apk/db/installed /tmp/installed.bak && printf 'P:r18abi1\\nV:1.0-r1\\ng:openwrt:abiversion=1\\n\\nP:r18plain\\nV:2.0\\n\\nP:r18nover\\n\\nP: r18spaced\\nV: 3.0 extra\\n\\n' >> /lib/apk/db/installed && printf 'r18abi\\nr18plain\\n' >> /etc/apk/world")
req("sys_pkglist_abi", "rpc-sys", "packagelist", {})
req("sys_pkglist_abi_all", "rpc-sys", "packagelist", {"all": True})
shx("db_restore", "cp /tmp/installed.bak /lib/apk/db/installed && cp /tmp/world.bak /etc/apk/world")
req("sys_upgrade_clean_missing", "rpc-sys", "upgrade_clean", {})
shx("firmware_prep", "printf 'not a firmware' > /tmp/firmware.bin")
req("sys_upgrade_test", "rpc-sys", "upgrade_test", {})
req("sys_upgrade_clean", "rpc-sys", "upgrade_clean", {})
shx("firmware_gone", "ls /tmp/firmware.bin")
req("sys_upgrade_test_nofile", "rpc-sys", "upgrade_test", {})
req("sys_password_noargs", "rpc-sys", "password_set", {"user": "root"})
req("sys_password_badtype", "rpc-sys", "password_set", {"user": "root", "password": 5})
req("sys_password_nouser", "rpc-sys", "password_set", {"user": "r18nosuchuser", "password": "x"})
shx("passwd_noexec", "chmod 0644 /bin/passwd")
req("sys_password_noexec", "rpc-sys", "password_set", {"user": "root", "password": "x"})
shx("passwd_gone", "mv /bin/passwd /bin/passwd.r18")
req("sys_password_missing", "rpc-sys", "password_set", {"user": "root", "password": "x"})
shx("passwd_restore", "mv /bin/passwd.r18 /bin/passwd && chmod 0755 /bin/passwd")
req("sys_nomethod", "rpc-sys", "nosuch", {})

# ---------------------------------------------------------------- network.rrdns
S = "127.0.0.1"
req("rr_basic", "network.rrdns", "lookup", {"addrs": ["192.168.1.20"], "server": S, "port": DNS_PORT, "timeout": 500})
req("rr_multi", "network.rrdns", "lookup", {"addrs": ["192.168.1.20", "192.168.1.1", "2001:db8::1", "10.9.9.9"], "server": S, "port": DNS_PORT, "timeout": 500})
req("rr_dup", "network.rrdns", "lookup", {"addrs": ["192.168.1.20", "192.168.1.20", "192.168.001.020"], "server": S, "port": DNS_PORT, "timeout": 500})
req("rr_limit1", "network.rrdns", "lookup", {"addrs": ["192.168.1.20", "192.168.1.1", "2001:db8::1"], "server": S, "port": DNS_PORT, "timeout": 500, "limit": 1})
req("rr_silent", "network.rrdns", "lookup", {"addrs": ["192.168.1.99", "192.168.1.20"], "server": S, "port": DNS_PORT, "timeout": 300, "limit": 1})
req("rr_silent_parallel", "network.rrdns", "lookup", {"addrs": ["192.168.1.99", "192.168.1.20"], "server": S, "port": DNS_PORT, "timeout": 300})
req("rr_badaddr", "network.rrdns", "lookup", {"addrs": ["nonsense", "192.168.1.1", 42, ["x"]], "server": S, "port": DNS_PORT, "timeout": 500})
req("rr_empty", "network.rrdns", "lookup", {"addrs": [], "server": S, "port": DNS_PORT, "timeout": 500})
req("rr_noaddrs", "network.rrdns", "lookup", {"server": S, "port": DNS_PORT})
req("rr_badport", "network.rrdns", "lookup", {"addrs": ["192.168.1.20"], "server": S, "port": 0})
req("rr_badlimit", "network.rrdns", "lookup", {"addrs": ["192.168.1.20"], "server": S, "port": DNS_PORT, "limit": 1001})
req("rr_badlimit0", "network.rrdns", "lookup", {"addrs": ["192.168.1.20"], "server": S, "port": DNS_PORT, "limit": 0})
req("rr_badtimeout", "network.rrdns", "lookup", {"addrs": ["192.168.1.20"], "server": S, "port": DNS_PORT, "timeout": 5001})
req("rr_badtimeout0", "network.rrdns", "lookup", {"addrs": ["192.168.1.20"], "server": S, "port": DNS_PORT, "timeout": 0})
req("rr_port_badtype", "network.rrdns", "lookup", {"addrs": ["192.168.1.20"], "server": S, "port": "5353"})
req("rr_unreach", "network.rrdns", "lookup", {"addrs": ["192.168.1.20"], "server": "127.0.0.1", "port": 5399, "timeout": 300})
shx("resolv_prep", "cp /etc/resolv.conf /tmp/resolv.bak 2>/dev/null; printf '# c\\nsearch lan\\nnameserver bogus\\nnameserver 127.0.0.1\\n' > /etc/resolv.conf")
req("rr_default_server", "network.rrdns", "lookup", {"addrs": ["192.168.1.20"], "port": DNS_PORT, "timeout": 500})
shx("resolv_none", "printf 'search lan\\n' > /etc/resolv.conf")
req("rr_no_server", "network.rrdns", "lookup", {"addrs": ["192.168.1.20"], "port": DNS_PORT, "timeout": 500})
shx("resolv_missing", "rm -f /etc/resolv.conf")
req("rr_no_resolvconf", "network.rrdns", "lookup", {"addrs": ["192.168.1.20"], "port": DNS_PORT, "timeout": 500})
req("rr_nomethod", "network.rrdns", "nosuch", {})


def build_steps():
    lines = [PRELUDE]
    for st in STEPS:
        sid, kind = st[0], st[1]
        if kind == "req":
            lines.append("req %s %s %s %s" % (sid, st[2], st[3], shquote(st[4])))
        else:
            lines.append("shx %s %s" % (sid, shquote(st[2])))
    lines.append(EPILOGUE)
    return "\n".join(lines) + "\n"


def shquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def sudo(*args, **kw):
    return subprocess.run(["sudo", "-n"] + list(args), check=kw.pop("check", True), **kw)


def run_side(rootfs, impl, binary):
    tmp = tempfile.mkdtemp(prefix="owrt-r18-")
    root = os.path.join(tmp, "root")
    sudo("cp", "-a", rootfs, root)
    sudo("chown", "-R", "root:root", os.path.join(root, "etc/init.d"), os.path.join(root, "etc/rc.d"), os.path.join(root, "etc/config"), os.path.join(root, "usr/share/acl.d"))
    if impl == "candidate":
        sudo("rm", "-f", os.path.join(root, "usr/lib/rpcd/file.so"), os.path.join(root, "usr/lib/rpcd/ucode.so"))
        sudo("cp", binary, os.path.join(root, "tmp/rpcd-rs"))
        sudo("chmod", "755", os.path.join(root, "tmp/rpcd-rs"))
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(build_steps())
        steps = f.name
    sudo("cp", steps, os.path.join(root, "tmp/steps.sh"))
    os.unlink(steps)
    sudo("setsid", "-w", "unshare", "--mount", "--fork", "/bin/sh", "-c", SCENARIO, "sh", root, impl, check=False, timeout=1800)
    out = {}
    resdir = os.path.join(root, "tmp/out/res")
    for name in sudo("ls", resdir, capture_output=True, text=True, check=False).stdout.split():
        out[name] = sudo("cat", os.path.join(resdir, name), capture_output=True, check=False).stdout
    logs = {}
    for name in ("rpcd.log", "rpcd-rs.log", "ubusd.log", "trace.txt"):
        logs[name] = sudo("cat", os.path.join(root, "tmp/out", name), capture_output=True, check=False).stdout.decode(errors="replace")[-3000:]
    sudo("rm", "-rf", "--", tmp, check=False)
    return out, logs


def normalize(sid, data):
    text = data.decode("utf-8", errors="replace")
    text = re.sub(r"^('[a-z.-]+') @[0-9a-f]{8}$", r"\1 @<typeid>", text, flags=re.M)
    # sysupgrade prefixes its messages with the wall clock
    text = re.sub(r"[A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d [A-Z]+ \d{4}", "<TS>", text)
    if sid in SORT_KEYS:
        try:
            text = json.dumps(json.loads(text), sort_keys=True)
        except Exception:
            pass
    return text


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    report = None
    if "--report" in sys.argv:
        report = sys.argv[sys.argv.index("--report") + 1]
        args.remove(report)
    rootfs, binary = args[0], args[1]
    stop = threading.Event()
    t = threading.Thread(target=dns_server, args=(stop,), daemon=True)
    t.start()
    try:
        orig, ologs = run_side(rootfs, "original", binary)
        cand, clogs = run_side(rootfs, "candidate", binary)
    finally:
        stop.set()
    ndiff = 0
    details = []
    for st in STEPS:
        sid = st[0]
        same = all(normalize(sid, orig.get("%s.%s" % (sid, e), b"")) == normalize(sid, cand.get("%s.%s" % (sid, e), b"")) for e in ("rc", "out", "err"))
        if same:
            print("OK   %s" % sid)
            continue
        ndiff += 1
        print("DIFF %s   [%s]" % (sid, " ".join(str(x) for x in st[1:])[:90]))
        for e in ("rc", "out", "err"):
            o = normalize(sid, orig.get("%s.%s" % (sid, e), b""))
            c = normalize(sid, cand.get("%s.%s" % (sid, e), b""))
            if o != c:
                print("   %s orig: %s" % (e, o[:700]))
                print("   %s cand: %s" % (e, c[:700]))
        details.append(sid)
    n = len(STEPS)
    print("\n%d steps: %d identical, %d differ" % (n, n - ndiff, ndiff))
    if ndiff:
        for name, v in clogs.items():
            if v.strip():
                print("[candidate %s]\n%s" % (name, v[-1200:]))
    if report:
        json.dump({"steps": n, "identical": n - ndiff, "differ": ndiff, "differing": details}, open(report, "w"), indent=2)
    sys.exit(1 if ndiff else 0)


if __name__ == "__main__":
    main()
