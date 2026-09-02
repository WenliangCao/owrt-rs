#!/usr/bin/env python3
"""Differential check of rpcd-rs (`file`, `luci` objects) against the original
rpcd plugins, each inside a disposable copy of the exact rootfs with the exact
ubusd + rpcd. The candidate sandbox removes file.so and ucode.so from the copy
and runs rpcd-rs next to rpcd, exactly like owrt-rpcd-switch enable does.

Usage: r13_rpcd_check.py <rootfs-files> <rpcd-rs-musl-binary> [--report out.json]
"""
import json, os, subprocess, sys, tempfile

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
chroot "$root" /bin/sh -s "$impl" <<'CHROOT_TEST'
set -u
impl=$1
mkdir -p /var/run/ubus /tmp/out /var/lock /var/state /var/lib
exec 2>/tmp/out/trace.txt
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
ubusd_pid=$!
sleep 1
rs_pid=
if [ "$impl" = candidate ]; then
  # since stage 7 rpcd-rs also owns session/uci/rc: it must register first
  /tmp/rpcd-rs -s /var/run/ubus/ubus.sock -t 30 >/tmp/out/rpcd-rs.log 2>&1 &
  rs_pid=$!
  for i in 1 2 3 4 5 6 7 8 9 10; do ubus list session >/dev/null 2>&1 && break; sleep 1; done
fi
/sbin/rpcd -s /var/run/ubus/ubus.sock -t 30 >/tmp/out/rpcd.log 2>&1 &
rpcd_pid=$!
for i in 1 2 3 4 5 6 7 8 9 10; do ubus list file >/dev/null 2>&1 && ubus list luci >/dev/null 2>&1 && break; sleep 1; done
ubus list > /tmp/out/objects.txt 2>&1
while IFS="	" read -r id obj method args; do
  out=$(ubus -S -t 60 call "$obj" "$method" "$args" 2>/tmp/out/err.txt); rc=$?
  printf '%s\t%s\t%s\n' "$id" "$rc" "$out" >> /tmp/out/results.txt
done < /tmp/out/requests.txt
kill $rs_pid $rpcd_pid $ubusd_pid 2>/dev/null || true
sleep 1
CHROOT_TEST
"""

REQUESTS = [
    ("file_read", "file", "read", {"path": "/etc/passwd"}),
    ("file_read_b64", "file", "read", {"path": "/etc/passwd", "base64": True}),
    ("file_read_canon", "file", "read", {"path": "/etc//config/../passwd"}),
    ("file_read_missing", "file", "read", {"path": "/nonexistent"}),
    ("file_read_dir", "file", "read", {"path": "/etc"}),
    ("file_read_noarg", "file", "read", {}),
    ("file_read_denied", "file", "read", {"path": "/etc/passwd", "ubus_rpc_session": "00000000000000000000000000000000"}),
    ("file_stat", "file", "stat", {"path": "/etc/passwd"}),
    ("file_stat_dir", "file", "stat", {"path": "/etc/config/"}),
    ("file_lstat_link", "file", "lstat", {"path": "/etc/rc.d/S19firewall"}),
    ("file_stat_link", "file", "stat", {"path": "/etc/rc.d/S19firewall"}),
    ("file_list", "file", "list", {"path": "/etc/config"}),
    ("file_list_rcd", "file", "list", {"path": "/etc/rc.d"}),
    ("file_list_file", "file", "list", {"path": "/etc/passwd"}),
    ("file_md5", "file", "md5", {"path": "/etc/passwd"}),
    ("file_md5_dir", "file", "md5", {"path": "/etc"}),
    ("file_write", "file", "write", {"path": "/tmp/r13-w.txt", "data": "hello\nworld\n"}),
    ("file_write_read", "file", "read", {"path": "/tmp/r13-w.txt"}),
    ("file_write_append", "file", "write", {"path": "/tmp/r13-w.txt", "data": "more", "append": True}),
    ("file_write_read2", "file", "read", {"path": "/tmp/r13-w.txt"}),
    ("file_write_b64", "file", "write", {"path": "/tmp/r13-b.bin", "data": "AAEC/w==", "base64": True, "mode": 384}),
    ("file_write_b64_stat", "file", "stat", {"path": "/tmp/r13-b.bin"}),
    ("file_write_b64_read", "file", "read", {"path": "/tmp/r13-b.bin", "base64": True}),
    ("file_write_nodata", "file", "write", {"path": "/tmp/r13-n.txt"}),
    ("file_remove", "file", "remove", {"path": "/tmp/r13-w.txt"}),
    ("file_remove_gone", "file", "stat", {"path": "/tmp/r13-w.txt"}),
    ("file_remove_missing", "file", "remove", {"path": "/tmp/r13-none"}),
    ("file_exec_echo", "file", "exec", {"command": "echo", "params": ["a", "b c"]}),
    ("file_exec_sh", "file", "exec", {"command": "/bin/sh", "params": ["-c", "echo out; echo err >&2; exit 3"]}),
    ("file_exec_env", "file", "exec", {"command": "/bin/sh", "params": ["-c", "echo $FOO"], "env": {"FOO": "bar"}}),
    ("file_exec_missing", "file", "exec", {"command": "nosuchcmd"}),
    ("file_exec_noarg", "file", "exec", {}),
    ("file_exec_denied_env", "file", "exec", {"command": "echo", "env": {"A": "b"}, "ubus_rpc_session": "00000000000000000000000000000000"}),
    ("file_exec_denied", "file", "exec", {"command": "echo", "ubus_rpc_session": "00000000000000000000000000000000"}),
    ("luci_version", "luci", "getVersion", {}),
    ("luci_initlist", "luci", "getInitList", {}),
    ("luci_initlist_one", "luci", "getInitList", {"name": "firewall"}),
    ("luci_initlist_none", "luci", "getInitList", {"name": "nosuch"}),
    ("luci_initlist_badarg", "luci", "getInitList", {"nam": "x"}),
    ("luci_initlist_badtype", "luci", "getInitList", {"name": 1}),
    ("luci_initaction_bad", "luci", "setInitAction", {"name": "cron", "action": "bogus"}),
    ("luci_initaction_none", "luci", "setInitAction", {"name": "nosuch", "action": "disable"}),
    ("luci_initaction_disable", "luci", "setInitAction", {"name": "cron", "action": "disable"}),
    ("luci_initlist_cron", "luci", "getInitList", {"name": "cron"}),
    ("luci_initaction_enable", "luci", "setInitAction", {"name": "cron", "action": "enable"}),
    ("luci_initlist_cron2", "luci", "getInitList", {"name": "cron"}),
    ("luci_unixtime", "luci", "getUnixtime", {}),
    ("luci_timezones", "luci", "getTimezones", {}),
    ("luci_leds", "luci", "getLEDs", {}),
    ("luci_usb", "luci", "getUSBDevices", {}),
    ("luci_helpers", "luci", "getConntrackHelpers", {}),
    ("luci_features", "luci", "getFeatures", {}),
    ("luci_swfeat", "luci", "getSwconfigFeatures", {}),
    ("luci_swport", "luci", "getSwconfigPortState", {"switch": "switch0"}),
    ("luci_block", "luci", "getBlockDevices", {}),
    ("luci_mounts", "luci", "getMountPoints", {}),
    ("luci_rt_bad", "luci", "getRealtimeStats", {"mode": "bogus"}),
    ("luci_rt_load", "luci", "getRealtimeStats", {"mode": "load"}),
    ("luci_conntrack", "luci", "getConntrackList", {}),
    ("luci_procs", "luci", "getProcessList", {}),
    ("luci_ports", "luci", "getBuiltinEthernetPorts", {}),
    ("luci_odhcp6c", "luci", "getOdhcp6cStats", {}),
    ("luci_nomethod", "luci", "noSuchMethod", {}),
]

# fields whose values differ per run / per rootfs copy
MASK_KEYS = {"inode", "atime", "ctime"}
# requests where only the shape (keys, types, list length class) is compared
SHAPE_ONLY = {"luci_unixtime", "luci_mounts", "luci_conntrack", "luci_procs", "luci_rt_load"}
# files created during the run carry the run's own mtime
MASK_MTIME = {"file_write_b64_stat"}
# the original file plugin races its exit-status read against pipe EOF and
# sometimes reports code 0 (observed in the sandbox, not on the device); the
# candidate must report the real exit status
EXPECT_CODE = {"file_exec_sh": 3}


def shape(v):
    if isinstance(v, dict):
        return {k: shape(x) for k, x in v.items()}
    if isinstance(v, list):
        return ["list", len(v) > 0, shape(v[0]) if v else None]
    return type(v).__name__


def normalize(rid, text):
    text = text.strip()
    if not text:
        return ""
    try:
        v = json.loads(text)
    except Exception:
        return text

    keys = MASK_KEYS | ({"mtime"} if rid in MASK_MTIME else set()) | ({"code"} if rid in EXPECT_CODE else set())

    def mask(x):
        if isinstance(x, dict):
            return {k: ("<masked>" if k in keys else mask(y)) for k, y in x.items()}
        if isinstance(x, list):
            return [mask(y) for y in x]
        return x

    v = mask(v)
    if rid in SHAPE_ONLY:
        v = shape(v)
    return json.dumps(v, sort_keys=True)


def run_side(rootfs, impl, binary):
    temp = tempfile.mkdtemp(prefix="owrt-r13-")
    root = os.path.join(temp, "rootfs")
    subprocess.run(["sudo", "-n", "cp", "-a", rootfs, root], check=True)
    subprocess.run(["sudo", "-n", "mkdir", "-p", os.path.join(root, "tmp/out")], check=True)
    subprocess.run(["sudo", "-n", "chmod", "1777", os.path.join(root, "tmp"), os.path.join(root, "tmp/out")], check=True)
    if impl == "candidate":
        subprocess.run(["sudo", "-n", "rm", "-f", os.path.join(root, "usr/lib/rpcd/file.so"), os.path.join(root, "usr/lib/rpcd/ucode.so")], check=True)
        subprocess.run(["sudo", "-n", "cp", binary, os.path.join(root, "tmp/rpcd-rs")], check=True)
        subprocess.run(["sudo", "-n", "chmod", "755", os.path.join(root, "tmp/rpcd-rs")], check=True)
    with open(os.path.join(root, "tmp/out/requests.txt"), "w") as f:
        for rid, obj, method, args in REQUESTS:
            f.write("%s\t%s\t%s\t%s\n" % (rid, obj, method, json.dumps(args)))
    subprocess.run(["sudo", "-n", "setsid", "-w", "unshare", "--mount", "--fork", "sh", "-c", SCENARIO, "scenario", root, impl], check=False, timeout=600)
    results = {}
    try:
        for line in subprocess.run(["sudo", "-n", "cat", os.path.join(root, "tmp/out/results.txt")], capture_output=True, text=True, check=True).stdout.splitlines(True):
            parts = line.rstrip("\n").split("\t", 2)
            if len(parts) == 3:
                results[parts[0]] = (int(parts[1]), parts[2])
    except FileNotFoundError:
        pass
    logs = {}
    for name in ("objects.txt", "rpcd.log", "rpcd-rs.log", "ubusd.log", "trace.txt"):
        p = os.path.join(root, "tmp/out", name)
        r = subprocess.run(["sudo", "-n", "cat", p], capture_output=True, check=False)
        if r.returncode == 0:
            logs[name] = r.stdout.decode(errors="replace")[-2000:]
    subprocess.run(["sudo", "-n", "rm", "-rf", "--", temp], check=False)
    return results, logs


def main():
    rootfs, binary = sys.argv[1], sys.argv[2]
    report_path = sys.argv[sys.argv.index("--report") + 1] if "--report" in sys.argv else None
    orig, orig_logs = run_side(rootfs, "original", binary)
    cand, cand_logs = run_side(rootfs, "candidate", binary)
    identical = differ = 0
    report = []
    for rid, obj, method, args in REQUESTS:
        o = orig.get(rid)
        c = cand.get(rid)
        if o is None or c is None:
            differ += 1
            print("%-26s MISSING (orig=%s cand=%s)" % (rid, o is not None, c is not None))
            continue
        same = o[0] == c[0] and normalize(rid, o[1]) == normalize(rid, c[1])
        if rid in EXPECT_CODE:
            try:
                same = same and json.loads(c[1]).get("code") == EXPECT_CODE[rid]
            except Exception:
                same = False
        if same:
            identical += 1
        else:
            differ += 1
            print("%-26s DIFFERS rc %d vs %d" % (rid, o[0], c[0]))
            print("   orig: %s" % normalize(rid, o[1])[:600])
            print("   cand: %s" % normalize(rid, c[1])[:600])
        report.append({"id": rid, "object": obj, "method": method, "args": args, "identical": same, "rc": [o[0], c[0]]})
    print("\n%d requests: %d identical, %d differ" % (len(REQUESTS), identical, differ))
    if differ:
        print("--- candidate logs ---")
        for k, v in cand_logs.items():
            if v.strip():
                print("[%s]\n%s" % (k, v[-800:]))
    if report_path:
        json.dump({"requests": report, "identical": identical, "differ": differ}, open(report_path, "w"), indent=2)
    sys.exit(1 if differ else 0)


if __name__ == "__main__":
    main()
