#!/usr/bin/env python3
"""Differential probe for the round-1 audit fixes to rpcd-rs `file`.

Runs a handful of file.write / file.exec requests that the 63-case harness did
not cover (mode/umask, exec 127 paths, base64 framing, overflow boundary,
signal exit code) against the original rpcd and against rpcd-rs, both inside a
disposable copy of the exact rootfs, and diffs the replies.

Usage: r13_audit_probe.py <rootfs-files> <rpcd-rs-musl-binary>
"""
import json, os, re, subprocess, sys, tempfile

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
chroot "$root" /bin/sh -s "$impl" <<'CHROOT'
set -u
impl=$1
mkdir -p /var/run/ubus /tmp/out /var/lock /var/state
umask 022
# fixtures
printf 'plaincontent' > /tmp/plain.txt
chmod 0644 /tmp/plain.txt
printf '#!/nonexistent\necho hi\n' > /tmp/bad.sh
chmod 0755 /tmp/bad.sh
printf 'PRESET-LONG-EXISTING-CONTENT' > /tmp/overwrite.txt
chmod 0644 /tmp/overwrite.txt
/sbin/ubusd >/tmp/out/ubusd.log 2>&1 &
ubusd_pid=$!
sleep 1
/sbin/rpcd -s /var/run/ubus/ubus.sock -t 30 >/tmp/out/rpcd.log 2>&1 &
rpcd_pid=$!
rs_pid=
if [ "$impl" = candidate ]; then
  /tmp/rpcd-rs -s /var/run/ubus/ubus.sock -t 30 >/tmp/out/rpcd-rs.log 2>&1 &
  rs_pid=$!
fi
for i in 1 2 3 4 5 6 7 8 9 10; do ubus list file >/dev/null 2>&1 && break; sleep 1; done
while IFS="	" read -r id obj method args; do
  out=$(ubus -S -t 60 call "$obj" "$method" "$args" 2>/tmp/out/err.txt); rc=$?
  printf '%s\t%s\t%s\n' "$id" "$rc" "$out" >> /tmp/out/results.txt
  # capture resulting mode for write cases
  case "$id" in
    write_default) m=$(ubus -S call file stat '{"path":"/tmp/w_default"}'); printf 'write_default_stat\t0\t%s\n' "$m" >> /tmp/out/results.txt;;
    write_mode777) m=$(ubus -S call file stat '{"path":"/tmp/w_777"}'); printf 'write_mode777_stat\t0\t%s\n' "$m" >> /tmp/out/results.txt;;
    write_short_over) m=$(ubus -S call file read '{"path":"/tmp/overwrite.txt"}'); printf 'write_short_over_read\t0\t%s\n' "$m" >> /tmp/out/results.txt;;
  esac
done < /tmp/out/requests.txt
kill $rs_pid $rpcd_pid $ubusd_pid 2>/dev/null || true
sleep 1
CHROOT
"""

REQUESTS = [
    # (id, object, method, args)
    ("write_default", "file", "write", {"path": "/tmp/w_default", "data": "hi"}),
    ("write_mode777", "file", "write", {"path": "/tmp/w_777", "data": "hi", "mode": 511}),
    ("write_short_over", "file", "write", {"path": "/tmp/overwrite.txt", "data": "SHORT"}),
    ("exec_nonexec", "file", "exec", {"command": "/tmp/plain.txt"}),
    ("exec_bad_interp", "file", "exec", {"command": "/tmp/bad.sh"}),
    ("exec_missing", "file", "exec", {"command": "/tmp/does-not-exist"}),
    ("exec_signal", "file", "exec", {"command": "/bin/sh", "params": ["-c", "kill -TERM $$"]}),
    ("exec_manyargs", "file", "exec", {"command": "/bin/true", "params": [str(i) for i in range(254)]}),
    ("exec_okargs", "file", "exec", {"command": "/bin/echo", "params": ["a", "b"]}),
    ("write_b64_bad1", "file", "write", {"path": "/tmp/b1", "data": "Q", "base64": True}),
    ("write_b64_bad3", "file", "write", {"path": "/tmp/b3", "data": "QQ=", "base64": True}),
    ("write_b64_ok", "file", "write", {"path": "/tmp/bok", "data": "QQ==", "base64": True}),
    ("setlocaltime_empty", "luci", "setLocaltime", {}),
]

MASK_KEYS = {"inode", "atime", "ctime", "mtime", "size"}
# size masked only where it legitimately differs? keep size for read; for stat we compare mode explicitly.

def norm(rid, text):
    text = text.strip()
    if not text:
        return {"_empty": True}
    try:
        v = json.loads(text)
    except Exception:
        return {"_raw": text}
    def mask(x):
        if isinstance(x, dict):
            return {k: ("<m>" if k in MASK_KEYS else mask(y)) for k, y in x.items()}
        if isinstance(x, list):
            return [mask(y) for y in x]
        return x
    return mask(v)

def run(rootfs, impl, binary):
    with tempfile.TemporaryDirectory() as tmp:
        root = os.path.join(tmp, "root")
        subprocess.run(["sudo", "-n", "cp", "-a", rootfs, root], check=True)
        if impl == "candidate":
            subprocess.run(["sudo", "-n", "cp", binary, os.path.join(root, "tmp/rpcd-rs")], check=True)
            subprocess.run(["sudo", "-n", "chmod", "755", os.path.join(root, "tmp/rpcd-rs")], check=True)
            # trim ucode/so plugins like owrt-rpcd-switch does, so rpcd-rs serves file
            for so in ("file.so", "ucode.so"):
                p = os.path.join(root, "usr/lib/rpcd", so)
                if os.path.exists(p):
                    subprocess.run(["sudo", "-n", "rm", "-f", p], check=True)
        reqp = os.path.join(root, "tmp/out")
        subprocess.run(["sudo", "-n", "mkdir", "-p", reqp], check=True)
        lines = "".join("%s\t%s\t%s\t%s\n" % (i, o, m, json.dumps(a)) for i, o, m, a in REQUESTS)
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(lines); reqfile = f.name
        subprocess.run(["sudo", "-n", "cp", reqfile, os.path.join(reqp, "requests.txt")], check=True)
        os.unlink(reqfile)
        subprocess.run(["sudo", "-n", "setsid", "-w", "unshare", "--mount", "--fork",
                        "/bin/sh", "-c", SCENARIO, "sh", root, impl], check=True)
        out = subprocess.run(["sudo", "-n", "cat", os.path.join(reqp, "results.txt")],
                             capture_output=True, text=True).stdout
        res = {}
        for line in out.splitlines():
            parts = line.split("\t", 2)
            if len(parts) == 3:
                res[parts[0]] = (parts[1], parts[2])
        return res

def main():
    rootfs, binary = sys.argv[1], sys.argv[2]
    orig = run(rootfs, "original", binary)
    cand = run(rootfs, "candidate", binary)
    ids = list(dict.fromkeys(list(orig) + list(cand)))
    ndiff = 0
    for rid in ids:
        o = orig.get(rid, ("?", ""))
        c = cand.get(rid, ("?", ""))
        # for stat cases compare only mode
        if rid.endswith("_stat"):
            def mode(x):
                try:
                    return json.loads(x[1]).get("mode")
                except Exception:
                    return None
            same = o[0] == c[0] and mode(o) == mode(c)
            detail = "mode orig=%s cand=%s" % (mode(o), mode(c))
        else:
            same = o[0] == c[0] and norm(rid, o[1]) == norm(rid, c[1])
            detail = ""
        mark = "OK " if same else "DIFF"
        if not same:
            ndiff += 1
        print("%s %-22s rc(o=%s c=%s) %s" % (mark, rid, o[0], c[0], detail))
        if not same:
            print("     orig: %s" % str(norm(rid, o[1]) if not rid.endswith('_stat') else o[1])[:400])
            print("     cand: %s" % str(norm(rid, c[1]) if not rid.endswith('_stat') else c[1])[:400])
    print("\n%d ids, %d differ" % (len(ids), ndiff))
    sys.exit(1 if ndiff else 0)

if __name__ == "__main__":
    main()
