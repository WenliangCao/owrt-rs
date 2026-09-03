#!/usr/bin/env python3
"""Differential check of uci-rs against the original /sbin/uci on the exact
rootfs and device configs.

Two disposable copies of the rootfs are made. In the candidate copy the
uci-rs musl binary is bind-mounted over /sbin/uci (the same shape
owrt-uci-switch enable produces), so argv[0] and every script path are
identical. The same command script then runs inside both chroots; per-step
stdout, stderr and exit code are recorded, and afterwards the full content and
mode of /etc/config, /tmp/.uci and /var/state are dumped. Everything is
compared byte for byte.

Usage: r16_uci_check.py <rootfs-files> <uci-rs-musl-binary> [--report out.json]
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
trap 'umount "$root/sbin/uci" 2>/dev/null || true; umount "$root/dev" 2>/dev/null || true; umount "$root/proc" 2>/dev/null || true' EXIT
if [ "$impl" = candidate ]; then
  mount --bind "$root/tmp/uci-rs" "$root/sbin/uci"
fi
chroot "$root" /bin/sh /tmp/steps.sh
"""

# Each step: (id, shell command). Commands run in order inside the chroot with
# stdout/stderr/rc captured to /tmp/out/<id>.{out,err,rc}. `uci` resolves to
# /sbin/uci in both trees.
STEPS = []

def step(sid, cmd):
    STEPS.append((sid, cmd))

# --- implementation probe (expected to differ; reported, not counted)
step("probe_impl", "wc -c < /sbin/uci; uci -q show dhcp >/dev/null; echo rc=$?")
PROBES = {"probe_impl"}

# --- read-only over the device configs
for pkg in ["dhcp", "dropbear", "firewall", "luci", "rpcd", "uhttpd"]:
    step(f"show_{pkg}", f"uci show {pkg}")
    step(f"export_{pkg}", f"uci export {pkg}")
    step(f"exportSn_{pkg}", f"uci -S -n export {pkg}")
    step(f"exportX_{pkg}", f"uci -X show {pkg}")
step("show_all", "uci show")
step("export_all", "uci export")
step("changes_all_empty", "uci changes")
step("get_dropbear_port", "uci get dropbear.@dropbear[0].Port")
step("get_dropbear_last", "uci get dropbear.@dropbear[-1]")
step("get_fw_defaults_type", "uci get firewall.@defaults[0]")
step("get_fw_zone_name1", "uci get firewall.@zone[1].name")
step("get_fw_zone_network", "uci get firewall.@zone[0].network")
step("get_fw_zone_network_d", "uci -d , get firewall.@zone[0].network")
step("get_missing_pkg", "uci get nonexist.a.b")
step("get_missing_pkg_q", "uci -q get nonexist.a.b")
step("get_missing_sec", "uci get dhcp.nosuch.opt")
step("get_missing_opt", "uci -q get dhcp.@dnsmasq[0].nosuch")
step("get_bad_tuple1", "uci get dhcp.")
step("get_bad_tuple2", "uci get dhcp.a.b.c")
step("get_bad_ext1", "uci get dhcp.@")
step("get_bad_ext2", "uci get dhcp.@dnsmasq[9]")
step("get_bad_ext3", "uci get dhcp.@zer.")
step("get_with_value", "uci get dhcp.@dnsmasq[0]=x")
step("show_missing_sec", "uci show dhcp.nosuch")
step("show_opt", "uci show dhcp.@dnsmasq[0].domain")
step("show_sec", "uci show firewall.@zone[0]")
step("get_dot_file", "uci get 'system.@system[0]'")
step("show_state_missing", "uci -P /var/state show dhcp.@dnsmasq[0].domain")

# --- mutations on a scratch copy of the real config
step("prep_copy", "cp /etc/config/firewall /etc/config/fwtest && cp /etc/config/dhcp /etc/config/dhcptest && chmod 0644 /etc/config/fwtest")
step("set_new_opt", "uci set fwtest.@defaults[0].newopt=hello")
step("set_existing_opt", "uci set fwtest.@defaults[0].input=DROP")
step("set_same_value", "uci set fwtest.@defaults[0].input=DROP")
step("set_named_section", "uci set fwtest.mysec=rule")
step("set_named_section_type_change", "uci set fwtest.mysec=redirect")
step("set_bad_type", "uci set fwtest.mysec2='bad type'")
step("set_empty_missing", "uci set fwtest.nosuch.opt=")
step("set_empty_existing", "uci set fwtest.@defaults[0].newopt=")
step("set_multiline", "uci set fwtest.mysec.text=\"Hello,\\'\nWorld\\\"\"")
step("add_anon", "uci add fwtest rule")
step("add_anon2", "uci add fwtest zone")
step("add_list1", "uci add_list fwtest.mysec.l=a")
step("add_list2", "uci add_list fwtest.mysec.l='b c'")
step("add_list_on_string", "uci add_list fwtest.mysec.text=more")
step("del_list", "uci del_list fwtest.mysec.l=a")
step("del_list_missing_opt", "uci del_list fwtest.mysec.nosuch=a")
step("del_list_on_string", "uci del_list fwtest.@defaults[0].input=DROP")
step("changes_fwtest", "uci changes fwtest")
step("show_fwtest_pre", "uci show fwtest")
step("get_list_pre", "uci get fwtest.mysec.l")
step("rename_opt", "uci rename fwtest.mysec.l=lst")
step("rename_sec", "uci rename fwtest.@rule[-1]=lastrule")
step("rename_to_bad", "uci rename fwtest.lastrule='x-y'")
step("reorder", "uci reorder fwtest.mysec=0")
step("reorder_same", "uci reorder fwtest.mysec=0")
step("reorder_big", "uci reorder fwtest.lastrule=999")
step("reorder_missing", "uci reorder fwtest.nosuch=1")
step("del_list_idx", "uci delete fwtest.mysec.lst=0")
step("del_list_idx_bad", "uci delete fwtest.mysec.lst=abc")
step("del_opt", "uci delete fwtest.mysec.text")
step("del_missing", "uci delete fwtest.nosuch")
step("changes_fwtest2", "uci changes fwtest")
step("show_fwtest_mid", "uci show fwtest")
step("export_fwtest_mid", "uci export fwtest")
step("cat_delta_fwtest", "cat /tmp/.uci/fwtest")
step("revert_opt", "uci revert fwtest.@defaults[0].input")
step("changes_after_revert_opt", "uci changes fwtest")
step("commit_fwtest", "uci commit fwtest")
step("cat_delta_after_commit", "cat /tmp/.uci/fwtest; ls -la /tmp/.uci")
step("show_fwtest_post", "uci show fwtest")
step("stat_fwtest", "ls -l /etc/config/fwtest")
step("set_then_revert_sec", "uci set fwtest.mysec.x=1 && uci set fwtest.lastrule.y=2 && uci changes fwtest && uci revert fwtest.mysec && uci changes fwtest")
step("revert_pkg", "uci revert fwtest && uci changes fwtest")
step("commit_nochange", "uci commit fwtest && ls -l /etc/config/fwtest")

# --- state (-P /var/state), like uci_set_state / uci_get_state
step("state_set", "uci -P /var/state set dhcptest.@dnsmasq[0].statev=1")
step("state_set2", "uci -P /var/state set dhcptest.newsec=state")
step("state_get", "uci -P /var/state -q get dhcptest.@dnsmasq[0].statev")
step("state_get_plain", "uci -q get dhcptest.@dnsmasq[0].statev")
step("state_show", "uci -P /var/state show dhcptest")
step("state_cat", "cat /var/state/dhcptest; ls -la /var/state")
step("state_commit_noop", "uci -P /var/state commit dhcptest && ls -l /etc/config/dhcptest")
step("state_revert", "uci -P /var/state revert dhcptest.@dnsmasq[0].statev && cat /var/state/dhcptest")
step("state_export", "uci -P /var/state -S -n export dhcptest")

# --- override dir -C (/var/run/uci)
step("conf2_prep", "mkdir -p /var/run/uci && printf 'config foo bar\\n\\toption a b\\n' > /var/run/uci/dhcptest")
step("conf2_show", "uci show dhcptest")
step("conf2_show_disabled", "uci -C '' show dhcptest.bar")
step("conf2_set", "uci set dhcptest.bar.a=c && uci commit dhcptest && cat /var/run/uci/dhcptest && ls -l /etc/config/dhcptest")
step("conf2_cleanup", "rm -f /var/run/uci/dhcptest")

# --- extra delta paths -p / -t
step("p_prep", "mkdir -p /tmp/altdelta && uci -t /tmp/altdelta set dhcptest.@dnsmasq[0].alt=1 && cat /tmp/altdelta/dhcptest")
step("p_changes_combined", "uci -p /tmp/altdelta changes dhcptest")
step("p_export_combined", "uci -p /tmp/altdelta export dhcptest")
step("p_dup", "uci -p /tmp/.uci changes dhcptest")
step("P_commit_noop", "uci -P /tmp/altdelta commit dhcptest && cat /tmp/altdelta/dhcptest")
step("p_commit", "uci -p /tmp/altdelta commit dhcptest && ls -la /tmp/altdelta /tmp/.uci && uci get dhcptest.@dnsmasq[0].alt")

# --- import
step("import_named", "printf 'config type sec\\n\\toption o v\\n\\tlist l 1\\n\\tlist l 2\\n' | uci import imptest && cat /etc/config/imptest && ls -l /etc/config/imptest")
step("import_pkgline", "printf 'package imp2\\n\\nconfig t s\\n\\toption o \"q\\\\\"x\"\\n' | uci import && cat /etc/config/imp2")
step("import_nopkg", "printf 'config t s\\n' | uci import")
step("import_merge", "printf 'config type sec\\n\\toption o w\\n\\toption n 1\\n' | uci -m import imptest && uci changes imptest && uci export imptest")
step("import_merge_noname", "printf 'config t s\\n' | uci -m import")
step("import_toomany", "uci import a b")
step("import_f_missing", "uci -f /nonexistent import imptest")
step("import_f", "printf 'config t s\\n\\toption a 1\\n' > /tmp/imp.txt && uci -f /tmp/imp.txt import imp3 && cat /etc/config/imp3")

# --- parse errors, strict vs -S
step("perr_prep", "printf 'config a\\n\\toption x 1\\nbogus line\\nconfig b\\n\\toption y 2\\n' > /etc/config/broken; printf 'config \"unterminated\\n' > /etc/config/broken2; printf 'config a\\n\\toption bad-name 1\\n' > /etc/config/broken3; printf 'option x 1\\n' > /etc/config/broken4; printf 'config a b c\\n' > /etc/config/broken5; printf 'config\\n' > /etc/config/broken6; printf 'config a\\n\\toption x 1\\nconfig other a\\n' > /etc/config/broken7")
for i, n in enumerate(["broken", "broken2", "broken3", "broken4", "broken5", "broken6", "broken7"]):
    step(f"perr_strict_{n}", f"uci show {n}")
    step(f"perr_S_{n}", f"uci -S show {n}")
    step(f"perr_export_{n}", f"uci -S -n export {n}")
step("perr_then_notfound", "uci -S get broken.@a[0].nosuch")
step("perr_get_q", "uci -q get broken.@a[0].x")

# --- list configs / show all with junk files
step("junk_prep", "touch /etc/config/has.dot /etc/config/.hidden 'bad name' 2>/dev/null; mkdir -p /etc/config/adir; touch /etc/config/adir/x")
step("show_all_junk", "uci show 2>&1 | head -3; uci show >/dev/null; echo rc=$?")
step("export_all_junk_count", "uci export | grep -c '^package '")
step("junk_cleanup", "rm -rf /etc/config/has.dot /etc/config/.hidden /etc/config/adir")
step("empty_confdir", "mkdir -p /tmp/emptyconf && uci -c /tmp/emptyconf show; uci -c /tmp/emptyconf export")
step("missing_confdir", "uci -c /tmp/nodir show")

# --- batch
step("batch_basic", "printf 'set imptest.bsec=btype\\nset imptest.bsec.o=\"multi\\nline\"\\nadd_list imptest.bsec.l=x\\nget imptest.bsec.o\\ncommit imptest\\n' | uci batch && uci export imptest")
step("batch_errors", "printf 'get imptest.nosuch.x\\nget imptest.nosuch.y\\nbogus\\nshow imptest.bsec\\ntoo many args here now\\nexit\\nget imptest.bsec.o\\n' | uci batch; echo rc=$?")
step("batch_q_errors", "printf 'get imptest.nosuch.x\\nbogus\\n' | uci -q batch; echo rc=$?")
step("batch_nested", "printf 'batch\\nget imptest.bsec.o\\n' | uci batch; echo rc=$?")
step("batch_comment_blank", "printf '# c\\n\\n  # indented\\nset imptest.bsec.z=1\\n\\ncommit imptest\\n' | uci batch && uci get imptest.bsec.z")
step("batch_parse_error", "printf 'set imptest.bsec.q=\"unterminated\\n' | uci batch; echo rc=$?")
step("batch_add", "printf 'add imptest btype\\nadd imptest btype\\ncommit imptest\\n' | uci batch && uci show imptest")

# --- CLI edge cases
step("no_args", "uci; echo rc=$?")
step("help", "uci help; echo rc=$?")
step("unknown_cmd", "uci frobnicate x; echo rc=$?")
step("bad_argc", "uci get; echo rc=$?")
step("bad_argc2", "uci set a b; echo rc=$?")
step("unknown_opt", "uci -z show dhcp; echo rc=$?")
step("opt_missing_arg", "uci -c; echo rc=$?")
step("opt_L", "uci -L show dhcp; echo rc=$?")
step("opt_after_cmd", "uci show -q dhcp; echo rc=$?")
step("dash_dash", "uci -- show dhcp.@dnsmasq[0].domain; echo rc=$?")
step("case_insensitive", "uci SHOW dhcp.@dnsmasq[0].domain; uci Get dhcp.@dnsmasq[0].domain")
step("add_missing_pkg", "uci add nosuchpkg foo; echo rc=$?")
step("add_bad_argc", "uci add nosuchpkg; echo rc=$?")
step("abs_path_load", "cp /etc/config/imptest /tmp/abs.conf && uci show /tmp/abs.conf && uci set /tmp/abs.conf.sec.o=viaabs && cat /tmp/abs.conf; ls /tmp/.uci")
step("rel_path_bad", "uci show ./tmp/abs.conf; uci show .tmp; echo rc=$?")
step("delete_pkg_section_all", "uci delete imptest.bsec && uci delete imptest.sec && uci commit imptest && cat /etc/config/imptest && ls -la /etc/config/imptest")

# --- final state dump
step("final_dump", "for f in /etc/config/* /tmp/.uci/* /var/state/* /tmp/altdelta/*; do [ -f \"$f\" ] || continue; printf '== %s %s\\n' \"$f\" \"$(ls -l \"$f\")\"; cat \"$f\"; done")


def build_steps_script():
    lines = ["#!/bin/sh", "mkdir -p /tmp/out /var/state /var/lock", "cd /"]
    for sid, cmd in STEPS:
        # each step runs in a subshell; capture streams and rc
        lines.append(f"( {cmd} ) >/tmp/out/{sid}.out 2>/tmp/out/{sid}.err; echo $? > /tmp/out/{sid}.rc")
    return "\n".join(lines) + "\n"


def run(rootfs, impl, binary):
    tmp = tempfile.mkdtemp(prefix="r16-")
    try:
        root = os.path.join(tmp, "root")
        subprocess.run(["sudo", "-n", "cp", "-a", rootfs, root], check=True)
        if impl == "candidate":
            subprocess.run(["sudo", "-n", "cp", binary, os.path.join(root, "tmp/uci-rs")], check=True)
            subprocess.run(["sudo", "-n", "chmod", "755", os.path.join(root, "tmp/uci-rs")], check=True)
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write(build_steps_script())
            steps = f.name
        subprocess.run(["sudo", "-n", "cp", steps, os.path.join(root, "tmp/steps.sh")], check=True)
        os.unlink(steps)
        subprocess.run(["sudo", "-n", "setsid", "-w", "unshare", "--mount", "--fork",
                        "/bin/sh", "-c", SCENARIO, "sh", root, impl], check=True)
        out = {}
        outdir = os.path.join(root, "tmp/out")
        listing = subprocess.run(["sudo", "-n", "ls", outdir], capture_output=True, text=True).stdout.split()
        for name in listing:
            data = subprocess.run(["sudo", "-n", "cat", os.path.join(outdir, name)], capture_output=True).stdout
            out[name] = data
        return out
    finally:
        subprocess.run(["sudo", "-n", "rm", "-rf", tmp], check=False)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    report = None
    if "--report" in sys.argv:
        report = sys.argv[sys.argv.index("--report") + 1]
        if report in args:
            args.remove(report)
    rootfs, binary = args[0], args[1]
    orig = run(rootfs, "original", binary)
    cand = run(rootfs, "candidate", binary)
    ndiff = 0
    details = []
    for sid, _cmd in STEPS:
        if sid in PROBES:
            print(f"PROBE {sid}: orig={orig.get(sid + '.out', b'')!r} cand={cand.get(sid + '.out', b'')!r}")
            continue
        same = True
        for ext in ("rc", "out", "err"):
            k = f"{sid}.{ext}"
            if orig.get(k) != cand.get(k):
                same = False
        if same:
            print(f"OK   {sid}")
        else:
            ndiff += 1
            print(f"DIFF {sid}   [{_cmd[:70]}]")
            for ext in ("rc", "out", "err"):
                k = f"{sid}.{ext}"
                o, c = orig.get(k, b""), cand.get(k, b"")
                if o != c:
                    print(f"   {ext} orig: {o[:600]!r}")
                    print(f"   {ext} cand: {c[:600]!r}")
            details.append(sid)
    n = len(STEPS) - len(PROBES)
    print(f"\n{n} steps: {n - ndiff} identical, {ndiff} differ")
    if report:
        with open(report, "w") as f:
            json.dump({"steps": n, "identical": n - ndiff, "differ": details}, f, indent=2)
    sys.exit(1 if ndiff else 0)


if __name__ == "__main__":
    main()
