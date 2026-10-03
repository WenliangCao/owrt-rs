#!/usr/bin/env python3
"""Check real APK scripts and replacement transactions in a disposable image.

Run under run_isolated.sh. The image APK, ubusd, logd, procd, init script and
ujail run in private network, mount and PID namespaces. No force-overwrite or
script suppression is allowed. This is a package check, not M4 acceptance.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import time

from build_package import PACKAGE_ID, PAYLOAD_FILES, audit_metadata, audit_payload
from dns_service_probe import query, semantics
from m2_rootfs import STOCK_SHA256, command, image_path, prepare, sha256

ROOT = Path(__file__).resolve().parents[2]
PRIVATE = ROOT / "private"
CONFIG_FILES = ("etc/config/dhcp", "etc/dnsmasq.conf", "etc/dnsmasq.d/m4-user.conf")
MIGRATION_FILES = {
    "etc/uci-defaults/50-dnsmasq-migrate-ipset.sh",
    "etc/uci-defaults/50-dnsmasq-migrate-resolv-conf-auto.sh",
}
# No external interface, resolver, netifd or DHCP client is needed for APK
# script verification. Both stock and replacement must serve this profile.
DHCP_CONFIG = """# M4 user configuration: preserve across all APK transactions.
config dnsmasq 'm4'
 option port '1053'
 option noresolv '1'
 option localuse '0'
 option nonwildcard '0'
 option leasefile '/tmp/dhcp.leases'
 list address '/m4-package.lan/192.0.2.44'
"""


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def installed_packages(text):
    """Read the image's installed database, retaining every file's owner."""
    packages = {}
    for block in text.strip().split("\n\n"):
        fields, files, directory = {}, [], ""
        for line in block.splitlines():
            kind, sep, value = line.partition(":")
            if not sep:
                continue
            if kind == "F":
                directory = value
            elif kind == "R":
                relative = str(Path(directory) / value)
                require(not relative.startswith("/") and ".." not in Path(relative).parts,
                        "unsafe path in installed database")
                files.append(relative)
            elif kind in ("P", "V", "A", "D", "p"):
                fields[kind] = value
        if "P" in fields:
            name = fields["P"]
            require(name not in packages, f"duplicate package {name}")
            packages[name] = {"version": fields.get("V"), "arch": fields.get("A"),
                              "depends": fields.get("D", ""), "provides": fields.get("p", ""),
                              "files": sorted(files)}
    return packages


def database(root):
    return installed_packages(image_path(root, "lib/apk/db/installed").read_text())


def assert_database(packages, expected_version, baseline):
    expected = baseline["dnsmasq"]["files"] if expected_version != PACKAGE_ID else sorted(PAYLOAD_FILES)
    require(packages.get("dnsmasq", {}).get("version") == expected_version,
            f"wrong dnsmasq version: {packages.get('dnsmasq')}")
    require(packages["dnsmasq"]["files"] == expected, "dnsmasq file ownership list changed")
    require({k: v for k, v in packages.items() if k != "dnsmasq"} ==
            {k: v for k, v in baseline.items() if k != "dnsmasq"},
            "transaction changed another installed package")
    for name, item in packages.items():
        if name != "dnsmasq":
            require(not (set(item["files"]) & set(expected)), f"duplicate file owner: {name}")


def file_state(root, names):
    state = {}
    for name in sorted(names):
        path = image_path(root, name, follow_leaf=False)
        if path.is_symlink():
            state[name] = {"symlink": str(path.readlink())}
        elif path.is_file():
            stat = path.stat()
            state[name] = {"sha256": sha256(path), "mode": stat.st_mode & 0o7777,
                           "uid": stat.st_uid, "gid": stat.st_gid}
        else:
            state[name] = None
    return state


def descendants(pid):
    found, pending = set(), [pid]
    while pending:
        current = pending.pop()
        try:
            children = Path(f"/proc/{current}/task/{current}/children").read_text().split()
        except FileNotFoundError:
            continue
        for child in map(int, children):
            if child not in found:
                found.add(child)
                pending.append(child)
    return found


def stop_group(process):
    # A timed-out script may have descendants even after its immediate parent
    # exits. Each invocation owns a new session, so always kill that session.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            continue
    process.wait(timeout=2)


def invoke(root, argv, log, check=True, timeout=30):
    cmd = command(root, *argv)
    # Avoid inheriting host build variables that silently disable APK scripts.
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, env=env, start_new_session=True)
    record = {"command": cmd, "timeout_seconds": timeout, "timed_out": False}
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        record["timed_out"] = True
        stop_group(process)
        stdout, stderr = process.communicate(timeout=2)
    record.update(returncode=process.returncode, stdout=stdout, stderr=stderr)
    log.write_text(json.dumps(record, indent=2) + "\n")
    require(not record["timed_out"], f"command timed out; see {log}")
    if check:
        require(process.returncode == 0, f"command failed; see {log}")
    return record


def assert_variant_rejected(result, variant):
    text = result["stdout"] + result["stderr"]
    require(result["returncode"] != 0, f"solver allows simultaneous candidate and {variant}")
    require("no such package" not in text.lower() and "not available" not in text.lower(),
            f"{variant} fixture dependencies are incomplete; rejection is not exclusion evidence")
    owner, conflict = None, False
    for line in text.splitlines():
        # An unrelated dependency conflict must not count merely because the
        # candidate and variant names also appear in the requested world.
        header = re.match(r"\s*([A-Za-z0-9_.+-]+-[0-9][^\s:]*):\s*(.*)", line)
        if header:
            owner, line = header.groups()
        if not re.search(r"(?:conflicts|breaks):", line):
            continue
        if owner and owner.startswith(variant + "-"):
            conflict |= bool(re.search(r"\bdnsmasq-[0-9]", line))
        elif owner and re.match(r"dnsmasq-[0-9]", owner):
            conflict |= bool(re.search(rf"\b{re.escape(variant)}-[0-9]", line))
    require(conflict, f"{variant} failed without evidence of a dnsmasq solver conflict")


class Scenario:
    def __init__(self, root, out, report):
        self.root, self.out, self.report = root, out, report
        self.children, self.logs = [], []
        self.sequence = 0

    def run(self, argv, label, check=True):
        self.sequence += 1
        return invoke(self.root, argv, self.out / f"{self.sequence:03d}-{label}.json", check)

    def apk(self, args, label, check=True):
        return self.run(["/usr/bin/apk", "--root", "/", "--no-network", "--allow-untrusted", *args],
                        label, check)

    def bus(self, obj, method, payload):
        result = self.run(["/bin/ubus", "-t", "3", "call", obj, method, json.dumps(payload)],
                          f"ubus-{obj}-{method}")
        return json.loads(result["stdout"] or "{}")

    def wait(self, probe, label):
        deadline, last = time.monotonic() + 20, None
        while time.monotonic() < deadline:
            try:
                value = probe()
                if value:
                    return value
            except (OSError, RuntimeError, ValueError) as error:
                last = str(error)
            time.sleep(.1)
        raise RuntimeError(f"{label} not ready: {last}")

    def start_support(self):
        for binary, obj in (("/sbin/ubusd", None), ("/sbin/logd", "log"), ("/sbin/procd", "service")):
            log = (self.out / (Path(binary).name + ".log")).open("w")
            self.logs.append(log)
            process = subprocess.Popen(command(self.root, binary), stdout=log, stderr=log,
                                       start_new_session=True)
            self.children.append(process)
            def ready():
                args = ["/bin/ubus", "-t", "2", "list"] + ([obj] if obj else [])
                result = self.run(args, f"ready-{Path(binary).name}", check=False)
                return result["returncode"] == 0 and (not obj or obj in result["stdout"].splitlines())
            self.wait(ready, binary)

    def service(self, expected_sha):
        def live():
            listing = self.bus("service", "list", {"name": "dnsmasq", "verbose": True})
            instances = listing.get("dnsmasq", {}).get("instances", {})
            for instance in instances.values():
                if not instance.get("running"):
                    continue
                wrapper = int(instance["pid"])
                for pid in {wrapper} | descendants(wrapper):
                    executable = Path(f"/proc/{pid}/exe")
                    try:
                        if sha256(executable) == expected_sha:
                            cmdline = Path(f"/proc/{wrapper}/cmdline").read_bytes().replace(b"\0", b" ").decode()
                            require("ujail" in cmdline, "dnsmasq was started without the stock ujail wrapper")
                            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                                sock.settimeout(.5)
                                sock.sendto(query("m4-package.lan", 1), ("127.0.0.1", 1053))
                                reply = semantics(sock.recv(4096))
                            require("192.0.2.44" in json.dumps(reply), "package DNS probe differs")
                            if "stock_service" in self.report:
                                require(reply == self.report["stock_service"]["dns_reply"],
                                        "package DNS probe differs from image C semantics")
                            return {"listing": listing, "pid": pid, "wrapper_pid": wrapper,
                                    "wrapper_cmdline": cmdline, "elf_sha256": expected_sha,
                                    "dns_reply": reply}
                    except (FileNotFoundError, ProcessLookupError):
                        pass
            return None
        return self.wait(live, "jailed dnsmasq with expected ELF and DNS answer")

    def stopped(self):
        listing = self.bus("service", "list", {"name": "dnsmasq"})
        return not listing.get("dnsmasq", {}).get("instances")

    def capture(self, label, expected_sha, version, baseline, expected_files, configs):
        packages = database(self.root)
        assert_database(packages, version, baseline)
        actual = file_state(self.root, expected_files)
        for path, wanted in expected_files.items():
            if path in MIGRATION_FILES:
                require(actual[path] is None, f"postinst failed to consume migration {path}")
            elif path not in CONFIG_FILES:
                require(actual[path] == wanted, f"installed file differs: {path}")
        require(file_state(self.root, CONFIG_FILES) == configs, "APK did not preserve user configuration")
        user = [line.split(":") for line in image_path(self.root, "etc/passwd").read_text().splitlines()
                if line.startswith("dnsmasq:")]
        group = [line.split(":") for line in image_path(self.root, "etc/group").read_text().splitlines()
                 if line.startswith("dnsmasq:")]
        require(len(user) == len(group) == 1 and user[0][2:4] == ["453", "453"] and group[0][2] == "453",
                "dnsmasq account/group is absent, duplicated or has the wrong identity")
        init_links = {str(p.relative_to(self.root)): str(p.readlink())
                      for p in (self.root / "etc/rc.d").iterdir()
                      if p.is_symlink() and "dnsmasq" in p.name}
        require(any("/S" in path for path in init_links), "postinst did not enable dnsmasq")
        stage = {"name": label, "version": version, "packages": packages, "files": actual,
                 "user": user, "group": group, "init_links": init_links,
                 "service": self.service(expected_sha)}
        self.report["stages"].append(stage)
        return stage

    def remove(self, label, configs):
        previous = self.report["stages"][-1].get("service", {})
        self.apk(["del", "dnsmasq"], label)
        require("dnsmasq" not in database(self.root), "uninstall retained package database entry")
        for path in PAYLOAD_FILES - set(CONFIG_FILES):
            target = image_path(self.root, path, follow_leaf=False)
            require(not target.exists() and not target.is_symlink(), f"uninstall retained owned file {path}")
        require(file_state(self.root, CONFIG_FILES) == configs, "uninstall changed modified configuration")
        self.wait(self.stopped, "dnsmasq removed from procd")
        self.wait(lambda: all(not Path(f"/proc/{pid}").exists() for pid in
                              (previous.get("pid"), previous.get("wrapper_pid")) if pid),
                  "uninstalled dnsmasq and ujail processes reaped")
        require(not any(p.is_symlink() and "dnsmasq" in p.name for p in (self.root / "etc/rc.d").iterdir()),
                "pre-deinstall did not disable dnsmasq init links")
        self.report["stages"].append({"name": label, "package_absent": True,
                                      "elf_absent": True, "modified_configuration_retained": True})

    def variants(self, fixtures, dependency_fixtures):
        rows, names = [], set()
        dependencies, dependency_rows = [], []
        for index, fixture in enumerate(dependency_fixtures):
            target = f"/m4/variant-dependency-{index}.apk"
            shutil.copy2(fixture, image_path(self.root, target))
            dependencies.append(target)
            dependency_rows.append({"file": fixture.name, "sha256": sha256(fixture)})
        for index, fixture in enumerate(fixtures):
            target = f"/m4/variant-{index}.apk"
            shutil.copy2(fixture, image_path(self.root, target))
            metadata = self.apk(["adbdump", target], f"variant-{index}-metadata")
            match = re.search(r"^  name: (dnsmasq-(?:dhcpv6|full))$", metadata["stdout"], re.MULTILINE)
            require(match is not None, "variant fixture is neither stock dnsmasq-dhcpv6 nor dnsmasq-full")
            name = match.group(1)
            require(name not in names, f"duplicate variant fixture {name}")
            names.add(name)
            before = database(self.root)
            result = self.apk(["add", "--simulate", "/m4/candidate.apk", target, *dependencies],
                              f"{name}-solver-exclusion", check=False)
            assert_variant_rejected(result, name)
            require(database(self.root) == before, "solver simulation changed the package database")
            rows.append({"name": name, "apk_sha256": sha256(fixture), "simultaneous_install_rejected": True})
        self.report["variant_exclusion"] = {
            "status": "passed" if names == {"dnsmasq-dhcpv6", "dnsmasq-full"} else "partial" if names else "not-run",
            "results": rows, "dependency_apks_for_simulation_only": dependency_rows,
            "missing": sorted({"dnsmasq-dhcpv6", "dnsmasq-full"} - names)}

    def cleanup(self):
        errors = []
        try:
            self.run(["/etc/init.d/dnsmasq", "stop"], "cleanup-init-stop", check=False)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            errors.append(str(error))
        owned = descendants(os.getpid())
        for process in reversed(self.children):
            try:
                stop_group(process)
            except (OSError, subprocess.SubprocessError) as error:
                errors.append(str(error))
        for pid in owned:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if not pid:
                time.sleep(.05)
        for log in self.logs:
            log.close()
        remaining = descendants(os.getpid())
        if remaining:
            errors.append(f"processes remain after cleanup: {sorted(remaining)}")
        return {"errors": errors, "remaining_children": sorted(remaining)}


def execute(args, root, out, report):
    case = Scenario(root, out, report)
    report["cleanup"] = {"status": "pending"}
    try:
        baseline = database(root)
        require(baseline.get("dnsmasq", {}).get("version") == "2.93-r1", "image database is not stock 2.93-r1")
        require(set(baseline["dnsmasq"]["files"]) == PAYLOAD_FILES, "unexpected stock file contract")
        stock_files = file_state(root, PAYLOAD_FILES)
        for directory in ("m4", "tmp/resolv.conf.d", "tmp/hosts", "etc/dnsmasq.d"):
            image_path(root, directory).mkdir(parents=True, exist_ok=True)
        for source, name in ((args.stock_apk, "stock.apk"), (args.candidate_apk, "candidate.apk")):
            shutil.copy2(source, root / "m4" / name)
        metadata = case.apk(["adbdump", "/m4/candidate.apk"], "candidate-metadata")
        report["candidate_metadata"] = audit_metadata(metadata["stdout"])
        (root / "m4/candidate-payload").mkdir()
        case.apk(["extract", "--destination", "/m4/candidate-payload", "/m4/candidate.apk"], "extract-payload")
        payload = root / "m4/candidate-payload"
        report["candidate_payload_hashes"] = audit_payload(payload)
        candidate_files = file_state(payload, PAYLOAD_FILES)
        require(candidate_files["usr/sbin/dnsmasq"]["sha256"] == args.candidate_elf_sha256,
                "APK ELF differs from frozen identity")
        # Ancillary paths are part of the image contract, including init/ACL,
        # UID declaration, config declarations, hotplug, and ujail invocation.
        for path in PAYLOAD_FILES - {"usr/sbin/dnsmasq", "lib/apk/packages/dnsmasq.list"}:
            require(candidate_files[path] == stock_files[path], f"candidate changed stock ancillary contract: {path}")
        image_path(root, "etc/config/dhcp").write_text(DHCP_CONFIG)
        for path in CONFIG_FILES[1:]:
            image_path(root, path).write_text("# M4 modified user file; preserve this exact content.\n")
        configs = file_state(root, CONFIG_FILES)
        report["modified_configuration"] = configs
        case.start_support()
        case.run(["/etc/init.d/dnsmasq", "start"], "stock-start")
        report["stock_service"] = case.service(STOCK_SHA256)
        # A genuine upgrade changes the installed version. Same-version
        # force-reinstall is measured separately and never called an upgrade.
        case.apk(["add", "/m4/candidate.apk"], "stock-to-candidate-upgrade")
        case.capture("stock-to-candidate-upgrade", args.candidate_elf_sha256, PACKAGE_ID,
                     baseline, candidate_files, configs)
        case.apk(["add", "--force-reinstall", "/m4/candidate.apk"], "candidate-reinstall")
        case.capture("candidate-reinstall", args.candidate_elf_sha256, PACKAGE_ID,
                     baseline, candidate_files, configs)
        case.remove("candidate-uninstall", configs)
        # Emulate first installation's missing account after uninstall. The
        # actual post-install script must recreate it with the stock UID/GID.
        for path in ("etc/passwd", "etc/group", "etc/shadow"):
            target = image_path(root, path)
            target.write_text("".join(line for line in target.read_text().splitlines(True)
                                      if not line.startswith("dnsmasq:")))
        case.apk(["add", "/m4/candidate.apk"], "candidate-fresh-install")
        case.capture("candidate-fresh-install", args.candidate_elf_sha256, PACKAGE_ID,
                     baseline, candidate_files, configs)
        case.remove("candidate-remove-for-rollback", configs)
        case.apk(["add", "/m4/stock.apk"], "stock-rollback-after-removal")
        case.capture("stock-rollback-after-removal", STOCK_SHA256, "2.93-r1", baseline, stock_files, configs)
        case.apk(["add", "/m4/candidate.apk"], "candidate-upgrade-for-downgrade")
        case.capture("candidate-upgrade-for-downgrade", args.candidate_elf_sha256, PACKAGE_ID,
                     baseline, candidate_files, configs)
        case.variants(args.variant_apk, args.variant_dependency_apk)
        case.apk(["add", "/m4/stock.apk"], "direct-stock-downgrade")
        case.capture("direct-stock-downgrade", STOCK_SHA256, "2.93-r1", baseline, stock_files, configs)
        report["status"] = "passed"
    finally:
        report["cleanup"] = case.cleanup()
        if report["cleanup"]["errors"]:
            report["status"] = "failed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--stock-apk", type=Path, required=True)
    parser.add_argument("--candidate-apk", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--candidate-elf-sha256", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--variant-apk", type=Path, action="append", default=[],
                        help="actual stock dnsmasq-dhcpv6/full APK; repeat for both solver tests")
    parser.add_argument("--variant-dependency-apk", type=Path, action="append", default=[],
                        help="exact image-release dependency APK for solver simulation only; never installed")
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0 or os.environ.get("DNSMASQ_TEST_ISOLATED") != "1":
        parser.error("root inside run_isolated.sh is required")
    if not re.fullmatch(r"[0-9a-f]{64}", args.candidate_elf_sha256) or not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        parser.error("full frozen ELF SHA256 and source commit SHA1 required")
    args.rootfs, args.stock_apk, args.candidate_apk, args.out = (
        path.resolve() for path in (args.rootfs, args.stock_apk, args.candidate_apk, args.out))
    args.variant_apk = [path.resolve() for path in args.variant_apk]
    args.variant_dependency_apk = [path.resolve() for path in args.variant_dependency_apk]
    out = args.out
    if not out.is_relative_to(PRIVATE) or out == PRIVATE or out.exists():
        parser.error("--out must be a new path below private/")
    if not all(path.is_file() for path in (args.stock_apk, args.candidate_apk, args.rootfs / "usr/bin/apk")):
        parser.error("stock APK, candidate APK and exact image apk executable required")
    if any(not path.is_file() for path in args.variant_apk + args.variant_dependency_apk):
        parser.error("variant APK fixtures must exist")
    if args.variant_dependency_apk and not args.variant_apk:
        parser.error("variant dependency fixtures require --variant-apk")
    out.mkdir(parents=True)
    root = out / "rootfs-stage/rootfs"
    report = {"status": "failed", "source_commit": args.source_commit,
              "runner_files": {name: sha256(Path(__file__).with_name(name)) for name in
                               ("m4_package_lifecycle.py", "build_package.py", "m2_rootfs.py", "dns_service_probe.py")},
              "stock_elf_sha256": STOCK_SHA256, "candidate_elf_sha256": args.candidate_elf_sha256,
              "stock_apk_sha256": sha256(args.stock_apk), "candidate_apk_sha256": sha256(args.candidate_apk),
              "namespaces": {name: os.readlink(f"/proc/self/ns/{name}") for name in ("net", "mnt", "pid")},
              "scripts_enabled": True, "stages": [],
              "variant_exclusion": {"status": "not-run", "reason": "separate actual-variant APK solver test required"},
              "scope": "isolated exact-image APK transactions and stock scripts; no physical router or deployment acceptance"}
    try:
        prepare(args.rootfs, None, out / "rootfs-stage", args.rootfs / "usr/sbin/dnsmasq")
        # prepare's auxiliary ELF is unused here; only the APK-installed path
        # may satisfy service identity checks.
        image_path(root, "usr/sbin/dnsmasq-rs").unlink()
        execute(args, root, out, report)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        report.update(status="failed", error=repr(error))
    finally:
        if root.exists():
            try:
                result = subprocess.run(["umount", "--recursive", str(root)], capture_output=True, text=True, timeout=15)
                report["unmount"] = {"returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
                require(result.returncode == 0, "private rootfs unmount failed; keep tree until namespace exit")
                shutil.rmtree(root)
            except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                report["status"] = "failed"
                report["cleanup_error"] = repr(error)
        report["recorded_at"] = time.time()
        (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "stages": [stage["name"] for stage in report["stages"]]}))
    return int(report["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
