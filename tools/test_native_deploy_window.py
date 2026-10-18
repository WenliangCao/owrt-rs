#!/usr/bin/env python3
"""Prove reboot observation cannot invoke another upgrade or reboot."""
import contextlib
import io
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import native_deploy_window as driver


class ObserveOnly(unittest.TestCase):
    def test_observe_confirms_new_boot_without_flash_or_reboot(self):
        self.exercise_observe()

    def test_eleven_observation_also_checks_live_odhcpd(self):
        self.exercise_observe(odhcpd=True)

    def exercise_observe(self, odhcpd=False):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            old_boot = "11111111-1111-1111-1111-111111111111"
            new_boot = "22222222-2222-2222-2222-222222222222"
            digest = "a" * 64
            paths = {name: "/sbin/" + name for name in
                     ("procd", "ubusd", "netifd", "rpcd", "logd", "uci", "fw4")}
            paths.update({"httpd": "/usr/sbin/uhttpd", "dnsmasq": "/usr/sbin/dnsmasq",
                          "reload-config": "/sbin/reload_config"})
            if odhcpd:
                paths["odhcpd"] = "/usr/sbin/odhcpd"
            manifest = {"deployment_layout": "native-eleven" if odhcpd else "native-ten", "source_commit": "a" * 40,
                        "components": {name: {"path": path, "rust_sha256": digest,
                                               "stock_sha256": "b" * 64} for name, path in paths.items()},
                        "integration_files": {path: {"path": path, "replacement_sha256": digest}
                                              for path in ("/etc/init.d/dnsmasq", "/usr/share/acl.d/dnsmasq_acl.json")}}
            for name in ("image.bin", "trial-config.tar.gz", "guard-evidence.tar.gz"):
                (base / name).write_bytes(b"fixture")
            image_hash = driver.sha(base / "image.bin")
            (base / "manifest.json").write_text(json.dumps(manifest))
            (base / "recovery-gate.json").write_text(json.dumps({
                "ready_for_staging": True, "rollback_source_commit": "b" * 40,
                "ujail_sha256": "c" * 64,
                "previous_boot_id": old_boot, "image_path": str(base / "image.bin"),
                "manifest_path": str(base / "manifest.json"), "guard_evidence_sha256": image_hash,
                "backup_sha256": {}}))
            (base / "trial-config.tar.json").write_text(json.dumps({
                "image": {"sha256": image_hash}, "archive_sha256": image_hash,
                "token": "private-token", "payload_sha256": {"root/fixture": digest}}))
            (base / "stage-ready.json").write_text(json.dumps({
                "sysupgrade_test_passed": True, "driver_sha256": driver.sha(Path(driver.__file__)),
                "image_sha256": image_hash, "config_sha256": image_hash}))
            (base / "config-before.sha256").write_text(digest + "  /etc/config/network\n")
            (base / "protected-before.sha256").write_text(digest + "  /etc/shadow\n")
            commands = []

            def remote(arguments, **_):
                self.assertEqual(arguments[0], "ssh")
                command = arguments[-1]
                commands.append(command)
                self.assertNotIn("sysupgrade", command)
                self.assertNotIn("reboot", command)
                if command == "cat /proc/sys/kernel/random/boot_id":
                    output = new_boot
                elif command == "cat /usr/share/owrt-control-plane/release.json":
                    output = json.dumps(manifest)
                elif command.startswith("set -eu\nsha256sum"):
                    names = ("procd", "ubusd", "netifd", "rpcd", "logd", "uhttpd", "dnsmasq")
                    if odhcpd:
                        self.assertIn("uhttpd odhcpd;", command)
                        names += ("odhcpd",)
                    output = "\n".join(name + " " + digest for name in names)
                elif command.startswith("sha256sum "):
                    output = "\n".join(digest + "  " + path for path in command.split()[1:])
                elif command == "ubus -S -t 3 call luci getMountPoints":
                    output = '{"result": []}'
                elif command.startswith(("set -eu\nfor s", "printf %s ", "/bin/sh /root/owrt-native-trial/native_trial_guard.sh confirm ")):
                    output = ""
                else:
                    self.fail("unhandled SSH command: " + command)
                return subprocess.CompletedProcess(arguments, 0, output, "")

            clock = iter(range(0, 2000, 100))
            argv = [driver.__file__, "observe", directory, "--previous-boot-id", old_boot, "--label", "normal-reboot"]
            with patch("sys.argv", argv), patch.object(driver.subprocess, "run", side_effect=remote), \
                    patch.object(driver.subprocess, "Popen", side_effect=AssertionError("observe attempted to launch an upgrade")), \
                    patch.object(driver, "probe", return_value={"boot_id": new_boot}), \
                    patch.object(driver, "dnsmasq_runtime", return_value=[{"sha256": digest}]), \
                    patch.object(driver.time, "monotonic", side_effect=lambda: next(clock)), \
                    patch.object(driver.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
                driver.main()
            result = json.loads((base / "result-normal-reboot.json").read_text())
            self.assertEqual(result["boot_id"], new_boot)
            self.assertGreaterEqual(result["continuous_client_health_s"], 180)
            self.assertTrue(any(" confirm private-token " + new_boot in command for command in commands))
            self.assertFalse((base / "ACTIVATION_STARTED").exists())


class RuntimeIdentity(unittest.TestCase):
    digest, ujail = "a" * 64, "b" * 64

    def collect(self, count=1, fault=None):
        instances = {str(number): {"running": True, "jail": {"name": "dnsmasq"},
                     "pid": 40 + number, "command": ["/usr/sbin/dnsmasq", "-C", f"/var/etc/dnsmasq.{number}"]}
                     for number in range(1, count + 1)}

        def stat(pid, parent, start):
            return f"{pid} (process name) " + " ".join(["S", str(parent)] + ["0"] * 17 + [str(start)]) + "\n"

        def remote(command, **_):
            if command.startswith("ubus "):
                return json.dumps({"dnsmasq": {"instances": instances}})
            if "for process in /proc/" in command:
                total = count - 1 if fault == "missing-instance" else count
                return "\n".join(f"{100 + number} {self.digest}" for number in range(1, total + 1))
            pid = int(re.search(r"^pid=(\d+)$", command, re.MULTILINE).group(1))
            number, parent = pid - 100, pid - 60
            argv = instances[str(number)]["command"][:]
            if fault == "wrong-argv":
                argv[-1] = "/unrelated.conf"
            fields = [stat(pid, parent, 900), "/host/fixture/usr/sbin/dnsmasq\n",
                      self.digest + f" /proc/{pid}/exe\n", "\0".join(argv) + "\0",
                      f"Name:\tdnsmasq\nPPid:\t{parent}\n", stat(parent, 1, 800), "/sbin/ujail\n",
                      ("c" * 64 if fault == "wrong-parent" else self.ujail) + f" /proc/{parent}/exe\n",
                      "/sbin/ujail\0", stat(parent, 1, 800),
                      stat(pid, parent, 901 if fault == "reused-pid" else 900), self.digest + f" /proc/{pid}/exe\n"]
            return "\x1c".join(fields)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runtime.jsonl"
            try:
                result = driver.dnsmasq_runtime(remote, self.digest, self.ujail, path)
            except RuntimeError:
                self.assertFalse(json.loads(path.read_text())["passed"])
                raise
            self.assertTrue(json.loads(path.read_text())["passed"])
            return result

    def test_jail_path_does_not_replace_executable_identity(self):
        rows = self.collect()
        self.assertEqual(rows[0]["exe"], "/host/fixture/usr/sbin/dnsmasq")
        self.assertEqual(rows[0]["parent_pid"], 41)

    def test_every_instance_is_verified(self):
        self.assertEqual({row["instance"] for row in self.collect(count=2)}, {"1", "2"})
        with self.assertRaises(RuntimeError):
            self.collect(count=2, fault="missing-instance")

    def test_wrong_parent_argv_and_reused_pid_fail_closed(self):
        for fault in ("wrong-parent", "wrong-argv", "reused-pid"):
            with self.subTest(fault=fault), self.assertRaises(RuntimeError):
                self.collect(fault=fault)


class NativeProductionProbe(unittest.TestCase):
    def setUp(self):
        import r84_device_probe as health
        self.health = health
        self.manifest = {
            "deployment_layout": "native-ten", "source_commit": "a" * 40,
            "components": {name: {"path": path, "rust_sha256": f"{number:064x}",
                                   "stock_sha256": "b" * 64}
                           for number, (name, path) in enumerate(health.NATIVE_PATHS.items(), 1)},
        }
        self.release = {**self.manifest, "layout": "native-ten"}
        self.instances = {"cfg": {"running": True, "jail": {"name": "dnsmasq"}, "pid": 40,
                                  "command": ["/usr/sbin/dnsmasq", "-C", "/private/config"]}}
        self.rows = []
        for number, name in enumerate(("procd", "ubusd", "netifd", "rpcd", "logd", "httpd"), 1):
            pid = 1 if name == "procd" else 10 + number
            self.rows.append([pid, 0 if pid == 1 else 1, 100 + number,
                              self.manifest["components"][name]["rust_sha256"]])
        self.rows.extend([[40, 1, 400, health.STOCK_UJAIL_SHA256],
                          [41, 40, 410, self.manifest["components"]["dnsmasq"]["rust_sha256"]]])
        self.calls = []
        self.snapshots = 0
        self.fault = None

    def test_eleven_manifest_requires_exact_odhcpd_path_and_complete_set(self):
        manifest = {**self.manifest, "deployment_layout": "native-eleven",
                    "components": {**self.manifest["components"],
                                   "odhcpd": {"path": "/usr/sbin/odhcpd", "rust_sha256": "c" * 64,
                                              "stock_sha256": "d" * 64}}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(manifest))
            self.assertEqual(len(self.health.load_native_manifest(path)[0]["components"]), 11)
            for bad in ("wrong-path", "missing", "old-layout", "unknown-layout"):
                changed = json.loads(json.dumps(manifest))
                if bad == "wrong-path":
                    changed["components"]["odhcpd"]["path"] = "/sbin/odhcpd"
                elif bad == "missing":
                    del changed["components"]["odhcpd"]
                else:
                    changed["deployment_layout"] = "native-ten" if bad == "old-layout" else "native-twelve"
                path.write_text(json.dumps(changed))
                with self.subTest(bad=bad), self.assertRaises(RuntimeError):
                    self.health.load_native_manifest(path)

    def test_client_egress_requires_both_families_on_the_lan(self):
        answers = ["example.com. 60 IN A 192.0.2.1", "example.com. 60 IN AAAA 2001:db8::1"]
        response = subprocess.CompletedProcess([], 0, b"<title>Example Domain</title>", b"")
        with patch.object(self.health, "run", side_effect=answers) as dns, \
                patch.object(self.health.subprocess, "run", return_value=response) as https:
            result = self.health.client_egress("en0", "192.168.1.100")
        self.assertTrue(all(result.values()))
        self.assertEqual(len(result), 5)
        self.assertEqual(result["client_dns_transport"], "tcp")
        self.assertEqual(dns.call_count, 2)
        self.assertTrue(all("+tcp" in call.args[0] for call in dns.call_args_list))
        for family, call in zip(("-4", "-6"), https.call_args_list):
            argv = call.args[0]
            self.assertIn(family, argv)
            self.assertEqual(argv[argv.index("--interface") + 1], "en0")
            self.assertEqual(argv[argv.index("--noproxy") + 1], "*")
            self.assertNotIn("-k", argv)

    def test_client_egress_rejects_missing_dns_and_false_https_success(self):
        with patch.object(self.health, "run", return_value=""):
            with self.assertRaisesRegex(RuntimeError, "DNS answer"):
                self.health.client_egress("en0", "192.168.1.100", False)
        for code, body in ((7, b"Example Domain"), (0, b"captive portal")):
            with patch.object(self.health, "run", return_value="example.com. 60 IN A 192.0.2.1"), \
                    patch.object(self.health.subprocess, "run", return_value=subprocess.CompletedProcess([], code, body, b"")):
                with self.assertRaisesRegex(RuntimeError, "HTTPS"):
                    self.health.client_egress("en0", "192.168.1.100", False)

    def remote(self, host, command, **_):
        import shlex
        self.assertEqual(host, "fixture-host")
        self.calls.append(command)
        self.assertNotIn("stack-switch", command)
        self.assertNotIn("native_trial_guard", command)
        if command.startswith("sha256sum "):
            hashes = {prefix + item["path"]: item["rust_sha256"]
                      for item in self.manifest["components"].values() for prefix in ("", "/rom")}
            hashes.update({prefix + "/sbin/ujail": self.health.STOCK_UJAIL_SHA256 for prefix in ("", "/rom")})
            if self.fault == "installed":
                hashes["/sbin/procd"] = "f" * 64
            return "\n".join(hashes[path] + "  " + path for path in shlex.split(command)[1:])
        if command.startswith("cat /usr/share/"):
            return json.dumps(self.release)
        if command.startswith("ubus "):
            return json.dumps({"dnsmasq": {"instances": self.instances}})
        if command.startswith("set -eu\nfor process"):
            self.snapshots += 1
            rows = [row[:] for row in self.rows]
            if self.fault == "reused" and self.snapshots == 2:
                rows[-1][2] += 1
            return "\n".join(" ".join(map(str, row)) for row in rows)
        if command == "cat /proc/41/cmdline":
            return "\0".join(self.instances["cfg"]["command"]) + "\0" if self.fault != "argv" else "wrong\0"
        self.fail("unexpected native read: " + command)

    def identity(self):
        with patch.object(self.health, "ssh", side_effect=self.remote):
            return self.health.native_identity("fixture-host", self.manifest)

    def test_native_rows_bind_ten_components_and_ignore_isolated_names(self):
        # Same executable bytes in isolated siblings are not production.
        self.rows.extend([[99, 98, 900, self.manifest["components"]["rpcd"]["rust_sha256"]],
                          [101, 100, 1000, self.manifest["components"]["dnsmasq"]["rust_sha256"]]])
        rows = [line.split() for line in self.identity().splitlines()]
        self.assertEqual({row[0] for row in rows}, set(self.health.NATIVE_PATHS))
        self.assertEqual(len(rows), 10)
        self.assertEqual(next(row[1:3] for row in rows if row[0] == "procd"), ["1", "101"])
        self.assertEqual(next(row[1:3] for row in rows if row[0] == "dnsmasq"), ["41", "410"])
        for row in rows:
            if row[0] in ("uci", "fw4", "reload-config"):
                self.assertEqual(row[1:3], ["-", "-"])
        self.assertEqual(self.snapshots, 2)

    def test_wrong_installed_release_argv_and_reused_pid_fail(self):
        for fault in ("installed", "argv", "reused"):
            with self.subTest(fault=fault):
                self.fault, self.snapshots = fault, 0
                with self.assertRaises(RuntimeError):
                    self.identity()
        self.fault = None
        self.release["source_commit"] = "c" * 40
        with self.assertRaisesRegex(RuntimeError, "release"):
            self.identity()

    def test_duplicate_production_daemon_and_wrong_dns_parent_fail(self):
        self.rows.append([22, 1, 222, self.manifest["components"]["rpcd"]["rust_sha256"]])
        with self.assertRaisesRegex(RuntimeError, "one production process"):
            self.identity()
        self.rows.pop()
        self.rows[-2][3] = "f" * 64
        with self.assertRaisesRegex(RuntimeError, "production ujail"):
            self.identity()

    def test_two_dns_children_are_not_silently_picked(self):
        self.rows.append([42, 40, 420, self.manifest["components"]["dnsmasq"]["rust_sha256"]])
        with self.assertRaisesRegex(RuntimeError, "one DNS child"):
            self.identity()

    def test_local_native_manifest_requires_exact_paths_and_components(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(self.manifest))
            manifest, digest = self.health.load_native_manifest(path)
            self.assertEqual(manifest, self.manifest)
            self.assertEqual(digest, driver.sha(path))
            del self.manifest["components"]["dnsmasq"]
            path.write_text(json.dumps(self.manifest))
            with self.assertRaisesRegex(RuntimeError, "component set differs"):
                self.health.load_native_manifest(path)

    def test_native_runner_rejects_missing_guard_and_rom_before_ssh(self):
        import sys
        sys.path.insert(0, str(Path(__file__).parent / "benchmark"))
        import run_candidate
        base = [run_candidate.__file__, "candidate", "out", "--interface", "en0", "--stack", "native"]
        for extra in ([], ["--native-manifest", "unused", "--reference-root", "/stock"],
                      ["--native-manifest", "unused", "--guard", "guard", "--reference-root", "/stock"],
                      ["--native-manifest", "unused", "--guard", "guard", "--reference-root", "/rom/",
                       "--health-guard-root", "/tmp/dnsmasq-perf-core"]):
            with self.subTest(extra=extra), patch("sys.argv", base + extra), \
                    patch.object(run_candidate.subprocess, "run", side_effect=AssertionError("unexpected process")), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                run_candidate.main()
            self.assertEqual(caught.exception.code, 2)

    def test_native_runner_uses_configured_tools_and_stock_root_without_switching(self):
        self.native_runner_fixture()

    def test_native_guard_failure_archives_before_raising_and_never_prunes(self):
        self.native_runner_fixture(fail_workload=True)

    def native_runner_fixture(self, fail_workload=False):
        import hashlib
        import shlex
        import sys
        sys.path.insert(0, str(Path(__file__).parent / "benchmark"))
        import run_candidate

        class WorkloadReached(BaseException):
            pass

        identity = self.identity()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            candidate, guard, manifest = (base / name for name in ("candidate", "guard", "manifest.json"))
            candidate.write_bytes(b"candidate"); guard.write_bytes(b"guard")
            manifest.write_text(json.dumps(self.manifest))
            sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
            tools = {"ns-exec": "c" * 64, "owrt-benchmark": "d" * 64}
            comparison = {"components": {name: {"original": {"sha256": item["stock_sha256"]},
                                                "rust": {"sha256": item["rust_sha256"]}}
                                          for name, item in self.manifest["components"].items() if name != "dnsmasq"},
                          "tools": {name: {"sha256": value} for name, value in tools.items()}}
            health = {"boot_id": "boot", "mode": "native", "native_identity": identity,
                      "native_manifest_sha256": sha(manifest)}
            commands = []

            def run(arguments, **options):
                if arguments[0] == "scp":
                    return subprocess.CompletedProcess(arguments, 0, b"", b"")
                self.assertEqual(arguments[0], "ssh")
                command = arguments[-1]
                commands.append(command)
                self.assertNotIn("stack-switch", command)
                self.assertNotIn("/root/r84", command)
                if command.startswith('set -eu\ntest ! -L /tmp/dnsmasq-perf-core'):
                    value = '55 66\n'
                elif command.startswith('tar -czf - -C '):
                    import tarfile
                    with tarfile.open(fileobj=options['stdout'], mode='w:gz') as archive:
                        data = b'failed window retained\n'
                        info = tarfile.TarInfo('partial.txt'); info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
                    return subprocess.CompletedProcess(arguments, 0)
                elif command.startswith('cd ') and 'find . -type f' in command:
                    value = hashlib.sha256(b'failed window retained\n').hexdigest() + '  ./partial.txt\n'
                elif command.startswith('cat ') and command.endswith('.identity'):
                    value = '77 88\n'
                elif command.startswith("cat ") and command.endswith("/manifest.json"):
                    self.assertIn(command, ("cat /host-tools/manifest.json", "cat /v021/manifest.json"))
                    value = json.dumps(comparison)
                elif command == "readlink -f /stock-root":
                    value = "/stock-root"
                elif command == "sha256sum /etc/config/*":
                    value = "same config"
                elif command.startswith("sha256sum "):
                    values = []
                    for path in shlex.split(command)[1:]:
                        name = Path(path).name
                        if path.startswith("/stock-root/"):
                            digest = "b" * 64
                        elif name == "guard":
                            digest = sha(guard)
                        elif name == "isolated.sh":
                            digest = sha(Path(run_candidate.__file__).with_name("isolated.sh"))
                        elif name == "owned_group.sh":
                            digest = sha(Path(run_candidate.__file__).with_name("owned_group.sh"))
                        elif name == "procd-rs":
                            digest = sha(candidate)
                        else:
                            digest = tools[name]
                        values.append(digest + "  " + path)
                    value = "\n".join(values)
                elif command.startswith("/host-tools/bins/owrt-benchmark snapshot "):
                    value = "{}"
                elif command.startswith(("test ! -e ", "cp ", "cat /proc/")):
                    value = ""
                else:
                    self.fail("unexpected collector operation: " + command)
                return subprocess.CompletedProcess(arguments, 0, value.encode(), b"")

            def workload(*args):
                self.assertTrue(args[2].startswith('OWRT_BENCH_GUARD='))
                self.assertIn('/isolated.sh /stock-root ', args[2])
                if fail_workload:
                    raise RuntimeError('fixture guard died')
                raise WorkloadReached()

            argv = [run_candidate.__file__, str(candidate), str(base / "out"), "--component", "procd",
                    "--interface", "en0", "--stack", "native", "--native-manifest", str(manifest),
                    "--host-bundle", "/host-tools", "--baseline-bundle", "/v021", "--baseline-label", "v021",
                    "--reference-root", "/stock-root", "--guard", str(guard), "--sides", "stock", "candidate",
                    "--schedule", "two-side-balanced", "--repeats", "2",
                    "--health-guard-root", "/tmp/dnsmasq-perf-core"]
            with patch("sys.argv", argv), patch.object(run_candidate, "probe", return_value=health), \
                    patch.object(run_candidate, "native_identity", return_value=identity), \
                    patch.object(run_candidate.subprocess, "run", side_effect=run), \
                    patch.object(run_candidate, 'health_guarded_window', side_effect=workload), \
                    contextlib.redirect_stdout(io.StringIO()), self.assertRaises(RuntimeError if fail_workload else WorkloadReached):
                run_candidate.main()
            plan = json.loads((base / "out/settings.json").read_text())
            self.assertEqual(plan["reference_root"], "/stock-root")
            self.assertEqual(plan["host_bundle"], "/host-tools")
            self.assertEqual(plan["native_manifest_sha256"], sha(manifest))
            self.assertEqual(len(json.loads((base / "out/reference-identities.json").read_text())), 10)
            if fail_workload:
                window = base / 'out/01-stock'
                self.assertEqual((window / 'raw/partial.txt').read_text(), 'failed window retained\n')
                result = json.loads((window / 'result.json').read_text())
                self.assertTrue(result['remote_evidence_retained'])
                self.assertTrue(any('fixture guard died' in value for value in result['failures']))
                self.assertFalse(any(command.startswith('rm -rf') for command in commands))
                self.assertFalse((window / 'COMPLETE').exists())


if __name__ == "__main__":
    unittest.main()
