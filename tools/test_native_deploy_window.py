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
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            old_boot = "11111111-1111-1111-1111-111111111111"
            new_boot = "22222222-2222-2222-2222-222222222222"
            digest = "a" * 64
            paths = {name: "/sbin/" + name for name in
                     ("procd", "ubusd", "netifd", "rpcd", "logd", "uci", "fw4")}
            paths.update({"httpd": "/usr/sbin/uhttpd", "dnsmasq": "/usr/sbin/dnsmasq",
                          "reload-config": "/sbin/reload_config"})
            manifest = {"deployment_layout": "native-ten", "source_commit": "a" * 40,
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
                    output = "\n".join(name + " " + digest for name in
                                       ("procd", "ubusd", "netifd", "rpcd", "logd", "uhttpd", "dnsmasq"))
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


if __name__ == "__main__":
    unittest.main()
