#!/usr/bin/env python3
"""C-only lease_update_from_configs reverse-host startup/HUP baseline.

Uses the complete exact C daemon in a private namespace. No DHCP packets,
replacement handlers or Rust-generated expectations are used. File and first
post-reload DNS observations are retained; external timing does not prove the
internal ordering of two statements in one C event handler.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

from dns_service_probe import query, semantics
from dhcp_lease_lifecycle import rows as lease_rows

REFERENCE_SHA = "bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431"
ADDRESS = "127.0.0.40"
INITIAL = f"0 02:00:00:00:00:01 {ADDRESS} oldname *\n".encode()


def fixtures():
    # Each step is (stage, static-host name or None, expected persisted lease name).
    return [
        ("startup-short", 15353, "", [("startup", "fromhosts", "fromhosts")]),
        ("startup-domain", 15353, "", [("startup", "fromhosts.pool.test", "fromhosts")]),
        ("startup-wrong-domain", 15353, "", [("startup", "fromhosts.other.test", "oldname")]),
        ("startup-invalid-host", 15353, "", [("startup", "_invalid", "oldname")]),
        ("startup-no-host", 15353, "", [("startup", None, "oldname")]),
        ("configured-wins", 15353, "dhcp-host=02:00:00:00:00:01,127.0.0.40,configured,600s\n",
         [("startup", "fromhosts", "configured"), ("hup-change", "renamed", "configured")]),
        ("configured-address-mismatch", 15353, "dhcp-host=02:00:00:00:00:01,127.0.0.41,configured,600s\n",
         [("startup", "fromhosts", "fromhosts")]),
        ("hup-rename", 15353, "",
         [("startup", "fromhosts", "fromhosts"), ("hup-change", "renamed.pool.test", "renamed")]),
        ("hup-remove", 15353, "",
         [("startup", "fromhosts", "fromhosts"), ("hup-remove", None, "fromhosts")]),
        ("port-zero", 0, "",
         [("startup", "fromhosts", "oldname"), ("hup-change", "renamed.pool.test", "oldname")]),
    ]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def wait_until(process, predicate, label, seconds=3):
    deadline = time.monotonic() + seconds
    while not predicate():
        if process.poll() is not None:
            raise RuntimeError(f"daemon exited before {label}: {process.returncode}")
        if time.monotonic() >= deadline:
            raise TimeoutError(label)
        time.sleep(.005)


def dns(process, folder, stage, host, kind):
    packet = query(host, kind)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(2)
        client.sendto(packet, ("127.0.0.1", 15353))
        answer = client.recv(65535)
    assert process.poll() is None
    stem = folder / f"{stage}-{host}-{kind}"
    stem.with_suffix(stem.suffix + ".query").write_bytes(packet)
    stem.with_suffix(stem.suffix + ".answer").write_bytes(answer)
    return semantics(answer)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--inject-error", action="store_true")
    args = parser.parse_args()
    assert os.environ.get("DNSMASQ_TEST_ISOLATED") == "1" and os.geteuid() == 0
    assert not Path("/etc/openwrt_release").exists()
    assert sorted(name for _, name in socket.if_nameindex()) == ["lo"]
    reference = args.reference_build.resolve()
    binary = reference / "dnsmasq/dnsmasq"
    assert digest(binary) == REFERENCE_SHA, "exact reference ELF mismatch"
    out = args.out.resolve()
    assert "private" in out.parts
    out.mkdir(parents=True, exist_ok=False)
    # The matching CLI supplies a synchronous completion barrier after a
    # logged reload marker, including port=0 where no DNS reply is possible.
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=0755", "reverse-lifecycle", "/run"], check=True)
    Path("/run/ubus").mkdir()
    cases = fixtures()
    assert len(cases) == 10 and sum(len(case[3]) for case in cases) == 14
    (out / "plan.json").write_text(json.dumps(cases, indent=2) + "\n")
    checks, observations, failures = [], [], []
    def check(label, actual, expected):
        checks.append({"case": label, "actual": actual, "expected": expected, "pass": actual == expected})
    env = dict(os.environ, LD_LIBRARY_PATH=str(reference / "deps/lib"))
    with (out / "ubusd.log").open("wb") as stream:
        bus = subprocess.Popen([str(reference / "deps/sbin/ubusd"), "-s", "/run/ubus/ubus.sock"],
                               stdout=stream, stderr=subprocess.STDOUT, env=env)
    wait_until(bus, lambda: Path("/run/ubus/ubus.sock").exists(), "private ubusd")
    for label, port, extra, steps in cases:
        folder = out / label
        folder.mkdir()
        hosts, leases, config, log = [folder / name for name in ("hosts", "leases", "dnsmasq.conf", "daemon.log")]
        marker = folder / "dhcp-hosts"
        marker.write_text("# Empty source: a reload marker, never a hostname override.\n")
        leases.write_bytes(INITIAL)
        (folder / "initial.leases").write_bytes(INITIAL)
        config.write_text("no-resolv\nno-hosts\nno-ping\nlisten-address=127.0.0.1\n"
                          f"port={port}\naddn-hosts={hosts}\ndhcp-leasefile={leases}\n"
                          f"dhcp-hostsfile={marker}\nenable-ubus=reverse.lifecycle\n"
                          "domain=pool.test\nlocal-ttl=60\ndhcp-ttl=60\n"
                          "dhcp-range=127.0.0.10,127.0.0.50,255.0.0.0,600s\n" + extra)
        process = None
        try:
            for index, (stage, static_name, lease_name) in enumerate(steps):
                before = log.read_text().count("read " + str(marker)) if log.exists() else 0
                hosts.write_text("" if static_name is None else f"{ADDRESS} {static_name}\n")
                (folder / f"{stage}.hosts").write_bytes(hosts.read_bytes())
                if index == 0:
                    with log.open("wb") as stream:
                        process = subprocess.Popen([str(binary), "--keep-in-foreground", "--user=root", "--group=root",
                            "--log-facility=-", "--pid-file=" + str(folder / "pid"), "--conf-file=" + str(config)],
                            stdout=stream, stderr=subprocess.STDOUT, env=env)
                else:
                    process.send_signal(signal.SIGHUP)
                wait_until(process, lambda: log.read_text().count("read " + str(marker)) > before,
                           label + "-DHCP-source-read")
                barrier = subprocess.run([str(reference / "deps/bin/ubus"), "-s", "/run/ubus/ubus.sock",
                                          "call", "reverse.lifecycle", "metrics"],
                                         capture_output=True, env=env, timeout=3)
                (folder / f"{stage}.barrier").write_bytes(barrier.stdout)
                (folder / f"{stage}.barrier-error").write_bytes(barrier.stderr)
                barrier.check_returncode()
                answers = {}
                if port:
                    # Observe DNS and the file immediately after the verified
                    # completion barrier; no DHCP exchange changes either.
                    answers[lease_name] = dns(process, folder, stage, lease_name, 1)
                    first_file = lease_rows(leases)
                    for host in ("oldname", "oldname.pool.test", "fromhosts", "fromhosts.pool.test",
                                 "renamed", "renamed.pool.test", "configured", "configured.pool.test"):
                        if host not in answers:
                            answers[host] = dns(process, folder, stage, host, 1)
                    answers["ptr"] = dns(process, folder, stage, "40.0.0.127.in-addr.arpa", 12)
                    check(label + "-" + stage + "-live-short-name",
                          [record["data"] for record in answers[lease_name]["records"] if record["type"] == 1], [ADDRESS])
                else:
                    first_file = lease_rows(leases)
                file = lease_rows(leases)
                (folder / f"{stage}.leases").write_bytes(leases.read_bytes())
                expected_name = "deliberately-wrong" if args.inject_error and label == "startup-short" else lease_name
                check(label + "-" + stage + "-lease-name", [row["name"] for row in file], [expected_name])
                if port:
                    check(label + "-" + stage + "-first-DNS-file", first_file, file)
                check(label + "-" + stage + "-lease-identity",
                      [{key: value for key, value in row.items() if key != "name"} for row in file],
                      [{"expiry": 0, "mac": "02:00:00:00:00:01", "address": ADDRESS, "clid": "*"}])
                observations.append({"scenario": label, "stage": stage, "port": port, "lease_rows": file,
                                     "first_dns_file": first_file, "dns": answers})
        except Exception as error:
            failures.append({"scenario": label, "error": repr(error)})
            check(label + "-exception", repr(error), None)
        finally:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                        check(label + "-forced-kill", True, False)
                check(label + "-normal-exit", process.returncode, 0)
                check(label + "-released", Path(f"/proc/{process.pid}").exists(), False)
    bus.terminate()
    bus.wait(3)
    if len(observations) == 14 and not failures:
        assert len(checks) == 72, "frozen source-check count changed"
    frozen = out / "c-observations.json"
    frozen.write_text(json.dumps(observations, indent=2) + "\n")
    report = {"scope": __doc__, "reference_sha256": REFERENCE_SHA, "tool_sha256": digest(__file__),
              "observations_sha256": digest(frozen),
              "planned_steps": 14, "completed_steps": len(observations), "unexecuted": 14 - len(observations),
              "passed": sum(row["pass"] for row in checks), "failed": sum(not row["pass"] for row in checks),
              "checks": checks, "observations": observations, "failures": failures,
              "rust_compared": False, "DHCP_packets_sent": 0,
              "barrier": "empty DHCP hosts-file reread log, then synchronous ubus metrics",
              "ubusd_sha256": digest(reference / "deps/sbin/ubusd"),
              "ubus_cli_sha256": digest(reference / "deps/bin/ubus")}
    (out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key not in ("checks", "observations", "scope", "failures")}, indent=2))
    return bool(report["failed"] or report["unexecuted"])


if __name__ == "__main__":
    raise SystemExit(main())
