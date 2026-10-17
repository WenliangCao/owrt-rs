#!/usr/bin/env python3
"""Component experiment: exact image, frozen baselines, and candidate.

Physical use requires the already-authorized recovery gate. The production
stack stays active; each subject runs in the existing isolated harness. Every
download is checksummed before deleting its exact owned temporary directory.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import random
import shlex
import subprocess
import sys
import tarfile
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from r84_device_probe import load_native_manifest, native_identity, probe  # noqa: E402

ORDER = ("stock", "r84", "candidate", "candidate", "r84", "stock",
         "r84", "stock", "candidate", "candidate", "stock", "r84")
TWO_SIDE_BALANCED = ("stock", "candidate", "candidate", "stock")


def extra_baseline_records(elf_args, evidence_args, baseline_label):
    """Freeze original ELF/provenance identities without inventing a manifest."""
    def paths(items):
        result = {}
        for item in items:
            label, sep, path = item.partition("=")
            if not sep or not re.fullmatch(r"[a-z][a-z0-9_-]*", label) or label in ("stock", "candidate", "r84", baseline_label):
                raise ValueError("invalid extra baseline label: " + label)
            if label in result:
                raise ValueError("duplicate extra baseline label: " + label)
            result[label] = Path(path).resolve(strict=True)
        return result
    elfs, evidence = paths(elf_args), paths(evidence_args)
    if elfs.keys() != evidence.keys():
        raise ValueError("each extra baseline requires exactly one ELF and provenance JSON")
    records = {}
    for label, path in elfs.items():
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        raw = evidence[label].read_bytes()
        provenance = json.loads(raw)
        if not isinstance(provenance, dict) or provenance.get("subject_sha256") != sha:
            raise ValueError("extra baseline provenance subject_sha256 mismatch: " + label)
        records[label] = {"subject_sha256": sha, "elf_path": str(path),
                          "evidence_path": str(evidence[label]),
                          "evidence_sha256": hashlib.sha256(raw).hexdigest(), "provenance": provenance}
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--component", choices=("httpd", "rpcd", "procd", "ubusd", "netifd",
                                                "uci", "reload-config", "logd", "fw4"), default="httpd")
    parser.add_argument("output", type=Path)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--access", choices=("wired", "wifi"), default="wifi",
                        help="management path recorded with the measurements; both are authorized")
    parser.add_argument("--host", default="openwrt")
    parser.add_argument("--stack", choices=("rust", "stock", "native"), default="rust",
                        help="production stack the device must be running (verified, never switched)")
    parser.add_argument("--native-manifest", type=Path, help="local exact native release manifest for production identity")
    parser.add_argument("--host-bundle", default="/root/r84", help="verified host tools and comparison manifest")
    parser.add_argument("--reference-root", help="exact stock rootfs; defaults to /rom only in legacy modes")
    parser.add_argument("--baseline-bundle", default="/root/r84",
                        help="frozen comparison bundle on the router, including manifest.json")
    parser.add_argument("--baseline-label", default="r84", help="evidence label for that frozen bundle")
    parser.add_argument("--extra-baseline", action="append", default=[], metavar="LABEL=ELF",
                        help="additional historical original ELF; requires random-blocks, --bench and matching evidence")
    parser.add_argument("--extra-baseline-evidence", action="append", default=[], metavar="LABEL=JSON",
                        help="provenance JSON with subject_sha256; records diagnostic/build gaps without claiming a formal manifest")
    parser.add_argument("--cpus", help="optional fixed taskset CPU list for every isolated subject/client")
    parser.add_argument("--repeats", type=int, default=4)
    parser.add_argument("--schedule", choices=("default", "two-side-balanced", "three-side-sequential", "calibration", "random-blocks"), default="default",
                        help="default interleaving, stock/candidate ABBA, or C then baseline then candidate; --repeats is windows per side for three-side-sequential")
    parser.add_argument("--seed", type=int, help="frozen seed for independent random complete comparison blocks")
    parser.add_argument("--guard", type=Path, help="router-side lifetime guard for each namespace (600 seconds)")
    parser.add_argument("--iterations", type=int, default=10000)
    parser.add_argument("--resume", action="store_true",
                        help="continue an interrupted collection with the same owned remote directory and identities")
    parser.add_argument("--matrix", action="store_true", help="expanded component workloads, including four clients")
    parser.add_argument("--exec-resource-probe", type=Path,
                        help="separate wait4 lifecycle probe for UCI/reload-config; never included in timing samples")
    parser.add_argument("--exec-task-probe", type=Path,
                        help="separate task lifecycle probe for reload-config; diagnostic only")
    parser.add_argument("--reload-packages", type=int, choices=(4, 24, 64, 128), default=4)
    parser.add_argument("--reload-workloads", nargs="+", choices=("first_baseline", "unchanged_config", "single_change", "multi_change", "comment_only"))
    parser.add_argument("--reload-warmup", type=int, default=5)
    parser.add_argument("--httpd-workloads", nargs="+", help="explicit subset of the HTTP matrix")
    parser.add_argument("--rpcd-workloads", nargs="+", help="explicit RPCD matrix lanes, including targeted UCI/ACL/LuCI queries")
    parser.add_argument("--procd-workloads", nargs="+", help="explicit procd query lanes; service_list_instance_fields is opt-in")
    parser.add_argument("--procd-warmup", type=int, default=20)
    parser.add_argument("--fw4-workloads", nargs="+", choices=("print", "check"),
                        help="fw4 command subset; defaults to print check")
    parser.add_argument("--fw4-count", type=int,
                        help="fw4 measured calls per command; defaults to max(iterations / 100, 1)")
    parser.add_argument("--fw4-warmup", type=int, default=3)
    parser.add_argument("--fw4-fixture", type=Path,
                        help="private firewall UCI file; requires --bench for private bundles")
    parser.add_argument("--netifd-scale", type=int, choices=(32, 64, 128), default=32)
    parser.add_argument("--netifd-fixture", type=Path, help="private wireless config, schema, stub and exact expected reply")
    parser.add_argument("--netifd-event-contracts", type=Path,
                        help="frozen stock.json, <baseline-label>.json, candidate.json event output contracts")
    parser.add_argument("--netifd-workloads", nargs="+", help="explicit subset of the netifd matrix")
    parser.add_argument("--netifd-warmup", type=int, default=20)
    parser.add_argument("--memory-probe", type=Path,
                        help="separate diagnostic binary with http-resident mode; measure 64 held connections only")
    parser.add_argument("--rpc-client-probe", type=Path,
                        help="separate diagnostic client: compare repeated JSON decoding with complete wire-byte validation")
    parser.add_argument("--sides", nargs="+", choices=("stock", "r84", "candidate"),
                        default=["stock", "r84", "candidate"])
    parser.add_argument("--bench", type=Path,
                        help="benchmark client uploaded into every selected temporary bundle")
    parser.add_argument("--extended", action="store_true",
                        help="ubusd: registration/event lanes and normalized daemon start")
    args = parser.parse_args()
    native_manifest = None
    native_manifest_sha256 = None
    if args.stack == "native":
        if not args.native_manifest or not args.guard or not args.reference_root:
            parser.error("native requires --native-manifest, --guard and an explicit --reference-root")
        if args.reference_root.rstrip("/") == "/rom":
            parser.error("native /rom contains Rust; --reference-root must be the exact stock rootfs")
        try:
            native_manifest, native_manifest_sha256 = load_native_manifest(args.native_manifest)
        except (OSError, ValueError, RuntimeError, TypeError, KeyError) as exc:
            parser.error(str(exc))
    elif args.native_manifest:
        parser.error("--native-manifest requires --stack native")
    args.reference_root = args.reference_root or "/rom"
    for path in (args.host_bundle, args.reference_root):
        if not path.startswith("/") or any(c in path for c in ("\0", "\n", "\r")):
            parser.error("host bundle and reference root must be absolute paths")
    if not 1 <= args.repeats <= 64:
        parser.error("repeats must be in 1..64")
    if args.schedule in ("default", "two-side-balanced") and args.repeats not in (2, 4):
        parser.error("legacy schedules require 2 or 4 repeats")
    if args.schedule in ("calibration", "random-blocks") and not args.guard:
        parser.error("new experiments require a router-side lifetime guard")
    if (args.schedule == "random-blocks") != (args.seed is not None):
        parser.error("--seed is required only for random-blocks")
    if not re.fullmatch(r"[a-z][a-z0-9_-]*", args.baseline_label) or args.baseline_label in ("stock", "candidate"):
        parser.error("invalid baseline label")
    if not args.baseline_bundle.startswith("/") or (args.cpus and not re.fullmatch(r"[0-9,-]+", args.cpus)):
        parser.error("baseline path must be absolute; CPU list must be numeric")
    try:
        extra_baselines = extra_baseline_records(args.extra_baseline, args.extra_baseline_evidence,
                                                 args.baseline_label)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    if extra_baselines and (args.schedule != "random-blocks" or not args.bench or args.netifd_event_contracts):
        parser.error("extra baselines require random-blocks and --bench; netifd event contracts are not supported")
    if args.iterations <= 0:
        parser.error("iterations must be positive")
    if args.schedule == "calibration":
        if args.sides != ["candidate"]:
            parser.error("calibration requires exactly --sides candidate")
    elif len(set(args.sides)) != len(args.sides) or not {"stock", "candidate"}.issubset(args.sides):
        parser.error("sides must include stock and candidate, without duplicates")
    if args.component != "httpd" and args.memory_probe:
        parser.error("held-connection memory currently requires HTTPD")
    if args.matrix and args.component not in ("httpd", "rpcd", "procd", "ubusd", "netifd", "uci", "reload-config"):
        parser.error("expanded matrix is not defined for this component")
    if args.exec_resource_probe and (args.component not in ("uci", "reload-config") or not args.bench):
        parser.error("exec resource probe requires UCI/reload-config and --bench")
    if args.exec_task_probe and (args.component != "reload-config" or not args.bench):
        parser.error("exec task probe requires reload-config and --bench")
    if args.reload_workloads or args.reload_warmup != 5 or args.reload_packages != 4:
        if args.component != "reload-config" or not args.matrix:
            parser.error("reload workload/warmup controls require its matrix")
    if not 0 <= args.reload_warmup <= 100000:
        parser.error("reload warmup must be in 0..100000")
    if args.reload_workloads and len(set(args.reload_workloads)) != len(args.reload_workloads):
        parser.error("duplicate reload workload")
    if args.netifd_scale != 32 and (args.component != "netifd" or not args.matrix):
        parser.error("--netifd-scale requires a netifd matrix")
    if args.httpd_workloads:
        allowed = {"jsonrpc", "jsonrpc_c4", "jsonrpc_large", "jsonrpc_large_c4", "cgi", "cgi_c4"}
        allowed |= {name + suffix for name in ("static_512_dat", "static_16k_dat", "static_16k_css", "static_image_css", "static_64k_dat", "static_1m_dat") for suffix in ("_c1", "_c4")}
        if args.component != "httpd" or not args.matrix or len(set(args.httpd_workloads)) != len(args.httpd_workloads) or not set(args.httpd_workloads) <= allowed:
            parser.error("invalid HTTP matrix workload subset")
    if args.rpcd_workloads:
        lanes = ("uci_configs", "uci_get_network", "file_stat", "session_access", "uci_get_64",
                 "uci_get_authorized", "session_access_granted", "file_list", "session_access_64",
                 "uci_state_network", "uci_get_delta", "session_access_acl256", "luci_version", "luci_features", "luci_devices")
        allowed = {name + suffix for name in lanes for suffix in ("", "_c4")}
        if args.component != "rpcd" or not args.matrix or len(set(args.rpcd_workloads)) != len(args.rpcd_workloads) or not set(args.rpcd_workloads) <= allowed:
            parser.error("invalid RPCD matrix workload subset")
    if args.procd_workloads or args.procd_warmup != 20:
        if args.component != "procd" or not args.matrix:
            parser.error("procd workload/warmup controls require its matrix")
    if not 0 <= args.procd_warmup <= 100000:
        parser.error("procd warmup must be in 0..100000")
    if args.procd_workloads:
        allowed = {lane + suffix for lane in ("system_info", "service_list_32", "service_list_128", "service_list_named_128")
                   for suffix in ("", "_c4")} | {"service_list_instance_fields"}
        if len(set(args.procd_workloads)) != len(args.procd_workloads) or not set(args.procd_workloads) <= allowed:
            parser.error("invalid or duplicate procd workload")
    if args.fw4_workloads or args.fw4_count is not None or args.fw4_warmup != 3 or args.fw4_fixture:
        if args.component != "fw4":
            parser.error("fw4 controls require --component fw4")
    if args.fw4_workloads and len(set(args.fw4_workloads)) != len(args.fw4_workloads):
        parser.error("duplicate fw4 workload")
    if args.fw4_count is not None and args.fw4_count <= 0:
        parser.error("fw4 count must be positive")
    if not 0 <= args.fw4_warmup <= 100000:
        parser.error("fw4 warmup must be in 0..100000")
    fw4_fixture_hash = None
    if args.fw4_fixture:
        if not args.bench:
            parser.error("--fw4-fixture requires --bench for private bundles")
        if not args.fw4_fixture.is_file():
            parser.error("fw4 fixture must be a regular file")
        fw4_fixture_hash = hashlib.sha256(args.fw4_fixture.read_bytes()).hexdigest()
    fixture_hashes = {}
    if args.netifd_workloads or args.netifd_warmup != 20:
        if args.component != "netifd" or not args.matrix:
            parser.error("netifd workload/warmup controls require its matrix")
    if not 0 <= args.netifd_warmup <= 100000:
        parser.error("netifd warmup must be in 0..100000")
    if args.netifd_workloads:
        lanes = ["interface_dump", "lan_status", "device_status", "wireless_status", "device_status_all",
                 f"interface_dump_{args.netifd_scale}", f"interface_named_{args.netifd_scale}"]
        allowed = {name + suffix for name in lanes for suffix in ("", "_c4")} | {"events_static2", "reload_unchanged"}
        if len(set(args.netifd_workloads)) != len(args.netifd_workloads) or not set(args.netifd_workloads) <= allowed:
            parser.error("invalid or duplicate netifd workload")
    events = args.netifd_workloads == ["events_static2"]
    if args.netifd_workloads and "events_static2" in args.netifd_workloads and not events:
        parser.error("events_static2 requires its own fixture and separate run")
    if events != bool(args.netifd_event_contracts) or (events and (not args.bench or args.netifd_fixture)):
        parser.error("event lane requires --bench and --netifd-event-contracts, with no wireless fixture")
    event_contracts = {}
    if events:
        for side in ("stock", args.baseline_label, "candidate"):
            path = args.netifd_event_contracts / (side + ".json")
            contract = json.loads(path.read_text())
            if contract.get("schema") != 1 or set(contract.get("steps", {})) != {"lan-down", "lan-up", "wired-down", "wired-up"}:
                parser.error("invalid event contract: " + str(path))
            event_contracts[side] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                     "reference_subject_sha256": contract["reference_subject_sha256"]}
    if args.netifd_fixture:
        if args.component != "netifd" or not args.matrix or not args.bench:
            parser.error("--netifd-fixture requires a netifd matrix and --bench for private bundles")
        for name in ("wireless", "handler-schema.json", "mac80211.sh", "expected-wireless.json"):
            fixture_hashes[name] = hashlib.sha256((args.netifd_fixture / name).read_bytes()).hexdigest()
    if args.memory_probe and (args.matrix or "r84" in args.sides):
        parser.error("held-connection memory uses --sides stock candidate without --matrix")
    if args.rpc_client_probe and (args.component != "rpcd" or args.matrix or args.memory_probe or "r84" in args.sides):
        parser.error("RPC client diagnostics require rpcd, --sides stock candidate, and no other experiment mode")
    if args.bench and (args.memory_probe or args.rpc_client_probe):
        parser.error("--bench is not used with diagnostic probes")
    if args.bench and "r84" in args.sides and args.schedule not in ("three-side-sequential", "random-blocks"):
        parser.error("--bench with a frozen baseline requires three-side-sequential")
    if args.extended and args.component != "ubusd":
        parser.error("--extended is a ubusd mode")
    if args.schedule == "two-side-balanced" and args.sides != ["stock", "candidate"]:
        parser.error("two-side-balanced requires exactly --sides stock candidate")
    if args.schedule == "three-side-sequential" and args.sides != ["stock", "r84", "candidate"]:
        parser.error("three-side-sequential requires exactly --sides stock r84 candidate")
    if args.schedule == "random-blocks" and args.sides != ["stock", "r84", "candidate"]:
        parser.error("random-blocks requires base --sides stock r84 candidate; extra baselines are added automatically")
    component = args.component
    binary = "reload_config_rs" if component == "reload-config" else component + "-rs"
    if args.resume and (not (args.output / "STARTED").exists() or (args.output / "COMPLETE").exists()):
        parser.error("resume requires an existing, incomplete collection")
    args.output.mkdir(mode=0o700, parents=True, exist_ok=args.resume)
    out = args.output.resolve()
    (out / "STARTED").touch()
    ssh_args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=4", "-o",
                "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3", args.host]

    def ssh(command, timeout=30):
        return subprocess.run(ssh_args + [command], check=True, capture_output=True,
                              timeout=timeout).stdout

    def save(name, value):
        (out / name).write_text(json.dumps(value, indent=2) + "\n")

    def initial(name, value):
        if args.resume:
            assert json.loads((out / name).read_text()) == value, "resume settings changed: " + name
        else:
            save(name, value)

    def device_probe():
        health = probe(host=args.host, mode=args.stack, interface=args.interface,
                       native_manifest=args.native_manifest, host_bundle=args.host_bundle)
        if native_manifest is not None:
            assert health["native_manifest_sha256"] == native_manifest_sha256, "local native manifest changed"
        return health

    def production_identity():
        if native_manifest is not None:
            return native_identity(args.host, native_manifest).encode()
        return ssh("/bin/sh " + shlex.quote(args.host_bundle + "/stack-switch.sh") + " verify " + args.stack)

    current = device_probe()
    if args.resume:
        pre = json.loads((out / "health-before.json").read_text())
        assert current["boot_id"] == pre["boot_id"], "host rebooted before resume"
        save("resume-health-" + uuid.uuid4().hex[:12] + ".json", current)
    else:
        pre = current
        save("health-before.json", pre)
    identity = production_identity()
    if native_manifest is not None:
        assert current["native_identity"].encode() == identity, "native process changed after health probe"
        raw_manifest = args.native_manifest.read_bytes()
        assert hashlib.sha256(raw_manifest).hexdigest() == native_manifest_sha256
        if args.resume:
            assert (out / "native-manifest.json").read_bytes() == raw_manifest, "native manifest changed before resume"
        else:
            (out / "native-manifest.json").write_bytes(raw_manifest)
    config = ssh("sha256sum /etc/config/*")
    for name, value in (("host-running-hashes.txt", identity), ("config-before.sha256", config)):
        if args.resume:
            assert (out / name).read_bytes() == value, "host state changed before resume"
        else:
            (out / name).write_bytes(value)
    manifest = json.loads(ssh("cat " + shlex.quote(args.host_bundle + "/manifest.json")))
    baseline = json.loads(ssh("cat " + shlex.quote(args.baseline_bundle + "/manifest.json")))
    if native_manifest is not None:
        reference = ssh("readlink -f " + shlex.quote(args.reference_root)).decode().strip()
        assert reference.startswith("/") and reference != "/rom", "native reference resolves to /rom or is missing"
        expected_reference = {}
        for name, item in native_manifest["components"].items():
            expected = item["stock_sha256"]
            if name != "dnsmasq":
                assert manifest["components"][name]["original"]["sha256"] == expected, "comparison C identity differs from native stock reference"
            expected_reference[args.reference_root.rstrip("/") + item["path"]] = expected
        observed = dict(line.split(None, 1)[::-1] for line in ssh(
            "sha256sum " + " ".join(shlex.quote(path) for path in expected_reference)).decode().splitlines())
        assert observed == expected_reference, "reference root does not contain exact stock components"
        initial("reference-identities.json", expected_reference)
    hashes = {"stock": manifest["components"][component]["original"]["sha256"],
              args.baseline_label: baseline["components"][component]["rust"]["sha256"],
              "candidate": hashlib.sha256(args.candidate.read_bytes()).hexdigest()}
    hashes.update({label: record["subject_sha256"] for label, record in extra_baselines.items()})
    for name in ("ns-exec", "owrt-benchmark"):
        if baseline["tools"][name]["sha256"] != manifest["tools"][name]["sha256"]:
            raise RuntimeError("frozen baseline and host benchmark tools differ")
    tool_hashes = {name: manifest["tools"][name]["sha256"] for name in ("ns-exec", "owrt-benchmark")}
    if args.bench:
        tool_hashes["owrt-benchmark"] = hashlib.sha256(args.bench.read_bytes()).hexdigest()
    initial("subjects.json", hashes)
    initial("host-manifest.json", manifest)
    initial("baseline-manifest.json", baseline)
    initial("tool-identities.json", {**tool_hashes, "driver": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()})
    if args.schedule == "calibration":
        order = ("candidate",) * args.repeats
    elif args.schedule == "random-blocks":
        rng = random.Random(args.seed)
        order = tuple(side for _ in range(args.repeats)
                      for side in rng.sample(["stock", args.baseline_label, *extra_baselines, "candidate"], 3 + len(extra_baselines)))
    elif args.schedule == "two-side-balanced":
        order = TWO_SIDE_BALANCED * args.repeats
    elif args.schedule == "three-side-sequential":
        order = tuple(args.baseline_label if side == "r84" else side
                      for side in (("stock",) * args.repeats + ("r84",) * args.repeats
                                   + ("candidate",) * args.repeats))
    else:
        order = tuple(args.baseline_label if side == "r84" else side
                      for side in ORDER[:args.repeats * 3] if side in args.sides)
    initial("order.json", list(order))
    settings = {"component": component, "iterations": args.iterations, "matrix": args.matrix,
                           "stack": args.stack, "host_bundle": args.host_bundle, "reference_root": args.reference_root,
                           "held_connections": 64 if args.memory_probe else None,
                           "rpc_client_diagnostic": bool(args.rpc_client_probe),
                           "baseline_label": args.baseline_label, "baseline_bundle": args.baseline_bundle,
                           "cpu_affinity": args.cpus,
                           "management_access": args.access, "workload_transport": "namespace loopback"}
    if native_manifest_sha256:
        settings["native_manifest_sha256"] = native_manifest_sha256
    if args.schedule != "default":
        settings["schedule"] = args.schedule
    if args.seed is not None:
        settings["seed"] = args.seed
    if extra_baselines:
        settings["extra_baselines"] = extra_baselines
    if component == "procd":
        settings["procd_warmup"] = args.procd_warmup
        if args.procd_workloads:
            settings["procd_workloads"] = args.procd_workloads
    if args.httpd_workloads:
        settings["httpd_workloads"] = args.httpd_workloads
    if args.rpcd_workloads:
        settings["rpcd_workloads"] = args.rpcd_workloads
    if component == "reload-config":
        settings["reload_workloads"] = args.reload_workloads or (["first_baseline", "unchanged_config", "single_change", "multi_change", "comment_only"] if args.matrix else ["unchanged_config"])
        settings["reload_warmup"] = args.reload_warmup
        settings["reload_packages"] = args.reload_packages
        settings["reload_prepared_exec"] = True
    if component == "fw4":
        settings["fw4_workloads"] = args.fw4_workloads or ["print", "check"]
        settings["fw4_count"] = args.fw4_count if args.fw4_count is not None else max(args.iterations // 100, 1)
        settings["fw4_warmup"] = args.fw4_warmup
        if fw4_fixture_hash:
            settings["fw4_fixture_sha256"] = fw4_fixture_hash
    if component == "netifd":
        settings["netifd_scale"] = args.netifd_scale
        settings["netifd_warmup"] = args.netifd_warmup
        if args.netifd_workloads:
            settings["netifd_workloads"] = args.netifd_workloads
        if event_contracts:
            # Candidate must match C. Formal R89 retains its actual baseline
            # contract; source/output differences are reviewed before calibration.
            for side in event_contracts:
                expected_source = hashes[args.baseline_label] if side == args.baseline_label else hashes["stock"]
                assert event_contracts[side]["reference_subject_sha256"] == expected_source, "event contract source identity mismatch"
            assert (args.netifd_event_contracts / "candidate.json").read_bytes() == (args.netifd_event_contracts / "stock.json").read_bytes(), "candidate contract must match the frozen C contract"
            settings["netifd_event_contracts"] = event_contracts
        if fixture_hashes:
            settings["netifd_fixture_sha256"] = fixture_hashes
    if args.guard:
        settings["guard_sha256"] = hashlib.sha256(args.guard.read_bytes()).hexdigest()
        settings["namespace_timeout_seconds"] = 600
    if args.bench:
        settings["bench_sha256"] = tool_hashes["owrt-benchmark"]
    if args.exec_resource_probe:
        settings["exec_resource_probe_sha256"] = hashlib.sha256(args.exec_resource_probe.read_bytes()).hexdigest()
    if args.exec_task_probe:
        settings["exec_task_probe_sha256"] = hashlib.sha256(args.exec_task_probe.read_bytes()).hexdigest()
    if args.extended:
        settings["extended"] = True
    initial("settings.json", settings)
    script = Path(__file__).with_name("isolated.sh")
    if args.resume:
        collector = json.loads((out / "collector.json").read_text())
        remote = collector["remote"]
        assert re.fullmatch("/tmp/r85-" + component + "-[a-f0-9]{12}", remote)
        assert collector["harness_sha256"] == hashlib.sha256(script.read_bytes()).hexdigest()
        assert ssh("sha256sum " + remote + "/isolated.sh").decode().split()[0] == collector["harness_sha256"]
    else:
        remote = "/tmp/r85-" + component + "-" + uuid.uuid4().hex[:12]
        ssh("test ! -e " + remote + " && mkdir -p " + remote + "/bundle")
        save("collector.json", {"remote": remote, "harness_sha256": hashlib.sha256(script.read_bytes()).hexdigest()})
    bundle = remote + "/bundle"
    if args.guard:
        if not args.resume:
            subprocess.run(["scp", "-O", str(args.guard.resolve()), args.host + ":" + remote + "/guard"], check=True)
        assert ssh("sha256sum " + remote + "/guard").decode().split()[0] == settings["guard_sha256"]
    # With --bench, use the same uploaded client in every selected bundle.
    # Every historical side gets its own temporary bundle containing its
    # original ELF; historical source bundles remain untouched.
    stock_bundle = remote + "/stock-bundle" if args.bench else args.baseline_bundle + "/bins"
    baseline_bundle = remote + "/baseline-bundle" if args.bench and "r84" in args.sides else None
    extra_bundles = {label: remote + "/baseline-" + label for label in extra_baselines}
    if not args.resume:
        if args.bench:
            targets = [bundle, stock_bundle, *extra_bundles.values()]
            if baseline_bundle:
                targets.append(baseline_bundle)
            ssh("mkdir -p " + " ".join(shlex.quote(target) for target in targets)
                + " && " + " && ".join("cp " + shlex.quote(args.host_bundle + "/bins/ns-exec") + " " + shlex.quote(target) + "/"
                                       for target in targets))
            for target in targets:
                subprocess.run(["scp", "-O", str(args.bench.resolve()), args.host + ":" + target + "/owrt-benchmark"], check=True)
            if baseline_bundle:
                ssh("cp " + shlex.quote(args.baseline_bundle + "/bins/" + binary)
                    + " " + shlex.quote(baseline_bundle + "/" + binary))
        else:
            ssh("cp " + " ".join(shlex.quote(args.host_bundle + "/bins/" + name)
                                 for name in ("ns-exec", "owrt-benchmark")) + " " + bundle + "/")
        for label, target in extra_bundles.items():
            subprocess.run(["scp", "-O", extra_baselines[label]["elf_path"],
                            args.host + ":" + target + "/" + binary], check=True)
        for local, target in ((args.candidate, bundle + "/" + binary), (script, remote + "/isolated.sh")):
            subprocess.run(["scp", "-O", str(local.resolve()), args.host + ":" + target], check=True)
    if args.exec_resource_probe:
        for target in [bundle, stock_bundle, *extra_bundles.values(), *([baseline_bundle] if baseline_bundle else [])]:
            if not args.resume:
                subprocess.run(["scp", "-O", str(args.exec_resource_probe.resolve()),
                                args.host + ":" + target + "/exec-resource"], check=True)
            assert ssh("sha256sum " + target + "/exec-resource").decode().split()[0] == settings["exec_resource_probe_sha256"]
    if args.exec_task_probe:
        for target in [bundle, stock_bundle, *([baseline_bundle] if baseline_bundle else []), *extra_bundles.values()]:
            if not args.resume:
                subprocess.run(["scp", "-O", str(args.exec_task_probe.resolve()),
                                args.host + ":" + target + "/exec-task-counts"], check=True)
            assert ssh("sha256sum " + target + "/exec-task-counts").decode().split()[0] == settings["exec_task_probe_sha256"]
    if args.memory_probe:
        digest = hashlib.sha256(args.memory_probe.read_bytes()).hexdigest()
        if not args.resume:
            subprocess.run(["scp", "-O", str(args.memory_probe.resolve()), args.host + ":" + bundle + "/memory-probe"], check=True)
        if ssh("sha256sum " + bundle + "/memory-probe").decode().split()[0] != digest:
            raise RuntimeError("memory probe upload checksum mismatch")
        initial("memory-probe.json", {"sha256": digest})
    if args.rpc_client_probe:
        digest = hashlib.sha256(args.rpc_client_probe.read_bytes()).hexdigest()
        if not args.resume:
            subprocess.run(["scp", "-O", str(args.rpc_client_probe.resolve()), args.host + ":" + bundle + "/rpc-client-probe"], check=True)
        if ssh("sha256sum " + bundle + "/rpc-client-probe").decode().split()[0] != digest:
            raise RuntimeError("RPC client probe upload checksum mismatch")
        initial("client-probe.json", {"sha256": digest, "diagnostic_only": True})
    assert ssh("sha256sum " + remote + "/isolated.sh").decode().split()[0] == hashlib.sha256(script.read_bytes()).hexdigest()
    bundle_targets = [bundle, stock_bundle, *([baseline_bundle] if baseline_bundle else []), *extra_bundles.values()]
    if fw4_fixture_hash:
        for target in bundle_targets:
            destination = target + "/fw4-firewall"
            if not args.resume:
                subprocess.run(["scp", "-O", str(args.fw4_fixture.resolve()),
                                args.host + ":" + destination], check=True)
            assert ssh("sha256sum " + shlex.quote(destination)).decode().split()[0] == fw4_fixture_hash
    if fixture_hashes:
        for target in bundle_targets:
            directory = target + "/netifd-fixture"
            if not args.resume:
                ssh("mkdir " + shlex.quote(directory))
                for name in fixture_hashes:
                    subprocess.run(["scp", "-O", str((args.netifd_fixture / name).resolve()),
                                    args.host + ":" + directory + "/" + name], check=True)
                ssh("chmod 755 " + shlex.quote(directory + "/mac80211.sh"))
            for name, digest in fixture_hashes.items():
                assert ssh("sha256sum " + shlex.quote(directory + "/" + name)).decode().split()[0] == digest
    if event_contracts:
        selections = [(bundle, "candidate"), (stock_bundle, "stock")]
        if baseline_bundle: selections.append((baseline_bundle, args.baseline_label))
        for target, side in selections:
            destination = target + "/event-contract.json"
            if not args.resume:
                subprocess.run(["scp", "-O", str((args.netifd_event_contracts / (side + ".json")).resolve()),
                                args.host + ":" + destination], check=True)
            assert ssh("sha256sum " + shlex.quote(destination)).decode().split()[0] == event_contracts[side]["sha256"]
    for name in ("ns-exec", "owrt-benchmark"):
        for where in bundle_targets:
            if ssh("sha256sum " + where + "/" + name).decode().split()[0] != tool_hashes[name]:
                raise RuntimeError("benchmark identity mismatch: " + name)
    if ssh("sha256sum " + bundle + "/" + binary).decode().split()[0] != hashes["candidate"]:
        raise RuntimeError("candidate upload checksum mismatch")
    if "r84" in args.sides and ssh("sha256sum " + (baseline_bundle or stock_bundle) + "/" + binary).decode().split()[0] != hashes[args.baseline_label]:
        raise RuntimeError("baseline upload checksum mismatch")
    for label, target in extra_bundles.items():
        if ssh("sha256sum " + target + "/" + binary).decode().split()[0] != hashes[label]:
            raise RuntimeError("extra baseline upload checksum mismatch: " + label)
    monitors = ",".join(line.split()[1] for line in identity.decode().splitlines()
                        if line.split()[1] != "-")
    snapshot = shlex.quote(args.host_bundle + "/bins/owrt-benchmark") + " snapshot " + monitors
    for index, side in enumerate(order, 1):
        local = out / f"{index:02d}-{side}"
        if args.resume and local.exists():
            raw = local / "raw"
            assert (local / "COMPLETE").exists() and (raw / "COMPLETE").exists(), (
                "incomplete sample requires explicit recovery or archival before resume", local.name)
            assert (raw / "binary-sha256.txt").read_text().split()[0] == hashes[side]
            assert (raw / "boot-id.txt").read_text().strip() == pre["boot_id"]
            assert (raw / "harness-sha256.txt").read_text().split()[0] == collector["harness_sha256"]
            for line in (local / "raw.sha256").read_text().splitlines():
                expected, name = line.split(None, 1)
                path = (raw / name).resolve()
                assert path.is_relative_to(raw.resolve()) and hashlib.sha256(path.read_bytes()).hexdigest() == expected
            print(json.dumps({"event": "preserved", "side": side, "index": index}), flush=True)
            continue
        local.mkdir(mode=0o700)
        run_out = remote + f"/run-{index:02d}"
        if side == "candidate" or args.memory_probe or args.rpc_client_probe:
            selected = bundle
        elif side in extra_bundles:
            selected = extra_bundles[side]
        elif side == args.baseline_label and baseline_bundle:
            selected = baseline_bundle
        else:
            selected = stock_bundle
        impl = "c" if side == "stock" else "rs"
        (local / "host-before.json").write_bytes(ssh(snapshot))
        mounts = ssh("cat /proc/self/mountinfo")
        (local / "mounts-before.txt").write_bytes(mounts)
        for suffix, cmd in (("config-before.sha256", "sha256sum /etc/config/*"),
                            ("production-before.txt", None)):
            value = production_identity() if cmd is None else ssh(cmd)
            (local / suffix).write_bytes(value)
            assert value == (config if suffix.startswith("config") else identity), "production state changed"
        (local / "environment-before.txt").write_bytes(ssh("cat /proc/uptime /proc/loadavg; for f in /sys/class/thermal/thermal_zone*/temp; do test ! -f \"$f\" || cat \"$f\"; done"))
        print(json.dumps({"event": "started", "side": side, "index": index,
                          "at": datetime.datetime.now(datetime.timezone.utc).isoformat()}), flush=True)
        command = (f"/bin/sh {remote}/isolated.sh {shlex.quote(args.reference_root)} {shlex.quote(selected)} {component} {impl} "
                   f"{run_out} {args.iterations}")
        if args.cpus:
            command = "taskset -c " + shlex.quote(args.cpus) + " " + command
        if args.matrix:
            command = "OWRT_" + component.upper().replace("-", "_") + "_MATRIX=1 " + command
            if component == "netifd":
                command = ("OWRT_NETIFD_SCALE=" + str(args.netifd_scale)
                           + " OWRT_NETIFD_WARMUP=" + str(args.netifd_warmup) + " " + command)
                if args.netifd_workloads:
                    command = "OWRT_NETIFD_WORKLOADS=" + shlex.quote(" ".join(args.netifd_workloads)) + " " + command
        if component == "reload-config":
            command = ("OWRT_RELOAD_CONFIG_WORKLOADS=" + shlex.quote(" ".join(settings["reload_workloads"]))
                       + " OWRT_RELOAD_CONFIG_WARMUP=" + str(args.reload_warmup)
                       + " OWRT_RELOAD_CONFIG_PACKAGES=" + str(args.reload_packages) + " " + command)
        if component == "fw4":
            command = ("OWRT_FW4_WORKLOADS=" + shlex.quote(" ".join(settings["fw4_workloads"]))
                       + " OWRT_FW4_COUNT=" + str(settings["fw4_count"])
                       + " OWRT_FW4_WARMUP=" + str(args.fw4_warmup) + " " + command)
            if fw4_fixture_hash:
                command = "OWRT_FW4_FIXTURE_SHA256=" + fw4_fixture_hash + " " + command
        if args.httpd_workloads:
            command = "OWRT_HTTPD_WORKLOADS=" + shlex.quote(" ".join(args.httpd_workloads)) + " " + command
        if args.rpcd_workloads:
            command = "OWRT_RPCD_WORKLOADS=" + shlex.quote(" ".join(args.rpcd_workloads)) + " " + command
        if component == "procd":
            command = "OWRT_PROCD_WARMUP=" + str(args.procd_warmup) + " " + command
            if args.procd_workloads:
                command = "OWRT_PROCD_WORKLOADS=" + shlex.quote(" ".join(args.procd_workloads)) + " " + command
        if args.guard:
            command = "OWRT_BENCH_GUARD=" + remote + "/guard " + command
        if args.extended:
            command = "OWRT_UBUSD_EXTENDED=1 OWRT_UBUSD_NORMALIZED=1 " + command
        if args.memory_probe:
            command = "OWRT_HTTPD_MEMORY=1 " + command
        if args.rpc_client_probe:
            mode_order = "tree-first" if index % 2 else "wire-first"
            command = "OWRT_RPCD_CLIENT_DIAGNOSTIC=1 OWRT_RPCD_CLIENT_ORDER=" + mode_order + " " + command
        failures = []
        run_exit = None
        try:
            with (local / "run.log").open("xb") as log:
                run_exit = subprocess.run(ssh_args + [command], stdout=log, stderr=subprocess.STDOUT, timeout=1800).returncode
            if run_exit != 0:
                failures.append(f"namespace exited {run_exit}")
        except Exception as exc:
            failures.append(f"launch: {type(exc).__name__}: {exc}")
        # Preserve a failed window before raising, including collection errors.
        # The router-side guard remains responsible for bounded termination.
        archive = local / "raw.tar.gz"
        raw = local / "raw"
        try:
            with archive.open("xb") as target:
                subprocess.run(ssh_args + ["tar -czf - -C " + shlex.quote(run_out) + " ."],
                               stdout=target, check=True, timeout=180)
            checksums = ssh("cd " + shlex.quote(run_out) + " && find . -type f -exec sha256sum '{}' ';'")
            (local / "raw.sha256").write_bytes(checksums)
            raw.mkdir(mode=0o700)
            with tarfile.open(archive) as tar:
                tar.extractall(raw, filter="data")
            for line in checksums.decode().splitlines():
                digest, name = line.split(None, 1)
                path = raw / name
                assert path.resolve().is_relative_to(raw) and hashlib.sha256(path.read_bytes()).hexdigest() == digest, "download checksum mismatch"
            assert (raw / "COMPLETE").exists(), "incomplete isolated run"
            assert (raw / "binary-sha256.txt").read_text().split()[0] == hashes[side], "subject identity mismatch"
            if (raw / "subject-sha256.txt").exists():
                assert (raw / "subject-sha256.txt").read_text().split()[0] == hashes[side], "live subject identity mismatch"
            assert (raw / "boot-id.txt").read_text().strip() == pre["boot_id"], "host boot changed"
            assert (raw / "harness-sha256.txt").read_text().split()[0] == hashlib.sha256(script.read_bytes()).hexdigest(), "harness identity mismatch"
            observed_tools = {Path(path).name: digest for digest, path in
                              (line.split() for line in (raw / "benchmark-sha256.txt").read_text().splitlines())}
            assert observed_tools == tool_hashes, "measured tool identities differ"
            if component == "httpd":
                dependencies = [line.split()[0] for line in (raw / "dependencies-sha256.txt").read_text().splitlines()]
                assert dependencies == [manifest["components"][name]["original"]["sha256"] for name in ("rpcd", "ubusd")], "HTTP dependencies are not the exact image C binaries"
            if component == "procd":
                dependencies = [line.split()[0] for line in (raw / "dependencies-sha256.txt").read_text().splitlines()]
                assert dependencies == [manifest["components"]["ubusd"]["original"]["sha256"]], "procd dependency is not the exact image C ubusd"
        except Exception as exc:
            failures.append(f"raw evidence: {type(exc).__name__}: {exc}")
        for filename, cmd, expected_value in (
                ("host-after.json", snapshot, None),
                ("environment-after.txt", "cat /proc/uptime /proc/loadavg; for f in /sys/class/thermal/thermal_zone*/temp; do test ! -f \"$f\" || cat \"$f\"; done", None),
                ("mounts-after.txt", "cat /proc/self/mountinfo", mounts),
                ("config-after.sha256", "sha256sum /etc/config/*", config),
                ("production-after.txt", None, identity)):
            try:
                value = production_identity() if cmd is None else ssh(cmd)
                (local / filename).write_bytes(value)
                assert expected_value is None or value == expected_value, filename + " changed"
            except Exception as exc:
                failures.append(f"{filename}: {type(exc).__name__}: {exc}")
        if failures:
            try:
                save(local.name + "/health-after-failure.json", device_probe())
            except Exception as exc:
                failures.append(f"health: {type(exc).__name__}: {exc}")
        save(local.name + "/result.json", {"command": command, "exit": run_exit, "failures": failures,
                                          "remote_evidence_retained": run_out if failures else None})
        if failures:
            raise RuntimeError("window failed; evidence preserved: " + "; ".join(failures))
        ssh("rm -rf -- " + shlex.quote(run_out))
        (local / "COMPLETE").touch()
        print(json.dumps({"event": "complete", "side": side, "index": index}), flush=True)
    post = device_probe()
    save("health-after.json", post)
    after = ssh("sha256sum /etc/config/*")
    (out / "config-after.sha256").write_bytes(after)
    if pre["boot_id"] != post["boot_id"] or config != after:
        raise RuntimeError("host boot/configuration changed")
    if production_identity() != identity:
        raise RuntimeError("host process identities changed")
    ssh("rm -rf -- " + remote)
    (out / "COMPLETE").touch()
    print(component + " comparison complete", flush=True)


if __name__ == "__main__":
    main()
