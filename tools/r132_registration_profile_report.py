#!/usr/bin/env python3
"""Local-only exact-PC audit of the frozen R132 registration profiles.

Usage: python3 tools/r132_registration_profile_report.py RAW NEW_OUTPUT
--smoke accepts the separately named three-run smoke plan, never pools it with
the formal twelve windows. No network, subprocesses, perf collection or router.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re

import r121_symbolize as sym

ROOT = Path(__file__).resolve().parents[1]
LOCAL = {
    "c": ("private/r95/ubusd-pilot/stock", "private/r121-symbol-profile/c-symbols"),
    "r124": ("private/r130-add-reply/maps/r124", "private/r131-event-batch/maps/r124.map"),
    "r131": ("private/r131-event-batch/maps/r131", "private/r131-event-batch/maps/r131.map"),
}
FAMILY_RULES = {
    "object_event": "send_obj_event, dispatch_event or ubusd_send_obj_event in bounded emitted symbol name",
    "handle_or_free_object": "Rust Server handle/free_object, or C ubusd handle-add/handle-remove/free-object symbols",
    "registry_object_lookup": "Rust HashMap<Object> get/get_mut, Registry get/get_mut, or C ubusd_find_object",
    "allocator": "exact malloc/calloc/realloc/free/cfree and musl/Rust allocator implementation names",
    "allocation_support": "Rust raw_vec grow/finish_grow; separate from allocator entry points",
    "other_user": "resolved user PCs outside these named families; not ignored",
}
COLLECTOR_VERSIONS = {
    "c32372bf8eb4c1cb6a9e755519ef92d3583fe3525a958220ca72f10e308a7be1": "c3be8e7",
    "b04130d90ee66e5dee8a44e8078fcbd2ba022eebe9d18a5f29ab5e3126367638": "f0da992",
}


def check(ok, message):
    if not ok:
        raise ValueError(message)


def read(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def family(names):
    joined = " ".join(names)
    if re.search(r"send_obj_event|dispatch_event", joined):
        return "object_event"
    if re.search(r"Server(?:6handle|11free_object)|Server::(?:handle|free_object)|ubusd_(?:handle_(?:add|remove)_object|free_object)", joined):
        return "handle_or_free_object"
    if re.search(r"ubusd_find_object|Registry::get|Registry(?:3get|7get_mut)|HashMap.*(?:obj6Object|obj::Object).*(?:E3get|E7get_mut|::get)", joined):
        return "registry_object_lookup"
    allocation_names = {"malloc", "calloc", "realloc", "free", "cfree", "aligned_alloc", "posix_memalign",
                        "__libc_malloc", "__libc_malloc_impl", "__libc_free", "__libc_realloc", "__libc_calloc", "__malloc_alloc_meta",
                        "__malloc_alloc_area", "__malloc_atfork", "__malloc_donate", "__libc_memalign", "alloc_slot",
                        "try_avail", "alloc_group", "nontrivial_free", "free_group", "__rust_alloc", "__rust_dealloc",
                        "__rust_realloc", "__rust_alloc_zeroed"}
    if any(name in allocation_names or re.search(r"__rdl_(?:alloc|dealloc|realloc)|__rust_(?:alloc|dealloc|realloc)", name) for name in names):
        return "allocator"
    if "raw_vec" in joined and re.search(r"grow|finish_grow", joined):
        return "allocation_support"
    return "other_user"


def kernel_family(name):
    if re.search(r"schedule|sched_|wake_up|try_to_wake|finish_task_switch|pick_next_task|enqueue_task|dequeue_task|resched", name):
        return "scheduler_reported"
    if re.search(r"unix_|sendmsg|recvmsg|skb_|sock_|socket|copy_msghdr|scm_", name):
        return "socket_ipc_reported"
    return "other_kernel_reported"


def images_for(plan, label, raw):
    dso = plan["launch_directory"] + "/ubusd"
    binary, symbol_source = [ROOT / name for name in LOCAL[label]]
    spec = plan["subjects"][label]
    check(sha(binary) == spec["sha256"] and sha(symbol_source) == spec["symbols"]["sha256"], "exact subject/symbol identity")
    elf = sym.ELF(binary)
    companion = sym.ELF(symbol_source) if label == "c" else elf
    text = companion.section(".text")
    check(text and text.flags & 4 and elf.kind == companion.kind, "symbol .text metadata")
    body = elf.virtual_bytes(text.address, text.size)
    check(body == companion.virtual_bytes(text.address, text.size), "different .text companion")
    ranges = sym.elf_function_ranges(companion) if label == "c" else sym.linker_map_ranges(symbol_source.read_text(), text.address, text.size)
    check(ranges, "no function ranges")
    images = {dso: {"elf": elf, "ranges": ranges}}
    identities = {dso: {"sha256": sha(binary), "symbol_source_sha256": sha(symbol_source),
                       "text_sha256": hashlib.sha256(body).hexdigest(), "function_ranges": len(ranges)}}
    if label == "c":
        for index, (name, digest) in enumerate(plan["rootfs"]["libraries"].items()):
            remote = plan["rootfs"]["path"] + name
            local = ROOT / "private/r121-symbol-profile/libraries" / Path(name).name
            check(sha(local) == digest, f"exact library: {name}")
            elf = sym.ELF(local)
            text_path = raw / f"library-{index}-dynsym.txt"
            check(read(raw / f"library-{index}-dynsym.command.json") == ["readelf", "--use-dynamic", "--symbols", "-W", remote], "dynamic symbol source command")
            check(not (raw / f"library-{index}-dynsym.stderr").read_bytes(), "dynamic symbol extraction failed")
            ranges = sym.dynamic_symbol_ranges(text_path.read_text(), elf)
            images[remote] = {"elf": elf, "ranges": ranges}
            identities[remote] = {"sha256": digest, "dynamic_symbol_text_sha256": sha(text_path),
                                  "function_ranges": len(ranges), "coverage": "exports only; hidden/unmatched PCs stay unknown"}
    return images, identities


def classify(report, samples, mappings):
    categories, unknown_by_dso, kernel = Counter(), Counter(), Counter()
    for row in report["top_functions"]:
        categories[family(row["names"])] += row["sample_count"]
    # This report requests every unknown IP, not just a top-N truncation.
    for row in report["top_unknown_ips"]:
        ip = int(row["ip"], 16)
        matches = [m.path for m in mappings if m.start <= ip < m.end and "x" in m.permissions]
        path = matches[0] if len(matches) == 1 else row["dso"]
        unknown_by_dso[(path, row["reason"])] += row["sample_count"]
    for sample in samples:
        if sample.mode.startswith("K"):
            kernel[kernel_family(sample.reported_symbol)] += 1
    check(sum(categories.values()) == report["symbolized_count"], "resolved samples omitted by category")
    check(sum(unknown_by_dso.values()) == report["unknown_count"], "unknown samples omitted")
    return {"user_families": dict(categories), "unknown_user_by_dso_reason": [
        {"dso": dso, "reason": reason, "samples": count} for (dso, reason), count in unknown_by_dso.items()],
        "kernel_families": dict(kernel)}


def proc_identity(path):
    text = path.read_text(); head, tail = text.rsplit(") ", 1); fields = tail.split()
    return int(head.split(" (", 1)[0]), fields[19], int(fields[17])


def audit_window(raw, plan, item, index):
    name = f"{index:03d}-{item['subject']}-{item['methods']}"
    check(raw.name == name and (raw / "COMPLETE").exists() and not (raw / "FAILED").exists(), f"{name}: incomplete")
    meta, caller = read(raw / "meta.json"), read(raw / "client.json")
    check(meta["status"] == "complete" and meta["mode"] == "profile" and meta["run"] == item, f"{name}: metadata")
    label = item["subject"]; dso = plan["launch_directory"] + "/ubusd"
    socket = plan["launch_directory"] + "/ubus.sock"
    check(meta["normalized_subject_path"] == dso and meta["normalized_socket_path"] == socket and meta["program_argv0"] == "/sbin/ubusd", f"{name}: normalization")
    check(meta["subject_sha256"] == plan["subjects"][label]["sha256"], f"{name}: subject")
    check(meta["returncodes"]["client"] == 0 and meta["returncodes"]["perf"] in (0, -2) and meta["returncodes"]["daemon"] in (0, -15), f"{name}: exit codes")
    check(caller["fixture"] == "rust_register_cycle" and caller["wire_reply_bytes_checked"] is False, f"{name}: caller contract")
    for key in ("perf_controlled", "full_signature_checked", "warmup_empty", "final_empty"):
        check(caller[key] is True, f"{name}: {key}")
    for key in ("n", "warmup", "methods", "name_bytes"):
        check(caller[key] == item[key], f"{name}: {key}")
    check(caller["successful"] == item["n"] and caller["errors"] == 0 and caller["subject_pid"] == meta["daemon_pid"] and caller["client_pid"] == meta["client_pid"], f"{name}: caller PID/count")
    check(caller["subject_cpu"] == 1 and caller["client_cpu"] == 0, f"{name}: affinity")
    samples_ns = caller["latency_ns"]
    check(len(samples_ns) == caller["latency_sample_count"] == item["n"] and all(type(v) is int and v > 0 for v in samples_ns), f"{name}: latency samples")
    clocks = {clock: caller[f"{clock}_after_ns"] - caller[f"{clock}_before_ns"] for clock in ("subject", "client", "wall")}
    check(all(v > 0 for v in clocks.values()) and sum(samples_ns) <= clocks["wall"] and max(clocks["subject"], clocks["client"]) <= clocks["wall"], f"{name}: clocks")
    check(meta["elapsed_ns"] == clocks, f"{name}: derived clocks")
    check(meta["client_command"] == [plan["client"]["path"], "register-cycle", socket, str(item["methods"]), str(item["name_bytes"]), str(item["n"]), str(item["warmup"]), str(meta["daemon_pid"])], f"{name}: client argv")
    caller_identity = read(raw / "client-identity.json")
    check(caller_identity["pid"] == meta["client_pid"] and caller_identity["affinity"] == [0] and caller_identity["mapped_sha256"] == {plan["client"]["path"]: plan["client"]["sha256"]}, f"{name}: live caller")
    identities = [read(raw / f"identity-{stage}.json") for stage in ("before", "after")]
    check(identities[0] == identities[1], f"{name}: daemon changed")
    identity = identities[0]
    expected = {plan["rootfs"]["path"] + path: digest for path, digest in plan["rootfs"]["libraries"].items()}
    expected[dso] = plan["subjects"][label]["sha256"]
    check(identity["pid"] == meta["daemon_pid"] and identity["affinity"] == [1] and identity["mapped_sha256"].get(dso) == expected[dso], f"{name}: live daemon")
    check(all(expected.get(path) == digest for path, digest in identity["mapped_sha256"].items()), f"{name}: unplanned mapping")
    process = [proc_identity(raw / f"stat-{stage}.txt") for stage in ("before", "after")]
    check(process[0] == process[1] and process[0][0] == meta["daemon_pid"] and process[0][2] == 1, f"{name}: process identity")
    maps = [sym.parse_proc_maps((raw / f"maps-{stage}.txt").read_text()) for stage in ("before", "after")]
    check([m for m in maps[0] if "x" in m.permissions] == [m for m in maps[1] if "x" in m.permissions], f"{name}: executable maps")
    for m in maps[0]:
        if m.path.startswith("/"):
            check(m.path in identity["mapped_sha256"], f"{name}: map missing identity")
    perf = meta["perf_command"]
    for option, value in (("-D", "-1"), ("-e", "cpu-clock"), ("-F", str(plan["profile"]["frequency_hz"])), ("-m", "8M"), ("-p", str(meta["daemon_pid"]))):
        check(perf[perf.index(option) + 1] == value, f"{name}: perf {option}")
    check(all(x in perf for x in ("--control", "--strict-freq", "--no-buildid-cache", "-T", "-P")) and "-g" not in perf and "--call-graph" not in perf, f"{name}: perf collection")
    stats = {}
    for key, value in re.findall(r"^\s*([A-Z0-9_]+) events:\s*(\d+)", (raw / "stats.txt").read_text(), re.M):
        stats.setdefault(key, int(value))
    check(all(stats.get(k) == 0 for k in ("LOST", "LOST_SAMPLES", "THROTTLE", "UNTHROTTLE")), f"{name}: dropped/throttled")
    lost = re.findall(r"Total Lost Samples:\s*([0-9,]+)", (raw / "report.txt").read_text())
    check(lost and all(int(v.replace(",", "")) == 0 for v in lost), f"{name}: report loss")
    samples = sym.parse_perf_script((raw / "samples.txt").read_text()); summary = read(raw / "sample-summary.json")
    check(len(samples) == stats["SAMPLE"] == summary["parsed_samples"] > 0 and summary["unparsed_lines"] == 0, f"{name}: sample accounting")
    details = [line for line in (raw / "samples-detail.txt").read_text().splitlines() if line.strip()]
    check(len(details) == len(samples) and all(line.lstrip().startswith(f'{meta["daemon_pid"]}/{meta["daemon_pid"]} ') for line in details), f"{name}: sampled PID/TID")
    for stem in ("client", "report", "samples", "samples-detail", "events", "stats", "symbolize"):
        check(not (raw / f"{stem}.stderr").read_bytes(), f"{name}: {stem} warning/error")
    images, image_identities = images_for(plan, label, raw)
    regenerated = sym.sample_report(samples, maps[0], images, top=1000000)
    old = read(raw / "symbolized.json")
    for key in ("sample_count", "samples_by_mode", "user_sample_count", "symbolized_count", "unknown_count", "unknown_fraction_of_user_samples", "unknown_reasons"):
        check(regenerated[key] == old[key], f"{name}: symbolized {key}")
    for key in ("top_functions", "top_unknown_ips", "non_user_perf_symbols"):
        check(regenerated[key][:len(old[key])] == old[key], f"{name}: symbolized {key} differs")
    classified = classify(regenerated, samples, maps[0])
    return {"index": index, "directory": name, "run": item, "all_checks_passed": True,
            "sample_counts": {key: regenerated[key] for key in ("sample_count", "samples_by_mode", "user_sample_count", "symbolized_count", "unknown_count")},
            "classifications": classified, "images": image_identities, "stats": stats, "clocks_under_sampling_ns": clocks,
            "functions": regenerated["top_functions"], "unknown_ips": regenerated["top_unknown_ips"],
            "kernel_symbols_reported_only": regenerated["non_user_perf_symbols"],
            "raw_file_sha256": {p.name: sha(p) for p in raw.iterdir() if p.is_file()}}


def merge(rows):
    totals, families, unknown, kernel = Counter(), Counter(), Counter(), Counter()
    functions = Counter(); details = {}
    for row in rows:
        for key in ("sample_count", "user_sample_count", "symbolized_count", "unknown_count"):
            totals[key] += row["sample_counts"][key]
        families.update(row["classifications"]["user_families"])
        kernel.update(row["classifications"]["kernel_families"])
        for item in row["classifications"]["unknown_user_by_dso_reason"]:
            unknown[(item["dso"], item["reason"])] += item["samples"]
        for item in row["functions"]:
            key = (item["dso"], item["start"], item["end"], tuple(item["names"]))
            functions[key] += item["sample_count"]; details[key] = item
    return {"windows": [r["directory"] for r in rows], "sample_counts": dict(totals),
            "user_families": {name: {"samples": families[name], "fraction_of_all_samples": families[name] / totals["sample_count"],
                                       "fraction_of_user_samples": families[name] / totals["user_sample_count"] if totals["user_sample_count"] else None}
                              for name in FAMILY_RULES},
            "unknown_user_by_dso_reason": [{"dso": d, "reason": reason, "samples": n} for (d, reason), n in unknown.most_common()],
            "kernel_families": dict(kernel), "functions": [{**details[key], "sample_count": n,
                  "fraction_of_all_samples": n / totals["sample_count"], "fraction_of_user_samples": n / totals["user_sample_count"]}
                  for key, n in functions.most_common()]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("raw", type=Path); parser.add_argument("output", type=Path); parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args(); plan = read(args.raw / "plan.json")
    check((args.raw / "COMPLETE").exists() and plan["mode"] == "profile", "incomplete/nonprofile series")
    check(plan["runner_sha256"] in COLLECTOR_VERSIONS, "collector version needs explicit historical identity audit")
    check(plan["profile"]["frequency_hz"] in (249, 499, 997), "unexpected frozen sample rate")
    check(sha(ROOT / "tools/r121_symbolize.py") == plan["support_sha256"]["r121_symbolize.py"], "symbolizer identity changed")
    check(read(args.raw / "host.json")["runner_sha256"] == plan["runner_sha256"] and
          read(args.raw / "host.json")["perf_sha256"] == plan["perf"]["sha256"], "collector identity")
    expected = ([{"subject": label, "methods": 1, "name_bytes": 8, "n": 5000, "warmup": 500} for label in ("c", "r124", "r131")] if args.smoke else
                [{"subject": label, "methods": methods, "name_bytes": 8, "n": 300000, "warmup": 5000}
                 for methods in (1, 16) for label in ("c", "r124", "r131", "r131", "r124", "c")])
    check(plan["runs"] == expected, "frozen schedule differs")
    names = {f"{i:03d}-{item['subject']}-{item['methods']}" for i, item in enumerate(expected, 1)}
    check({p.name for p in args.raw.iterdir() if p.is_dir() and re.match(r"\d{3}-", p.name)} == names, "window set differs")
    args.output.mkdir(parents=True, exist_ok=False)
    rows = []
    for index, item in enumerate(plan["runs"], 1):
        name = f"{index:03d}-{item['subject']}-{item['methods']}"
        row = audit_window(args.raw / name, plan, item, index)
        save(args.output / f"{name}.json", row); rows.append(row)
        print(name, row["sample_counts"], flush=True)
    grouped = {f"{label}-{methods}": merge([r for r in rows if r["run"]["subject"] == label and r["run"]["methods"] == methods])
               for methods in sorted({r["run"]["methods"] for r in rows}) for label in ("c", "r124", "r131")}
    result = {"schema_version": 1, "scope": "R132 exact-PC Oracle registration profile audit, smoke only" if args.smoke else "R132 exact-PC Oracle registration profile audit, formal 12 windows",
              "all_checks_passed": True, "plan_sha256": sha(args.raw / "plan.json"), "auditor_sha256": sha(__file__),
              "collector_sha256": plan["runner_sha256"], "collector_commit": COLLECTOR_VERSIONS[plan["runner_sha256"]],
              "sample_frequency_hz": plan["profile"]["frequency_hz"],
              "classification_rules": FAMILY_RULES, "windows": rows, "groups": grouped,
              "limits": ["Flat sampled emitted-code PCs, not calls, inline attribution, or inclusive time.",
                         "C shared-library dynamic exports omit hidden ranges; unknown samples remain explicit, never zero cost.",
                         "Kernel groups rely on perf-reported names; user ELF validation does not validate kernel symbols.",
                         "Two windows per method/subject describe this diagnostic only, not the router tail-regression cause.",
                         "An empty-pattern experiment requires static semantic reasoning plus observed relevant execution; profile alone cannot prove safety or causation.",
                         "Zero samples in a symbol do not mean the code was not executed."]}
    save(args.output / "results.json", result); (args.output / "COMPLETE").touch()


if __name__ == "__main__":
    main()
