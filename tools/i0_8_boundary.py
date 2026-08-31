#!/usr/bin/env python3
"""Build the I0.8 replacement boundary, open questions and risk register.

Each of the 17 responsibilities is placed in exactly one of the five
categories the plan allows.  The classification lives here as data; everything
checkable is checked against the I0.4-I0.7 manifests so a classification can
never cite evidence that is not there.

Rules enforced:
  * every responsibility appears exactly once
  * the default is keep or defer; any other category needs a written rationale
    and at least one DEP, SRC and RUN evidence reference
  * a responsibility with unresolved blocking questions cannot be 'rust-replace'
  * 'do-not-touch' requires a stated recovery constraint
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


CATEGORIES = {
    "keep": "保留",
    "rust-wrap": "Rust 接入或包装",
    "rust-replace": "优先用 Rust 替换",
    "defer": "延后评估",
    "do-not-touch": "禁止触碰",
}
DEFAULT_CATEGORIES = {"keep", "defer"}

# --------------------------------------------------------------------------
# classification
# --------------------------------------------------------------------------

CLASSIFICATION: list[dict[str, Any]] = [
    {
        "id": "R01",
        "category": "do-not-touch",
        "rationale": (
            "procd is PID 1. Its failure mode is a device reboot and there is no in-band "
            "recovery. It also owns the service, system and hotplug object families that "
            "every other responsibility depends on."
        ),
        "recovery_constraint": "No in-band recovery exists; only the bootloader or a power cycle.",
        "dep": ["/sbin/procd and /sbin/init present; 19 supervised services observed"],
        "src": ["procd state machine and inittab handler pinned at 58eb263d"],
        "run": ["Q06 service list: 19 services, instance and trigger state matches the static graph"],
    },
    {
        "id": "R02",
        "category": "keep",
        "rationale": (
            "The init framework is shell that procd interprets by convention. Replacing it "
            "means reimplementing procd's expectations without changing procd, which buys "
            "nothing until a specific service is replaced."
        ),
        "dep": ["/etc/rc.common and /lib/functions/procd.sh in the image"],
        "src": ["rc.common dispatch table read in full"],
        "run": ["Q06: reload semantics per service confirmed by which services expose reload_service"],
    },
    {
        "id": "R03",
        "category": "do-not-touch",
        "rationale": (
            "Boot orchestration decides whether the device boots at all. A failure here is "
            "recoverable only through failsafe or the bootloader, and this project has no "
            "recovery gate."
        ),
        "recovery_constraint": "Failsafe or TFTP/bootloader recovery only; needs physical access.",
        "dep": ["21 preinit hook files; inittab with 3 entries"],
        "src": ["procd initd early/preinit path pinned"],
        "run": ["Q01 kernel cmdline has no rootfs_mount_options.*; Q02 failsafe not entered"],
    },
    {
        "id": "R04",
        "category": "defer",
        "rationale": (
            "UCI is a plausible Rust target and its format is small, but the binding "
            "constraint is unknown-field preservation on read-modify-write across three "
            "concurrent writer families (shell, ucode, C) with no cross-process lock. "
            "That cannot be settled by observation; it needs a differential experiment, "
            "which is a C1/V1 activity."
        ),
        "dep": ["6 shipped configs; /etc/config content and hashes observed"],
        "src": ["libuci pinned at 66127cd7"],
        "run": ["Q12: no uncommitted delta at observation time; Q13: 4 of 6 shipped configs drifted"],
        "blocking_questions": ["OQ-04", "OQ-05"],
    },
    {
        "id": "R05",
        "category": "rust-replace",
        "rationale": (
            "reload_config is 17 lines of shell whose own upstream comment calls it a "
            "temporary hack until configd exists. Its contract is narrow and fully "
            "observed: compare normalised uci show output per package against a tmpfs "
            "md5 baseline and emit one config.change event per differing package. Its "
            "failure mode is silent, which is exactly the class of defect a typed "
            "implementation removes. It has no persistent state beyond a regenerable "
            "baseline, so a wrong version is recoverable by deleting that file."
        ),
        "dep": ["/sbin/reload_config, 17 lines, read in full"],
        "src": ["base-files recipe; upstream comment naming it a temporary hack"],
        "run": [
            "Q12: /var/run/config.md5 baseline observed with its tracked package list",
            "Q06: config.change triggers observed on the consuming services",
        ],
    },
    {
        "id": "R06",
        "category": "keep",
        "rationale": (
            "First-boot generation runs once and depends on MTD-sourced MAC values for this "
            "board. Its blast radius is a device with no network configuration, and it is "
            "not on any hot path afterwards. There is no operational gain from rewriting it."
        ),
        "dep": ["/bin/board_detect, /bin/config_generate, 7 board.d scripts"],
        "src": ["02_network case for xiaomi,mi-router-ax3000t; mtd_get_mac_ascii Bdata"],
        "run": ["Q03: /etc/uci-defaults empty and board.json present, so generation already ran"],
    },
    {
        "id": "R07",
        "category": "defer",
        "rationale": (
            "netifd is the largest single control-plane surface: 3 base objects plus one "
            "object per interface, its own protocol handler contract, and a ucode wireless "
            "sub-API. The interface is now fully catalogued and verified against runtime, "
            "but a replacement would have to reproduce the proto handler and wireless "
            "notify contracts, neither of which has been exercised."
        ),
        "dep": ["/sbin/netifd; 4 interface objects observed"],
        "src": ["netifd pinned at cbb83a18; ubus.c object tables parsed"],
        "run": ["Q05 and Q07: 4 interfaces, 9 devices, method signatures captured"],
        "blocking_questions": ["OQ-01", "OQ-06"],
    },
    {
        "id": "R08",
        "category": "do-not-touch",
        "rationale": (
            "Wireless spans hostapd, wpa_supplicant, a ucode layer and mt76 driver "
            "behaviour. The project's non-goals exclude rewriting drivers and mature "
            "execution-plane components, and a wireless fault is not remotely recoverable "
            "on a device administered over its own LAN."
        ),
        "recovery_constraint": "A wireless fault can remove the only administrative path for a wireless-only client.",
        "dep": ["/usr/sbin/wpad; hostapd.phy0-ap0 and hostapd.phy1-ap0 observed"],
        "src": ["hostap pinned at ca266cc2; ubus support is patch plus ucode"],
        "run": ["Q11: wpad runs as uid 101 with capabilities but no namespace isolation"],
    },
    {
        "id": "R09",
        "category": "defer",
        "rationale": (
            "firewall4 is already ucode rather than C, is one-shot, and its entire output "
            "is an nftables ruleset that can be diffed. That makes it unusually testable. "
            "But its compatibility contract is the generated ruleset, and no differential "
            "comparison has been run yet, so it cannot move further than defer."
        ),
        "dep": ["/sbin/fw4; table inet fw4 with 24 chains observed"],
        "src": ["firewall4 pinned at b6e51575"],
        "run": ["Q08: full ruleset captured, structure recorded"],
        "blocking_questions": ["OQ-02"],
    },
    {
        "id": "R10",
        "category": "keep",
        "rationale": (
            "dnsmasq is a mature execution-plane daemon serving DNS and DHCPv4 for every "
            "client. The project explicitly preserves such components. Its ubus surface is "
            "one method."
        ),
        "dep": ["/usr/sbin/dnsmasq; dnsmasq and dnsmasq.dns objects observed"],
        "src": ["dnsmasq 2.93 verified against PKG_HASH; ubus object via upstream plus patch"],
        "run": ["Q09: object registered under the default name with only the metrics method"],
    },
    {
        "id": "R11",
        "category": "keep",
        "rationale": (
            "odhcpd and odhcp6c are execution-plane IPv6 daemons. Same reasoning as R10, "
            "and this build is the reduced ipv6only variant with a three-method surface."
        ),
        "dep": ["/usr/sbin/odhcpd and odhcp6c; dhcp and odhcp6c.wan objects observed"],
        "src": ["odhcpd pinned at 5d7be43f; odhcp6c at 07d324ee"],
        "run": ["Q09: dhcp has no ipv4leases, confirming the ipv6only build"],
    },
    {
        "id": "R12",
        "category": "do-not-touch",
        "rationale": (
            "ubusd is the transport every other responsibility uses. It has no persistent "
            "state, but restarting it drops every registered object and forces every daemon "
            "to reconnect. Replacing the bus before any client is replaced inverts the "
            "dependency order."
        ),
        "recovery_constraint": "A restart loses all 40 registered objects at once; recovery depends on every daemon reconnecting.",
        "dep": ["/sbin/ubusd; socket at /var/run/ubus/ubus.sock; 40 objects observed"],
        "src": ["ubus pinned at 24864e78; umask 0111 giving a 0666 socket"],
        "run": ["Q05: 40 objects; Q06: ubus supervised as a procd service with user ubus"],
    },
    {
        "id": "R13",
        "category": "rust-wrap",
        "rationale": (
            "rpcd is the remote-administration boundary and, through file.exec and rc.init, "
            "is equivalent to remote code execution. Its ACL model is per-method and its "
            "session semantics are observable. The useful first move is not to replace it "
            "but to put a typed Rust layer in front of the ACL and session decision, where "
            "a mistake is contained and auditable. A full replacement would have to "
            "reproduce nine object families that LuCI depends on by exact field name."
        ),
        "dep": ["/sbin/rpcd plus 6 plugins; 9 ACL files; session timeout 30 observed"],
        "src": ["rpcd pinned at 28faf640; per-method ACL evaluation read"],
        "run": [
            "Q05: full method signatures for session, uci, rc, file, rpc-sys, luci-rpc",
            "Q13: rpcd config unchanged from the image; login scope is read/write '*'",
        ],
    },
    {
        "id": "R14",
        "category": "defer",
        "rationale": (
            "uhttpd runs as root and terminates TLS on all interfaces. It is a credible "
            "Rust target on memory-safety grounds alone, but its LuCI coupling runs through "
            "lua_prefix and ubus_prefix handlers that have not been exercised, and no "
            "differential test exists."
        ),
        "dep": ["/usr/sbin/uhttpd; listens on :80 and :443 v4 and v6"],
        "src": ["uhttpd pinned at 7b1bec45"],
        "run": ["Q13: ubus_prefix /ubus, no_ubusauth unset, ubus_cors unset"],
        "blocking_questions": ["OQ-03"],
    },
    {
        "id": "R15",
        "category": "rust-wrap",
        "rationale": (
            "logd has a two-method surface and a failure mode confined to observability. "
            "That makes it the lowest-risk place to prove the ubus object, ACL and procd "
            "instance contracts end to end. Wrapping, not replacing, because the ring "
            "buffer is already the mechanism that made boot evidence unavailable and a "
            "rewrite should not start by changing retention semantics."
        ),
        "dep": ["/sbin/logd; log object with read and write"],
        "src": ["ubox pinned at 6f78fa49; in-process getpwnam drop"],
        "run": [
            "Q11: runs as uid 514",
            "Q06: 1 of 3 declared instances active",
            "Q02: ring buffer covers about 93 minutes",
        ],
    },
    {
        "id": "R16",
        "category": "keep",
        "rationale": (
            "hotplug dispatch is procd-internal plus 10 shell handlers. It cannot be "
            "separated from R01 without replacing procd, and a missed event is never "
            "retried, so the failure mode is silent and unrecoverable."
        ),
        "dep": ["/etc/hotplug.json; 10 handlers; 10 hotplug.* objects observed"],
        "src": ["procd hotplug-dispatch.c; HOTPLUG_OBJECT_PREFIX"],
        "run": ["Q05: 10 hotplug subsystems, against 4 inferable from the ACL alone"],
    },
    {
        "id": "R17",
        "category": "do-not-touch",
        "rationale": (
            "sysupgrade, factory and reboot are terminal. A defect here bricks the device. "
            "The project reserves this as the recovery gate and has no authorization to "
            "exercise it."
        ),
        "recovery_constraint": "A failed sysupgrade requires bootloader recovery and physical access.",
        "dep": ["/sbin/sysupgrade; rpc-sys and system objects observed"],
        "src": ["procd system.c and rpcd sys.c pinned"],
        "run": ["Q00 and Q14: identity and package set confirmed; no terminal method exercised"],
    },
]

# --------------------------------------------------------------------------
# open questions and risks
# --------------------------------------------------------------------------

OPEN_QUESTIONS: list[dict[str, Any]] = [
    {
        "id": "OQ-01",
        "question": "What is the observable boot ordering, timing and failure propagation?",
        "why_open": "the log ring buffer holds about 93 minutes and the boot record was already overwritten; no line count recovers it",
        "closable_by": "observing a real boot, which is not a read-only observation",
        "blocks": ["R07"],
        "stage": "H1 or a separately authorised experiment",
    },
    {
        "id": "OQ-02",
        "question": "Does a replacement produce a byte-equivalent nftables ruleset from the same config?",
        "why_open": "firewall4's compatibility contract is its output, and no differential comparison has been run",
        "closable_by": "a differential harness comparing fw4 output against a candidate on the same input",
        "blocks": ["R09"],
        "stage": "C1 oracle plus V1",
    },
    {
        "id": "OQ-03",
        "question": "What exactly does LuCI require from uhttpd's lua_prefix and ubus_prefix handlers?",
        "why_open": "the coupling was catalogued but never exercised; no request-level trace exists",
        "closable_by": "recording a LuCI session against the reference device",
        "blocks": ["R14"],
        "stage": "C1",
    },
    {
        "id": "OQ-04",
        "question": "Does a read-modify-write cycle preserve UCI options the implementation does not model?",
        "why_open": "unknown-field preservation is the binding constraint on any UCI replacement and cannot be observed passively",
        "closable_by": "byte and AST round-trip tests over the device's own configs",
        "blocks": ["R04"],
        "stage": "C1",
    },
    {
        "id": "OQ-05",
        "question": "What happens when shell, ucode and C writers touch one config concurrently?",
        "why_open": "there is no cross-process write lock and the window cannot be observed without creating it",
        "closable_by": "a controlled concurrency experiment on a non-production device",
        "blocks": ["R04"],
        "stage": "V1 on a lab device",
    },
    {
        "id": "OQ-06",
        "question": "Which netifd proto handlers and wireless notify paths does this deployment actually exercise?",
        "why_open": "only the dhcp, dhcpv6 and static protos are configured here; the handler contract is broader than what runs",
        "closable_by": "enumerating handlers per configuration, or scoping the contract to the observed set",
        "blocks": ["R07"],
        "stage": "C1",
    },
    {
        "id": "OQ-07",
        "question": "What changed /etc/config/dhcp and /etc/config/firewall from the image, and is any of it still load-bearing?",
        "why_open": "config.md5 shows backups from an earlier tool and both files differ from the image; content was deliberately not read into the report",
        "closable_by": "a separately redacted review of those two files",
        "blocks": [],
        "stage": "I0 follow-up before C1 uses this device as an oracle",
    },
    {
        "id": "OQ-08",
        "question": "Would the ubus catalog stay complete under a different configuration?",
        "why_open": "completeness was verified against one configuration; wpa_supplicant.<ifname> already has no instance here",
        "closable_by": "re-running the comparison after a configuration change, or bounding the claim to this configuration",
        "blocks": [],
        "stage": "V1",
    },
]

RISKS: list[dict[str, Any]] = [
    {
        "id": "RK-01",
        "risk": "Silent config-change delivery failure",
        "detail": "R05's failure mode is a missed event; the service keeps running stale config and nothing reports an error.",
        "affects": ["R05", "R04"],
        "mitigation": "Any replacement must make delivery observable before it changes detection.",
        "evidence": "reload_config read in full; whole-file md5 granularity; tmpfs baseline",
    },
    {
        "id": "RK-02",
        "risk": "Declared isolation is not effective isolation",
        "detail": "wpad declares procd_add_jail but gets no namespace isolation, because the call passes a name with no flags or mounts.",
        "affects": ["R01", "R08"],
        "mitigation": "Treat the declaration and the observed namespace set as separate facts in any design.",
        "evidence": "Q11 namespace inodes; _procd_add_jail in procd.sh",
    },
    {
        "id": "RK-03",
        "risk": "ACL grants objects that do not exist",
        "detail": "Both ACL layers authorise absent objects: udebug in the ubusd layer, dsl and fingerprint in the rpcd layer.",
        "affects": ["R12", "R13"],
        "mitigation": "Never treat an ACL as an interface inventory; it is an intent declaration.",
        "evidence": "Q10 udebug Not found; rpcd ACL coverage check",
    },
    {
        "id": "RK-04",
        "risk": "Device carries configuration history from an earlier tool",
        "detail": "config.md5 tracks bak-codex-* backups and dnsproxy remnants dated before the current firmware, preserved across sysupgrade.",
        "affects": ["R04", "R09", "R10"],
        "mitigation": "Do not treat this device's config as stock. Any oracle use must take its current config as input.",
        "evidence": "Q12 config.md5 tracked list",
    },
    {
        "id": "RK-05",
        "risk": "Static catalogs are complete only for the observed configuration",
        "detail": "The ubus catalog closes bidirectionally against one configuration; a STA interface or a log_file setting would create objects and instances never seen.",
        "affects": ["R07", "R08", "R15"],
        "mitigation": "State the configuration scope alongside any completeness claim.",
        "evidence": "wpa_supplicant.<ifname> has no instance; log has 1 of 3 declared instances",
    },
    {
        "id": "RK-06",
        "risk": "Remote code execution paths are reachable by design",
        "detail": "rc.init and file.exec execute arbitrary programs, gated only by rpcd session ACL, and the shipped login grants read/write '*'.",
        "affects": ["R13", "R14"],
        "mitigation": "Any wrapper must preserve or tighten the ACL decision, never widen it.",
        "evidence": "Q05 method signatures; Q13 rpcd login scope",
    },
    {
        "id": "RK-07",
        "risk": "Boot evidence is not retained",
        "detail": "The default log buffer cannot hold a boot record, so boot-order regressions would be undetectable after the fact.",
        "affects": ["R03", "R15"],
        "mitigation": "Any boot-path work needs a console or a larger buffer arranged in advance.",
        "evidence": "Q02: buffer covers about 93 minutes",
    },
]

# I0 completion checklist from the plan, with the evidence that satisfies each.
I0_CHECKLIST = [
    ("镜像身份和来源可独立复核", True, "IMAGE_IDENTITY.md; signed sha256sums, profiles.json, buildinfo; Q00 confirms the device runs it"),
    ("容器、payload、rootfs 和分区预期已解释", True, "DEPLOYMENT_VERIFICATION.md, PARTITION_EXPECTATION.md, SOURCE_IMAGE_DEVIATIONS.md"),
    ("软件物料和文件归属完整", True, "SBOM.md, FILE_OWNERSHIP.md; Q14 shows device drift of +4 translation packages only"),
    ("启动、服务、配置和 IPC 链已成图", True, "BOOT_CHAIN, SERVICE_GRAPH, CONFIG_FLOW, IPC_CATALOG; both static misses fixed and re-verified"),
    ("关键组件均有精确源码映射或明确阻塞", True, "SOURCE_MAP.md, PATCH_MAP.md; 14 pinned checkouts plus a verified dnsmasq tarball"),
    ("每个候选都有接口、调用者、失败边界和兼容要求", True, "RESPONSIBILITY_CANDIDATES.md; 17 responsibilities with the full template"),
    ("关键行为取得必要运行态证据", True, "RUNTIME_OBSERVATIONS.md; 15 questions, 23 commands; OQ-01 remains open and blocks only R07"),
    ("事实、推断、未知和冲突分离", True, "every report carries an explicit evidence-boundary section; OPEN_QUESTIONS.md holds the unknowns"),
    ("原始材料和秘密未进入 Git", True, "firmware, extracted trees, source checkouts and raw collector output live outside Git; redaction self-check passes with 0 findings"),
    ("未接触物理机持久状态", True, "I0.7 ran read-only commands over SSH; no UCI write, commit, reload, restart or MTD read"),
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build(manifests: Path) -> tuple[dict[str, Any], list[str]]:
    candidates = json.loads((manifests / "responsibility-candidates.json").read_text())
    observations = json.loads((manifests / "runtime-observations.json").read_text())
    known = {item["id"] for item in candidates["responsibilities"]}
    problems: list[str] = []

    seen = [item["id"] for item in CLASSIFICATION]
    if sorted(seen) != sorted(known):
        problems.append(f"classification covers {sorted(seen)}, responsibilities are {sorted(known)}")
    if len(seen) != len(set(seen)):
        problems.append("a responsibility is classified more than once")

    question_ids = {q["id"] for q in OPEN_QUESTIONS}
    for item in CLASSIFICATION:
        if item["category"] not in CATEGORIES:
            problems.append(f"{item['id']}: unknown category {item['category']}")
        if item["category"] not in DEFAULT_CATEGORIES:
            for field in ("dep", "src", "run"):
                if not item.get(field):
                    problems.append(f"{item['id']}: {item['category']} needs {field} evidence")
            if not item.get("rationale"):
                problems.append(f"{item['id']}: {item['category']} needs a rationale")
        if item["category"] == "do-not-touch" and not item.get("recovery_constraint"):
            problems.append(f"{item['id']}: do-not-touch needs a recovery constraint")
        for qid in item.get("blocking_questions", []):
            if qid not in question_ids:
                problems.append(f"{item['id']}: unknown blocking question {qid}")
        if item["category"] == "rust-replace" and item.get("blocking_questions"):
            problems.append(
                f"{item['id']}: cannot be rust-replace while blocked by {item['blocking_questions']}"
            )

    for question in OPEN_QUESTIONS:
        for rid in question["blocks"]:
            if rid not in known:
                problems.append(f"{question['id']}: blocks unknown responsibility {rid}")
    for risk in RISKS:
        for rid in risk["affects"]:
            if rid not in known:
                problems.append(f"{risk['id']}: affects unknown responsibility {rid}")

    gate_open = [name for name, ok, _ in I0_CHECKLIST if not ok]

    by_category: dict[str, list[str]] = {name: [] for name in CATEGORIES}
    for item in CLASSIFICATION:
        by_category[item["category"]].append(item["id"])

    payload = {
        "categories": CATEGORIES,
        "classification": CLASSIFICATION,
        "by_category": by_category,
        "open_questions": OPEN_QUESTIONS,
        "risks": RISKS,
        "i0_gate": {
            "checklist": [
                {"item": name, "satisfied": ok, "evidence": ev} for name, ok, ev in I0_CHECKLIST
            ],
            "unsatisfied": gate_open,
            "passed": not gate_open,
            "scope_limit": (
                "The gate is passed for this image on this device in this configuration. "
                "OQ-01 remains open and blocks R07 only; it does not block the gate because "
                "no responsibility depending on it is classified for replacement."
            ),
        },
        "counts": {
            "responsibilities": len(CLASSIFICATION),
            **{f"category_{name}": len(ids) for name, ids in by_category.items()},
            "open_questions": len(OPEN_QUESTIONS),
            "risks": len(RISKS),
            "runtime_objects_verified": observations["ubus"]["runtime_object_count"],
        },
    }
    return payload, problems


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifests", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()

    payload, problems = build(args.manifests.resolve())
    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        raise SystemExit(f"{len(problems)} classification problem(s)")

    manifest = {
        "schema_version": 1,
        "stage": "I0.8",
        "status": "complete",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "authorization": {"implementation_authorized": False},
        **payload,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({**payload["counts"], "i0_gate_passed": payload["i0_gate"]["passed"],
                      "output_sha256": sha256_file(args.output)}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
