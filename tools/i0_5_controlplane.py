#!/usr/bin/env python3
"""Build I0.5 boot chain, service graph, config flow, and IPC manifests.

The tool only reads an already extracted OpenWrt root filesystem and immutable
source checkouts.  It never executes target binaries or target scripts and
writes only derived JSON into the requested output directory.

Every extracted fact carries a file path, a file SHA-256 and, where the fact
comes from a specific statement, the logical line and its text.  Facts that a
static read cannot decide are recorded as open questions instead of guesses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations, keeping the first physical line number."""
    out: list[tuple[int, str]] = []
    pending: str | None = None
    start = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\n")
        if pending is None:
            start = number
            pending = line
        else:
            pending = pending[:-1] + " " + line.strip()
        if pending.endswith("\\"):
            continue
        out.append((start, pending))
        pending = None
    if pending is not None:
        out.append((start, pending))
    return out


def strip_comment(line: str) -> str:
    """Remove a trailing shell comment outside quotes.  Best effort only."""
    quote = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
            continue
        if char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def rootfs_path(root: Path, target: str) -> str:
    return "/" + str(target.relative_to(root)) if isinstance(target, Path) else target


def rel(root: Path, path: Path) -> str:
    return "/" + str(path.relative_to(root))


def evidence(path: str, line: int, text: str) -> dict[str, Any]:
    return {"path": path, "line": line, "text": text.strip()}


def sorted_unique(values: Iterable[str]) -> list[str]:
    return sorted({value for value in values if value})


# --------------------------------------------------------------------------
# shell script parsing
# --------------------------------------------------------------------------

ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
FUNCTION_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{?")
UBUS_CALL_RE = re.compile(r"\bubus\s+(?:-[A-Za-z]\s+\S+\s+)*(call|listen|send|subscribe|wait_for)\s+(\S+)(?:\s+(\S+))?")
UCI_VALIDATE_RE = re.compile(r"uci_validate_section\s+(\S+)\s+(\S+)")
CONFIG_LOAD_RE = re.compile(r"\b(?:config_load|reload_config|uci_load)\s+([A-Za-z0-9_.-]+)")
UCI_ACCESS_RE = re.compile(r"\buci(?:_[a-z_]+)?\s+(?:-[A-Za-z]\s+\S+\s+)*(?:get|set|add_list|del|delete|show|commit|revert|batch)?\s*['\"]?([A-Za-z0-9_-]+)[.'\"]")


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


class ShellScript:
    """A minimal, explicit reader for OpenWrt shell control-plane scripts."""

    def __init__(self, root: Path, path: Path) -> None:
        self.path = path
        self.rel = rel(root, path)
        self.text = read_text(path)
        self.sha256 = sha256_file(path)
        self.lines = [
            (number, strip_comment(line).strip())
            for number, line in logical_lines(self.text)
        ]
        self.assignments: dict[str, str] = {}
        self.functions: list[str] = []
        for number, line in self.lines:
            match = ASSIGN_RE.match(line)
            if match and " " not in match.group(1):
                self.assignments.setdefault(match.group(1), unquote(match.group(2)))
            match = FUNCTION_RE.match(line)
            if match:
                self.functions.append(match.group(1))

    def find(self, pattern: str) -> list[dict[str, Any]]:
        regex = re.compile(pattern)
        return [
            evidence(self.rel, number, line)
            for number, line in self.lines
            if regex.search(line)
        ]

    def expand(self, value: str) -> str:
        """Substitute plain $VAR and ${VAR} references defined in this script.

        Shell parameter expansions that carry an operator (``${x:-y}``,
        ``${x:1}``, ``${x:+...}``) are left verbatim: rewriting them would
        invent an argv that the image never produces.
        """
        seen = 0
        while seen < 4 and "$" in value:
            replaced = re.sub(
                r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))",
                lambda m: self.assignments.get(m.group(1) or m.group(2), m.group(0)),
                value,
            )
            if replaced == value:
                break
            value = replaced
            seen += 1
        return value


# --------------------------------------------------------------------------
# boot chain
# --------------------------------------------------------------------------

HOOK_ADD_RE = re.compile(r"boot_hook_add\s+(\S+)\s+(\S+)")
HOOK_INIT_RE = re.compile(r"boot_hook_init\s+(\S+)")
HOOK_RUN_RE = re.compile(r"boot_run_hook\s+(\S+)")
INITTAB_RE = re.compile(r"^([^:#]*):([^:]*):([^:]*):?(.*)$")


def build_boot_chain(root: Path, sources: Path) -> dict[str, Any]:
    preinit_entry = root / "etc/preinit"
    entry = ShellScript(root, preinit_entry)
    hook_namespaces = [
        {"hook": match.group(1), **evidence(entry.rel, number, line)}
        for number, line in entry.lines
        for match in [HOOK_INIT_RE.search(line)]
        if match
    ]
    hook_runs = [
        {"hook": match.group(1), **evidence(entry.rel, number, line)}
        for number, line in entry.lines
        for match in [HOOK_RUN_RE.search(line)]
        if match
    ]

    hook_files = []
    registrations: dict[str, list[dict[str, Any]]] = {}
    for path in sorted((root / "lib/preinit").iterdir()):
        if not path.is_file():
            continue
        script = ShellScript(root, path)
        adds = []
        for number, line in script.lines:
            match = HOOK_ADD_RE.search(line)
            if not match:
                continue
            record = {
                "hook": match.group(1),
                "function": match.group(2),
                "file": script.rel,
                "file_order": path.name,
                **evidence(script.rel, number, line),
            }
            adds.append(record)
            registrations.setdefault(match.group(1), []).append(record)
        hook_files.append(
            {
                "path": script.rel,
                "sha256": script.sha256,
                "defined_functions": script.functions,
                "hook_registrations": adds,
                "settings": script.assignments if path.name.endswith(".conf") else {},
            }
        )

    inittab_path = root / "etc/inittab"
    inittab = []
    for number, line in logical_lines(read_text(inittab_path)):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = INITTAB_RE.match(stripped)
        if match:
            inittab.append(
                {
                    "id": match.group(1),
                    "action": match.group(2),
                    "process": ":".join(filter(None, [match.group(3), match.group(4)])),
                    **evidence(rel(root, inittab_path), number, stripped),
                }
            )

    procd_state = []
    state_path = sources / "components/procd/state.c"
    state_text = read_text(state_path)
    for number, line in enumerate(state_text.splitlines(), start=1):
        match = re.match(r"\s*case (STATE_[A-Z]+):", line)
        if match:
            procd_state.append(
                {
                    "state": match.group(1),
                    **evidence("sources/components/procd/state.c", number, line),
                }
            )

    initd_exec = []
    for name in ("initd/init.c", "initd/preinit.c", "initd/early.c"):
        path = sources / "components/procd" / name
        text = read_text(path)
        for number, line in enumerate(text.splitlines(), start=1):
            if re.search(r"(char \*(argv|init|plug|kmod)\[\]|execvp?\(|setenv\(\"PREINIT)", line):
                initd_exec.append(evidence(f"sources/components/procd/{name}", number, line))

    rc_common = ShellScript(root, root / "etc/rc.common")
    rcS = ShellScript(root, root / "etc/init.d/rcS") if (root / "etc/init.d/rcS").is_file() else None

    boot_script = ShellScript(root, root / "etc/init.d/boot")
    boot_actions = [
        evidence(boot_script.rel, number, line)
        for number, line in boot_script.lines
        if re.search(r"(kmodloader|uci_apply_defaults|reload_config|/sbin/wifi|mount_root|/etc/board\.json)", line)
    ]

    return {
        "entry_point": {
            "kernel_init": "/etc/preinit is reached only when PREINIT is set; otherwise /sbin/init runs directly",
            "preinit_script": {
                "path": entry.rel,
                "sha256": entry.sha256,
                "hook_namespaces": hook_namespaces,
                "hook_runs": hook_runs,
            },
            "procd_initd_exec_evidence": initd_exec,
        },
        "preinit_hook_files": hook_files,
        "preinit_hook_registrations": {
            hook: sorted(items, key=lambda item: item["file_order"])
            for hook, items in sorted(registrations.items())
        },
        "procd_states": procd_state,
        "inittab": inittab,
        "rc_common": {
            "path": rc_common.rel,
            "sha256": rc_common.sha256,
            "defined_functions": rc_common.functions,
        },
        "rcS": None if rcS is None else {"path": rcS.rel, "sha256": rcS.sha256},
        "boot_service_actions": boot_actions,
    }


# --------------------------------------------------------------------------
# service graph
# --------------------------------------------------------------------------

PROCD_PARAM_RE = re.compile(r"procd_(?:set|append)_param\s+(\S+)\s*(.*)$")
TRIGGER_RE = re.compile(
    r"procd_add_(reload_trigger|config_trigger|interface_trigger|raw_trigger|mount_trigger|action_mount_trigger|reload_data_trigger|reload_interface_trigger|validation)\s*(.*)$"
)
JAIL_RE = re.compile(r"procd_add_jail(_mount|_mount_rw)?\s*(.*)$")
SIGNAL_RE = re.compile(r"procd_send_signal\s+(.*)$")


def parse_instances(script: ShellScript) -> list[dict[str, Any]]:
    instances: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for number, line in script.lines:
        if "procd_open_instance" in line:
            name = line.split("procd_open_instance", 1)[1].strip()
            current = {
                "declared_name": unquote(name) or None,
                "opened_at": evidence(script.rel, number, line),
                "params": [],
                "jail": [],
                "closed_at": None,
            }
            continue
        if "procd_close_instance" in line:
            if current is not None:
                current["closed_at"] = evidence(script.rel, number, line)
                instances.append(current)
                current = None
            continue
        if current is None:
            continue
        match = PROCD_PARAM_RE.search(line)
        if match:
            current["params"].append(
                {
                    "key": match.group(1),
                    "raw_value": match.group(2).strip(),
                    "expanded_value": script.expand(match.group(2).strip()),
                    "append": "procd_append_param" in line,
                    **evidence(script.rel, number, line),
                }
            )
            continue
        match = JAIL_RE.search(line)
        if match:
            current["jail"].append(
                {
                    "kind": "jail" + (match.group(1) or ""),
                    "raw_value": match.group(2).strip(),
                    **evidence(script.rel, number, line),
                }
            )
    if current is not None:
        current["unterminated"] = True
        instances.append(current)
    return instances


def build_service_graph(root: Path, executables: dict[str, Any]) -> dict[str, Any]:
    owner_by_path = {item["path"]: item for item in executables.get("init_services", [])}
    rc_links: dict[str, list[dict[str, Any]]] = {}
    for link in executables.get("rc_links", []):
        target = link.get("target_path") or link.get("target") or ""
        rc_links.setdefault(Path(target).name, []).append(link)

    services = []
    for path in sorted((root / "etc/init.d").iterdir()):
        if not path.is_file():
            continue
        script = ShellScript(root, path)
        owner = owner_by_path.get(script.rel, {})

        triggers = []
        for number, line in script.lines:
            match = TRIGGER_RE.search(line)
            if match:
                triggers.append(
                    {
                        "kind": match.group(1),
                        "raw_value": match.group(2).strip(),
                        **evidence(script.rel, number, line),
                    }
                )

        validations = [
            {
                "config": match.group(1),
                "section_type": unquote(match.group(2)),
                **evidence(script.rel, number, line),
            }
            for number, line in script.lines
            for match in [UCI_VALIDATE_RE.search(line)]
            if match
        ]

        ubus_calls = [
            {
                "verb": match.group(1),
                "object": match.group(2),
                "method": match.group(3),
                **evidence(script.rel, number, line),
            }
            for number, line in script.lines
            for match in [UBUS_CALL_RE.search(line)]
            if match
        ]

        signals = [
            {"raw_value": match.group(1).strip(), **evidence(script.rel, number, line)}
            for number, line in script.lines
            for match in [SIGNAL_RE.search(line)]
            if match
        ]

        instances = parse_instances(script)
        commands = []
        for instance in instances:
            for param in instance["params"]:
                if param["key"] == "command":
                    commands.append(param["expanded_value"])

        configs = sorted_unique(
            [unquote(item["config"]) for item in validations]
            + [unquote(match.group(1)) for _, line in script.lines for match in [CONFIG_LOAD_RE.search(line)] if match]
            + [
                unquote(word)
                for item in triggers
                if item["kind"] in ("reload_trigger", "reload_data_trigger")
                for word in item["raw_value"].split()
            ]
        )

        services.append(
            {
                "name": path.name,
                "path": script.rel,
                "sha256": script.sha256,
                "owner_package": owner.get("owner_package"),
                "source_key": owner.get("source_key"),
                "start": script.assignments.get("START"),
                "stop": script.assignments.get("STOP"),
                "uses_procd": script.assignments.get("USE_PROCD") == "1",
                "extra_commands": script.assignments.get("EXTRA_COMMANDS")
                or script.assignments.get("extra_commands"),
                "defined_functions": script.functions,
                "boot_enabled_links": sorted(
                    link["path"] for link in rc_links.get(path.name, [])
                ),
                "instances": instances,
                "instance_commands": sorted_unique(commands),
                "triggers": triggers,
                "validations": validations,
                "ubus_calls": ubus_calls,
                "procd_signals": signals,
                "referenced_configs": configs,
            }
        )

    ucitrack_dir = root / "usr/share/ucitrack"
    ucitrack = []
    if ucitrack_dir.is_dir():
        for path in sorted(ucitrack_dir.iterdir()):
            if not path.is_file():
                continue
            payload = json.loads(read_text(path))
            ucitrack.append(
                {
                    "path": rel(root, path),
                    "sha256": sha256_file(path),
                    "entries": payload if isinstance(payload, list) else [payload],
                }
            )

    return {
        "services": services,
        "ucitrack_registrations": ucitrack,
        "counts": {
            "init_scripts": len(services),
            "procd_services": sum(1 for item in services if item["uses_procd"]),
            "declared_instances": sum(len(item["instances"]) for item in services),
            "triggers": sum(len(item["triggers"]) for item in services),
            "validations": sum(len(item["validations"]) for item in services),
            "ucitrack_files": len(ucitrack),
        },
    }


# --------------------------------------------------------------------------
# config flow
# --------------------------------------------------------------------------

UCI_SECTION_RE = re.compile(r"^\s*config\s+(\S+)(?:\s+'?\"?([^'\"]+)'?\"?)?")
UCI_OPTION_RE = re.compile(r"^\s*(option|list)\s+(\S+)")

CONFIG_SCAN_DIRS = (
    "etc/init.d",
    "etc/uci-defaults",
    "etc/hotplug.d",
    "etc/board.d",
    "lib/preinit",
    "lib/functions",
    "lib/netifd",
    "lib/wifi",
    "usr/share/rpcd",
    "usr/libexec",
    "usr/lib/lua",
    "usr/share/ucode",
    "sbin",
    "bin",
    "usr/sbin",
    "usr/bin",
)


def parse_uci_config(root: Path, path: Path) -> dict[str, Any]:
    sections = []
    current: dict[str, Any] | None = None
    for number, line in logical_lines(read_text(path)):
        match = UCI_SECTION_RE.match(line)
        if match:
            current = {
                "type": match.group(1),
                "name": (match.group(2) or "").strip() or None,
                "line": number,
                "options": [],
            }
            sections.append(current)
            continue
        match = UCI_OPTION_RE.match(line)
        if match and current is not None:
            current["options"].append({"kind": match.group(1), "name": match.group(2)})
    return {
        "path": rel(root, path),
        "sha256": sha256_file(path),
        "sections": sections,
    }


def scan_config_consumers(root: Path, package_names: Iterable[str]) -> dict[str, list[dict[str, Any]]]:
    patterns = {
        name: re.compile(r"(?<![A-Za-z0-9_./-])" + re.escape(name) + r"(?![A-Za-z0-9_-])")
        for name in package_names
    }
    consumers: dict[str, list[dict[str, Any]]] = {name: [] for name in patterns}
    for directory in CONFIG_SCAN_DIRS:
        base = root / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:4096]:
                continue
            text = data.decode("utf-8", errors="replace")
            if "config" not in text and "uci" not in text:
                continue
            file_rel = rel(root, path)
            for number, line in logical_lines(text):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not re.search(r"\b(uci|config_load|config_get|config_foreach|cursor|reload_config|ucitrack)\b", stripped):
                    continue
                for name, pattern in patterns.items():
                    if pattern.search(stripped):
                        consumers[name].append(evidence(file_rel, number, stripped))
    return consumers


def build_config_flow(root: Path, executables: dict[str, Any]) -> dict[str, Any]:
    owner_by_path = {}
    for group in ("scripts", "elf_files", "executable_regular_files"):
        for item in executables.get(group, []) or []:
            if isinstance(item, dict) and "path" in item:
                owner_by_path.setdefault(item["path"], item)
    for group in executables.get("control_plane_files", {}).values():
        for item in group if isinstance(group, list) else []:
            if isinstance(item, dict) and "path" in item:
                owner_by_path.setdefault(item["path"], item)

    deployed = []
    for path in sorted((root / "etc/config").iterdir()):
        if not path.is_file():
            continue
        record = parse_uci_config(root, path)
        record["owner_package"] = owner_by_path.get(record["path"], {}).get("owner_package")
        deployed.append(record)
    deployed_names = [Path(item["path"]).name for item in deployed]

    uci_defaults = []
    for path in sorted((root / "etc/uci-defaults").iterdir()):
        if not path.is_file():
            continue
        script = ShellScript(root, path)
        uci_defaults.append(
            {
                "path": script.rel,
                "sha256": script.sha256,
                "owner_package": owner_by_path.get(script.rel, {}).get("owner_package"),
                "uci_statements": script.find(r"\buci\b"),
                "touched_configs": sorted_unique(
                    match.group(1)
                    for _, line in script.lines
                    for match in [UCI_ACCESS_RE.search(line)]
                    if match
                ),
                "self_deleting": bool(script.find(r"\bexit 0\b")),
            }
        )

    board_d = []
    for path in sorted((root / "etc/board.d").iterdir()) if (root / "etc/board.d").is_dir() else []:
        if not path.is_file():
            continue
        script = ShellScript(root, path)
        board_d.append(
            {
                "path": script.rel,
                "sha256": script.sha256,
                "owner_package": owner_by_path.get(script.rel, {}).get("owner_package"),
                "defined_functions": script.functions,
                "board_config_statements": script.find(r"(ucidef_|board_config_)"),
            }
        )

    generators = []
    for candidate in (
        "bin/config_generate",
        "sbin/reload_config",
        "sbin/wifi",
        "etc/init.d/boot",
        "lib/functions/uci-defaults.sh",
        "lib/functions/migrations.sh",
        "etc/hotplug.d/ieee80211/10-wifi-detect",
        "etc/hotplug.d/ieee80211/05-wifi-migrate",
    ):
        path = root / candidate
        if not path.is_file():
            continue
        script = ShellScript(root, path)
        generators.append(
            {
                "path": script.rel,
                "sha256": script.sha256,
                "owner_package": owner_by_path.get(script.rel, {}).get("owner_package"),
                "writes_config_evidence": script.find(
                    r"(/etc/config/|uci -q|uci_(set|add|commit)|ucidef_|json_init|board\.json)"
                )[:40],
            }
        )

    referenced = set(deployed_names)
    for name in ("network", "system", "wireless", "ucitrack", "fstab", "luci", "dhcp", "firewall"):
        referenced.add(name)
    consumers = scan_config_consumers(root, sorted(referenced))

    packages = []
    for name in sorted(referenced):
        deployed_record = next(
            (item for item in deployed if Path(item["path"]).name == name), None
        )
        packages.append(
            {
                "config": name,
                "shipped_in_image": deployed_record is not None,
                "path": deployed_record["path"] if deployed_record else f"/etc/config/{name}",
                "sha256": deployed_record["sha256"] if deployed_record else None,
                "owner_package": deployed_record["owner_package"] if deployed_record else None,
                "section_types": sorted_unique(
                    section["type"] for section in (deployed_record or {}).get("sections", [])
                ),
                "consumer_evidence_count": len(consumers.get(name, [])),
                "consumer_files": sorted_unique(
                    item["path"] for item in consumers.get(name, [])
                ),
            }
        )

    return {
        "deployed_configs": deployed,
        "config_packages": packages,
        "uci_defaults": uci_defaults,
        "board_d": board_d,
        "generators": generators,
        "consumer_evidence": consumers,
        "counts": {
            "deployed_configs": len(deployed),
            "config_packages_tracked": len(packages),
            "uci_defaults": len(uci_defaults),
            "board_d_scripts": len(board_d),
            "generators": len(generators),
        },
    }


# --------------------------------------------------------------------------
# IPC catalog
# --------------------------------------------------------------------------

UBUS_OBJECT_RE = re.compile(r"struct ubus_object\s+(\w+)\s*=\s*\{")
UBUS_NAME_RE = re.compile(r"\.name\s*=\s*\"([^\"]+)\"")
UBUS_TYPE_RE = re.compile(r"\.type\s*=\s*&(\w+)")
UBUS_METHODS_FIELD_RE = re.compile(r"\.methods\s*=\s*(\w+)")
UBUS_OBJECT_TYPE_RE = re.compile(r"(\w+)\s*=\s*\n?\s*UBUS_OBJECT_TYPE\(\"([^\"]+)\",\s*(\w+)\)")
UBUS_METHOD_TABLE_RE = re.compile(r"struct ubus_method\s+(\w+)\s*\[\]\s*=\s*\{")
UBUS_METHOD_ENTRY_RE = re.compile(
    r"UBUS_METHOD(?:_NOARG|_TAG|_MASK)?\(\s*\"([^\"]+)\"|\{\s*\.name\s*=\s*\"([^\"]+)\""
)


def parse_c_ubus(path: Path, label: str) -> dict[str, Any]:
    text = read_text(path)
    lines = text.splitlines()

    method_tables: dict[str, dict[str, Any]] = {}
    for match in UBUS_METHOD_TABLE_RE.finditer(text):
        start_line = text[: match.start()].count("\n") + 1
        depth = 0
        methods: list[str] = []
        for index in range(start_line - 1, len(lines)):
            line = lines[index]
            depth += line.count("{") - line.count("}")
            for entry in UBUS_METHOD_ENTRY_RE.finditer(line):
                methods.append(entry.group(1) or entry.group(2))
            if index > start_line - 1 and depth <= 0:
                break
        method_tables[match.group(1)] = {
            "methods": methods,
            "line": start_line,
        }

    object_types: dict[str, dict[str, str]] = {}
    for match in re.finditer(r"(\w+)\s*=\s*UBUS_OBJECT_TYPE\(\"([^\"]+)\",\s*(\w+)\)", text.replace("\n", " ")):
        object_types[match.group(1)] = {
            "type_name": match.group(2),
            "method_table": match.group(3),
        }

    objects = []
    for match in UBUS_OBJECT_RE.finditer(text):
        start_line = text[: match.start()].count("\n") + 1
        block: list[str] = []
        depth = 0
        for index in range(start_line - 1, len(lines)):
            line = lines[index]
            block.append(line)
            depth += line.count("{") - line.count("}")
            if index > start_line - 1 and depth <= 0:
                break
        block_text = "\n".join(block)
        name_match = UBUS_NAME_RE.search(block_text)
        type_match = UBUS_TYPE_RE.search(block_text)
        methods_match = UBUS_METHODS_FIELD_RE.search(block_text)
        table = None
        if methods_match:
            table = methods_match.group(1)
        elif type_match and type_match.group(1) in object_types:
            table = object_types[type_match.group(1)]["method_table"]
        objects.append(
            {
                "variable": match.group(1),
                "object_name": name_match.group(1) if name_match else None,
                "object_type": object_types.get(type_match.group(1), {}).get("type_name")
                if type_match
                else None,
                "method_table": table,
                "methods": method_tables.get(table, {}).get("methods", []),
                "source": f"{label}:{start_line}",
            }
        )
    return {"objects": objects, "method_tables": sorted(method_tables)}


UBUS_SOURCE_UNITS = {
    "procd": [
        "components/procd/service/service.c",
        "components/procd/system.c",
        "components/procd/hotplug-dispatch.c",
    ],
    "netifd": ["components/netifd/ubus.c"],
    "rpcd": [
        "components/rpcd/session.c",
        "components/rpcd/uci.c",
        "components/rpcd/rc.c",
        "components/rpcd/file.c",
        "components/rpcd/iwinfo.c",
        "components/rpcd/sys.c",
    ],
    "odhcpd": ["components/odhcpd/src/ubus.c"],
    "rpcd-mod-luci": ["luci/libs/rpcd-mod-luci/src/luci.c"],
    "rpcd-mod-rrdns": ["luci/libs/rpcd-mod-rrdns/src/rrdns.c"],
    "ubox-log": ["components/ubox/log/logd.c"],
    "dnsmasq": ["components/dnsmasq/src/ubus.c"],
    "odhcp6c": ["components/odhcp6c/src/ubus.c"],
}

# Which deployed artifact provides each source unit.  Recorded so a source-only
# object is never reported as a deployed interface.
UBUS_UNIT_ARTIFACT = {
    "components/procd/service/service.c": "/sbin/procd",
    "components/procd/system.c": "/sbin/procd",
    "components/procd/hotplug-dispatch.c": "/sbin/procd",
    "components/netifd/ubus.c": "/sbin/netifd",
    "components/rpcd/session.c": "/sbin/rpcd",
    "components/rpcd/uci.c": "/sbin/rpcd",
    "components/rpcd/rc.c": "/sbin/rpcd",
    "components/rpcd/file.c": "/usr/lib/rpcd/file.so",
    "components/rpcd/iwinfo.c": "/usr/lib/rpcd/iwinfo.so",
    "components/rpcd/sys.c": "/usr/lib/rpcd/rpcsys.so",
    "components/odhcpd/src/ubus.c": "/usr/sbin/odhcpd",
    "luci/libs/rpcd-mod-luci/src/luci.c": "/usr/lib/rpcd/luci.so",
    "luci/libs/rpcd-mod-rrdns/src/rrdns.c": "/usr/lib/rpcd/rrdns.so",
    "components/ubox/log/logd.c": "/sbin/logd",
    "components/dnsmasq/src/ubus.c": "/usr/sbin/dnsmasq",
    "components/odhcp6c/src/ubus.c": "/usr/sbin/odhcp6c",
}

# ubus objects whose published name is computed at run time.  The naming rule is
# static evidence; the concrete instance names are not, so each entry states the
# rule and leaves enumeration to a run-time observation.
DYNAMIC_UBUS_OBJECTS = [
    {
        "name_rule": "network.interface.<interface name from /etc/config/network>",
        "component": "netifd",
        "deployed_artifact": "/sbin/netifd",
        "source_unit": "sources/components/netifd/ubus.c",
        "source_symbol": "netifd_ubus_add_interface",
        "resolved_statically": False,
    },
    {
        "name_rule": "hotplug.<subsystem registered by procd>",
        "component": "procd",
        "deployed_artifact": "/sbin/procd",
        "source_unit": "sources/components/procd/hotplug-dispatch.c",
        "source_symbol": "add_subsystem / HOTPLUG_OBJECT_PREFIX",
        "resolved_statically": False,
    },
    {
        "name_rule": "container (registered only when procd runs the ujail container path)",
        "component": "procd",
        "deployed_artifact": "/sbin/ujail",
        "source_unit": "sources/components/procd/jail/jail.c",
        "source_symbol": "container_object",
        "resolved_statically": False,
    },
    {
        "name_rule": "dnsmasq instance name from --ubus option, default DNSMASQ_UBUS_NAME",
        "component": "dnsmasq",
        "deployed_artifact": "/usr/sbin/dnsmasq",
        "source_unit": "sources/components/dnsmasq/src/ubus.c",
        "source_symbol": "ubus_object.name = daemon->ubus_name",
        "resolved_statically": False,
    },
    {
        "name_rule": "odhcp6c.<interface>",
        "component": "odhcp6c",
        "deployed_artifact": "/usr/sbin/odhcp6c",
        "source_unit": "sources/components/odhcp6c/src/ubus.c",
        "source_symbol": "snprintf(ubus_name, 24, \"odhcp6c.%s\", interface)",
        "resolved_statically": False,
    },
    {
        "name_rule": "wpa_supplicant.<ifname>",
        "component": "wpad",
        "deployed_artifact": "/usr/share/hostap/wpa_supplicant.uc",
        "source_unit": "deployed ucode",
        "source_symbol": "ubus.publish(`wpa_supplicant.${ifname}`)",
        "resolved_statically": False,
    },
]

# Deployed script trees that publish or consume ubus objects from ucode.
UCODE_SCAN_DIRS = ("lib/netifd", "usr/share/hostap", "usr/share/rpcd", "usr/share/ucode", "usr/libexec")

# Which deployed binary loads a ucode tree.  The pairing is only recorded when
# the binary's own string data names the script path, so the link is DEP-backed.
UCODE_HOST_ARTIFACTS = {
    "/lib/netifd": "/sbin/netifd",
    "/usr/share/hostap": "/usr/sbin/wpad",
}
UCODE_PUBLISH_RE = re.compile(r"""\.publish\(\s*[`'"]([^`'"]+)[`'"]""")

# rpcd's ucode plugin loader names each ubus object after a top-level key of the
# object the script returns, not after the file name.
RPCD_UCODE_RETURN_RE = re.compile(r"^return\s*\{\s*([^}]*)\};?\s*$")
RPCD_UCODE_KEY_RE = re.compile(r"^['\"]?([A-Za-z_][A-Za-z0-9_.-]*)['\"]?$")


UBUS_ENTRY_POINTS = ("ubus_add_object", "ubus_connect", "ubus_invoke", "ubus_register_subscriber")


def classify_ubus_role(path: Path) -> list[str]:
    """Report which libubus entry-point names occur in an artifact's bytes.

    Section headers are stripped in this image, so the dynamic symbol table
    cannot be walked with section-based tooling.  The dynamic string data is
    still present, so a byte search reports the linked interface honestly
    without claiming the call is reached at run time.
    """
    if not path.is_file():
        return []
    data = path.read_bytes()
    return [name for name in UBUS_ENTRY_POINTS if name.encode() in data]


def build_ipc_catalog(root: Path, sources: Path, executables: dict[str, Any]) -> dict[str, Any]:
    deployed_paths = {
        item["path"]
        for group in ("elf_files", "executable_regular_files", "scripts")
        for item in executables.get(group, []) or []
        if isinstance(item, dict) and "path" in item
    }

    ubus_objects = []
    for component, units in UBUS_SOURCE_UNITS.items():
        for unit in units:
            path = sources / unit
            if not path.is_file():
                continue
            parsed = parse_c_ubus(path, f"sources/{unit}")
            artifact = UBUS_UNIT_ARTIFACT.get(unit)
            for obj in parsed["objects"]:
                obj["component"] = component
                obj["source_unit"] = f"sources/{unit}"
                obj["source_sha256"] = sha256_file(path)
                obj["deployed_artifact"] = artifact
                obj["artifact_present_in_image"] = artifact in deployed_paths
                ubus_objects.append(obj)

    ucode_publishers = []
    for directory in UCODE_SCAN_DIRS:
        base = root / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="strict")
            except (UnicodeDecodeError, OSError):
                continue
            if ".publish(" not in text:
                continue
            file_rel = rel(root, path)
            file_hash = sha256_file(path)
            for number, line in logical_lines(text):
                for match in UCODE_PUBLISH_RE.finditer(line):
                    literal = match.group(1)
                    ucode_publishers.append(
                        {
                            "object_name": literal,
                            "name_is_literal": "${" not in literal,
                            "path": file_rel,
                            "sha256": file_hash,
                            "line": number,
                            "text": line.strip(),
                        }
                    )

    ubus_linked_artifacts = sorted(
        {
            item["path"]
            for item in executables.get("elf_files", []) or []
            if any(
                need.startswith("libubus.so")
                for need in (item.get("elf", {}) or {}).get("needed", []) or []
            )
        }
    )
    artifacts_with_resolved_objects = {
        item["deployed_artifact"] for item in ubus_objects if item["deployed_artifact"]
    } | {item["deployed_artifact"] for item in DYNAMIC_UBUS_OBJECTS}
    ucode_publisher_files = {item["path"] for item in ucode_publishers}
    ucode_hosts = []
    for directory, artifact in sorted(UCODE_HOST_ARTIFACTS.items()):
        published = sorted(
            {item["path"] for item in ucode_publishers if item["path"].startswith(directory + "/")}
        )
        if not published:
            continue
        binary = root / artifact.lstrip("/")
        confirmed = binary.is_file() and directory.encode() in binary.read_bytes()
        ucode_hosts.append(
            {
                "artifact": artifact,
                "ucode_directory": directory,
                "publisher_files": published,
                "artifact_string_references_directory": confirmed,
            }
        )
        if confirmed:
            artifacts_with_resolved_objects.add(artifact)

    acl_files = []
    acl_dir = root / "usr/share/rpcd/acl.d"
    for path in sorted(acl_dir.iterdir()) if acl_dir.is_dir() else []:
        if not path.is_file():
            continue
        payload = json.loads(read_text(path))
        scopes = []
        for group_name, group in payload.items():
            if not isinstance(group, dict):
                continue
            for access in ("read", "write"):
                block = group.get(access) or {}
                for scope, entries in block.items():
                    if isinstance(entries, dict):
                        for target, methods in entries.items():
                            scopes.append(
                                {
                                    "group": group_name,
                                    "access": access,
                                    "scope": scope,
                                    "target": target,
                                    "methods": methods if isinstance(methods, list) else [methods],
                                }
                            )
                    elif isinstance(entries, list):
                        scopes.append(
                            {
                                "group": group_name,
                                "access": access,
                                "scope": scope,
                                "target": None,
                                "methods": entries,
                            }
                        )
        acl_files.append(
            {
                "path": rel(root, path),
                "sha256": sha256_file(path),
                "groups": sorted(payload),
                "scopes": scopes,
            }
        )

    # ubusd's own ACL layer, distinct from the rpcd session ACL above.  It binds
    # publish / send / subscribe / access rights to a unix user or group.
    ubusd_acl = []
    ubusd_acl_dir = root / "usr/share/acl.d"
    for path in sorted(ubusd_acl_dir.iterdir()) if ubusd_acl_dir.is_dir() else []:
        if not path.is_file():
            continue
        payload = json.loads(read_text(path))
        entries = payload if isinstance(payload, list) else [payload]
        for entry in entries:
            ubusd_acl.append(
                {
                    "path": rel(root, path),
                    "sha256": sha256_file(path),
                    "user": entry.get("user"),
                    "group": entry.get("group"),
                    "publish": entry.get("publish", []),
                    "subscribe": entry.get("subscribe", []),
                    "send": entry.get("send", []),
                    "access": {
                        obj: spec.get("methods", [])
                        for obj, spec in (entry.get("access") or {}).items()
                    },
                }
            )

    plugins = []
    plugin_dir = root / "usr/lib/rpcd"
    for path in sorted(plugin_dir.iterdir()) if plugin_dir.is_dir() else []:
        if not path.is_file():
            continue
        plugins.append({"path": rel(root, path), "sha256": sha256_file(path)})
    ucode_plugin_dir = root / "usr/share/rpcd/ucode"
    ucode_plugins = []
    for path in sorted(ucode_plugin_dir.rglob("*")) if ucode_plugin_dir.is_dir() else []:
        if not path.is_file():
            continue
        text = read_text(path)
        names: list[dict[str, Any]] = []
        for number, line in logical_lines(text):
            match = RPCD_UCODE_RETURN_RE.match(line)
            if not match:
                continue
            for part in match.group(1).split(","):
                # `{ name: value }` declares the object; `{ name }` is shorthand
                # for the same key.  Anything else is not an object declaration.
                key = part.split(":", 1)[0].strip()
                name = RPCD_UCODE_KEY_RE.match(key)
                if name:
                    names.append({"object_name": name.group(1), "line": number})
        ucode_plugins.append(
            {
                "path": rel(root, path),
                "sha256": sha256_file(path),
                "registered_objects": names,
            }
        )

    socket_evidence: list[dict[str, Any]] = []
    for candidate in (
        "etc/config/rpcd",
        "etc/config/uhttpd",
        "etc/init.d/rpcd",
        "etc/init.d/uhttpd",
        "etc/init.d/log",
        "etc/init.d/dnsmasq",
        "etc/init.d/odhcpd",
        "usr/libexec/login.sh",
    ):
        path = root / candidate
        if not path.is_file():
            continue
        script = ShellScript(root, path)
        socket_evidence.extend(script.find(r"(\.sock|/var/run/[A-Za-z0-9_.-]+|-U\b|socket)"))

    ubusd_defaults = []
    ubusd_source = sources / "components/ubus/ubusd.c"
    if ubusd_source.is_file():
        text = read_text(ubusd_source)
        for number, line in enumerate(text.splitlines(), start=1):
            if re.search(r"(UBUS_UNIX_SOCKET|usock|chmod|umask|ubus_socket)", line):
                ubusd_defaults.append(evidence("sources/components/ubus/ubusd.c", number, line))

    hotplug_dirs = []
    hotplug_root = root / "etc/hotplug.d"
    for path in sorted(hotplug_root.rglob("*")) if hotplug_root.is_dir() else []:
        if path.is_file():
            script = ShellScript(root, path)
            hotplug_dirs.append(
                {
                    "path": script.rel,
                    "subsystem": path.parent.name,
                    "sha256": script.sha256,
                    "environment_reads": sorted_unique(
                        re.findall(r"\$\{?(ACTION|INTERFACE|DEVICE|DEVICENAME|DEVPATH|SUBSYSTEM|PHYNBR|FIRMWARE|BUTTON|SEEN|IFNAME)\b", script.text)
                    ),
                }
            )

    hotplug_json = root / "etc/hotplug.json"
    hotplug_rules = None
    if hotplug_json.is_file():
        payload = json.loads(read_text(hotplug_json))
        hotplug_rules = {
            "path": rel(root, hotplug_json),
            "sha256": sha256_file(hotplug_json),
            "top_level_rules": len(payload) if isinstance(payload, list) else None,
        }

    netlink_evidence = []
    for unit, label in (
        ("components/netifd", "netifd"),
        ("components/odhcpd", "odhcpd"),
        ("components/procd", "procd"),
    ):
        base = sources / unit
        if not base.is_dir():
            continue
        hits: dict[str, int] = {}
        for path in base.rglob("*.c"):
            text = read_text(path)
            for family in (
                "NETLINK_ROUTE",
                "NETLINK_KOBJECT_UEVENT",
                "NETLINK_NETFILTER",
                "NETLINK_GENERIC",
                "genl_",
                "nl80211",
                "rtnl",
            ):
                if family in text:
                    hits[family] = hits.get(family, 0) + text.count(family)
        netlink_evidence.append({"component": label, "symbol_occurrences": hits})

    literal_objects = {
        name
        for entry in ubusd_acl
        for name in entry["publish"]
        if not name.endswith("*")
    } | {
        item["object_name"] for item in ubus_objects if item["object_name"]
    } | {
        item["object_name"] for item in ucode_publishers if item["name_is_literal"]
    } | {
        name["object_name"]
        for plugin in ucode_plugins
        for name in plugin["registered_objects"]
    }
    dynamic_prefixes = [
        rule["name_rule"].split("<", 1)[0]
        for rule in DYNAMIC_UBUS_OBJECTS
        if "<" in rule["name_rule"]
    ]

    def acl_target_has_provider(target: str) -> bool:
        probe = target.rstrip("*")
        candidates = {target, probe, probe.rstrip(".")}
        if candidates & literal_objects:
            return True
        if any(name.startswith(probe) for name in literal_objects):
            return True
        return any(
            probe.startswith(prefix) or prefix.startswith(probe)
            for prefix in dynamic_prefixes
            if prefix
        )

    acl_ubus_targets = sorted(
        {
            scope["target"]
            for item in acl_files
            for scope in item["scopes"]
            if scope["scope"] == "ubus" and scope["target"]
        }
    )
    acl_coverage = [
        {"target": target, "has_deployed_provider": acl_target_has_provider(target)}
        for target in acl_ubus_targets
    ]

    return {
        "ubus_objects": ubus_objects,
        "ubus_objects_from_deployed_ucode": ucode_publishers,
        "ubus_dynamic_objects": DYNAMIC_UBUS_OBJECTS,
        "ubus_linked_artifacts": [
            {
                "path": path,
                "dynamic_symbol_names": classify_ubus_role(root / path.lstrip("/")),
                "has_resolved_object_set": path in artifacts_with_resolved_objects,
            }
            for path in ubus_linked_artifacts
        ],
        "ubus_role_note": (
            "dynamic_symbol_names records which libubus entry-point names appear in the "
            "stripped artifact's dynamic string data.  It shows the linked interface, not "
            "that the code path runs on this device."
        ),
        "ucode_publisher_files": sorted(ucode_publisher_files),
        "ucode_object_hosts": ucode_hosts,
        "ubus_socket_evidence": {
            "ubusd_source_statements": ubusd_defaults,
            "consumer_statements": socket_evidence,
        },
        "ubusd_acl": ubusd_acl,
        "rpcd": {
            "acl_files": acl_files,
            "acl_ubus_target_coverage": acl_coverage,
            "binary_plugins": plugins,
            "ucode_plugins": ucode_plugins,
        },
        "hotplug": {
            "procd_rules": hotplug_rules,
            "script_handlers": hotplug_dirs,
        },
        "netlink_symbol_evidence": netlink_evidence,
        "counts": {
            "ubus_objects_source": len(ubus_objects),
            "ubus_objects_with_deployed_artifact": sum(
                1 for item in ubus_objects if item["artifact_present_in_image"]
            ),
            "ubus_objects_from_deployed_ucode": len(ucode_publishers),
            "ubus_dynamic_object_rules": len(DYNAMIC_UBUS_OBJECTS),
            "ubus_linked_artifacts": len(ubus_linked_artifacts),
            "ubus_linked_artifacts_without_resolved_objects": sum(
                1 for path in ubus_linked_artifacts if path not in artifacts_with_resolved_objects
            ),
            "ubusd_acl_entries": len(ubusd_acl),
            "rpcd_acl_files": len(acl_files),
            "rpcd_acl_ubus_targets": len(acl_coverage),
            "rpcd_acl_ubus_targets_without_provider": sum(
                1 for item in acl_coverage if not item["has_deployed_provider"]
            ),
            "rpcd_binary_plugins": len(plugins),
            "hotplug_handlers": len(hotplug_dirs),
        },
    }


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--executables", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()

    root = args.rootfs.resolve()
    sources = args.sources.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if output == root or root in output.parents:
        raise SystemExit("output directory must be outside the extracted root filesystem")

    executables = json.loads(read_text(args.executables))

    header = {
        "schema_version": 1,
        "stage": "I0.5",
        "status": "complete",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "method": {
            "reads_only": True,
            "executes_target_content": False,
            "rootfs": "extracted squashfs root, read-only",
            "sources": "pinned OpenWrt buildroot, feeds and component checkouts",
        },
    }

    outputs = {
        "boot-chain.json": {**header, **build_boot_chain(root, sources)},
        "service-graph.json": {**header, **build_service_graph(root, executables)},
        "config-flow.json": {**header, **build_config_flow(root, executables)},
        "ipc-catalog.json": {**header, **build_ipc_catalog(root, sources, executables)},
    }
    for filename, payload in outputs.items():
        (output / filename).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    summary = {
        "boot_chain": {
            "preinit_hook_files": len(outputs["boot-chain.json"]["preinit_hook_files"]),
            "hook_namespaces": len(outputs["boot-chain.json"]["entry_point"]["preinit_script"]["hook_namespaces"]),
            "inittab_entries": len(outputs["boot-chain.json"]["inittab"]),
        },
        "service_graph": outputs["service-graph.json"]["counts"],
        "config_flow": outputs["config-flow.json"]["counts"],
        "ipc_catalog": outputs["ipc-catalog.json"]["counts"],
        "output_sha256": {name: sha256_file(output / name) for name in outputs},
    }
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
