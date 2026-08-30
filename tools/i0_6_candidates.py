#!/usr/bin/env python3
"""Build the I0.6 responsibility candidate table and runtime question list.

The responsibility and question declarations live in this file.  Everything
that can be derived is joined from the I0.5 manifests instead of being retyped,
so the two stay consistent and a change in I0.5 shows up here as a validation
failure rather than as silent drift.

The tool reads manifests only.  It never contacts a device and never emits a
runnable collector: an approved command list is data, not an executable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


# --------------------------------------------------------------------------
# responsibility declarations
#
# `provides` / `consumes` name ubus objects; `configs` name UCI packages;
# `artifacts` name deployed files.  Each is checked against the I0.5 manifests.
# --------------------------------------------------------------------------

RESPONSIBILITIES: list[dict[str, Any]] = [
    {
        "id": "R01",
        "responsibility": "service supervision and process lifecycle",
        "current_implementation": "procd",
        "artifacts": ["/sbin/procd", "/sbin/init", "/sbin/ujail"],
        "init_services": [],
        "configs": [],
        "provides": ["service", "system"],
        "provides_runtime_named": [
            "container (registered only when procd runs the ujail container path)",
            "hotplug.<subsystem registered by procd>",
        ],
        "consumes": [],
        "persistent_side_effects": "none of its own; owns child process state and /var/run pidfiles",
        "timing_notes": "runqueue-ordered rcS; respawn windows per instance; watchdog kicked from STATE_EARLY",
        "failure_boundary": "PID 1. Failure is a device reboot.",
        "compatibility_requirements": [
            "ubus service object method set and blobmsg policy",
            "instance definition semantics including respawn, watch, netdev, file, limits",
            "trigger registration and delivery ordering",
            "inittab handler set and built-in rcS",
        ],
        "recovery": "none in-band; failure requires bootloader or power cycle",
    },
    {
        "id": "R02",
        "responsibility": "init script framework and service definition",
        "current_implementation": "/etc/rc.common + /lib/functions/procd.sh shell",
        "artifacts": ["/etc/rc.common", "/lib/functions/procd.sh", "/lib/functions/service.sh"],
        "init_services": ["*"],
        "configs": [],
        "provides": [],
        "consumes": ["service"],
        "persistent_side_effects": "creates and removes /etc/rc.d symlinks on enable/disable",
        "timing_notes": "synchronous shell; reload semantics differ per service",
        "failure_boundary": "one service per invocation; a failing script leaves procd definition unchanged",
        "compatibility_requirements": [
            "START/STOP ordering and rc.d link naming",
            "reload falling back to start when reload_service is undefined",
            "EXTRA_COMMANDS surface",
            "validate section registration",
        ],
        "recovery": "re-run the init script; no automatic rollback",
    },
    {
        "id": "R03",
        "responsibility": "boot orchestration and early root filesystem setup",
        "current_implementation": "procd initd + /etc/preinit + /lib/preinit hooks",
        "artifacts": ["/sbin/init", "/etc/preinit", "/sbin/mount_root", "/sbin/kmodloader"],
        "init_services": ["boot", "done"],
        "configs": [],
        "provides": [],
        "consumes": [],
        "persistent_side_effects": "mounts overlay; restores sysupgrade.tgz; writes /etc/board.json and first UCI set",
        "timing_notes": "strictly sequential hook order; failsafe window is 4 s by 00_preinit.conf",
        "failure_boundary": "whole device; a failure here yields an unbootable or failsafe-only system",
        "compatibility_requirements": [
            "hook namespace names and execution order",
            "overlay mount and config restore behaviour",
            "kernel command line consumption in 80_mount_root",
        ],
        "recovery": "failsafe mode and TFTP/bootloader recovery only",
    },
    {
        "id": "R04",
        "responsibility": "configuration storage and transactions",
        "current_implementation": "uci / libuci",
        "artifacts": ["/sbin/uci", "/lib/libuci.so.20250120"],
        "init_services": [],
        "configs": ["*"],
        "provides": [],
        "consumes": [],
        "persistent_side_effects": "writes /etc/config/*; session deltas in /tmp/.uci and /var/run/uci",
        "timing_notes": "no cross-process write lock; shell, ucode and C writers coexist",
        "failure_boundary": "one config package per commit; partial writes possible on power loss",
        "compatibility_requirements": [
            "unknown option preservation on read-modify-write",
            "section ordering and anonymous section naming",
            "changes/revert/commit semantics against the delta directory",
            "exact uci show output shape, because reload_config compares it",
        ],
        "recovery": "uci revert before commit; no post-commit rollback outside rpcd apply/confirm",
    },
    {
        "id": "R05",
        "responsibility": "configuration change detection and dispatch",
        "current_implementation": "/sbin/reload_config + procd config.change triggers",
        "artifacts": ["/sbin/reload_config"],
        "init_services": ["ucitrack"],
        "configs": ["*"],
        "provides": [],
        "consumes": ["service"],
        "persistent_side_effects": "rewrites /var/run/config.md5 baseline in tmpfs",
        "timing_notes": "whole-file granularity; baseline lost on reboot; upstream calls it a temporary hack",
        "failure_boundary": "a missed event leaves a service running stale config with no error",
        "compatibility_requirements": [
            "uci show normalisation used for the md5 baseline",
            "config.change event payload shape",
            "trigger matching including ucitrack affects fan-out",
        ],
        "recovery": "next reload_config run re-detects; no explicit retry",
    },
    {
        "id": "R06",
        "responsibility": "first-boot configuration generation",
        "current_implementation": "board_detect + config_generate + /etc/board.d",
        "artifacts": ["/bin/board_detect", "/bin/config_generate"],
        "init_services": ["boot"],
        "configs": ["network", "system"],
        "provides": [],
        "consumes": [],
        "persistent_side_effects": "creates /etc/board.json, /etc/config/network and /etc/config/system",
        "timing_notes": "runs once, guarded by /etc/board.json presence and non-empty network+system",
        "failure_boundary": "device has no network configuration; recoverable only via failsafe",
        "compatibility_requirements": [
            "ucidef_* accumulation format and board.json schema",
            "MTD-sourced MAC derivation for this board",
            "the guard conditions that make generation idempotent",
        ],
        "recovery": "delete board.json and regenerate; destroys user network config",
    },
    {
        "id": "R07",
        "responsibility": "network interface and device management",
        "current_implementation": "netifd",
        "artifacts": ["/sbin/netifd"],
        "init_services": ["network"],
        "configs": ["network"],
        "provides": ["network", "network.device", "network.interface"],
        "provides_runtime_named": [
            "network.interface.<interface name from /etc/config/network>",
        ],
        "consumes": ["service"],
        "persistent_side_effects": "kernel link, address, route and rule state; resolv.conf.auto",
        "timing_notes": "asynchronous protocol handlers; interface events drive downstream triggers",
        "failure_boundary": "all connectivity; watch network.interface makes procd restart it",
        "compatibility_requirements": [
            "per-interface ubus object naming and method set",
            "interface event names consumed by hotplug and raw triggers",
            "proto handler contract in /lib/netifd/proto",
            "wireless ucode object contract",
        ],
        "recovery": "procd respawn; ifup/ifdown; no config rollback",
    },
    {
        "id": "R08",
        "responsibility": "wireless configuration and AP/STA management",
        "current_implementation": "wifi-scripts + netifd wireless.uc + hostapd/wpa_supplicant ucode",
        "artifacts": ["/sbin/wifi", "/lib/netifd/wireless.uc", "/usr/sbin/wpad", "/usr/share/hostap/hostapd.uc"],
        "init_services": ["wpad"],
        "configs": ["wireless"],
        "provides": ["network.wireless", "hostapd", "hostapd-auth", "wpa_supplicant"],
        "provides_runtime_named": ["wpa_supplicant.<ifname>"],
        "consumes": ["network.wireless", "service"],
        "persistent_side_effects": "writes /etc/config/wireless on detect; radio state",
        "timing_notes": "ieee80211 hotplug driven; wifi config runs before kmodloader in /etc/init.d/boot",
        "failure_boundary": "all wireless clients; wpad runs as user network under a jail",
        "compatibility_requirements": [
            "ubusd ACL publish list for hostapd.* and wpa_supplicant.*",
            "netifd wireless notify protocol",
            "wifi detect output format written into /etc/config/wireless",
        ],
        "recovery": "wifi reload; procd respawn 3600 1 0",
    },
    {
        "id": "R09",
        "responsibility": "firewall rule generation",
        "current_implementation": "firewall4 (fw4, ucode) targeting nftables",
        "artifacts": ["/sbin/fw4"],
        "init_services": ["firewall"],
        "configs": ["firewall"],
        "provides": [],
        "consumes": ["service"],
        "persistent_side_effects": "the entire nftables ruleset",
        "timing_notes": "one-shot; no resident process; also invoked from the iface hotplug handler",
        "failure_boundary": "whole packet path; a flush leaves the device open or unreachable",
        "compatibility_requirements": [
            "generated ruleset structure that hotplug and reload assume",
            "reload versus restart versus flush semantics",
            "interaction with the 20-firewall iface hotplug handler",
        ],
        "recovery": "fw4 restart; no rollback of an intermediate ruleset",
    },
    {
        "id": "R10",
        "responsibility": "DNS and DHCPv4 service",
        "current_implementation": "dnsmasq",
        "artifacts": ["/usr/sbin/dnsmasq"],
        "init_services": ["dnsmasq"],
        "configs": ["dhcp"],
        "provides": [],
        "provides_runtime_named": [
            "dnsmasq instance name from --ubus option, default DNSMASQ_UBUS_NAME",
        ],
        "consumes": ["hotplug.dhcp", "hotplug.neigh", "hotplug.tftp"],
        "persistent_side_effects": "lease file, generated /var/etc/dnsmasq.conf.*, DNS cache",
        "timing_notes": "instance per UCI section; file trigger restarts the instance on config change",
        "failure_boundary": "name resolution and IPv4 address assignment for all clients",
        "compatibility_requirements": [
            "the generated config file format consumed by the binary",
            "lease file format read by luci-rpc getDHCPLeases",
            "ubusd ACL publish name and hotplug call rights",
        ],
        "recovery": "procd respawn; leases persist in the lease file",
    },
    {
        "id": "R11",
        "responsibility": "IPv6 RA, DHCPv6 and prefix delegation",
        "current_implementation": "odhcpd (ipv6only variant) and odhcp6c",
        "artifacts": ["/usr/sbin/odhcpd", "/usr/sbin/odhcp6c"],
        "init_services": ["odhcpd"],
        "configs": ["dhcp", "network"],
        "provides": ["dhcp"],
        "provides_runtime_named": ["odhcp6c.<interface>"],
        "consumes": [],
        "persistent_side_effects": "IPv6 addresses, routes and RA state; lease state",
        "timing_notes": "reacts to network and dhcp config change; odhcp6c is spawned per WAN interface",
        "failure_boundary": "all IPv6 connectivity",
        "compatibility_requirements": [
            "this build has no dhcp.ipv4leases method",
            "odhcp6c.<interface> object naming",
            "netifd protocol handler integration",
        ],
        "recovery": "procd respawn",
    },
    {
        "id": "R12",
        "responsibility": "IPC bus",
        "current_implementation": "ubusd",
        "artifacts": ["/sbin/ubusd", "/lib/libubus.so.20251202"],
        "init_services": [],
        "configs": [],
        "provides": [],
        "consumes": [],
        "persistent_side_effects": "none; all state is in-memory and lost on restart",
        "timing_notes": "started by procd in STATE_UBUS as user ubus, before any init script",
        "failure_boundary": "every control-plane interaction on the device",
        "compatibility_requirements": [
            "socket path /var/run/ubus/ubus.sock created with umask 0111",
            "ACL evaluation from /usr/share/acl.d by unix user",
            "wire format, object lookup, notify and subscribe semantics",
        ],
        "recovery": "restart loses every registered object; every daemon must reconnect",
    },
    {
        "id": "R13",
        "responsibility": "RPC gateway, sessions and access control",
        "current_implementation": "rpcd plus its plugins, fronted by uhttpd_ubus",
        "artifacts": ["/sbin/rpcd", "/usr/lib/rpcd/file.so", "/usr/lib/rpcd/luci.so", "/usr/lib/uhttpd_ubus.so"],
        "init_services": ["rpcd"],
        "configs": ["rpcd"],
        "provides": ["session", "uci", "rc", "file", "iwinfo", "rpc-sys", "luci-rpc", "network.rrdns", "luci"],
        "consumes": ["uci", "session"],
        "persistent_side_effects": "uci.apply writes config; file.write and file.exec are arbitrary write and execute",
        "timing_notes": "30 s session timeout from /etc/config/rpcd; apply/confirm has a rollback window",
        "failure_boundary": "remote administration and, through file.exec and rc.init, the whole device",
        "compatibility_requirements": [
            "session ACL evaluation against /usr/share/rpcd/acl.d",
            "uci apply/confirm/rollback semantics",
            "the LuCI client depends on exact method and field names",
        ],
        "recovery": "procd respawn; uci rollback within the confirm window",
    },
    {
        "id": "R14",
        "responsibility": "HTTP server and ubus-over-HTTP bridge",
        "current_implementation": "uhttpd with uhttpd_ubus and ucode handlers",
        "artifacts": ["/usr/sbin/uhttpd", "/usr/lib/uhttpd_ubus.so"],
        "init_services": ["uhttpd"],
        "configs": ["uhttpd", "network"],
        "provides": [],
        "consumes": ["session", "uci", "file", "luci-rpc"],
        "persistent_side_effects": "generates TLS keys on first start; writes /var/etc/uhttpd/httpd.*.conf",
        "timing_notes": "raw interface.*.up triggers a start with 1000 ms delay",
        "failure_boundary": "the web administration surface; runs as root",
        "compatibility_requirements": [
            "ubus_prefix default /ubus written by a uci-default, not by the shipped config",
            "session cookie and authentication flow expected by LuCI",
        ],
        "recovery": "procd respawn",
    },
    {
        "id": "R15",
        "responsibility": "system logging",
        "current_implementation": "logd and logread from ubox",
        "artifacts": ["/sbin/logd", "/sbin/logread", "/usr/libexec/logread-ubox"],
        "init_services": ["log"],
        "configs": ["system"],
        "provides": ["log"],
        "consumes": [],
        "persistent_side_effects": "optional log file when log_file is configured; otherwise memory ring only",
        "timing_notes": "three instances: logd, logfile, logremote; respawn 5 1 -1",
        "failure_boundary": "observability only; loss is silent",
        "compatibility_requirements": [
            "log.read stream and oneshot semantics",
            "ubusd ACL publish right for user logd",
            "ring buffer sizing from log_buffer_size",
        ],
        "recovery": "procd respawn; buffered messages are lost",
    },
    {
        "id": "R16",
        "responsibility": "hotplug event dispatch",
        "current_implementation": "procd hotplug with /etc/hotplug.json and /etc/hotplug.d",
        "artifacts": ["/sbin/procd", "/etc/hotplug.json"],
        "init_services": [],
        "configs": [],
        "provides": [],
        "provides_runtime_named": ["hotplug.<subsystem registered by procd>"],
        "consumes": [],
        "persistent_side_effects": "creates device nodes; the handlers themselves change network and firewall state",
        "timing_notes": "kernel uevents plus injected iface and ntp events; handlers run as root",
        "failure_boundary": "device node creation and every downstream handler",
        "compatibility_requirements": [
            "hotplug.json rule language",
            "environment variable names each handler reads",
            "hotplug.<subsystem> call rights in the ubusd ACL",
        ],
        "recovery": "none; a missed event is not retried",
    },
    {
        "id": "R17",
        "responsibility": "system information, upgrade and reboot",
        "current_implementation": "procd system object and rpcd rpcsys plugin",
        "artifacts": ["/sbin/procd", "/usr/lib/rpcd/rpcsys.so", "/sbin/sysupgrade"],
        "init_services": [],
        "configs": [],
        "provides": ["system", "rpc-sys"],
        "consumes": [],
        "persistent_side_effects": "sysupgrade rewrites flash; factory erases the overlay",
        "timing_notes": "one-shot, terminal operations",
        "failure_boundary": "the device itself; a failed sysupgrade can brick it",
        "compatibility_requirements": [
            "image validation before write",
            "config preservation list and sysupgrade.tgz handling",
        ],
        "recovery": "bootloader recovery only; this is the recovery gate the project reserves",
        "no_run_question_justification": (
            "Every method on this responsibility is terminal: reboot, sysupgrade, factory. "
            "There is no read-only observation of it beyond the method list, which Q05 "
            "already collects. Exercising it belongs to H1 behind a recovery gate, not to "
            "a read-only observation."
        ),
    },
]

# --------------------------------------------------------------------------
# runtime question declarations
#
# Every command carries a side-effect review with a source citation.  A command
# whose class is not "read-only" may not appear in an approved observation.
# --------------------------------------------------------------------------

SIDE_EFFECT_CLASSES = {"read-only", "executes-code", "mutates-state", "disrupts-service"}

EXCLUDED_COMMANDS: list[dict[str, Any]] = [
    {
        "command": "ubus call rc list",
        "class": "executes-code",
        "review": "rc_list forks and execl()s every /etc/init.d script with the 'running' action",
        "source": "sources/components/rpcd/rc.c:122-172,251-255",
    },
    {
        "command": "ubus call iwinfo scan",
        "class": "disrupts-service",
        "review": "calls iw->scanlist, which triggers an active nl80211 scan on the radio",
        "source": "sources/components/rpcd/iwinfo.c:377-396",
    },
    {
        "command": "ubus call luci getFeatures",
        "class": "executes-code",
        "review": "runs hostapd -v, wpa_supplicant -v, dnsmasq --version, odhcpd -h and ipset --help",
        "source": "/usr/share/rpcd/ucode/luci:268,275,278,294,315",
    },
    {
        "command": "ubus call luci setBlockDetect",
        "class": "mutates-state",
        "review": "system('/sbin/block detect > /etc/config/fstab') overwrites a config file",
        "source": "/usr/share/rpcd/ucode/luci:532",
    },
    {
        "command": "ubus call luci setLocaltime",
        "class": "mutates-state",
        "review": "sets the system clock and restarts /etc/init.d/sysfixtime",
        "source": "/usr/share/rpcd/ucode/luci:111-112",
    },
    {
        "command": "ubus call luci setPassword",
        "class": "mutates-state",
        "review": "pipes a new password into busybox passwd",
        "source": "/usr/share/rpcd/ucode/luci:474",
    },
    {
        "command": "ubus call luci setInitAction",
        "class": "executes-code",
        "review": "init_action runs env -i /etc/init.d/<name> <action>",
        "source": "/usr/share/ucode/luci/sys.uc:153-159",
    },
    {
        "command": "ubus call network.interface.<name> up|down|renew",
        "class": "disrupts-service",
        "review": "changes interface state; renew restarts the protocol handler",
        "source": "sources/components/netifd/ubus.c:1096-1101",
    },
    {
        "command": "ubus call uci get|configs|changes",
        "class": "mutates-state",
        "review": "every uci method requires ubus_rpc_session, so calling it means creating an rpcd session first; read the files directly instead",
        "source": "sources/components/rpcd/uci.c:52,612-615",
    },
    {
        "command": "ubus call file read|exec",
        "class": "executes-code",
        "review": "file.exec runs arbitrary programs; both need an rpcd session",
        "source": "sources/components/rpcd/file.c:1115-1126",
    },
    {
        "command": "ubus call system reboot | rpc-sys upgrade_start | rpc-sys factory",
        "class": "mutates-state",
        "review": "terminal operations on the device",
        "source": "sources/components/procd/system.c:855-862; sources/components/rpcd/sys.c:486-497",
    },
]

QUESTIONS: list[dict[str, Any]] = [
    {
        "id": "Q01",
        "question": "What is the actual kernel command line?",
        "closes": "BOOT_CHAIN.md §8 kernel command line unknown",
        "why_static_is_insufficient": "the device tree chosen node carries only stdout-path; bootargs come from the bootloader and are absent from the image",
        "fields": ["full /proc/cmdline string"],
        "commands": [
            {
                "command": "cat /proc/cmdline",
                "class": "read-only",
                "review": "procfs read; no kernel state change",
                "source": "REF: Linux procfs",
                "expected_status": 0,
                "timeout_s": 5,
            }
        ],
        "redaction": "none needed; record verbatim, but review for any vendor serial before commit",
        "responsibility_ids": ["R03"],
    },
    {
        "id": "Q02",
        "question": "Which boot stage did this device actually take, and did failsafe trigger?",
        "closes": "BOOT_CHAIN.md §8 actual boot order and failsafe unknown",
        "why_static_is_insufficient": "hook order is static but branch outcomes, timing and failsafe entry are not",
        "fields": ["boot-time log lines from procd and preinit", "presence of /tmp/.failsafe"],
        "commands": [
            {
                "command": "logread -l 400",
                "class": "read-only",
                "review": "log.read walks the ring buffer without consuming it; pass an explicit line bound so the call is not a stream subscription",
                "source": "sources/components/ubox/log/logd.c:96-141",
                "expected_status": 0,
                "timeout_s": 20,
            },
            {
                "command": "test -e /tmp/.failsafe; echo $?",
                "class": "read-only",
                "review": "stat only",
                "source": "/etc/init.d/boot:47",
                "expected_status": 0,
                "timeout_s": 5,
            },
        ],
        "redaction": "log lines may contain client MAC addresses, hostnames and SSIDs; redact before commit",
        "responsibility_ids": ["R03", "R15"],
    },
    {
        "id": "Q03",
        "question": "Is this device past first boot, and which uci-defaults remain?",
        "closes": "CONFIG_FLOW.md §7 which uci-defaults ran; BOOT_CHAIN.md §8 first versus subsequent boot",
        "why_static_is_insufficient": "uci_apply_defaults deletes each file it applies successfully, so the outcome is only visible on the device",
        "fields": ["listing of /etc/uci-defaults", "existence of /etc/board.json", "existence of /etc/rc.local"],
        "commands": [
            {
                "command": "ls -la /etc/uci-defaults/ /etc/board.json /etc/rc.local",
                "class": "read-only",
                "review": "directory and stat reads only",
                "source": "/etc/init.d/boot:8-19",
                "expected_status": 0,
                "timeout_s": 5,
            }
        ],
        "redaction": "none",
        "responsibility_ids": ["R03", "R06"],
    },
    {
        "id": "Q04",
        "question": "What are the generated network, system and wireless configurations, and the board.json they came from?",
        "closes": "CONFIG_FLOW.md §7 generated config content unknown",
        "why_static_is_insufficient": "none of these files ship in the image; they are produced from board.json and MTD-sourced MAC values",
        "fields": ["/etc/board.json", "/etc/config/network", "/etc/config/system", "/etc/config/wireless"],
        "commands": [
            {
                "command": "cat /etc/board.json",
                "class": "read-only",
                "review": "plain file read; config_generate only writes it when absent",
                "source": "/lib/preinit/82_config_generate",
                "expected_status": 0,
                "timeout_s": 5,
            },
            {
                "command": "cat /etc/config/network /etc/config/system /etc/config/wireless",
                "class": "read-only",
                "review": "plain file read; deliberately not 'uci show', which would need an rpcd session or would read the tmpfs delta",
                "source": "CONFIG_FLOW.md §4",
                "expected_status": 0,
                "timeout_s": 5,
            },
        ],
        "redaction": "MANDATORY. Remove wireless keys and passphrases, MAC addresses, ULA prefix, DUID, hostname and any WAN credentials before anything is committed.",
        "responsibility_ids": ["R04", "R06", "R07", "R08"],
    },
    {
        "id": "Q05",
        "question": "Which ubus objects are actually registered, and what are their method signatures?",
        "closes": "IPC_CATALOG.md §10 actual object list and dynamic instance names",
        "why_static_is_insufficient": "six object families are named at run time, and registration depends on which daemons started",
        "fields": ["object names", "per-method argument names and types from the verbose listing"],
        "commands": [
            {
                "command": "ubus list",
                "class": "read-only",
                "review": "a lookup request against ubusd; it returns the object table and does not create, notify or subscribe",
                "source": "sources/components/ubus/libubus-obj.c lookup path",
                "expected_status": 0,
                "timeout_s": 10,
            },
            {
                "command": "ubus -v list",
                "class": "read-only",
                "review": "same lookup with signatures included",
                "source": "same",
                "expected_status": 0,
                "timeout_s": 10,
            },
        ],
        "redaction": "object names embed interface and PHY names; keep them, but check for SSIDs in wpa_supplicant.* names",
        "responsibility_ids": ["R12", "R07", "R08", "R11", "R16"],
    },
    {
        "id": "Q06",
        "question": "Which services and instances does procd actually supervise, and with which triggers?",
        "closes": "SERVICE_GRAPH.md §7 actual instance count and ucitrack registration result",
        "why_static_is_insufficient": "instance counts come from config_foreach over run-time UCI, and ucitrack registration depends on a run-time 'enabled' test",
        "fields": ["service names", "instance names", "running flag", "pid", "registered triggers", "validate registrations"],
        "commands": [
            {
                "command": "ubus call service list '{\"verbose\":true}'",
                "class": "read-only",
                "review": "service_handle_list walks the service avl tree and serialises it; no fork, no exec, no state change. This is the safe counterpart to the excluded rc.list.",
                "source": "sources/components/procd/service/service.c:515-543",
                "expected_status": 0,
                "timeout_s": 15,
            }
        ],
        "redaction": "instance command lines contain interface names and file paths; review for credentials passed as arguments",
        "responsibility_ids": ["R01", "R02", "R05"],
    },
    {
        "id": "Q07",
        "question": "What is the actual interface and device state netifd exposes?",
        "closes": "SERVICE_GRAPH.md §7 and IPC_CATALOG.md §10 network.interface.* instance set",
        "why_static_is_insufficient": "per-interface objects are created from run-time config; protocol state is not derivable from the image",
        "fields": ["interface names", "up/pending/available/autostart flags", "proto", "device", "l3_device"],
        "commands": [
            {
                "command": "ubus call network.interface dump",
                "class": "read-only",
                "review": "netifd_handle_dump serialises the interface vlist; it is the one iface method not rewritten to the per-interface handler and it mutates nothing",
                "source": "sources/components/netifd/ubus.c:956-974,1178-1179",
                "expected_status": 0,
                "timeout_s": 15,
            },
            {
                "command": "ubus call network.device status",
                "class": "read-only",
                "review": "netifd_dev_status serialises device state",
                "source": "sources/components/netifd/ubus.c:396",
                "expected_status": 0,
                "timeout_s": 15,
            },
        ],
        "redaction": "MANDATORY. Addresses, prefixes, DNS servers, MAC addresses and the WAN peer must be redacted.",
        "responsibility_ids": ["R07", "R11"],
    },
    {
        "id": "Q08",
        "question": "What nftables ruleset does fw4 actually produce?",
        "closes": "SERVICE_GRAPH.md §7 fw4 generated ruleset unknown",
        "why_static_is_insufficient": "firewall4 is one-shot with no resident state; the ruleset is the only evidence of what it built",
        "fields": ["table, chain, and rule structure", "which chains hotplug adds to"],
        "commands": [
            {
                "command": "nft -a list ruleset",
                "class": "read-only",
                "review": "netlink dump of the current ruleset; no commit transaction is issued",
                "source": "REF: nftables list semantics",
                "expected_status": 0,
                "timeout_s": 20,
            }
        ],
        "redaction": "MANDATORY. Rules embed addresses, prefixes and possibly client identifiers.",
        "responsibility_ids": ["R09"],
        "notes": "fw4 print is deliberately NOT used: it regenerates from config and would answer a different question than what is loaded.",
    },
    {
        "id": "Q09",
        "question": "Does dnsmasq register its ubus object under the default name, and is odhcpd the ipv6only build?",
        "closes": "IPC_CATALOG.md §10 dnsmasq registered name; confirms the build-gating conclusions",
        "why_static_is_insufficient": "the name comes from a run-time option; the build conclusion should be confirmed rather than assumed",
        "fields": ["presence of a dnsmasq object in ubus list", "method list of the dhcp object"],
        "commands": [
            {
                "command": "ubus -v list dnsmasq",
                "class": "read-only",
                "review": "lookup only",
                "source": "sources/components/dnsmasq/src/ubus.c:113",
                "expected_status": 0,
                "timeout_s": 10,
            },
            {
                "command": "ubus -v list dhcp",
                "class": "read-only",
                "review": "lookup only; confirms whether ipv4leases is absent as the recipe predicts",
                "source": "sources/components/odhcpd/src/ubus.c:247-254",
                "expected_status": 0,
                "timeout_s": 10,
            },
        ],
        "redaction": "none",
        "responsibility_ids": ["R10", "R11"],
    },
    {
        "id": "Q10",
        "question": "Which artifact provides the udebug ubus object?",
        "closes": "IPC_CATALOG.md §10 udebug provider unknown",
        "why_static_is_insufficient": "the wpad ubusd ACL grants access to and subscription on udebug, but no deployed binary was resolved as its provider",
        "fields": ["whether a udebug object exists", "its methods"],
        "commands": [
            {
                "command": "ubus -v list udebug",
                "class": "read-only",
                "review": "lookup only",
                "source": "/usr/share/acl.d/wpad_acl.json",
                "expected_status": 0,
                "timeout_s": 10,
            }
        ],
        "redaction": "none",
        "responsibility_ids": ["R12", "R08"],
    },
    {
        "id": "Q11",
        "question": "Are the declared jails and capability drops actually in effect?",
        "closes": "SERVICE_GRAPH.md §7 whether jail takes effect",
        "why_static_is_insufficient": "procd_add_jail depends on ujail and kernel namespace support at run time",
        "fields": ["uid and gid of wpad, ntpd, dnsmasq and logd processes", "namespace links for those pids"],
        "commands": [
            {
                "command": "for p in $(pgrep -f 'hostapd|wpa_supplicant|ntpd|dnsmasq|logd'); do echo \"== $p\"; cat /proc/$p/status | grep -E '^(Name|Uid|Gid|CapEff|NoNewPrivs|Seccomp)'; ls -l /proc/$p/ns; done",
                "class": "read-only",
                "review": "procfs reads only; no signal is sent and pgrep does not modify process state",
                "source": "SERVICE_GRAPH.md §6",
                "expected_status": 0,
                "timeout_s": 20,
            },
        ],
        "redaction": "process arguments may contain paths and interface names; review before commit",
        "responsibility_ids": ["R01", "R08", "R10", "R15"],
    },
    {
        "id": "Q13",
        "question": "Do the six shipped UCI configs still match the image, and what did the uci-defaults migrations write?",
        "closes": "CONFIG_FLOW.md §7 whether migrations ran and whether the user modified configs; IPC_CATALOG.md §7 actual uhttpd ubus settings",
        "why_static_is_insufficient": "the shipped files are a build artifact; uci-defaults rewrite uhttpd.main.ubus_prefix and rpcd.@rpcd.socket on first boot, and the user may have edited anything",
        "fields": [
            "sha256 of each /etc/config file shipped in the image",
            "uhttpd.main.ubus_prefix and ubus_socket and no_ubusauth",
            "rpcd socket and timeout and the login section shape",
        ],
        "commands": [
            {
                "command": "sha256sum /etc/config/dhcp /etc/config/dropbear /etc/config/firewall /etc/config/luci /etc/config/rpcd /etc/config/uhttpd",
                "class": "read-only",
                "review": "hash only, so drift is detected without exporting content; compare against the image hashes in config-flow.json",
                "source": "CONFIG_FLOW.md §1",
                "expected_status": 0,
                "timeout_s": 10,
            },
            {
                "command": "cat /etc/config/uhttpd /etc/config/rpcd",
                "class": "read-only",
                "review": "plain file read; these two decide the HTTP-to-ubus and RPC surface, so their content is needed, not just a hash",
                "source": "IPC_CATALOG.md §6 and §7",
                "expected_status": 0,
                "timeout_s": 5,
            },
        ],
        "redaction": "MANDATORY. /etc/config/rpcd carries the login section; drop the password field entirely, never record its value even if it is still the $p$root placeholder.",
        "responsibility_ids": ["R04", "R13", "R14"],
    },
    {
        "id": "Q12",
        "question": "What is the current config change baseline, and are there uncommitted UCI deltas?",
        "closes": "CONFIG_FLOW.md §7 /var/run/config.md5 baseline and user modification unknown",
        "why_static_is_insufficient": "the baseline lives in tmpfs and the delta directory only exists at run time",
        "fields": ["existence and file list of /var/run/config.md5", "listing of /tmp/.uci and /var/run/uci"],
        "commands": [
            {
                "command": "ls -la /tmp/.uci /var/run/uci 2>&1; cut -c35- /var/run/config.md5 2>&1",
                "class": "read-only",
                "review": "directory listing and a field-limited read of the md5 baseline; the hashes themselves are not needed, only which packages are tracked",
                "source": "/sbin/reload_config",
                "expected_status": 0,
                "timeout_s": 5,
            }
        ],
        "redaction": "session directory names under /tmp/.uci are session identifiers; drop them",
        "responsibility_ids": ["R04", "R05"],
    },
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build(manifests: Path) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    services = load(manifests / "service-graph.json")
    configs = load(manifests / "config-flow.json")
    ipc = load(manifests / "ipc-catalog.json")
    executables = load(manifests / "executables.json")

    problems: list[str] = []

    known_services = {item["name"] for item in services["services"]}
    known_configs = {item["config"] for item in configs["config_packages"]}
    known_paths = {
        item["path"]
        for group in (
            "elf_files",
            "executable_regular_files",
            "executable_symlinks",
            "scripts",
            "ucode_lua",
            "init_services",
        )
        for item in executables.get(group, []) or []
        if isinstance(item, dict) and "path" in item
    }
    for group in executables.get("control_plane_files", {}).values():
        for item in group if isinstance(group, list) else []:
            if isinstance(item, dict) and "path" in item:
                known_paths.add(item["path"])
    # data files that are IPC or boot surfaces rather than programs
    procd_rules = ipc.get("hotplug", {}).get("procd_rules") or {}
    if procd_rules.get("path"):
        known_paths.add(procd_rules["path"])
    known_paths.update(item["path"] for item in ipc["ubusd_acl"])
    known_paths.update(item["path"] for item in ipc["rpcd"]["acl_files"])
    known_paths.update(item["path"] for item in ipc["rpcd"]["binary_plugins"])
    known_paths.update(item["path"] for item in ipc["rpcd"]["ucode_plugins"])
    known_paths.update(item["path"] for item in configs["deployed_configs"])
    literal_objects = (
        {item["object_name"] for item in ipc["ubus_objects"] if item["object_name"]}
        | {item["object_name"] for item in ipc["ubus_objects_from_deployed_ucode"] if item["name_is_literal"]}
        | {
            name["object_name"]
            for plugin in ipc["rpcd"]["ucode_plugins"]
            for name in plugin["registered_objects"]
        }
    )
    dynamic_rules = {rule["name_rule"] for rule in ipc["ubus_dynamic_objects"]}

    # caller index: which init scripts call which ubus object
    ubus_callers: dict[str, set[str]] = {}
    for service in services["services"]:
        for call in service["ubus_calls"]:
            ubus_callers.setdefault(call["object"], set()).add(service["path"])
    # caller index: which init scripts react to which config package
    config_reactors: dict[str, set[str]] = {}
    for service in services["services"]:
        for name in service["referenced_configs"]:
            config_reactors.setdefault(name, set()).add(service["path"])
    acl_grants: dict[str, set[str]] = {}
    for acl in ipc["rpcd"]["acl_files"]:
        for scope in acl["scopes"]:
            if scope["scope"] == "ubus" and scope["target"]:
                acl_grants.setdefault(scope["target"], set()).add(acl["path"])

    records = []
    for entry in RESPONSIBILITIES:
        for path in entry["artifacts"]:
            if path not in known_paths:
                problems.append(f"{entry['id']}: artifact not in image inventory: {path}")
        for name in entry["init_services"]:
            if name != "*" and name not in known_services:
                problems.append(f"{entry['id']}: unknown init service: {name}")
        for name in entry["configs"]:
            if name != "*" and name not in known_configs:
                problems.append(f"{entry['id']}: unknown config package: {name}")
        for name in entry["provides"]:
            if name not in literal_objects:
                problems.append(f"{entry['id']}: provides unresolved ubus object: {name}")
        for rule in entry.get("provides_runtime_named", []):
            if rule not in dynamic_rules:
                problems.append(f"{entry['id']}: no dynamic naming rule matches: {rule}")

        callers = sorted(
            {caller for name in entry["provides"] for caller in ubus_callers.get(name, set())}
            | {caller for name in entry["configs"] for caller in config_reactors.get(name, set())}
        )
        records.append(
            {
                **entry,
                "known_callers": {
                    "init_scripts": callers,
                    "rpcd_acl_grants": sorted(
                        {
                            acl
                            for name in entry["provides"]
                            for acl in acl_grants.get(name, set())
                        }
                    ),
                },
                "dep_src_evidence": {
                    "artifacts_in_image": [p for p in entry["artifacts"] if p in known_paths],
                    "ubus_objects_resolved": [
                        n for n in entry["provides"] if n in literal_objects
                    ],
                    "ubus_objects_runtime_named": entry.get("provides_runtime_named", []),
                },
                "missing_run_evidence": sorted(
                    {
                        question["id"]
                        for question in QUESTIONS
                        if entry["id"] in question["responsibility_ids"]
                    }
                ),
            }
        )

    for question in QUESTIONS:
        for command in question["commands"]:
            if command["class"] not in SIDE_EFFECT_CLASSES:
                problems.append(f"{question['id']}: unknown side effect class: {command['class']}")
            if command["class"] != "read-only":
                problems.append(
                    f"{question['id']}: non read-only command in an approved observation: {command['command']}"
                )
            for field in ("review", "source", "expected_status", "timeout_s"):
                if not command.get(field) and command.get(field) != 0:
                    problems.append(f"{question['id']}: command missing {field}")
        for field in ("closes", "why_static_is_insufficient", "fields", "redaction"):
            if not question.get(field):
                problems.append(f"{question['id']}: missing {field}")
        for rid in question["responsibility_ids"]:
            if rid not in {entry["id"] for entry in RESPONSIBILITIES}:
                problems.append(f"{question['id']}: unknown responsibility id {rid}")

    covered = {rid for question in QUESTIONS for rid in question["responsibility_ids"]}
    uncovered = sorted({entry["id"] for entry in RESPONSIBILITIES} - covered)
    for entry in RESPONSIBILITIES:
        if entry["id"] in uncovered and not entry.get("no_run_question_justification"):
            problems.append(
                f"{entry['id']}: no runtime question and no justification for having none"
            )

    candidates = {
        "responsibilities": records,
        "counts": {
            "responsibilities": len(records),
            "responsibilities_with_open_run_questions": sum(
                1 for item in records if item["missing_run_evidence"]
            ),
            "responsibilities_without_run_questions": len(uncovered),
        },
        "responsibilities_without_run_questions": uncovered,
        "ranking": "none. I0.6 assesses evidence completeness and risk only.",
    }
    questions = {
        "questions": QUESTIONS,
        "excluded_commands": EXCLUDED_COMMANDS,
        "authorization": {
            "collector_approved": False,
            "device_access_approved": False,
            "note": (
                "Obtaining shell or ubus access to the device is a separate authorization, "
                "not part of a read-only observation. Enabling SSH, setting a root password "
                "or changing dropbear state all modify the device."
            ),
        },
        "counts": {
            "questions": len(QUESTIONS),
            "approved_commands": sum(len(q["commands"]) for q in QUESTIONS),
            "excluded_commands": len(EXCLUDED_COMMANDS),
        },
    }
    return candidates, questions, problems


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifests", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--recorded-at", required=True)
    args = parser.parse_args()

    candidates, questions, problems = build(args.manifests.resolve())
    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        raise SystemExit(f"{len(problems)} declaration(s) inconsistent with the I0.5 manifests")

    header = {
        "schema_version": 1,
        "stage": "I0.6",
        "status": "complete",
        "evidence_id": args.image_id,
        "recorded_at": args.recorded_at,
        "method": {
            "reads_only": True,
            "contacts_device": False,
            "emits_runnable_collector": False,
            "input": "I0.5 manifests",
        },
    }
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    outputs = {
        "responsibility-candidates.json": {**header, **candidates},
        "runtime-questions.json": {**header, **questions},
    }
    for name, payload in outputs.items():
        (output / name).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    print(
        json.dumps(
            {
                "candidates": candidates["counts"],
                "questions": questions["counts"],
                "output_sha256": {name: sha256_file(output / name) for name in outputs},
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
