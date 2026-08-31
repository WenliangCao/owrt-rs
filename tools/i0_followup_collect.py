#!/usr/bin/env python3
"""Collect the narrowly scoped, read-only evidence needed for the I0 follow-up.

This collector is intentionally separate from the redacting analyser.  It reads
the current DHCP/firewall configuration and the already identified historical
backup files over SSH, then writes them to a private evidence directory outside
Git.  Its runtime summary contains only booleans, counts and public firmware
identity fields.

Running this tool requires the same explicit device-access approval as I0.7.
It never writes the device, invokes UCI mutation commands, reloads a service or
touches MTD/UBI state.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


CONFIG_FILES = (
    "dhcp",
    "firewall",
    "dhcp.bak-codex-disable-ipv6-20260425",
    "dhcp.bak-codex-nextdns-doq-20260516-200927",
    "dhcp.bak-codex-rollback-dns-20260517-144734",
    "dnsproxy.bak-codex-rollback-dns-20260517-144734",
    "dnsproxy.disabled-codex-rollback-20260517-144902",
)

SUMMARY_SCRIPT = r"""
. /etc/openwrt_release
printf 'release=%s\n' "$DISTRIB_RELEASE"
printf 'revision=%s\n' "$DISTRIB_REVISION"
printf 'target=%s\n' "$DISTRIB_TARGET"
printf 'board_name='; cat /tmp/sysinfo/board_name
printf 'uptime_seconds='; cut -d' ' -f1 /proc/uptime
printf 'log_lines='; logread 2>/dev/null | wc -l
printf 'pstore_entries='; find /sys/fs/pstore -mindepth 1 -maxdepth 1 -type f 2>/dev/null | wc -l
printf 'pid1_cmdline='; tr '\000' ' ' </proc/1/cmdline; printf '\n'
printf 'pid1_dbglvl_present='; tr '\000' '\n' </proc/1/environ 2>/dev/null | grep -q '^DBGLVL=' && echo true || echo false
printf 'procd_rcs_debug_lines='; logread 2>/dev/null | grep -cE 'procd: (start|stop) /etc/rc.d/'
printf 'firewall_flow_offloading='; uci -q get firewall.@defaults[0].flow_offloading || echo absent
printf 'firewall_flow_offloading_hw='; uci -q get firewall.@defaults[0].flow_offloading_hw || echo absent
printf 'rendered_flowtable_mentions='; fw4 print 2>/dev/null | grep -c 'flowtable'
printf 'active_flowtable_mentions='; nft list ruleset 2>/dev/null | grep -c 'flowtable'
printf 'dns_noresolv_present='; uci -q get dhcp.@dnsmasq[0].noresolv >/dev/null 2>&1 && echo true || echo false
printf 'dns_server_values='; uci -q get dhcp.@dnsmasq[0].server 2>/dev/null | wc -w
printf 'dns_resolvfile_is_image_default='; [ "$(uci -q get dhcp.@dnsmasq[0].resolvfile)" = '/tmp/resolv.conf.d/resolv.conf.auto' ] && echo true || echo false
printf 'dnsproxy_processes='; ps w | grep -Ec '[d]nsproxy|[h]ttps-dns-proxy'
printf 'dnsproxy_active_config_present='; [ -f /etc/config/dnsproxy ] && echo true || echo false
""".strip()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ensure_private_output(path: Path) -> None:
    resolved = path.resolve()
    for parent in (resolved, *resolved.parents):
        if (parent / ".git").is_dir():
            raise SystemExit("raw evidence output must be outside a Git worktree")
    resolved.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(resolved, 0o700)


def ssh(ssh_target: str, command: str) -> bytes:
    result = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            ssh_target,
            command,
        ],
        check=False,
        capture_output=True,
        timeout=30,
    )
    if result.returncode:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise SystemExit(f"read-only SSH command failed ({result.returncode}): {stderr}")
    return result.stdout


def write_private(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    os.chmod(path, 0o600)


def parse_summary(text: str) -> dict[str, str]:
    summary: dict[str, str] = {}
    for line in text.splitlines():
        if "=" not in line:
            raise ValueError(f"unexpected summary line: {line!r}")
        key, value = line.split("=", 1)
        summary[key] = value
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ssh-target", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    output = args.output.resolve()
    ensure_private_output(output)
    device_dir = output / "device"
    device_dir.mkdir(mode=0o700, exist_ok=True)

    hashes: dict[str, str] = {}
    for name in CONFIG_FILES:
        data = ssh(args.ssh_target, f"cat /etc/config/{name}")
        write_private(device_dir / name, data)
        hashes[name] = sha256_bytes(data)

    summary = parse_summary(ssh(args.ssh_target, SUMMARY_SCRIPT).decode("utf-8"))
    summary_path = output / "runtime-summary.json"
    write_private(
        summary_path,
        (json.dumps(summary, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )

    print(
        json.dumps(
            {
                "files_collected": len(hashes),
                "file_sha256": hashes,
                "runtime_summary_fields": len(summary),
                "device_writes": False,
                "output": str(output),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
