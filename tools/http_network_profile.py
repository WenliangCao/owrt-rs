#!/usr/bin/env python3
"""Bounded, pinned IPv4 HTTPS load with read-only router observations.

No router configuration changes. Raw endpoints, client addresses and conntrack
records are private: output must be below private/. The endpoint must support a
large GET object or POST upload. An early EOF invalidates that load window.
"""
import argparse
import concurrent.futures
import ipaddress
import json
import math
import re
from pathlib import Path
import shlex
import socket
import statistics
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

from network_profile import cpu_delta, snapshot, write


def distribution(records):
    values = sorted(row["ms"] for row in records if "ms" in row)
    return {"samples": len(records), "failures": len(records) - len(values),
            "p50_ms": statistics.median(values) if values else None,
            "p95_ms": values[math.ceil(len(values) * .95) - 1] if values else None,
            "max_ms": max(values) if values else None}


def probes(host, port, interface, source, seconds, stop=None):
    started = time.monotonic()
    rows = []
    while time.monotonic() - started < seconds and not (stop and stop.is_set()):
        attempt = time.monotonic()
        row = {"at_s": attempt - started}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.settimeout(1)
                if sys.platform == "darwin":
                    # Darwin SDK netinet/in.h: bind this socket to one interface.
                    conn.setsockopt(socket.IPPROTO_IP, 25, socket.if_nametoindex(interface))
                conn.bind((source, 0))
                conn.connect((host, port))
                row["ms"] = (time.monotonic() - attempt) * 1000
                row["local_ip"] = conn.getsockname()[0]
                row["local_port"] = conn.getsockname()[1]
        except OSError as error:
            row["error"] = str(error)
        rows.append(row)
        pause = max(0, min(.5 - (time.monotonic() - attempt),
                           seconds - (time.monotonic() - started)))
        if stop:
            stop.wait(pause)
        else:
            time.sleep(pause)
    return rows


def curl_probes(url, endpoint, interface, source, seconds, stop=None):
    parsed = urlsplit(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    command = ["/usr/bin/curl", "--ipv4", "--interface", interface, "--noproxy", "*",
               "--resolve", f"{parsed.hostname}:{port}:{endpoint}", "--http1.1",
               "--connect-timeout", "1", "--max-time", "1",
               "--silent", "--show-error", "--output", "/dev/null", "--write-out", "%{json}",
               "--url", url]
    started = time.monotonic()
    rows = []
    while time.monotonic() - started < seconds and not (stop and stop.is_set()):
        attempt = time.monotonic()
        row = {"at_s": attempt - started}
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=3)
            data = json.loads(result.stdout)
            row.update({"returncode": result.returncode, "http_code": data["http_code"],
                        "time_connect_ms": data["time_connect"] * 1000,
                        "time_total_ms": data["time_total"] * 1000,
                        "remote_ip": data["remote_ip"], "local_ip": data["local_ip"],
                        "local_port": data["local_port"]})
            if result.returncode:
                row["error"] = result.stderr.strip() or f"curl exited {result.returncode}"
            elif data["remote_ip"] != endpoint or data["local_ip"] != source:
                row["error"] = "probe local/remote address differs from fixed path"
            elif not 200 <= data["http_code"] < 400:
                row["error"] = f"HTTP {data['http_code']}"
            else:
                row["ms"] = row["time_connect_ms"]
        except (OSError, subprocess.TimeoutExpired, ValueError, KeyError) as error:
            row["error"] = str(error)
        rows.append(row)
        pause = max(0, min(.5 - (time.monotonic() - attempt),
                           seconds - (time.monotonic() - started)))
        if stop:
            stop.wait(pause)
        else:
            time.sleep(pause)
    return rows


def selected_probes(args, name, host, port, seconds, stop=None):
    interface = getattr(args, "probe_interface", None) or args.interface
    source = getattr(args, "probe_source_ip", None) or args.source_ip
    if args.probe_mode == "curl":
        url = f"http://{host}/" if name == "router" else args.probe_url
        return curl_probes(url, host, interface, source, seconds, stop)
    return probes(host, port, interface, source, seconds, stop)


def shell_sampler(source, endpoint, seconds, probe_source=None):
    # Only validated IPv4 literals reach this awk expression.
    matcher = f"src={source} dst={endpoint} "
    probe_matcher = f"src={probe_source or source} dst={endpoint} "
    return f'''i=0
while [ "$i" -lt {seconds} ]; do
 printf '@@sample\\n@@uptime\\n'; cat /proc/uptime
 printf '@@stat\\n'; cat /proc/stat
 printf '@@netdev\\n'; cat /proc/net/dev
 printf '@@softirqs\\n'; cat /proc/softirqs
 printf '@@matching_conntrack\\n'
 if [ -r /proc/net/nf_conntrack ]; then
  awk -v match_text={shlex.quote(matcher)} -v probe_text={shlex.quote(probe_matcher)} 'index($0,match_text) || index($0,probe_text) {{print}}' /proc/net/nf_conntrack
 fi
 i=$((i+1))
 sleep 1
done
'''


class Sampler:
    def __init__(self, router, source, endpoint, seconds, output, probe_source=None):
        self.rows = []
        self.started = time.monotonic()
        self.ready = threading.Event()
        self.stderr = output.open("w")
        self.process = subprocess.Popen(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", router,
             "sh", "-c", shlex.quote(shell_sampler(source, endpoint, seconds + 10, probe_source))],
            stdout=subprocess.PIPE, stderr=self.stderr, text=True)
        self.thread = threading.Thread(target=self.read, daemon=True)
        self.thread.start()
        if not self.ready.wait(8):
            self.close()
            raise RuntimeError("router sampler did not start")

    def read(self):
        row = None
        for line in self.process.stdout:
            if line == "@@sample\n":
                if row:
                    self.rows.append(row)
                    self.ready.set()
                row = {"at_s": time.monotonic() - self.started, "raw": ""}
            elif row:
                row["raw"] += line
        if row:
            self.rows.append(row)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.thread.join(timeout=3)
        self.stderr.close()


def parse_netdev(raw):
    block = raw.split("@@netdev\n", 1)[1].split("@@softirqs\n", 1)[0]
    result = {}
    for line in block.splitlines():
        if ":" in line:
            name, fields = line.split(":", 1)
            values = list(map(int, fields.split()))
            result[name.strip()] = {"rx_bytes": values[0], "tx_bytes": values[8]}
    return result


def mac_counters(interfaces=("en0",)):
    raw = subprocess.check_output(["netstat", "-ibn"], text=True, timeout=5)
    counters = {}
    for line in raw.splitlines()[1:]:
        fields = line.split()
        name = fields[0].rstrip("*") if fields else ""
        if len(fields) >= 10 and (name in interfaces or name.startswith("utun")):
            # Last seven fields are packet/error/byte counters regardless of
            # whether this interface row has a link-layer address column.
            values = {"rx_bytes": int(fields[-5]), "tx_bytes": int(fields[-2])}
            counters[name] = {key: max(value, counters.get(name, {}).get(key, 0))
                              for key, value in values.items()}
    return {"raw": raw, "counters": counters}


def parse_softirqs(raw):
    block = raw.split("@@softirqs\n", 1)[1].split("@@matching_conntrack\n", 1)[0]
    result = {}
    for line in block.splitlines():
        if ":" in line:
            name, values = line.split(":", 1)
            result[name.strip()] = list(map(int, values.split()))
    return result


def summarize_samples(rows, start, end):
    inside = [row for row in rows if start <= row["at_s"] <= end]
    if len(inside) < 2:
        raise RuntimeError("not enough router samples inside load window")
    first, last = inside[0], inside[-1]
    a, b = parse_netdev(first["raw"]), parse_netdev(last["raw"])
    sa, sb = parse_softirqs(first["raw"]), parse_softirqs(last["raw"])
    connections = [line for row in inside for line in
                   row["raw"].split("@@matching_conntrack\n", 1)[1].splitlines() if line]
    uptime = lambda row: float(row["raw"].split("@@uptime\n", 1)[1].split()[0])
    cpu = cpu_delta(first["raw"], last["raw"])
    interval = uptime(last) - uptime(first)
    cores = sum(name != "cpu" for name in cpu)
    source_ports = {}
    for line in connections:
        match = re.search(r" src=([0-9.]+) dst=[0-9.]+ sport=(\d+) dport=443 ", line)
        if match:
            source_ports.setdefault(match.group(1), set()).add(int(match.group(2)))
    return {"sample_count": len(inside), "interval_s": interval,
            "cpu_core_count": cores,
            "busy_cpu_seconds": cpu["cpu"]["busy_pct"] / 100 * cores * interval,
            "direct_source_ports": sorted({int(match.group(1)) for line in connections
                                            if (match := re.search(r" sport=(\d+) dport=443 ", line))}),
            "direct_source_ports_by_ip": {source: sorted(ports) for source, ports in source_ports.items()},
            "cpu": cpu,
            "netdev_delta": {dev: {key: b[dev][key] - a[dev][key] for key in a[dev]}
                             for dev in a.keys() & b.keys()},
            "softirq_delta": {name: [y - x for x, y in zip(sa[name], sb[name])]
                              for name in sa.keys() & sb.keys()},
            "direct_flow_samples": len(connections),
            "offload_flow_samples": sum("[OFFLOAD]" in row for row in connections),
            "hardware_flow_samples": sum("[HW_OFFLOAD]" in row for row in connections)}


def load(args, number, prefix):
    host = urlsplit(args.url).hostname
    command = ["curl", "--ipv4", "--interface", args.interface, "--noproxy", "*",
               "--resolve", f"{host}:443:{args.endpoint_ip}", "--http1.1",
               "--connect-timeout", "5", "--max-time", str(args.seconds),
               "--silent", "--show-error", "--output", "/dev/null", "--write-out", "%{json}",
               "--url", args.url]
    if args.direction == "upload":
        command += ["--request", "POST", "--upload-file", str(args.upload_file),
                    "--header", "Expect:", "--header", "Content-Type: application/octet-stream"]
    started = time.monotonic()
    result = subprocess.run(command, capture_output=True, text=True, timeout=args.seconds + 8)
    elapsed = time.monotonic() - started
    prefix.with_name(prefix.name + f".curl-{number}.json").write_text(result.stdout)
    prefix.with_name(prefix.name + f".curl-{number}.stderr").write_text(result.stderr)
    data = json.loads(result.stdout)
    count = data["size_download" if args.direction == "download" else "size_upload"]
    valid = (result.returncode == 28 and elapsed >= args.seconds - .5 and count > 0
             and data["remote_ip"] == args.endpoint_ip and data["local_ip"] == args.source_ip
             and (200 <= data["http_code"] < 300 or args.direction == "upload"))
    return {"stream": number, "returncode": result.returncode, "elapsed_s": elapsed,
            "bytes": count, "valid": valid, "http_code": data["http_code"],
            "remote_ip": data["remote_ip"], "local_ip": data["local_ip"],
            "local_port": data["local_port"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--url", required=True)
    parser.add_argument("--endpoint-ip", required=True)
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--probe-host", required=True, help="Router LAN IPv4 address")
    parser.add_argument("--probe-mode", choices=("python", "curl"), default="python")
    parser.add_argument("--probe-url", help="Small HTTPS response URL, required for curl probes")
    parser.add_argument("--probe-interface", help="Probe interface; defaults to load interface")
    parser.add_argument("--probe-source-ip", help="Expected probe IPv4; defaults to load source")
    parser.add_argument("--router", default="openwrt")
    parser.add_argument("--interface", default="en0")
    parser.add_argument("--counter-interface", action="append", default=[],
                        help="Also record byte counters for this Mac interface (repeatable)")
    parser.add_argument("--direction", choices=("download", "upload"), default="download")
    parser.add_argument("--upload-file", type=Path)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--streams", type=int, default=4)
    args = parser.parse_args()
    args.probe_interface = args.probe_interface or args.interface
    args.probe_source_ip = args.probe_source_ip or args.source_ip
    counter_interfaces = set(args.counter_interface) | {args.interface, args.probe_interface}
    private = Path(__file__).resolve().parent.parent / "private"
    parsed = urlsplit(args.url)
    assert args.output.resolve().is_relative_to(private)
    assert 1 <= args.rounds <= 3 and 5 <= args.seconds <= 30 and 1 <= args.streams <= 4
    assert parsed.scheme == "https" and parsed.hostname and parsed.port in (None, 443)
    assert not parsed.username and not parsed.password
    for value in (args.endpoint_ip, args.source_ip, args.probe_source_ip, args.probe_host):
        ipaddress.IPv4Address(value)
    if args.direction == "upload":
        assert args.upload_file and args.upload_file.is_file()
    if args.probe_mode == "curl":
        probe_url = urlsplit(args.probe_url or "")
        assert probe_url.scheme == "https" and probe_url.hostname and probe_url.port in (None, 443)
        assert not probe_url.username and not probe_url.password
    args.output.mkdir(parents=True, exist_ok=False)
    write(args.output / "plan.json", {**{k: str(v) if isinstance(v, Path) else v
                                        for k, v in vars(args).items()},
          "curl_version": subprocess.check_output(["curl", "--version"], text=True),
          "latency": ("TCP connect, one sample per 0.5 s, 1 s timeout; p95 nearest rank"
                      if args.probe_mode == "python" else
                      "curl TCP connect + HTTP total; 0.5 s cadence, 1 s max per request; "
                      "p95 nearest rank, failed HTTP probes counted separately"),
          "cpu": "first/last router snapshots strictly inside load; total and per core",
          "validity": "all streams sustain max-time; pinned local/remote IP; direct conntrack proof required"})
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = {name: pool.submit(selected_probes, args, name, host, port, 10)
                   for name, host, port in (("router", args.probe_host, 80),
                                            ("endpoint", args.endpoint_ip, 443))}
        idle = {name: future.result() for name, future in futures.items()}
    write(args.output / "idle-probes.json", idle)
    summary = {"idle": {name: distribution(rows) for name, rows in idle.items()}, "rounds": []}
    for trial in range(1, args.rounds + 1):
        prefix = args.output / f"{trial:02}"
        prefix.with_suffix(".before.txt").write_text(snapshot(args.router))
        sampler = Sampler(args.router, args.source_ip, args.endpoint_ip, args.seconds,
                          prefix.with_suffix(".sampler.stderr"), args.probe_source_ip)
        mac_before = mac_counters(counter_interfaces)
        stop = threading.Event()
        print("START", trial, args.direction, flush=True)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.streams + 2) as pool:
                probe_futures = {name: pool.submit(selected_probes, args, name, host, port,
                                                   args.seconds + 8, stop)
                                 for name, host, port in (("router", args.probe_host, 80),
                                                          ("endpoint", args.endpoint_ip, 443))}
                started = time.monotonic()
                futures = [pool.submit(load, args, n, prefix) for n in range(1, args.streams + 1)]
                try:
                    results = [future.result() for future in futures]
                finally:
                    ended = time.monotonic()
                    stop.set()
                measured = {name: future.result() for name, future in probe_futures.items()}
        finally:
            sampler.close()
            write(prefix.with_suffix(".router-samples.json"), sampler.rows)
        mac_after = mac_counters(counter_interfaces)
        write(prefix.with_suffix(".mac-counters.json"), {"before": mac_before, "after": mac_after})
        prefix.with_suffix(".after.txt").write_text(snapshot(args.router))
        write(prefix.with_suffix(".probes.json"), measured)
        router = summarize_samples(sampler.rows, started - sampler.started, ended - sampler.started)
        total_bytes = sum(result["bytes"] for result in results)
        direct_streams = all(result["local_port"] in router["direct_source_ports_by_ip"].get(args.source_ip, [])
                             for result in results)
        endpoint_probes = measured["endpoint"]
        probe_ports = set(router["direct_source_ports_by_ip"].get(args.probe_source_ip, []))
        counters_a, counters_b = mac_before["counters"], mac_after["counters"]
        row = {"trial": trial, "duration_s": ended - started, "streams": results,
               "direct_load_streams_verified": direct_streams,
               "endpoint_probe_conntrack_matches": sum(probe.get("local_ip") == args.probe_source_ip
                                                        and probe.get("local_port") in probe_ports
                                                        for probe in endpoint_probes),
               "mac_netdev_delta": {dev: {key: counters_b[dev][key] - counters_a[dev][key]
                                         for key in counters_a[dev]}
                                    for dev in counters_a.keys() & counters_b.keys()},
               "busy_cpu_seconds_per_gib": (router["busy_cpu_seconds"] / router["interval_s"]
                                            * (ended - started) * 2**30 / total_bytes) if total_bytes else None,
               "cpu_per_gib_method": "interior sampled busy CPU rate / whole-window HTTPS payload rate",
               "mbps": sum(result["bytes"] for result in results) * 8 / (ended - started) / 1e6,
               "router": router, "latency": {name: distribution(rows) for name, rows in measured.items()},
               "valid": all(result["valid"] for result in results) and direct_streams}
        summary["rounds"].append(row)
        write(args.output / "summary.json", summary)
        print("DONE", json.dumps(row), flush=True)
        if not row["valid"]:
            raise RuntimeError("invalid load or no direct router conntrack evidence; stop, do not replace window")
        if trial != args.rounds:
            time.sleep(5)


if __name__ == "__main__":
    main()
