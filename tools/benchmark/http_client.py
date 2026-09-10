#!/usr/bin/env python3
"""Verified HTTP/TLS load from the LAN client, using Python's standard library.

Exact request counts, per-thread results, persistent connections, byte/JSON
body validation and nonzero exit on any failure. Self-signed router TLS is
accepted only with --insecure. Save output under private/, not in Git.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
import math
from pathlib import Path
import ssl
import statistics
import threading
import time
from urllib.parse import urlsplit


def contains(actual, expected):
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(
            key in actual and contains(actual[key], value) for key, value in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(actual) >= len(expected) and all(
            contains(a, e) for a, e in zip(actual, expected))
    return type(actual) is type(expected) and actual == expected


class RequestPacer:
    """One request-start budget shared by all connections, including warm-up."""
    def __init__(self, rate):
        self.interval = 1 / rate
        self.next_start = 0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            scheduled = max(time.perf_counter(), self.next_start)
            self.next_start = scheduled + self.interval
        time.sleep(max(0, scheduled - time.perf_counter()))


def worker(url, count, warmup, body, expected, json_body, insecure, fresh, tls12, barrier, release_time, pacer, cipher):
    parsed = urlsplit(url)
    context = None
    if parsed.scheme == "https":
        context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
        if tls12:
            context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
        if cipher:
            context.set_ciphers(cipher)
    connection = (http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, context=context, timeout=10)
                  if parsed.scheme == "https" else
                  http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=10))
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    headers = {"Content-Type": "application/json", "Connection": "keep-alive"}
    tls_connections = []

    def request():
        if pacer is not None:
            pacer.wait()
        started = time.perf_counter_ns()
        new_connection = connection.sock is None
        connection.request("POST" if body is not None else "GET", path, body=body, headers=headers)
        if parsed.scheme == "https" and new_connection:
            tls_connections.append({"version": connection.sock.version(),
                                    "cipher": connection.sock.cipher()[0],
                                    "session_reused": connection.sock.session_reused})
        response = connection.getresponse()
        payload = response.read()
        elapsed = time.perf_counter_ns() - started
        if response.status != 200:
            raise RuntimeError(f"HTTP status {response.status}")
        valid = contains(json.loads(payload), expected) if json_body else payload == expected
        if not valid:
            raise RuntimeError("response body failed validation")
        if fresh:
            connection.close()
        return elapsed

    try:
        for _ in range(warmup):
            request()
        # Describe warm connections too, but count resumed handshakes only in
        # the measured phase below.
        warm_connections = len(tls_connections)
        barrier.wait(timeout=30)
        samples = [request() for _ in range(count)]
        finished = time.perf_counter_ns()
        return samples, (finished - release_time[0]) / 1e9, tls_connections, warm_connections
    except BaseException:
        barrier.abort()
        raise
    finally:
        connection.close()


def benchmark(url, n, concurrency, warmup, body, expected, json_body=False, insecure=False,
              fresh=False, tls12=False, rate=None, cipher=None):
    if n <= 0 or concurrency <= 0 or concurrency > n or warmup < 0:
        raise ValueError("require n >= concurrency >= 1 and warmup >= 0")
    if urlsplit(url).scheme not in ("http", "https"):
        raise ValueError("only HTTP and HTTPS are supported")
    if rate is not None and (not math.isfinite(rate) or rate <= 0):
        raise ValueError("rate must be finite and positive")
    if cipher and (not tls12 or urlsplit(url).scheme != "https"):
        raise ValueError("a controlled cipher requires HTTPS and --tls12")
    pacer = RequestPacer(rate) if rate is not None else None
    release_time = [0]

    def release():
        release_time[0] = time.perf_counter_ns()

    barrier = threading.Barrier(concurrency, action=release)
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(worker, url, n // concurrency + (index < n % concurrency),
                               warmup, body, expected, json_body, insecure, fresh, tls12, barrier, release_time, pacer, cipher)
                   for index in range(concurrency)]
        results = [future.result() for future in futures]
    samples = [sample for group, *_ in results for sample in group]
    assert len(samples) == n
    elapsed = max(result[1] for result in results)
    connections = [connection for _, _, group, _ in results for connection in group]
    measured_connections = [connection for _, _, group, warm in results for connection in group[warm:]]
    ordered = sorted(samples)

    def percentile(q):
        return ordered[round((n - 1) * q)] / 1e6

    return {"schema": 1, "successful": n, "errors": 0, "concurrency": concurrency,
            "connection_mode": "new_connection" if fresh else "keep_alive",
            "request_rate_limit_per_s": rate,
            "requested_cipher": cipher,
            "tls_versions": sorted({c["version"] for c in connections}),
            "tls_ciphers": sorted({c["cipher"] for c in connections}),
            "measured_tls_handshakes": len(measured_connections),
            "resumed_tls_handshakes": sum(c["session_reused"] for c in measured_connections),
            "warmup_per_connection": warmup, "wall_s": elapsed, "ops_per_s": n / elapsed,
            "mean_ms": statistics.mean(samples) / 1e6, "p50_ms": percentile(.5),
            "p95_ms": percentile(.95), "p99_ms": percentile(.99), "latency_ns": samples}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("-n", type=int, default=1000)
    parser.add_argument("-c", type=int, default=4)
    parser.add_argument("--warmup", type=int, default=10)
    parser.add_argument("--post", type=Path)
    expected_group = parser.add_mutually_exclusive_group(required=True)
    expected_group.add_argument("--expect-bytes", type=Path)
    expected_group.add_argument("--expect-json", type=Path)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--fresh-connection", action="store_true")
    parser.add_argument("--tls12", action="store_true", help="use common TLS 1.2 for the controlled comparison")
    parser.add_argument("--rate", type=float,
                        help="total request starts per second across all clients; pacing excluded from latency")
    parser.add_argument("--cipher", help="OpenSSL cipher selection for a controlled TLS 1.2 comparison")
    args = parser.parse_args()
    body = args.post.read_bytes() if args.post else None
    expected = (json.loads(args.expect_json.read_text()) if args.expect_json
                else args.expect_bytes.read_bytes())
    try:
        measured = benchmark(args.url, args.n, args.c, args.warmup, body, expected,
                             args.expect_json is not None, args.insecure, args.fresh_connection, args.tls12, args.rate,
                             args.cipher)
    except Exception as exc:
        print(json.dumps({"status": "invalid", "error": str(exc)}))
        return 1
    print(json.dumps(measured, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
