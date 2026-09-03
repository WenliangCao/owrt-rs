#!/usr/bin/env python3
"""Small HTTP load generator (stdlib only). macOS `ab` stalls at ~140 ms per
request against this router, so this drives keep-alive connections from N
threads and reports throughput and latency percentiles.

  bench_http_client.py URL [-n REQUESTS] [-c CONCURRENCY] [--post FILE] [--json]
Prints: req/s, mean/p50/p95 latency in ms, status histogram.
"""
import argparse
import http.client
import ssl
import statistics
import sys
import threading
import time
from urllib.parse import urlsplit


def worker(url, n, body, headers, results, statuses):
    u = urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    ctx = ssl._create_unverified_context() if u.scheme == "https" else None
    conn = None
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    for _ in range(n):
        if conn is None:
            conn = (http.client.HTTPSConnection(u.hostname, port, context=ctx, timeout=10)
                    if ctx else http.client.HTTPConnection(u.hostname, port, timeout=10))
        t0 = time.perf_counter()
        try:
            conn.request("POST" if body is not None else "GET", path, body=body, headers=headers)
            resp = conn.getresponse()
            resp.read()
            status = resp.status
            if resp.getheader("Connection", "").lower() == "close":
                conn.close(); conn = None
        except Exception as exc:  # noqa: BLE001 - counted, not analysed
            status = "ERR:" + exc.__class__.__name__
            conn = None
        results.append((time.perf_counter() - t0) * 1000.0)
        statuses[status] = statuses.get(status, 0) + 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("-n", type=int, default=400)
    ap.add_argument("-c", type=int, default=4)
    ap.add_argument("--post", help="file whose content is POSTed")
    ap.add_argument("--json", action="store_true", help="Content-Type: application/json")
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    body = open(a.post, "rb").read() if a.post else None
    headers = {"Content-Type": "application/json"} if a.json else {}
    per = max(1, a.n // a.c)
    results, statuses, threads = [], {}, []
    t0 = time.perf_counter()
    for _ in range(a.c):
        t = threading.Thread(target=worker, args=(a.url, per, body, headers, results, statuses))
        t.start(); threads.append(t)
    for t in threads:
        t.join()
    wall = time.perf_counter() - t0
    results.sort()
    p = lambda q: results[min(len(results) - 1, int(q * len(results)))]
    print(f"{a.label:<14} req/s={len(results)/wall:8.1f} mean={statistics.mean(results):7.2f}ms "
          f"p50={p(0.5):7.2f}ms p95={p(0.95):7.2f}ms n={len(results)} c={a.c} status={statuses}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
