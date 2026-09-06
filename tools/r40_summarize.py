#!/usr/bin/env python3
"""Median of the per-run means in an r40 transcript, per configuration."""
import re, sys, statistics
from collections import defaultdict

def load(path, tag):
    out = defaultdict(list)
    for line in open(path):
        m = re.match(r"(\S+) rep=\d+ lookup_all n=\d+ mean_us=([\d.]+)", line)
        if m:
            out[m.group(1)].append(float(m.group(2)))
    return out

c = load(sys.argv[1], "c")
r = load(sys.argv[2], "rs")
print(f"{'config':<14}{'C median':>10}{'RS median':>11}{'delta':>9}{'  C runs':>10}{'RS runs':>9}")
for k in c:
    if k not in r:
        continue
    cm, rm = statistics.median(c[k]), statistics.median(r[k])
    d = (rm - cm) / cm * 100
    print(f"{k:<14}{cm:>10.1f}{rm:>11.1f}{d:>8.1f}%{len(c[k]):>10}{len(r[k]):>9}")
