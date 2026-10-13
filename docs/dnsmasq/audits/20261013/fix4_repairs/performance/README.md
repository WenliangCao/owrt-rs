# N4 exact-image C comparison

These probes extend the preceding review's fixed cached-A workload by adding
exact-image C to every same-configuration comparison. Raw evidence stays on
Oracle under `/home/ubuntu/dnsmasq-fix4-repairs-20261013/private/`; only tooling
and derived reports are versioned. No physical router is involved.

`three_way.py prepare --output NEW_PRIVATE_DIRECTORY` freezes the baseline
three-way matrix. `three_way.py run --output NEW_PRIVATE_DIRECTORY` runs it as
root; `summarize` independently checks counters, cache proof, identities,
matching configurations, foreign-workload checks and throttling before reporting.
The frozen build uses product revision `74c6b453`; newer local document commits
do not change that product identity. The after-fix run supplies `--candidate`
and `--candidate-commit` to `prepare` and uses a separate new private directory.

Each round covers TCP and UDP, both with 100 and 1,000 unrelated-name TYPE A
`dns-rr` declarations. Orders are C/main/current, main/current/C, current/C/main,
so each implementation occupies each position once. The scenario, rate, random
seed, configuration and native tools match within every triple. Parameters
remain 1,000 queries/s, 20 clients, 3 seconds warmup, 15 seconds measurement,
CPU 0/1/2/3 for daemon/upstream/load/controller. TCP reconnects every 100 queries.
Every window first proves the configured raw record over UDP and TCP, populates
and individually proves all 4,096 cached names, then disables upstream answers.
No measurement is silently retried or dropped.

CPU comes from the service cgroup's `cpu.stat` usage delta, including C's forked
TCP children. Per-response figures include connection overhead and cannot be
interpreted as isolated raw-record lookup cost. Compare 100-to-1,000 scaling
within an implementation to assess configuration-size sensitivity; the C/main
absolute TCP gap also contains architecture and connection-management costs.
These are descriptive three-round medians and ranges, not proof of statistical
performance equivalence or a user-approved tolerance.

`ordinary_plan.py` prepares only the no-raw TCP profile with 30 seconds warmup
and 120 seconds measurement, using the same three-way runner, tools, order and
validation. Its selector is hashed into the frozen plan before any load starts.
