# Frozen final candidate: trial regression

All 12 original trial cases passed on the same frozen final ELF. The 39 recorded client checks each passed DHCP OFFER/ACK, DNS/router DHCP options, and UDP plus TCP DNS. No test case failed or was retried.

- Source: `19bd6162e1b33c92a1e5ea26e864497800c7cfed`.
- Candidate: `/dev/shm/full-integrated-fix-20261014/private/release-final/dnsmasq-rs`.
- Candidate SHA-256: `fbeabf4f5ffabfa5d6b5f4eec0c52540984fdabe882943ef165d5b990a9f7b4b`.
- Stock image ELF SHA-256: `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
- Trial script SHA-256: `dfa94d52cb132a181d78b8a0471b49868d9d3dd8bf9f79b00839edbd649f8b74`.
- Frozen `source-final/tools/dnsmasq`: 463 files matched the source commit; pre/post tool and ELF identities were unchanged.
- Oracle run: `2026-10-14T13:46:56.564191+00:00` through `2026-10-14T13:49:34.673165+00:00`; at most 2 concurrent cases, 210-second case limit.

| Case | Boundary exercised | Result | Client checks |
| --- | --- | --- | --- |
| confirm-rollback | confirm; wait 12 seconds; explicit rollback twice | PASS | 4 |
| deadline | unconfirmed candidate; deadline 20 seconds | PASS | 3 |
| crash | bind static exit(1) ELF over candidate; SIGKILL running candidate | PASS | 3 |
| hang | SIGSTOP running candidate | PASS | 3 |
| watch-killed | SIGKILL watch helper; deadline 25 seconds | PASS | 3 |
| partial-rollback | SIGKILL watch and deadline helpers; unmount candidate; explicit rollback | PASS | 3 |
| reload | stock init reload; assert candidate PID unchanged | PASS | 4 |
| rollback-killed | ptrace observes rollback request with candidate mounted; SIGKILL rollback process | PASS | 3 |
| confirmed-rollback-killed | confirm candidate; ptrace observes unmount; SIGKILL rollback process | PASS | 3 |
| rollback-cleanup-killed | ptrace observes helpers cleared; SIGKILL rollback process | PASS | 3 |
| rollback-c-dns-loss | drop UDP and TCP DNS; reject unhealthy C; retain owners; remove drop rules; automatic recovery | PASS | 3 |
| documented-path | documented /tmp script and ELF; confirm; explicit rollback; reject bad upload hash | PASS | 4 |

The three rollback interruption cases recorded the requested/unmounted/helpers-cleared ptrace boundary and actual SIGKILL exit (`-9`). All automatically returned to the stock C identity and healthy clients. The DNS-loss case rejected unhealthy C with exit 1, retained the watchdog/deadline owners, and automatically completed recovery after DNS rules were removed.

Every case recorded the frozen candidate hash from `/proc/PID/exe` and the stock hash after rollback. `reload` retained the candidate PID under the unchanged harness assertion. The documented `/tmp` path confirmed, rolled back, and rejected a bad upload hash while preserving stock service.

Raw evidence is retained at `oracle:/dev/shm/full-final-trial-20261014/private`. Each case has an exact argv JSON, receipt, log, original result, command trace, topology and fixture evidence. Local ignored backup: `private/final-trial-20261014/evidence.tar.gz`.

- Backup SHA-256: `92b12c6ce5644d23db987d2e916eff6a038b7e37fee5a88ac387e5c1ceab8528`.
- Verified 330 indexed regular files against the downloaded archive.
- Cleanup found no fixture-rooted processes and no fixture mounts in the host namespace.

The initial unprivileged directory creation was denied; the dedicated empty directory was then created with sudo before running any case. No trial output was overwritten. These are isolated exact-image Oracle observations; the physical router was not accessed.

Artifacts: [derived result](result.json), [raw index](raw-index.json), [runner](run_trial_suite.py), [derivation](derive.py).
