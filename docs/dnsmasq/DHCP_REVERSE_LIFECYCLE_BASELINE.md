# C reverse-host lease naming at startup and reload

This is a **C-only** baseline for `lease_update_from_configs` in the exact
patched dnsmasq 2.93 ELF
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
It changes no Rust runtime code and claims no Rust lifecycle equivalence.
The build-host runner uses private network/mount/PID namespaces containing
only loopback; no physical router was accessed.

The frozen corpus has **10 scenarios, 14 startup/HUP snapshots, 108 DNS
responses and 72 checks**, all passing. No DHCP packets are sent: every case
starts with the same infinite restored lease, so the observations isolate
startup/reload maintenance from ACK/INFORM naming. DNS is intentionally not
queried or counted as passed in either `port=0` snapshot.

| Input/change | Persisted lease name | Immediate DNS observation |
| --- | --- | --- |
| Static short host exists at startup | Old name becomes static short name | Short and configured-domain FQDN resolve; old lease name disappears. |
| Static name has matching domain suffix | Stored name is shortened | Short name and FQDN resolve; static FQDN retains PTR ownership. |
| Static name has wrong suffix or illegal hostname | Old lease name remains | Old short/FQDN resolve; the static hosts record can still own PTR. |
| No static hosts match | Old lease name remains | Old short/FQDN and lease FQDN PTR remain. |
| Matching `dhcp-host` supplies a name | Configured name wins at startup and HUP | A simultaneous static hosts name remains an independent local record. |
| Matching MAC config specifies another address | Static reverse name is used | The mismatching configured address does not rename this lease. |
| HUP replaces static name | Lease file changes to new short name | New short/FQDN resolve immediately; old names disappear. |
| HUP removes static hosts entry | Existing lease name is retained | Both lease names still resolve; PTR changes from the former static short name to lease FQDN. |
| `port=0`, startup and HUP | Old lease name remains | DNS checks are unexecuted by design. |

The source order is explicit in `dnsmasq.c:1834-1850`: reload hosts cache when
DNS is enabled, reread DHCP data sources, update DHCP configuration, update
lease names from configurations/static reverse hosts, write the lease file,
then rebuild lease DNS. `lease.c:254-274` prefers a matching configured name
whose optional address agrees, otherwise tries `host_from_dns`; no successful
match means it does not clear the existing name. `dhcp.c:1092-1127` gates that
lookup on DNS being enabled, F_HOSTS ownership, suffix agreement and legal
hostname, then strips the suffix.

For each observation, the tool waits for an empty DHCP hosts file's reread
log, then invokes the real synchronous UBus metrics method as a completion
barrier. The reload handler cannot dispatch this call until it returns.
Only then does the tool read the lease file and query DNS. The first DNS
response and all subsequent queries agree with the committed file. These
external observations establish completed-event consistency; they do not
measure the sub-statement timing of file write versus DNS publication.

The negative calibration changes only the expected startup lease name:
**71 checks pass, 1 fails, exit 1**. Its frozen C observations are byte-identical
to the positive run, with SHA256
`becefb0e67a0218958c813f22c7d7a2585d4a8b15b99c74b8b85a7167442c25d`.
The first run incorrectly expected the DHCP range log to recur at a DNS-disabled
HUP; it retained 13 snapshots, 1 failure and 1 unexecuted step. The final marker
and UBus barrier remove that harness assumption without dropping the case.

Raw configuration, packets, logs, lease files, `c-observations.json`, identities
and failures remain ignored under
`private/dnsmasq-rewrite/ubus-lifecycle-20261001/reverse-lifecycle-c-*`.
The final runs are `reverse-lifecycle-c-final` and
`reverse-lifecycle-c-negative`. Rust's startup/HUP name updater is the next
separate implementation and paired-test gate.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dhcp_reverse_lifecycle_diff.py \
  --reference-build "$EXACT_C_BUILD" --out private/reverse-lifecycle-c
```

Use a fresh directory and `--inject-error` for the negative calibration.

The subsequent [paired implementation stage](DHCP_REVERSE_LIFECYCLE_PHASE.md)
adds a common read-close/UBus completion marker and verifies the original
observation hash remains unchanged before comparing Rust.
