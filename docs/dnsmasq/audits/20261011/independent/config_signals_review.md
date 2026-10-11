# Independent config, interface and signal review

Audited commit: `6b8eee96eda8aaa4cc47580530e5f287baeaaaa4`.
Actual Rust ELF: `6ef1857c385c277ee00a186312e2bfb4400abd2eeb4c2a3a7ade9e16219c5c84`.
Exact-image C ELF: `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.
All executable tests ran on Oracle under `run_isolated.sh`, in a separate network,
mount and PID namespace. Product code was not changed. Physical routers were not
accessed. Native C was an additional control only in the original signal suite.

## Finding — P3: SIGUSR1 omits IPv6 upstream scope IDs

Confirmed with the exact image and newly built Rust release. Configure
`server=fe80::1%lo`, start the foreground daemon and send SIGUSR1. The C startup
and cache-dump logs identify `fe80::1%lo#53`; Rust's startup log identifies the
same server, but its dump says `server fe80::1#53`. The ordinary IPv4 control
retains its full address and port on both implementations. Both daemons remain
alive and exit normally on SIGTERM.

The new `components/dnsmasq/src/dns/daemon_dump.rs:50-52` formats the server with
`address.ip()` and `address.port()`. Taking only the IP discards `SocketAddrV6`'s
scope. Matching C `cache.c::dump_cache` uses `prettyprint_addr`, which includes
the interface. Existing Rust `logging::address_text` already implements that
interface-aware representation, and is used by the correct startup log.

Impact: diagnostics cannot identify the responsible link when multiple upstreams
use the same link-local IPv6 address on different interfaces. This is an
operational visibility defect in the newly added diagnostic path. It does not
by itself block merging and does not establish a DNS forwarding failure.
Evidence: [config_signals_dump.json](config_signals_dump.json).

Reproduce (OUT must be a new directory):

```sh
SOURCE=/home/ubuntu/dnsmasq-fix-independent-20261011/source
PRIVATE=/home/ubuntu/dnsmasq-fix-independent-20261011/private
IMAGE=/home/ubuntu/owrt-evidence/ax3000t-stock-openwrt-25.12.5/extracted/rootfs-files
sudo -n sh "$SOURCE/tools/dnsmasq/run_isolated.sh" \
  python3 "$PRIVATE/config_signals_dump_probe.py" \
  --image "$IMAGE" --rust "$PRIVATE/release/dnsmasq-rs" \
  --out "$PRIVATE/config_signals_dump-new"
```

The portable probe is committed alongside this note as
[config_signals_dump_probe.py](config_signals_dump_probe.py).

## Successful checks and controls

- Restored A05 options: reran `audit_20261011_config.py --a05-only` for all 11
  affected directives plus `no-ident`. All 12 pass syntax, startup, actual DNS
  wire comparison and normal shutdown. [config_signals_config.json](config_signals_config.json).
- Extended syntax: 65 valid/invalid configuration-file cases covering auth
  server interface family suffixes, empty tokens, quoting, peer IPv4/IPv6,
  auth TTL overflow/invalid text and inactive boolean extraneous arguments.
  Accept/reject decisions agree in all cases. Rejection text differs only in
  the existing executable prefix `dnsmasq` versus `dnsmasq-rs`.
- Auth interfaces and query logging: 54 configurations span wildcard,
  bind-interfaces and bind-dynamic; no-auth, lo, lo/4, lo/6, literal IPv4 and
  literal IPv6 auth selectors; ordinary, except-interface and listen-address
  ACLs. Each tests IPv4/IPv6 over UDP/TCP. Accepted DNS wire, admission/refusal
  and `log-queries=auth` output agree. Eight rows differ only in TCP refusal:
  C closes with EOF and Rust closes with reset. No-auth controls have the same
  distinction, so this is not attributed to the auth fix or an ACL bypass.
  [config_signals_probe.json](config_signals_probe.json) preserves those raw
  differences (`equal=false`) rather than treating them as exact matches.
- Signal regression suite: reran original HUP/USR2/USR1/ALRM tests on the exact
  image, native C and Rust (12 processes); repeated dumps with a real forwarded
  cache record and negative-reply counters; forced leasefile write failure
  followed by ALRM before the scheduled retry, proving persistence repair and
  a DHCP-name cache dump. All checks pass.
  [config_signals_signals.json](config_signals_signals.json).
- Additional mixed signal exercise: six runs (C/Rust crossed with file,
  closed-pipe and `/dev/full` log sinks). Across them the probe sent 268,840
  HUP/USR1/USR2/ALRM signals and completed 67,210 DNS queries, all successful.
  All daemons stayed alive and exited normally. Standard signals may coalesce;
  sent count is not a claim that each handler ran. These concurrent audit
  measurements are responsiveness checks, not performance benchmarks.
- TFTP interface policy: 96 configurations cross three binding modes, four
  auth interface selectors, ordinary/no-dhcpv6/no-dhcpv4/no-dhcp-interface
  exclusions and generic/dedicated enable-tftp. Each tests IPv4 and IPv6.
  Exact C and Rust agree in every case: per implementation 128 file transfers
  and 64 refusals, with all daemon exits zero.
  [config_signals_tftp.json](config_signals_tftp.json).

Extended probes are [config_signals_probe.py](config_signals_probe.py) and
[config_signals_tftp_probe.py](config_signals_tftp_probe.py). Their CLI options
record the image and candidate paths; results bind to the actual ELF hashes.
The exported frozen source is not a Git working tree, so the general probe's
`source_commit` field is empty; use the build receipt and the audited commit
above for source identity, rather than treating that field as a revision claim.

## Limits

No physical deployment, install/upgrade rollback, cross-host signal scheduling,
or long-duration soak was performed. The mixed-signal run uses DNS without
active DHCP; ALRM lease maintenance is covered separately by the original
failure-injection case. Interface tests use isolated loopback and do not claim
coverage of every live hotplug/alias topology. Exact cache-dump allocator
statistics, all cache record representations and line ordering are not covered.
The original dump checker compares selected counters and positive host/cache
rows; it does not compare every dump line, which is why it misses the confirmed
scope-ID defect. Internal allocator reporting and nonterminal cache rows differ
between implementations; those alone were not classified as defects.

No merge-blocking issue was found in this delegated scope. This conclusion does
not cover the separate package-build, DHCP naming/helper or performance audits.
