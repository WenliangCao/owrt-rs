# DNS TCP hosts snapshots across SIGHUP

2026-10-01. This gate confirms one real-daemon lifecycle contract: the exact C
`-k` daemon forks a hosts/cache snapshot per accepted TCP connection, and parent
SIGHUP reloads do not change the names visible to an already established child.
The Rust listener now creates the corresponding per-connection
`LocalDnsService` snapshot before spawning its worker; local query handling no
longer holds the parent's shared service lock during socket I/O.

`tools/dnsmasq/dns_tcp_reload_diff.py` runs both full binaries with the same
`-k`, configuration, hosts file and DNS queries. Within the dedicated
network/mount/PID namespace it makes mounts private, creates a `/run` tmpfs and
binds the ignored evidence directory at `/run/private`. The C default pid path
and syslog path therefore cannot affect host `/run`. The bind also lets the C
process read the identical fixture after dropping its startup privileges.
No DHCP listener, physical router or production network is involved.

The frozen sequence is eight queries across two parent SIGHUPs and three TCP
connections. Parent UDP queries see the current hosts generation; the oldest
TCP connection retains generation 1 after both reloads, the middle connection
retains generation 2, and the newest sees generation 3. Local TTL 37, question
IDs, flags, record contents and event order compare exactly. Only packet
compression representation is abstracted by the shared DNS semantics decoder.
The C trace and independent fixture values calibrate each generation; deliberate
address and TTL mutations must be detected.

`private/dnsmasq-rewrite/tcp-snapshot-20261001/run-01/summary.json` records
**8/8 queries matched**, both daemon shutdowns exited 0, and both calibration
mutations were rejected. Each response and stderr log is preserved. The exact
C ELF SHA256 is
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`;
the tested Rust ELF SHA256 is
`ece3dff0c322de8b478057b6ccf0ece4b007f97aae889dcbb03cabcd0bbf1131`.
`build-source-identity.json` records the working-tree source snapshot used for
that isolated build, rather than treating later edits as already tested.

Reproduce through `tools/dnsmasq/run_isolated.sh` with `--reference <exact C
binary> --rust <Rust binary> --output <new private directory>`. This confirms
TCP hosts snapshot visibility in normal fork mode. It does not qualify
privilege dropping, pid-file behavior, logging, full procd/ubus lifecycle,
TCP cache IPC, production packaging, or performance.
