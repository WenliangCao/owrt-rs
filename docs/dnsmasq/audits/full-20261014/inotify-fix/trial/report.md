# Inotify candidate: requested recovery confirmation

The single requested `confirmed-rollback-killed` case passed on source `340ed73e83e58ba845e0a645eb21e9ead0d0f108`. No additional case was run; the prior 19bd6162 12-case evidence remains separate and unchanged.

- ELF: `/dev/shm/full-inotify-fix-20261014/private/release-final/dnsmasq-rs`.
- ELF SHA-256: `edb5b4f91bac4486dd006400adc0c65380e0ec6fc36d36115d5ebc9475d3276d`.
- Trial script SHA-256: `dfa94d52cb132a181d78b8a0471b49868d9d3dd8bf9f79b00839edbd649f8b74`.
- All 463 frozen tool files matched source 340ed73e and were unchanged from 19bd6162; pre/post ELF and tool identities matched.

After confirming the candidate, ptrace observed the rollback process after unmount (`phase=unmounted`, `mounted=false`), injected actual SIGKILL, and recorded exit `-9`. Automatic recovery restored the exact stock C ELF (`097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`) and cleared the helper PID files. Running candidate identity was independently read from `/proc/PID/exe`.

All three client checkpoints—initial stock, candidate, and automatic stock recovery—passed real DHCP OFFER/ACK, DNS/router DHCP options, UDP DNS and TCP DNS. The run took 14.841 seconds, with no failure or retry. Cleanup found no fixture-rooted processes or fixture mounts in the host namespace.

Exact argv, receipts, original result, topology, commands and fixture evidence remain under `oracle:/dev/shm/full-inotify-trial-20261014/private`. Ignored local backup: `private/inotify-trial-20261014/evidence.tar.gz`.

- Backup SHA-256: `db2238ac2711c458d865f4c94223b392eaca8804f6c97375622a9207462ebc3b`.
- All 38 indexed regular files matched the downloaded archive.

This was an isolated exact-image Oracle namespace test; no physical router was accessed. Artifacts: [result](result.json), [raw index](raw-index.json), [runner](run_trial.py), [derivation](derive.py).
