# Performance research continuation

Branch: `perf/dnsmasq-20261015`; worktree:
`/Users/USER/Developer/owrt-perf-opt-20261015`.
Starting main: `51b03959`. Do not merge main, push, or deploy.
Original main worktree has user prompt edits; leave them intact.

Status: protocol frozen; no product optimization yet. Current best remains
deployed v0.2.0 SHA256 `8472be5a0c21972a9d4ca7570809d4f3156835611ae73f49c04a62d4289aade7`.
See `audits/perf-opt-20261015/FROZEN.md` and `frozen-inputs.json`.

Oracle initial observation: root 53 GiB used / 142 GiB free; `/dev/shm` empty,
12 GiB free. No cleanup needed to obtain space; no deletion performed. All
seven existing containers healthy, including vaultwarden/pocket-id/caddy,
with original September 24 start times. perf hardware counters available.
Matching SDK and exact image bases retained under `/home/ubuntu`.

Active directions (separate worktrees/branches):

- `perf/dnsmasq-dns-20261015`: DNS cache/name/answer allocation and copy cost.
- `perf/dnsmasq-loop-20261015`: UDP/TCP owner loop/syscalls/start-stop.
- `perf/dnsmasq-dhcp-20261015`: DHCP persistence/hosts loading and publication.
- `perf/dnsmasq-correctness-20261015`: immutable gates and independent review.

Root controls all router activity and Oracle timing reservations. Oracle task
root will be `/home/ubuntu/dnsmasq-perf-20261015`, separate agent subdirectories.
Raw artifacts/configuration/logs belong in ignored `private/` only.

Next: prepare tools and exact artifacts, collect router health baseline and
fresh full C/v0.2.0 pairs, run parallel counter screening, then qualified
candidate batches. Record every attempt in `PERF_OPT_20261015.md`.
