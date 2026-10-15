# Cache insertion copy screen

Independent base: B `9b91a192` plus approved stale compatibility fix
`b1136023`. Product change `93190195`; build source `de76526f`.
Branch `perf/dnsmasq-insert-20261015`, no cursor hint changes.

The exact SDK A profile identified `Cache::insert_at_counted` as 10.01% of
UDP-miss instruction samples and 18.29% of TCP-miss samples. Two discarded
name copies are source-proven: insertion/free construct the escaped dnsmasq
name only to compare its length with 75, and forward commit clones a name
used only by reverse-chain ordering.

The change counts escaped bytes without constructing the string, preserving
root, binary zero/one/dot expansion and the maximum 503-byte escaped form.
It conditionally clones the reverse name at the original point. Cache limits,
failure checks, pressure removal, generation/COW behavior and commit ordering
remain unchanged. No new allocation or representation is introduced. Static
independent review found no blocker. Native macOS tests on the independent
source pass; full exact-C/Linux/final artifact gates remain required.

`cache_insert_probe.rs` calls the real cache API, including the unchanged
caller record clone. Counter data and raw hashes are in `insert1-screen.json`.
At capacity 1000, ordinary replacement and full-pressure insertion each save
three allocations and 65 requested bytes per operation; reverse saves two
allocations and 42 bytes; escaped long names save three allocations plus two
reallocations and 268 bytes. Requested bytes are not copied-byte estimates.
Instruction changes: replacement −15.91%, full pressure −2.81%, reverse +0.16%,
long names −28.77%. Counters alone cannot qualify timing or device benefit.
All raw artifacts remain private. No router access.
