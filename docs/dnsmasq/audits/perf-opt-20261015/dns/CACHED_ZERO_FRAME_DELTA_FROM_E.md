# Exact185 performance delta from acceptedE

The actual comparison is E4f869c885b47dcf60d56c872e5b0b3c62237beea versus
185db90c9cabd26c0af09765636ef15bf6d35f79.185 inherits the intervening F and
fresh-address work. It is not merely a three-patch change relative to E.

The shipping changes form four groups:

- UDP admission validates the question without allocating a discarded Name.
  A later synchronous decode reuses its bounded retained name storage, including
  error and uneven-label capacity handling.
- Known static IPv4 DNS listeners avoid unnecessary receive pktinfo; dynamic,
  wildcard and IPv6 cases retain their original metadata paths.
- Eligible single fresh positive address answers use the existing query-local
  cache hint and direct writer, preserving cache ordering/expiry/LRU and all
  fallback behavior. Local address dispatch is narrower, and the local shortcut
  applies only after proving that an existing fresh cached address is unclaimed
  by current local owners. Full record assembly and fresh-writer frames stay
  outside their callers' common paths.
- The owner returns one bounded cached UDP reply buffer after its final send.
  Noncached/stale replies and oversized capacities retain the original disposal
  rules. No unbounded response pool is introduced.

Performance commits: b49f8ca3,445f3a09,3a3d8e3e,2a9d53b0,b343df11,11a33c95,
149c48fa,03ace8ec,185db90c. The54bd1e56 retained-lease fixture correction and
a5285d8d/0161ad9c scratch-capacity regression checks are separately identifiable.
The later7c2708f6 hosts collision-pair fixture repair is **not** in frozen185.

The approved historical expired-CNAME behavior repairb1136023 is already an
ancestor of acceptedE and is common to both sides. No new behavior repair is
introduced in the E/185 delta. This comparison cannot isolate that historical
repair's CPU cost; it is not a varying factor here. Count bookkeeping/guard
collection fixes belong to test tooling and do not change either measured ELF.
No C expectation or comparator is changed by these source optimizations.

Only direct same-round E/185 results measure the whole package's effect. Earlier
standalone screens, the local allocation counts and the static frame sizes
cannot be added to assign individual microsecond contributions. In particular,
the no-lease prepared API's5→0 allocations is not yet a measured185 whole-owner
A53 zero-allocation claim. The seven native regressions and high-load owner32
send-lag regressions remain part of the evidence even if full original11-scene
acceptance passes. No fresh total v0.2.0 improvement is inferred by adding
historical E/baseline percentages.
