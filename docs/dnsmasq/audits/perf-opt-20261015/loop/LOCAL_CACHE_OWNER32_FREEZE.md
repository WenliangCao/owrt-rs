# Exact artifact bindings for two unstarted owner32 screens

The [freeze receipt](local-cache-owner32-freeze.json) binds all three completed
SDK artifacts and the exact three-candidate related Linux receipt
`050fe64b167ad1c449449e074ff62df876ab132285317a18fa38813a25f43c53`.
It records 2,809 related passes, 537 source files, 30 logs and six test artifacts.
The original complete frozen-C qualification is still outstanding.

| Source | Related passes | SDK ELF bytes | SDK ELF SHA256 |
| --- | ---: | ---: | --- |
| Integration `8d572ba1` | 938 | 2,140,955 | `8048d5129f02f643774bd30a3d695f741dfbb94ebaf5eafc5cc7146015e83b83` |
| Owned miss `1676fbb6` | 935 | 2,136,859 | `0372b8b3096dce399d4ba5d1deedf27be84206ae87ae95a2a17058e8d74b8bbe` |
| Bounded miss `c44cd116` | 936 | 2,136,859 | `70f9512eb5c62b239d3ad25d3d1a61bc9d67f898e559ef9df20214d36ecd23a5` |

All three build/source-unchanged and original size-budget checks passed. The
review rehashed each ELF, map, build receipt and all 179 SDK source files per
variant. Map/build hashes are retained in the JSON. The SDK controller exited
after three successful builds with empty stderr.

The completed [integration controller](run_local_cache_integration_owner_screen.py)
and [bounded-miss controller](run_local_miss_stack_owner_screen.py) replace the
historical disabled `.py.in` templates with exact hashes and actual receipt
schema predicates. They select exactly one matching `source_commit` inside
the batch; they never assume the batch contains one candidate. Each checks
batch completion, no owned live processes, source/log/artifact rechecks, the
candidate identity and its exact original lib/live/bin/ignored pass counts.
Their pure qualification predicates passed against the retained exact receipt.

After this identity block, the existing owner32 measurement loop is byte-for-byte
unchanged from its candidate-mapped template: three PMU and five plain pairs at
each load, fixed low/high workload, original driver/load generator and failure
handling. No new measurement framework was added. Both controllers were parsed
but never executed or uploaded. This freeze is reviewable preparation, not an
owner32 launch or performance acceptance.

The latest coordinator authorization permits only integration native240 after
DHCP's three-bundle pre-download and an idle Oracle check. Bounded/owned native
plans and both owner32 controllers remain unstarted until a later decision.
The earlier prepared plans and disabled templates remain as historical evidence.
