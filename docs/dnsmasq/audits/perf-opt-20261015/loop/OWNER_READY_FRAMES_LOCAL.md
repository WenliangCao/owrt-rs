# Compact shared owner entry after existing readiness gates

Source5c995a85 is a child of025c2f2c. The two commits separately outline ready
DHCP work and SIGUSR1 cache-report formatting after their existing gates.
No work is deferred across turns and no cold attribute, new state, extra clock
read or readiness rule is added. Source peer70cf08da proves removal of the
nine new lines restores025 exactly;025's earlier eight lines restore6ab.
ALARM handling, atomic decrement, all borrow/drop ordering and the conditional
TCP high-water reset remain unchanged.

| Local final AArch64 range | 6ab | Bare025 | Combined5c |
| --- | ---: | ---: | ---: |
| step code bytes | 17608 | 13436 | 4692 |
| step explicit frame bytes | 2400 | 1312 | 640 |
| ready DHCP helper code/frame | in step | 4408/2016 | 4408/2016 |
| requested dump helper code/frame | in step | in step | 8884/1072 |

The actual locally linked ELF is5,022,096B, only144B below6ab and280B above025.
This experiment changes where code and frames live; it does not remove12KiB
from the executable. A normal no-request turn bypasses both helpers. Active
DHCP and requested reports each pay another call and nest their frame under
step; these explicit frames do not measure maximum stack or dynamic cache use.
wait_for_files remains7192B. No CPU or I-cache improvement is claimed.

Mac executable23tests and Linux-musl all-target compilation pass. Linux-only
helper execution and signal/DHCP/probe correctness still require the original
Linux groups, then normal screening. No new test framework is introduced.
Bare1df remains first; neither025 nor5c has an SDK or remote result, and no
in-progress source is changed. The bare025 disabled input remains preserved.

[Exact source, logs and local codegen receipt](owner-ready-frames-local.json).
