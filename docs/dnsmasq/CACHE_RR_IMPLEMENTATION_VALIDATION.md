# Configurable generic forward caching: bounded implementation

Source `4bf072d` implements `cache-rr` configuration and ordinary forward
generic insertion. The parser uses the exact C table's 97 case-insensitive
names, comma/repeated fields and defined signed-int-to-u16 narrowing. Zero
list entries do not select QTYPE0, while ANY still selects it. CNAME and ANY
questions preserve their special insertion rules.

The existing ordered extractor now admits default SRV/non-address PTR and
explicitly selected types. It reuses `RecordRef::canonical_rdata` for embedded
name decompression and opaque unknown bytes. CNAME targets, SOA-backed typed
negatives and NXDOMAIN for an unenabled positive type use the existing cache
transaction. CD still suppresses only commit. Address-form PTR replies remain
outside this implementation instead of being stored under a forward key.

The independent [normal-data gate](CACHE_RR_GATE_RESULT.md) passes 22/22
configuration cases and 78/78 paired forward observations against each of
native and actual image C. Its reverse-PTR nine observations remain C-only.
The separate [QTYPE0 gate](CACHE_RR_ZERO_RESULT.md) passes 9/9 against each
reference. Both negative controls detect one deliberate difference.

The first image paired run retained 75 matches and one startup readiness
timeout; its static readiness datagram did not return. The subsequent
sequential run passes the full 78. UBus registration occurs before UDP binding
in the main startup source, but no capture establishes that as this timeout's
cause. The failed run remains and startup reliability is not declared solved.

The same ELF preserves native/image DO750/750, native ordinary-CD134/134,
and both separate pressure gates at 120/120 per reference. Full isolated
library389/main7 tests, native/musl all-target Clippy and formatting pass;
16 ignored tests are not passes. These root-owned checks had no failures.
Native ELF SHA-256 is
`8406757bb3c597bdce1673ec7036a6d1d69728fe17b0d5a55d8b506b21192070`.
[The validation JSON](CACHE_RR_IMPLEMENTATION_VALIDATION.json) pins the fresh
source, ELF, command logs, results and raw evidence archive. Root evidence is
under ignored `private/dnsmasq-rewrite/cache-rr-fix-20261001/`; independent
gate evidence is separately identified in its reports.

Independent source review also found a remaining error-propagation gap:
malformed generic embedded-name data stops this cache extractor, but the
downstream policy scanner still handles only address/CNAME errors. A separate
C-first malformed-input gate and repair are in progress. The regular-data
passes above do not qualify malformed records. Reverse-cache integration,
generic DO/AD metadata, full type/configuration coverage, resource/performance
acceptance, a new SDK artifact and router deployment remain incomplete.
