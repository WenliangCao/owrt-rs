# script-arp exact-image contract

`script-arp` is qualified against image C `dnsmasq`2.93 from OpenWrt25.12.5. The complete frozen manifest passes **78 paired cases across17 source boundaries**, with no missing case or unclassified difference. All9 ARP negative controls reject their mutations. The [closure receipt](../../private/dnsmasq-rewrite/evidence/M5/script-arp/close-summary-7440-20261005.json) contains the full evidence identities.

The shared neighbor cache produces `arp-add`/`arp-del` through the existing helper, including port0 without DHCP or TFTP. It preserves IP/family/MAC identity, duplicate dump records, confirmed positions, zero-length positive hardware addresses, deletion-before-addition order and newest-first additions. Existing loop activity governs the90-second refresh check; four real91-second waits prove idle retention, HUP refresh and the existing active TFTP timer. EDNS and TFTP consume the same cache.

The helper keeps C's104-byte logical ARP command size and writes only when its command pipe reports `POLLOUT`. A real4096-byte stopped-helper pipe holds104 bytes before TERM; TERM flushes the already serialized second command to208 bytes and exits before helper execution. Exactly two callbacks finish, and every unsent ARP NEW record drops. An actual301-callback burst recovers in exact order while DNS remains responsive. Accepted DHCP ACK/lease state and completed TFTP DATA/ACK are queued behind that blocked slot; observed order is the serialized ARP prefix, DHCP, remaining ARP, then TFTP.

Actual allocator breakpoints return NULL at C record calloc48 and Rust record realloc96. The receipt records the realloc pointer fromx0 and size fromx1. The failed lookup stays uncached, and the next caller refreshes successfully. C helper calloc304 has its guarded NULL-buffer SIGSEGV; Rust malloc104 retains and retries the same record with DNS service healthy.

| Validation on the same candidate | Result |
| --- | --- |
| Complete ARP family | 78 paired/17 boundaries;9 controls |
| Complete EDNS regression | 196 paired;0 differences;21 controls |
| Existing helper/TERM/TFTP completion regression | 13 paired scenarios;8 controls |
| Linux library/main tests | 661+10 passed;19 ignored and excluded |

Candidate source is `7440f1fd8953abce33eeff6c72250023c36aa40a`; ELF SHA256 is `8d38c1d5fc2c1581d23e0af6dfb1b06b04fa381ef2b1115ce977970b84300c2b`,1,777,704 bytes. The matching allocation map SHA256 is `30348a2cbd0c4d27bf929521751836ea57edd03f4b65b6807fde953846108a89`. Exact C ELF SHA256 is `097a9e21a2ca479cf5add1725e672d48179e7973eea836d030eafbea588cab87`.

The [guarded known differences](../../private/dnsmasq-rewrite/evidence/M5/script-arp/known-differences.json) preserve C's netlink-error retirement, partial publication, missing-DONE parent stall, NULL helper buffer crash and TCP local-receiver prefetch anomaly. Ordinary order, pipe capacity, credentials, caller identity, termination prefix and producer ownership require equality; these guards do not waive them.

Raw callbacks, packet streams, syscall/allocator receipts, image C/libc, candidate/test ELFs, map and source snapshots stay private. The final archive SHA256 is `f3be43abb2a24d8964faa26a434721bda6949566664bacde38b329ca682b5a33` (4,693 entries/4,242 regular files). Local verification covers SHA256 and all file metadata before remote pruning. All previous failed/calibration runs remain verified archives. No physical router state was modified.
