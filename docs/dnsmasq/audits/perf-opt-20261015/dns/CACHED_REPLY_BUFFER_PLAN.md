# Return small cached UDP replies after their final send

Independent child `03ace8ec` of `0161ad9c` keeps one bounded response allocation
in LocalDnsService. Only the fresh-address writer takes it. The UDP owner returns
an owned Cached reply after logging, dump and the final send attempt; other
result paths retain their original order. No callback or result borrows the
storage. A caller can retain an answer indefinitely by not recycling it.
Capacity above512 is dropped, so a large general reply cannot permanently
enlarge the service's retained buffer. Existing TCP owners do not recycle.

PacketWriter uses the same initializer for fresh and returned buffers, clearing
old contents and resetting the header. The original576 fresh/general controls
now prefill the candidate buffer with0xff, exercising errors and TC limits.
A new prepared-UDP regression alternates longest/short names, A/AAAA and
EDNS/no-EDNS, retains an earlier owned reply through subsequent queries, and
checks that a4096-byte response does not enlarge retained storage. Mac721/8
and musl all-target checking pass. An independent source review found no
ownership/behavior blocker; related Linux and full44 qualification remain open.

[The local count receipt](cached-reply-buffer-local-allocation.json) reuses the
existing prepared-UDP probe and System allocation counter. It imports800 real
fresh cache replies, primes1000 calls, then counts8000 calls. The only probe
difference is the new owner's explicit recycle after reading the answer.
Exact0161 makes one allocation/128requested bytes per call;03ace makes zero.
Both checksum468800, zero reallocations and zero live-byte delta. This is Mac
synchronous API evidence, excluding sockets and the remaining owner loop; it
does not establish whole-query allocations or allocator CPU cost on A53.

Keep this source out of the active54bd/0161 builds and measurements. If their
results warrant pursuing the remaining allocation, bind exact related Linux
gates and an unchanged SDK build first, then use the existing independent
owner32 and A53ten protocols against0161 to isolate this increment. Every
sample and cold/full-matrix regression remains required before promotion.
An accepted-E claim still needs a fresh direct E comparison; historical deltas
are not summed. No compiler option, behavior repair or tool change joins this
prototype.
