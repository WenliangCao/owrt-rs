# Actual G / 9e SDK hot-entry layout

Both exact canonical SDK ELFs and their own maps/build receipts were rehashed
locally. G is185/9109e987;9e is9e8459dd/a91f0c88. Both sectionless ELFs are
2,145,051B. Original executable PT_LOAD ranges bound every extracted function;
all selected bytes decode completely as AArch64. No nearby-symbol inference,
new build, remote access or timing occurred.

| Emitted range |G bytes / frame bytes|9e bytes / frame bytes|
| --- | ---: | ---: |
|SinglePoll::step|17608 /2400|4692 /640|
|wait_for_files|7304 /352|7192 /352|
|step_udp|1764 /384|1700 /384|
|DnsDaemon::poll_inner|12448 /1520|528 /224|
|Shared local/cache answer|3980 /608|3848 /592|
|Fresh address writer|1088 /288|1028 /160|
|Cached local-ownership check|528 /368|528 /336|

9e's separate active helpers remain: ready DHCP4408/2016, requested cache dump
8892/1072, nonempty upstream completion5664/1024, active upstream poll6260/1088
and fallback address writer1148/288. Active DHCP can therefore use a nested
640+2016 frame, exceeding G's shared2400 frame. This is not a claim of globally
reduced stack use or total text size. Single-address eligibility is separately
emitted at384B in9e; the absent G symbol means it is inlined, not free work.

These actual SDK values confirm that the intended frame boundaries survived
canonical compilation. They differ in some ranges from the earlier local6ab
control and cannot be replaced with those local numbers. Equal ELF size does
not imply equal hot layout or memory footprint. No executed instruction count,
A53 cache-miss cause, IPC or CPU improvement follows from this inspection; the
ongoing original native/device/owner screens remain the performance evidence.

[Artifact identities, complete extracted ranges and entry instructions](cached-hit-9e-actual-sdk-codegen.json).
