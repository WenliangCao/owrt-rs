# UDP no-route REFUSED boundary

`DnsDaemon::handle_udp` previously dropped a valid query when no upstream
route matched. The pinned C path in `forward.c:342-365,589-602`,
`domain-match.c:411-419`, and `rfc1035.c:1349-1378` returns REFUSED instead,
with EDE NOT_READY (14) when the client sent OPT.

The Rust `NoMatchingRule` branch now returns that immediate response through
the same refusal builder as TCP. It retains the configured EDNS maximum
separately from the receive buffer limit. UDP supplies the C client reply
limit and explicitly clears DO; TCP preserves DO. Both preserve RD/CD/Z,
clear AA/TC/AD, set QR/RA, preserve the question and transaction ID, and emit
the configured OPT size rather than the client's advertised size.

`tools/dnsmasq/dns_udp_refusal_diff.py` runs the exact native C daemon and the
actual Rust executable, using the same configuration and a controlled UDP
upstream inside `run_isolated.sh`. Expected replies come from C. Comparison
uses full reply bytes without ID, flag, TTL, RR-order or EDNS normalization.
No-route cases must produce no upstream request; the positive route controls
must produce exactly the same upstream question sequence for C and Rust.
The comparator calibrates an equal response, changed wire bytes and a missing
response before starting the services.

The 2026-10-01 final `paired-04/` result has 558 queries per side and zero
differences. It covers IPv4/IPv6 client transport, RD/CD/AD combinations,
AA/TC/Z and request-RCODE flags, A/AAAA/unknown qtypes, IN/CHAOS/unknown qclass,
no OPT, DO on/off, client sizes 0/1/511/512/1232/4096/65535, configured maxima
512/1232, unmatched scoped routes and an entirely empty upstream list.
Sixteen positive controls use a matching scoped upstream, ensuring that
absence of a local record still forwards and does not become NXDOMAIN.
The fixture upstream uses IPv4; these results do not claim IPv6 upstream
coverage or all upstream failure modes.

Evidence is under `private/dnsmasq-rewrite/dns-udp-refusal-20260930/`:
`c-baseline-01/`, `paired-01/` through `paired-04/`, and `local-smoke-01/`.
The final summary records exact C/Rust ELF hashes and relevant source hashes.
An intermediate tool change reused the case label for the capture filename,
overwriting some `paired-03/` raw captures. The semantic comparisons were
unaffected, but that run is not the final evidence; the tool now rejects
capture-path collisions and `paired-04/` retains all six wire files.

The corrected local-service smoke passes 6/6, with `unowned-refused` replacing
the incorrect `unowned-dropped` expectation. Related daemon tests pass 21,
with the existing cache-oracle driver still ignored unless its explicit
oracle input is supplied. The musl library clippy gate passes. These results
close only the no-route refusal contract; local-answer EDNS sizing/truncation,
malformed opcode handling, other local-route gaps and full OpenWrt lifecycle
remain separate acceptance work.
