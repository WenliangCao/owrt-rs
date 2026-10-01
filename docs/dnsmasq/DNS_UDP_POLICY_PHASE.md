# Forwarded UDP reply policy

The UDP caller now shares the known-local NXDOMAIN conversion with TCP,
preserves the complete extended RCODE before OPT removal, advertises the
configured EDNS maximum, and adds C's EDE codes for blocked/rebind and malformed
address replies. Non-NOERROR/NXDOMAIN replies bypass address processing as in
`forward.c:process_reply`. Cache admission uses the same prepared reply and
known-name conversion, so an upstream NXDOMAIN for an existing local name
cannot enter the NXDOMAIN cache before client-side correction.

`poll_with_local` reads the caller's current local generation when a pending
UDP reply completes. This differs deliberately from a TCP connection's
fork-equivalent snapshot. `forward_udp_on_listener` also retains a socket token
through the shared forwarding table and each coalesced recipient; the runtime
must use that token to select the receiving listener's reply socket.

`dns_udp_policy_diff.py` runs the pinned native C daemon and Rust under identical
configuration, endpoints and upstream behavior in separate runs in a loopback-only
Linux namespace. Its 84 cases compare exact client replies plus upstream query
semantics/counts. They cover known host/file/configured-record ancestors, address
versus upstream rules, unknown query types/classes, extended RCODE, rebind,
malformed CNAME, truncation, DO and AD/CD, and absent/512/1232-byte client OPT.
Only upstream random query IDs are normalized. The tester calibrates equality,
changed replies and missing completions before running.

Evidence: `private/dnsmasq-rewrite/udp-policy-20261001/linux/udp-policy-01/`
passes 84/84; the same Linux source snapshot passes 235 exact-C TCP caller
cases in `linux/tcp-caller-02/`. The retained first TCP attempt used an incorrect
source path and executed no comparison. The 145 relevant DNS unit tests pass
with two pre-existing oracle-dependent tests ignored. The three new regressions
cover a changed local generation while a reply is pending, address-rule ownership,
and listener identity for two merged recipients.

The earlier UDP attempt under the preceding work directory was rejected by
Rust's unsupported `bind-interfaces` configuration and established no comparison.
The corrected gate uses identical supported listener options. These results do
not establish binding-policy, general EDNS cacheability, DNSSEC validation,
shared runtime cache budgets, metrics/ubus or full service equivalence.
