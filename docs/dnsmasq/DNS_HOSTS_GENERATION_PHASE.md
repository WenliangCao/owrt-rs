# Static DNS generation, address order and PTR ownership

The previous local-answer path scanned `config.host_records` independently
of the file-hosts table. That bypassed C's duplicate suppression, first-name
PTR ownership, reverse/non-reverse ordering and lookup rotation.

`local::configured_hosts(config, local_ttl)` now builds the configured prefix
in declaration/name/IPv4/IPv6 order. Callers load hosts files into that same
table afterward, as `cache_reload` does. Configuration and file records use
the existing indexed insertion path; no second input journal or per-query
config replay was added. `LocalDnsService` and `DnsDaemon` consume this complete
generation. The runtime caller also uses it when rebuilding after SIGHUP.

Address selection now goes through the shared hosts index. ANY performs
separate IPv4 then IPv6 lookups; other RR types do not accidentally rotate
address lists. `Hosts::addresses` is an explicit read-only view for callers
that need static ownership without cursor mutation. PTR responses use the
first reverse owner and its TTL; explicit `ptr-record` entries take precedence.
The parser retains C's defined IPv4 narrowing/partial-address forms, IPv6
nibbles, `ip6.int` and textual bitstring form. Signed decimal overflow remains
outside the defined C comparison domain. Addressless `host-record` entries
create neither an address nor an artificial known-domain marker.

Source contracts: `option.c:5262-5331`, `cache.c:312-339,1174-1260,1322-1385,
1646-1670`, and `rfc1035.c:202-303,1875-2018`. The integration exposes
`DnsDaemon::forward_udp` so a caller that already checked its shared local
generation does not perform another lookup in a private snapshot.

The initial order is not a portable byte contract. The exact C hash mixes
raw bytes of `typestr`, including string pointers. The native C ELF is PIE;
ASLR changes bucket collisions and can change the initial RR permutation.
`generation-aa-01/` observed 18 differing responses among 58 identical
no-round-robin C/C queries. Their inventories and PTR ownership agree. This
does not permit arbitrary changes to later address order.

`dns_hosts_generation_diff.py` therefore applies a narrow stateful rule:

1. Exact `read_opts/cache_reload` C objects supply the address/TTL/type/flag
   inventory, independently of Rust. Both implementations must return that
   complete inventory, with reverse-owned records ahead of non-reverse ones.
2. The first validated permutation is one seed per process, RR family and
   identical generation input. It is retained in the report. Repeated SIGHUP
   with the same input must restore that same seed, not learn another one.
3. Every subsequent order is predicted by the extracted, unchanged C
   `cache_find_by_name` function. New TCP sessions use a parent snapshot;
   their lookups cannot advance the parent cursor. No reply is sorted and
   no seed is reset on each response.
4. Non-address responses, including PTR, remain byte comparisons. The
   comparator independently rejects changed second-response order and TTL.

The normal `-k` C/Rust service gate uses identical configuration/network
endpoints and private `/run`, network and PID namespaces. It covers fixed and
rotating modes, mixed IPv4/IPv6 UDP clients, TCP snapshots, ANY family order,
configuration/file duplicates, inherited/explicit TTL, PTR precedence,
changed-input reload and identical-input reload after disturbing the cursor.
`generation-04/` passes 180 queries per side with zero inventory, envelope or
C-model transition failures. `generation-aa-normalized-fixed.json` applies
the same model to the retained 18/58 C/C permutation differences successfully.
This is state-machine equivalence in that corpus, not general byte equivalence.

Evidence remains in `private/dnsmasq-rewrite/dns-local-edns-20261001/`.
The earlier shared-address sizing counterexample also passes 528 exact-byte
cases in `shared-fixed-01/` for its observed seed. Failed `generation-01/`
is retained; it used debug `-d`, whose C TCP path does not fork, so it is not
evidence for normal TCP snapshot behavior. `generation-02/` is a test-adapter
failure: `cache_enumerate(1)` resets iteration and returns NULL; the corrected
inventory driver begins enumeration with the following `cache_enumerate(0)`.

This gate does not cover shared dynamic cache/query merging across listeners,
DHCP publication, arbitrary interface changes, hostsdir/inotify, all reverse
name encodings, privilege/logging/procd parity, long-run growth or performance.

The follow-up literal-label-dot audit closes another name ambiguity. A dot
inside a wire label must not alias a dotted hosts/config key or a reverse
address component. Local key conversion now rejects that ambiguous form;
domain-rule matching instead retains C's escaped bytes so real later labels
still match address/local suffixes. Rejecting the entire name for suffix
matching caused an observed lost reply and was corrected before commit.

`private/dnsmasq-rewrite/udp-policy-20261001/linux/hosts-generation-01/`
passes 192 queries per side, including literal-dot forward and PTR cases.
`hosts-suffix-before-01/` retains the subsequent suffix-rule timeout.
`hosts-generation-02/` passes the expanded 204 queries per side, covering both
suffix rules across IPv4/IPv6 with fixed and rotating modes and reloads.
The same C inventory, initial-seed restrictions and per-step C transition model
remain in force. All 17 local-answer unit tests and library clippy pass.
