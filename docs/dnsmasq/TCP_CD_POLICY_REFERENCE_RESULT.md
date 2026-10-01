# Private TCP CD and policy differential result

The unchanged private candidate `2a773f8` matches exact native C in **65/65
observations** across all five TCP CD/policy profiles. A fresh C-first run passes
**152/152 C checks and 152/152 candidate checks**, with zero comparison or
infrastructure failures. No implementation change was required for this gate.

The [C baseline](TCP_CD_POLICY_C_BASELINE.md) was qualified before candidate
execution. It includes IN A and AAAA ordinary extraction under request CD,
the plain request-CD=0/raw-reply-CD=1 TCP control, three-slot uncommitted cache
pressure, and independent bogus-wildcard insertion under CD plus `no-negcache`.

The candidate reproduces child-only target removal, pending CNAME visibility,
SERVFAIL inspection without cache healing, and pending cleanup at the next
empty ordinary extraction. It keeps the parent cache unchanged when no
transaction commits. Child filler eviction remains observable through a child
miss while the parent still hits the old filler. The plain TCP control clears
the raw reply CD bit to match request CD and publishes the ordinary insertion.

Bogus-wildcard processing remains an independent committed transaction under
request CD and `no-negcache`. It returns NXDOMAIN for the triggering query and
writes a negative entry to the parent. That entry coexists with the old positive
A: subsequent A/alias answers remain positive, while child TCP and parent UDP
AAAA queries hit the cached NXDOMAIN. This is an explicitly checked coexistence
boundary, not an assertion that bogus handling replaces every typed answer.

All 30 real parent UBus metrics match at every observation. The comparison also
preserves normalized request/reply headers, section counts, ordered records,
raw-upstream CD semantics and the ordered upstream event sequence. It normalizes
upstream transaction IDs and DNS name compression, and permits at most one
second of TTL difference only for actual cached hits. It does not normalize
CD flags, hit/miss outcomes, eviction victims, insertion counts or publication.

Comparison calibrations accept identical traces and reject a missing
observation, a changed parent insertion count, an altered CD bit and an extra
upstream request. The C-only deliberate failure and the initial bogus
coexistence calibration failure remain archived.

| Artifact | Identity |
| --- | --- |
| Exact C ELF | `bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431` |
| Candidate ELF | `012448b55401f3ca5e0550751b1cd695dc4b137f948c624a366afa6886233e4a` |
| Candidate source | `2a773f8` |
| Paired tool commit | `0c419db` |

The JSON records result, tool, archive and individual trace identities. Raw
evidence is retained under the independent tool worktree's ignored
`private/cd-policy-evidence/paired-01-evidence.tar.gz` and on oracle in
`/home/ubuntu/tcp-cd-gate-20261001/private/paired-01/`.

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/tcp_cd_policy_oracle.py \
  --reference-build /home/ubuntu/dnsmasq-rewrite-20260929/c-native-01 \
  --rust "$PRIVATE_CANDIDATE" \
  --out private/tcp-cd-paired
```

This qualification covers the five concrete profiles, including the named
CD/bogus combination. It does not establish every CD/DO/policy combination,
arbitrary EDNS metadata, actual options that set the forwarding `no_cache`
state, DNSSEC validation, every LRU lookup order,
malformed partial frames, OOM or performance. There is no actual image-musl
execution or product promotion. No physical router was accessed.
