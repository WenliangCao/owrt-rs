# Fixed quiet actual-API CPU screen

Status: completed after the coordinator-authorized DNS quiet-slot handoff;
the fixed result is recorded below. This is a standalone DNS socket API experiment,
not full DNS service or device acceptance. No router work is authorized here.

Reuse the two existing release artifacts without the counting allocator:

| Source | Private directory below `/home/ubuntu/dnsmasq-perf-20261015/loop/private` | ELF SHA256 |
| --- | --- | --- |
| E `4f869c885b47dcf60d56c872e5b0b3c62237beea` | `bound-dns-receive-e-counts-r2-20261015/socket-factory` | `8ebbeaa26f39005eec48e82ce75a3bf74a66595d1f0d50983b3924f467e27509` |
| Candidate `5a03fffe9fede0e5fe9b7a4401c90ca04de92e72` | `bound-dns-receive-candidate-counts-r2-20261015/socket-factory` | `b6b45000e1c8b63a3bf98958b64f97be0db3965ce05e7606ccbee97d6ab3fa51` |

The matrix contains `receive-bound4` and `receive-generic4`, each with bursts
one and sixteen: four cases, five pairs each, forty process windows. Case
order stays bound/1, bound/16, generic/1, generic/16 within every repeat.
E runs first in odd one-based repeats; candidate runs first in even repeats.
Every window executes exactly 10,000 iterations of the existing binary.
Do not extend short windows, add rounds, replace failures or select favorable
pairs after observing results. Keep payload, buffers, sixteen-packet budget,
terminal EAGAIN behavior and all existing result assertions unchanged.

Run the complete matrix through the existing `run_isolated.sh` with nice 10
and CPU 2 affinity. A Python supervisor reuses the existing
`device_perf_oracle_supplement.start/reap` helpers and `os.wait4` to record the
actual API child process's complete user and system CPU. Add these CPU values
and divide by the verified delivered packet count. Sender work, snapshots,
initialization, teardown, checking and output all remain included. No setup
subtraction, perf, strace, allocation instrumentation or compilation overlaps
the quiet window. Monotonic elapsed time is supplementary only. RUSAGE's
microsecond fields do not establish physical one-microsecond precision.

Record each fixed pair and report median, minimum, maximum, maximum relative
range W, and pair-direction count for total CPU per packet. A change inside W
or inconsistent across pairs remains inconclusive; a generic-path regression
must stay visible. These descriptive results do not replace device CPU tick
precision or the eleven-scene acceptance gates.

Prepared local runner:
`private/bound-dns-receive-20261015/plain.py`, SHA256
`fb676d378276d2959e1810f99e4dc373edc0fe87bc1b188605e88444ffde1af8`.
After slot handoff it may be copied to
`loop/private/bound-dns-receive-tools-r2-20261015/plain.py` on Oracle and run as:

```sh
sudo -n sh /home/ubuntu/dnsmasq-perf-20261015/root/source-e/tools/dnsmasq/run_isolated.sh \
  nice -n 10 taskset -c 2 python3 \
  /home/ubuntu/dnsmasq-perf-20261015/loop/private/bound-dns-receive-tools-r2-20261015/plain.py
```

The runner refuses an existing output directory and verifies the ELF and
instrumented source identities before and after the matrix. All raw records
remain under `loop/private/bound-dns-receive-plain-20261015`; only a small derived
summary may transfer. The earlier instruction screen suggests roughly 330
total instructions saved per bound packet in this transport fixture, while
the generic branch adds 3–8 user instructions. This motivates a small screen,
not a prediction of full-DNS benefit or an explanation of the C/E elapsed gap.

## Fixed result

All forty windows completed successfully, with all original results retained
and no reruns. ELF and private instrumented source hashes matched before and
after. The transferred 73,192-byte raw-derived summary has SHA256
`b73bd06cd002674d18550653622673eb4bd489df685942e336070f1e408d1a5b`;
`bound-dns-receive-plain.json` includes that receipt and every process result.

| Mode / burst | E CPU µs/packet median [min, max] | Candidate median [min, max] | Change | W | Same-direction pairs |
| --- | --- | --- | ---: | ---: | ---: |
| Bound / 1 | 4.8146 [4.7989, 4.8699] | 4.7034 [4.6889, 4.7436] | -2.310% | 1.475% | 5/5 |
| Bound / 16 | 4.05366 [4.04556, 4.07059] | 3.96401 [3.95029, 3.97317] | -2.212% | 0.617% | 5/5 |
| Generic / 1 | 4.8091 [4.7785, 4.8229] | 4.8172 [4.7738, 4.8281] | +0.168% | 1.127% | 3/5 |
| Generic / 16 | 4.05717 [4.05368, 4.05977] | 4.04326 [4.03454, 4.05028] | -0.343% | 0.389% | 5/5 |

The bound-path CPU reduction exceeds this screen's observed spread, with all
five pairs agreeing in both burst cases. Both generic-path changes remain
within observed spread. The earlier generic instruction increase of 3–8 user
instructions per packet is retained; an inconclusive CPU result does not erase
it. These results support considering the small change in a future complete
candidate, not declaring a full-DNS or A53 device gain. No per-query elapsed
gap is attributed to it. The Oracle slot was released immediately afterward
for the coordinator's next build.
