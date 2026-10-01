# Real TCP writeback buffering and ordering baseline

The exact native C dnsmasq 2.93 daemon passed **12/12 observations** on the
isolated Linux oracle. This baseline was frozen before testing the private Rust
prototype. It is an integration gate, not a performance measurement or a router
deployment result.

`tools/dnsmasq/dns_tcp_writeback_diff.py` runs real `-k` workers, a private ubusd,
UDP DNS and persistent TCP DNS. Its new libubus subscriber holds an actual UDP
DNS doctor callback through a private control socket. Both the downstream
session and its upstream connection are warmed before the hold. The subscriber
queues an **asynchronous** metrics invocation before returning the callback;
there is no synchronous nested invocation that could manufacture a deadlock.
No C timeout, pipe capacity, or source code is altered. A delayed/failed run is
retained and is never retried automatically.

| Case | Before: inserted / forwarded / active TCP | Queued metrics | After imports |
| --- | --- | --- | --- |
| One child, two sequential cold queries | 1 / 0 / 1 | 1 / 1 / 1 | 4 / 1 / 1 |
| Two children, same name, distinct answers; close both before release | 5 / 1 / 2 | 5 / 2 / 2 | 8 / 2 / 0 |

In the first case both child replies (`192.0.2.11`, `192.0.2.12`) arrive before
releasing the parent. The subscriber-held interval was 0.464 ms. Parent UDP
queries subsequently hit both imported cache entries without upstream traffic.
A single-message queue that blocks the second transfer until the parent drains
it cannot meet this observed contract; neither can an acknowledgement required
from the parent before replying to the client.

In the second case the first accepted child returns `192.0.2.21`, and the second
returns `192.0.2.22` for the same name. Both replies and both client closes precede
release of the parent. The subscriber-held interval was 0.435 ms. C's final
parent cache answer is **`192.0.2.21`**, as is a replacement child's inherited
answer, with no upstream requests. Queued metrics still show two occupied slots
while complete transfers await draining. After draining and child reaping the
active count is zero and `/proc` shows no child processes. This checks observed
release/reuse after data and EOF; it does not saturate the full TCP capacity.

The rewritten doctor reply (`192.0.2.250`) proves the callback completed inside
the unmodified 100 ms budget. The harness also enforces a 75 ms local work
deadline and checks the subscriber's monotonic timestamps against 100 ms. Each
queued snapshot runs before the doctor's own cache commit and before TCP pipe
imports. Its only changed counter is the parent's forwarded UDP query.

The matching native C source supplies these anchors:

- `dnsmasq.c:1304-1309`: UBus handling precedes DNS listener/pipe handling.
- `dnsmasq.c:1936-1957`: scan ready pipes from the lowest slot and return after
  one operation; release a slot only after EOF and child reaping.
- `dnsmasq.c:1994-2003`: allocate the highest free slot.
- `cache.c:844-855,917-923`: child emits transaction start/end without an ACK.
- `cache.c:950-985`: consume a whole insertion transaction through its end marker
  before returning to the event loop.
- `forward.c:2770-2780`: send the child DNS reply after processing the query.
- `ubus.c:398-406`: real notify completion uses a 100 ms timeout.

The two runtime cases establish buffered replies, queued UBus visibility,
competing-slot cache outcome, and eventual resource release. The exact
one-transaction-per-event loop boundary additionally rests on the above source
anchors; these cases alone do not distinguish every possible batch-drain
implementation. The gate retains source file hashes and source excerpts in its
private raw result.

Negative comparator calibration rejects an invented cache insertion during the
hold and the wrong slot winner, each as one differential failure. The first
harness attempt (`c-baseline-01`) stopped before any DNS query because an event
function parameter collided with a keyword argument. Its failure is retained;
`c-baseline-02` is the first behavioral run and passed without a timing retry.

Reference ELF SHA-256:
`bba5a0a8b1db6a82fcf9c59b4f4734dd77b5a986146ea3f1d5fd625b3f4e2431`.
The accompanying JSON records tool/helper identities, source hashes and ranges,
all semantic observations and counters, and hashes of the ignored raw input,
output, event order, subscriber and process-cleanup traces.

Reproduce from the repository on the Linux oracle:

```sh
sudo -n sh tools/dnsmasq/run_isolated.sh \
  python3 tools/dnsmasq/dns_tcp_writeback_diff.py \
  --reference-build /home/ubuntu/dnsmasq-rewrite-20260929/c-native-01 \
  --out private/tcp-writeback-c-new
```

A later candidate run adds `--rust /absolute/path/to/dnsmasq-rs`; C always runs
first again, and the comparison retains actual C observations as its expected
values. Firmware, build outputs, runtime logs and binaries remain outside Git.
