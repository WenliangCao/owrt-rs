# Fixed-corpus logd daemon comparison

`r93_logd_fixed_corpus.py` runs exact C, formal R89 and a supplied candidate
against identical input and unchanged C ubusd inside separate PID/mount/net
namespaces. It creates temporary copies of the exact image and a held empty
FIFO over kmsg, preserving the benchmark's idle-CPU guard. No host `/dev/log`,
physical router, deployment or network interface is used.

```sh
python3 tools/r93_logd_fixed_corpus.py ROOTFS R89_LOGD CANDIDATE_LOGD OUTPUT \
  --ns-exec /home/ubuntu/r90-batch1/baseline/ns-exec --smoke
```

For real measurements, omit `--smoke` during a quiet controlled window. Default
is 4,096 records, four repeats, balanced side order, five cases. `--count`,
`--repeats`, `--cases` and `--sides` allow an explicit subset. The tool requires
R89 SHA `a6f738144c561047bdd34188b084888ca5050ef01a7b7105a2b9f8d9152b975f`;
it never accepts a directory name as baseline identity. Candidate SHA, exact
C binaries, helper source and namespace launcher SHA are recorded per batch.

Cases:

- `no_subscriber`: 128-byte datagrams, full retained ring decoded and checked
  against the corpus, with retained IDs/hash compared across sides.
- `follow_1`, `follow_8`: every reader receives all ordered frames; all fields
  checked by existing strict `assert_records`, not a final-marker shortcut.
- `trim_heavy`: 1,023-byte datagrams normalize to short unique records; retains
  exact ring checks plus before/after/after-close RSS, PSS, HWM, private dirty.
- `backlog_600`: 600 × 992-byte messages with 2 MiB ring, oneshot reader;
  SIGSTOP proves a nonempty kernel prefix plus remaining daemon backlog,
  then SIGCONT and no new logs. All 600 frames and EOF must be correct.
  C pipe capacity differs from Rust socketpair; prefix size is recorded, not
  forced equal. The complete retained history is checked afterward.

Every run preserves its result, logs, explicit failure and exit code. No
averages discard failures. `/proc` CPU tick resolution is reported; fewer than
10 measured ticks are flagged low-resolution. Increase count or compare
repeated complete runs before claiming small CPU changes. The tool does not
run a sampler thread; RSS/HWM snapshots bound observed footprint, not a full
allocation profile. HWM is cumulative since each fresh daemon startup.

Follow timing starts after readers are registered and ends when all data is
received, before full-frame verification. Other intervals include sending and
the final delivery barrier. Driver CPU includes the producer/reader helper;
logd and ubusd CPU are separate. Backlog drain has a separate sub-interval.
Input generation and rootfs setup are excluded. The 600-history lane is fixed
at 600 regardless of `--count`. `--smoke` fixes 256 records/one repeat (600 for
history), labels all timing **non-performance**, and is only a harness check.

The no-subscriber lane proves the exact retained ring, not delivery of records
already overwritten by the ring. Only follow lanes prove all input records.
The initial C calloc-zero sentinel is explicitly recognized before the first
input; any actual preexisting log is rejected. No output log is removed to
make performance look better.

After any performance change, first rerun `test_logd_stream_recovery.py` and
historical logd correctness gates. Then run this tool on all three binary
identities. This tool does not replace disconnect/reconnect correctness tests.
# R93 增量接收器验证补记（2026-09-15）

固定输入工具复用的 `receive_frames` 已改为增量读取帧头，避免每次收到新数据都重新遍历
全部历史帧。最终 `assert_records` 的字段、字节、ID 和顺序检查保持原样；EOF 不足、
额外帧和碎尾不能被当成成功。测试：9 项碎帧单测、5 项真实流恢复、C/R89/span 五场景
15/15 smoke，通过 6912 个 follow 帧与 1800 个 backlog 帧的完整校验。
原始证据在 ignored `private/r93/logd-reader-validation-20260915/`。
修改前的 pilot 与修改后的正式采样使用不同接收器，不能直接混成同一批性能结果。
