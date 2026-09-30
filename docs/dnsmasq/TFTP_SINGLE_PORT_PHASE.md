# TFTP single-port service evidence

This phase uses the same pinned C daemon and Rust listener fixture as
`TFTP_LISTENER_PHASE.md`. Both execute on an isolated Linux loopback network;
there is no physical router or helper-script execution. Reference source:
`tftp.c:244-276` (peer replacement/admission), `301-309` (struct reuse),
`769-850` (ACK/ERR), `916-977` (OACK and cached DATA).

`run-10-single/` under
`private/dnsmasq-rewrite/tftp-listener-tid-20260930/` records IPv4 and IPv6.
Each has 28 normal service observations and four independent stale-replacement
observations, 64 total. They cover same-peer replacement, independent peers,
full-capacity dropping (not queueing), matched/unmatched WRQ, failed replacement,
abandoned ACK, reuse after completion, three-block windows, partial ACK,
duplicate ACK, retry, cleanup and shutdown. There are 12 precisely classified
reference-defect observations and zero unexpected mismatches. This is not
a zero-difference equivalence claim.

The exact C reference has three distinct problems in this path:

* With IPv4 `--bind-interfaces --tftp-single-port`, the `check_dest == false`
  branch does not initialize `addra`, which `send_from` then consumes for the
  single-port source address. `run-06/` retained the observed C send failure
  (`Network is unreachable`). Its uninitialized-source branch cannot provide
  a defined compatibility expectation. Normal single-port comparisons use
  the C wildcard/pktinfo branch and a Rust wildcard listener within the same
  isolated namespace. Bound-IPv4 single-port is not accepted by this evidence.
* Replacing an active same-peer request reuses the C transfer struct without
  clearing `daemon->srv_save`. With the same file offset, `get_block` returns
  the old file's cached DATA. `run-07/` first detected this; the independent
  `single-stale` case in `run-10-single/` preserves the wrong C DATA versus the
  requested Rust `alternate` bytes. The ordinary replacement case negotiates
  `tsize`, whose OACK clears the C cache, to continue testing the other paths.
* Struct reuse loses the old C file reference. After two replacements the C
  process retains two file descriptors; Rust returns to its original FD
  count. The stale-data case independently retains one C descriptor versus
  zero Rust descriptors. These are measured reference defects, not behavior
  the Rust implementation should reproduce.

The comparator only classifies exact known C/Rust pairs, including the full
old/new DATA bytes. Any different payload or a nonzero Rust FD remainder is
still an unexpected failure. Calibration verifies two accepted cases and
eight deliberately rejected cases before each run. Raw packets, sources,
ELFs and logs remain in private/. Failed intermediate runs 06-08 are retained.

The runtime regression checks fresh file bytes plus ownership counts after
both successful and failing single-port replacement. The 32 host TFTP tests
pass. A separate real-time `single-timeout` case has been added to exercise
the C/Rust 120-second timeout and listener reuse; its result must be recorded
before that lifecycle is accepted. Interface admission, pktinfo source
selection beyond loopback, helper integration and production startup are
outside these results.
