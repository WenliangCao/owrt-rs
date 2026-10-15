# Idle/busy UDP batching: empty-read reduction without fixed-read-one's busy cost

The independent F/idle-batch screen completed all36 fixed windows, with complete
traffic counts, no query errors, unscaled PMU groups and no substituted windows.
Source `1b934951`, original-SDK ELF `18794b7266a2c1f7ac5993fe5c01e955769afce178703d38ebefa5bc88ac23e2`,
2136859B, remains an unqualified performance prototype. Related Linux83+4 gates
passed before screening; full44 qualification and physical comparison are pending.

| Syscall observation | F | Idle/busy |
| --- | ---: | ---: |
| Low recvmsg/query | 2.0000 | 1.0002 |
| Low EAGAIN /5000 queries | 5000 | 1 |
| Low ppoll entered/query | 1.0002 | 1.0002 |
| High ppoll entered/query, traced | 0.062507 | 0.062523 |
| High EAGAIN, traced | 2 | 0 |

This confirms that the fixed1ms wait hint nearly eliminates the ordinary idle
empty read while retaining bounded batch amortization when busy. It is not a
guarantee: descheduling and observation can change the elapsed-wait hint. All
pending calls and selected parameter counts remain visible in the JSON.

| Plain result | F median | Idle/busy median | Change | W | Decision |
| --- | ---: | ---: | ---: | ---: | --- |
| Low CPU µs/query | 28 | 26 | −7.143% | 15.385% | Inconclusive;3 favorable pairs and only1tick median difference |
| High CPU µs/query | 4.66613 | 4.66074 | −0.116% | 1.166% | Inconclusive descriptive saturation comparison |
| High completed queries/s | 214055.55 | 214358.05 | +0.141% | 1.063% | Inconclusive |

No low-load CPU win is accepted, and this is not equivalence proof at high load.
The fixed single-packet experiment's earlier−22.3% high-rate pipeline change is
not reproduced in these independent pairs. Do not pool those earlier controls
or subtract one experiment's numbers from another. Saturated CPU/query uses
actual variable counts and does not claim the fixed-N tick precision gate.

The three low PMU pairs have median user instructions8950.065→8714.815, but
cycles20163.872→21044.624 and IPC0.44385→0.41411. Kernel instructions also fall
25702.491→23814.214 while kernel cycles rise40916.839→41878.630. These descriptive
counts do not establish a cycle win. High PMU medians stay close: user
instructions6765.998→6773.334 and cycles4385.329→4408.485. The complete windows,
latencies, sender CPU, enabled/running values and raw digests are retained.

No next candidate is selected solely from this screen. The next priority is
A53 attribution and allocation reduction, followed by a fully qualified product
comparison. This prototype remains separate from the E allocation/stage
diagnostic sources and all layout/compiler prototypes.

The setup controller initially stopped after the separate E allocation-meter
build exceeded the2200000B release ELF limit. That count-only diagnostic remains
unqualified and its failed setup record is retained. The idle SDK build then ran
once as the previously unstarted second build; its original release budget passed.
No release gate changed. A launcher SSH connection later disconnected while
waiting; the detached controller independently finished36/36 with all window
exit codes0, complete marker and empty error logs. No window was restarted.

[All results](udp-idle-batch-screen-result.json), [fixed plan](UDP_IDLE_BATCH_PLAN.md),
[related Linux gates](../correctness/udp-idle-batch-linux-gates.json).
