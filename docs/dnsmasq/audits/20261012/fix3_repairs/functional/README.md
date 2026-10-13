# TCP shared-answer repair verification

`validation_driver.py prepare` freezes a new output directory, product/tool/ELF
identities and the complete command inventory. `run` executes it sequentially and
keeps failures intact. All daemon correctness checks use the real SDK payload;
release performance and SDK compilation use separate controllers.

The eleven directed commands replay F02, fresh NXDOMAIN/DHCP publication, F08 stale,
R1 terminal records, R1 RD/DO controls, N1, the third-review DNS matrix, the original
A10/DNS boundary probe, N2, the 65 syntax/54 auth-ACL service combinations, and
an added same-connection TCP/UDP comparison.
The thirteen complete affected families contribute 34 registry commands:
`m5_dns_cache`, `m5_edns`, `m5_local_records`, `m5_option_matrix`,
`m5_option_matrix_next`, `m5_option_matrix_third`, `m5_option_matrix_lease_names`,
`m5_rr_filter`, `filterwin2k`, `m5_dns_endpoints`, `m5_interface_records`,
`dns-files`, and `logging-all-scopes`. Registry checks and full case inventories
are preserved. The SDK link map must belong to the actual SDK ELF; this round's
second clean build preserves the map and checks ELF/APK byte identity.

`tcp_udp_parity.py` reuses the third-review profile definitions and packet vectors.
Its 1,736 paired cases cover 14 profiles, positive/negative terminals, ordinary and
debug mode, 10 query types and RD/DO controls. Every tested protocol starts from a
HUP-cleared cache; TCP warms and queries on the same connection. All header bits,
questions, section counts and order, owner/type/class/RDATA, OPT words and trailing
bytes are compared. Compression and ordinary RR TTL aging are normalized; full
wire and upstream observations remain in private results. Large UDP replies may
only differ from TCP when the C control exhibits the same truncation and both
implementations match their respective C transport.

The original matrix proves nine C-internal, nontruncating protocol differences:
`target-local-positive` queries `6/12/15/16/28/33/255/257-rd`, and
`target-literal-positive/255-rd`. For these exact cases, the required shared behavior
is Rust TCP = Rust UDP = current C UDP, including upstream counts. This preserves
the requested single answering path instead of adding C's transport-specific
routing behavior. No other routing difference is waived.

Two inherited `forward-pointer` parser differences in the original malformed
matrix are compared against their exact prior Rust result, retained in
`historical-differences.json`. F08 stale is fully replayed and reported separately:
its execution/health check never becomes an equivalence claim when the old EDE
difference remains. N2 must match C's deliberate post-privilege-drop file reading.

Offline calibration against the retained third-review raw inputs rejects the old
artifact: the matrix checker finds 260 wrong TCP answers and their 260 transport
mismatches; the N1 checker finds 48 wrong answers. The nine C-internal routing
cases and two inherited parser cases do not suppress any additional failures.
The source raw matrix SHA is
`eecdbd9fc68be4ae86a6b24a607874d5c9fe36b9ecd5b96812bada64fd800fc9`;
N1 raw SHA is
`2b5a7a7052d92708b8ffe21e4b6b07b596c061b43d65739df9c0eb98869f1fb6`.
This calibration is read-only, not a new daemon run.

The auth/ACL probe preserves all 54 service combinations. Its eight previously
recorded EOF/RST differences must retain exactly their known flags and complete
C/Rust results; all other service results and all 65 syntax exit decisions must
match C. An existing rejection representation difference is not presented as a
fix or a successful DNS response.

After the source archive was frozen, two original hosts probes were retained as a
separate supplement because their cases include TCP answers. The archived main
controller and its 45-command plan stay unchanged. `supplemental_driver.py`
freezes two additional commands and requires the primary state to show 45 passes
before execution: the original hosts/CNAME/malformed-additional probe and the
ordinary hosts diagnostics probe. These retain full C/Rust query and diagnostic
checks. The total is 47 commands, 45 primary plus two supplemental; the additional
controller has its own Git commit and file SHA, separate from source commit
`0ff33bb0`. It executes from the private tool directory, never overwriting the
source archive.

The first main run stopped at command 9: the original strict DNS probe exited 1
because its local profile includes the same two forward-pointer baseline cases
already retained above. Its other 366 responses matched C. The original failed
state, plan, argv and log are preserved. Exact query, C response, Rust response
and empty-upstream identity against the frozen prior matrix were independently
checked; `a10-checker-calibration.json` records this comparison.

`continuation_driver.py` binds both original plans and the failed state by SHA,
revalidates the first eight passed result files, and separately assesses command
9 without changing its exit code. It then runs the original remaining 36 commands
and the two original supplemental argv lists once. Its final state distinguishes
46 zero-exit commands from one original strict nonzero exit whose only differences
are the two predeclared parser cases. No archived source, product code, earlier
result or plan is modified, and no already completed workload is repeated.

The registered endpoint `local-archive-gate` intentionally waits for a second-host
archive check. At that step, pack the finished `syntax` and `service` directories
on Oracle with `m5_option_matrix_archive.pack`, copy each archive and manifest to
the local host, and run `m5_final_archive_gate.py verify-local` there. Return those
local receipts; perform the required prune only after verification, then restore
plain evidence from the verified archives before publishing each prune receipt.
The complete original metadata stays in both retained archive copies, and the
original `result.json` bytes must be unchanged. The gate and subsequent source-row
audit enforce the receipts; they are not bypassed. The final collector separately
binds archives, manifests, local verification, pack/prune/restore receipts and
retained result bytes.
