# TFTP service boundary phase

This phase isolates the policy decisions in the patched dnsmasq 2.93 TFTP
request path. It intentionally has no UDP socket, file descriptor, helper
script, or daemon loop; it is not a TFTP service by itself.

| C source | Contract | Rust boundary | Evidence |
| --- | --- | --- | --- |
| `tftp.c:366-430` | WRQ returns `ERR_ILL`; RRQ has a non-empty NUL string and `octet`/`netascii`; backslashes become `/`; `tftp-lowercase` lowercases other bytes | `tftp::parse_request`, `tftp_service::resolve_path` | Existing wire parser tests; path byte tests |
| `tftp.c:432-507` | Prefix starts at `/`; relative root is therefore `/root`; absolute names are used directly only when they start with the prefix; otherwise their first slash is removed | `resolve_path` | Prefix, absolute, relative-root tests |
| `tftp.c:507-522` | C checks a `/..` substring after concatenation, then opens the path | `resolve_path` | Rust rejects every `..` component only when a prefix is configured; leading `../` is retained in no-root mode for C compatibility |
| `dns-protocol.h:50`, `tftp.c:437-439` | `MAXDNAMESTR=503`; C `strncat` truncates to the workspace | `MAX_PATH_BYTES`, `append_bounded` | 503-byte boundary test |
| `tftp.c:543-624` | Open then `fstat`; root requires `S_IROTH`; secure non-root requires effective-UID ownership | `permitted` | root/secure branch tests; open/fstat remains caller-owned |
| `tftp.c:242-271` | In single-port mode, a matching peer's non-RRQ is routed to its transfer; repeated RRQ replaces it; unmatched peers obey `tftp-max` | `admission` | peer/opcode/capacity tests |
| `tftp.c:769-850` | ACK block-wrap, duplicate/future ACK and ERR state are transfer-local | `tftp::Transfer` | Existing unit tests and `tftp_oracle.py` `get_block` byte oracle |
| `tftp.c:724-761,852` | Finished transfers enter the script queue; error/timeout frees transfer state | Not yet implemented | Explicit remaining gate |

`resolve_path` accepts raw Unix bytes, matching the C filename buffer even for
non-UTF-8 names. The component traversal check is stronger than C's textual
`/..` check, but only applies when `tftp-root` is configured. With no root C
allows an absolute or relative path (relative paths are rooted at `/`), so the
boundary retains that behavior and leaves deployment policy to the caller.

`admission` is deliberately a small decision function. The caller must first
validate interface/pktinfo, then use the result to open and `fstat` the file,
create a separate transfer socket when `tftp-single-port` is disabled, verify
the source TID before invoking `Transfer::receive`, and release the old
transfer on `Replace`. The C implementation also shares open files by
`(st_dev, st_ino, filename)` and queues successful transfers for
`queue_tftp`; those ownership and helper actions remain unimplemented.

Verification run:

```text
cargo test --manifest-path components/dnsmasq/Cargo.toml tftp_service
5 passed
cargo clippy --manifest-path components/dnsmasq/Cargo.toml --all-targets -- -D warnings
```

The pinned C oracle (`tools/dnsmasq/tftp_service_diff.py`) compared 255,528
path cases and 20,000 single-port admission cases against the Rust boundary:
0 unexpected mismatches and 2,408 explicitly classified `..` hardening
differences. Its generated source, inputs and JSON stay under ignored
`private/`.

The existing C extraction oracle covers `get_block` netascii bytes,
expansion, carry and the documented Rust optimization. It does not validate
socket admission, path races, interface selection, port ranges, retries,
PXE/BOOTP integration or package startup. Those remain delivery gates.
