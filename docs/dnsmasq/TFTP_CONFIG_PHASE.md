# TFTP configuration state phase

This phase covers option parsing and state only. It does not claim that every
accepted TFTP option is consumed by the current listener.

| C source | Contract | Rust state | Runtime gate |
| --- | --- | --- | --- |
| `option.c:2890-2925` | `enable-tftp` is optional and repeatable; it sets the enable bit and prepends each comma-separated interface selector | `TftpConfig::enabled`, `interfaces` | Interface selectors are retained, then rejected by `validate_ready` because listener binding is not interface-aware |
| `option.c:3634-3646` | `tftp-root` is repeatable; a root without a comma overwrites the global root, while `<path>,<iface>` prepends a per-interface prefix; empty strings are accepted as null pointers | `root`, `interface_roots` | Per-interface prefixes are retained, then rejected by `validate_ready` |
| `option.c:3624-3632` | `tftp-max` and `tftp-mtu` use `atoi_check`; zero is accepted and the default is 50/0 | `max_transfers`, `mtu` | Both scalar values are consumed by the current runtime |
| `option.c:3648-3661` | Port endpoints accept 0..65535, including empty-as-zero, and reversed endpoints are swapped | `port_range` | Accepted by `validate_ready`; `TftpListener::bind_with_port_range` consumes the range for dedicated sockets; callers must forward this field |
| `option.c:3663-3669` | `tftp-unique-root` defaults to IP when no argument is supplied; `ip` and `mac` set independent option bits | `unique_root_ip`, `unique_root_mac` | Retained, then rejected by `validate_ready` until path selection consumes the bits |

Numeric parsing is bounded to the defined C `int` domain. This avoids copying
the undefined signed overflow behaviour of `atoi` for out-of-range input while
matching all defined C values. Quoted commas remain data because parsing uses
the encoded argument splitter from `config::EncodedArg`.

`TFTP_PORT_RANGE_PHASE.md` records actual C/Rust socket selection, exhaustion,
error cleanup, zero-start and single-port behavior. The interface and
unique-root readiness gates remain in force; accepting a port range does not
enable those separate capabilities.

`tools/dnsmasq/tftp_config_diff.py` links the exact C `read_opts` object from a
caller-supplied reference build and compares acceptance plus serialized
TFTP state with the real Rust `TftpConfig` parser. The harness never opens a
listener or reads the configured root. Generated files and reports stay under
ignored `private/`.

```sh
python3 tools/dnsmasq/tftp_config_diff.py \
  --reference-build private/dnsmasq-rewrite/reference/build \
  --out private/dnsmasq-rs/tftp-config-diff
```

The reference build is the output directory of `tools/dnsmasq/build_reference.sh`:
it contains `dnsmasq/dnsmasq.o`, the companion objects, and `deps/` include and
library directories. A direct object directory is also accepted for ad-hoc
probes. The tool pins `option.c` SHA256 before compiling the probe.
