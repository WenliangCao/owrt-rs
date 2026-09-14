#!/usr/bin/env python3
"""Compare exact-source HT IE parsing without initiating any wireless scan.

The C parser functions are extracted verbatim from the supplied libiwinfo source;
the Rust harness includes the supplied repository's actual iwinfo module. The
private generated harnesses, corpus and binaries are never release artifacts.
Non-HT crypto parsing is deliberately excluded and aborts if accidentally used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

C_PREFIX = r'''
#define __IWINFO_UTILS_H_
#include <iwinfo.h>
#define min(a, b) ((a) < (b) ? (a) : (b))
#define NL80211_BSS_INFORMATION_ELEMENTS 0
struct nlattr { int len; unsigned char *data; };
static int nla_len(struct nlattr *a) { return a->len; }
static void *nla_data(struct nlattr *a) { return a->data; }
static void iwinfo_parse_rsn(struct iwinfo_crypto_entry *c, unsigned char *b,
                             int n, int cipher, int auth) {
    (void)c; (void)b; (void)n; (void)cipher; (void)auth; abort();
}
'''
C_MAIN = r'''
int main(void) {
    unsigned char len[2], input[256];
    while (fread(len, 1, 2, stdin) == 2) {
        size_t n = ((size_t)len[0] << 8) | len[1];
        if (n > sizeof(input) || fread(input, 1, n, stdin) != n) return 2;
        struct iwinfo_scanlist_entry entry = {0};
        struct nlattr attr = { .len = (int)n, .data = input };
        struct nlattr *bss[] = { &attr };
        nl80211_get_scanlist_ie(bss, &entry);
        unsigned char out[] = { entry.ht_chan_info.primary_chan,
            entry.ht_chan_info.secondary_chan_off, entry.ht_chan_info.chan_width };
        if (fwrite(out, 1, sizeof(out), stdout) != sizeof(out)) return 3;
    }
    return ferror(stdin) || fflush(stdout) != 0;
}
'''
RUST_MAIN = r'''
use std::io::{Read, Write};
fn main() {
    let mut input = Vec::new();
    std::io::stdin().read_to_end(&mut input).unwrap();
    let mut output = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() {
        let n = u16::from_be_bytes(input[cursor..cursor + 2].try_into().unwrap()) as usize;
        cursor += 2;
        let mut entry = iwinfo::ScanlistEntry::default();
        iwinfo::nl80211::nl80211_get_scanlist_ie(&input[cursor..cursor + n], &mut entry);
        output.extend_from_slice(&[entry.ht_chan_info.primary_chan,
            entry.ht_chan_info.secondary_chan_off, entry.ht_chan_info.chan_width]);
        cursor += n;
    }
    std::io::stdout().write_all(&output).unwrap();
}
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("reference", type=Path, help="exact libiwinfo source directory, containing include/iwinfo.h")
    p.add_argument("repository", type=Path, help="fixed candidate source checkout")
    p.add_argument("output", type=Path)
    p.add_argument("--cargo", default="cargo")
    p.add_argument("--cc", default="cc")
    a = p.parse_args()
    a.reference, a.repository, a.output = (v.resolve() for v in (a.reference, a.repository, a.output))
    a.output.mkdir(parents=True, exist_ok=False)
    source = a.reference / "iwinfo_nl80211.c"
    text = source.read_text()
    start = text.index("static void nl80211_get_scanlist_he_operation(")
    end = text.index("static int nl80211_get_scanlist_cb(", start)
    fragment = text[start:end]
    assert fragment.count("static void nl80211_get_scanlist_") == 4
    (a.output / "original.c").write_text(C_PREFIX + fragment + C_MAIN)
    project = a.output / "candidate"
    project.mkdir()
    manifest = '[package]\nname = "r92-scan-ie-probe"\nversion = "0.0.0"\nedition = "2021"\n[workspace]\n'
    manifest += '[dependencies]\n' + '\n'.join(
        f'owrt-{name} = {{ path = {json.dumps(str(a.repository / "components" / name))} }}'
        for name in ("ubus", "uci")) + '\n[[bin]]\nname = "scan-ie-probe"\npath = "main.rs"\n'
    (project / "Cargo.toml").write_text(manifest)
    modules = '\n'.join(f'#[path = {json.dumps(str(a.repository / "components/rpcd/src" / path))}] mod {name};'
                        for name, path in (("iwinfo", "iwinfo/mod.rs"), ("glob", "glob.rs")))
    (project / "main.rs").write_text(modules + RUST_MAIN)
    # Both fields that influenced the observed HT output are exhaustive. Two
    # representative channels and short/full-length operation IEs are separate.
    count = 0
    expected = bytearray()
    with (a.output / "corpus.bin").open("xb") as stream:
        for channel in (6, 36):
            for length in (3, 22):
                for secondary in range(256):
                    for flags in range(256):
                        payload = bytes((channel, secondary, flags)) + bytes(length - 3)
                        frame = bytes((61, length)) + payload
                        stream.write(struct.pack(">H", len(frame)) + frame)
                        expected.extend((channel, secondary & 3, (flags & 4) >> 2))
                        count += 1
    assert count == 262144
    commands = (
        [a.cc, "-std=c99", "-O2", "-I", str(a.reference / "include"), str(a.output / "original.c"), "-o", str(a.output / "original")],
        [a.cargo, "+1.98.1", "build", "--offline", "--release", "--manifest-path", str(project / "Cargo.toml")],
    )
    for index, command in enumerate(commands):
        with (a.output / f"build-{index}.log").open("xb") as log:
            subprocess.run(command, stdout=log, stderr=log, check=True, timeout=600)
    binaries = {"original": a.output / "original", "candidate": project / "target/release/scan-ie-probe"}
    for side, binary in binaries.items():
        with (a.output / "corpus.bin").open("rb") as corpus, (a.output / (side + ".bin")).open("xb") as output:
            subprocess.run([str(binary)], stdin=corpus, stdout=output, check=True, timeout=30)
        assert (a.output / (side + ".bin")).read_bytes() == expected
    files = sorted((a.repository / "components/rpcd/src/iwinfo").glob("*.rs"))
    files += [a.repository / "components/rpcd/src/glob.rs"]
    result = {"schema": 1, "passed": True, "cases": count, "byte_identical": True,
        "channels": [6, 36], "ie_payload_lengths": [3, 22], "second_byte_values": 256, "third_byte_values": 256,
        "source_sha256": {"reference_nl80211": sha(source), "reference_header": sha(a.reference / "include/iwinfo.h"),
            "reference_fragment": hashlib.sha256(fragment.encode()).hexdigest(),
            "candidate": {str(f.relative_to(a.repository)): sha(f) for f in files}, "driver": sha(Path(__file__))},
        "corpus_sha256": sha(a.output / "corpus.bin"), "output_sha256": sha(a.output / "candidate.bin"),
        "harness_binary_sha256": {side: sha(binary) for side, binary in binaries.items()},
        "scope": "Actual C and Rust HT IE parsers, fixed well-formed inputs; no radio or kernel mutation.",
        "limitations": ["Not a new runtime build or a replay of the earlier wireless frames.",
            "Both retain the exact library's third-payload-byte bit 2 rule; this does not certify advertised 20/40 MHz width.",
            "Non-HT crypto parsing, truncated IEs and RF acquisition are outside this focused comparison."]}
    (a.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    (a.output / "COMPLETE").touch()
    print(json.dumps({"passed": True, "cases": count, "byte_identical": True}))


if __name__ == "__main__":
    main()
