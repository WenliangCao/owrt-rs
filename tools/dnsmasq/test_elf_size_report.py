#!/usr/bin/env python3
"""Storage/attribution boundaries using synthetic ELF images; no product build."""
from pathlib import Path
import struct
import tempfile
import unittest

import elf_size_report as size_report


def fixture(symbols=(), text=b"X" * 32):
    """An ELF64 AArch64 section fixture (not runnable)."""
    labels = ["", ".text", ".rodata", ".bss", ".shstrtab", ".strtab", ".symtab"]
    names = b"\0" + b"".join(name.encode() + b"\0" for name in labels[1:])
    strings = bytearray(b"\0")
    symbol_data = bytearray(24)
    for name, address, length in symbols:
        index = len(strings)
        strings.extend(name.encode() + b"\0")
        symbol_data.extend(struct.pack("<IBBHQQ", index, 2, 0, 1, address, length))
    chunks = [b"", text, b"constant", b"", names, bytes(strings), bytes(symbol_data)]
    data = bytearray(64)
    headers = []
    for index, (name, content) in enumerate(zip(labels, chunks)):
        offset = len(data)
        data.extend(content)
        typ = (0, 1, 1, 8, 3, 3, 2)[index]
        flags = (0, 6, 2, 3, 0, 0, 0)[index]
        address = (0, 0x401000, 0x402000, 0x403000, 0, 0, 0)[index]
        length = 80 if index == 3 else len(content)
        headers.append(struct.pack("<IIQQQQIIQQ", names.index(name.encode() + b"\0"),
                                   typ, flags, address, offset, length,
                                   5 if index == 6 else 0, 0, 1, 24 if index == 6 else 0))
    section_offset = len(data)
    data.extend(b"".join(headers))
    data[:64] = struct.pack("<16sHHIQQQIHHHHHH", b"\x7fELF\x02\x01\x01" + bytes(9),
                            2, 183, 1, 0x401000, 0, section_offset, 0, 64, 0, 0, 64, 7, 4)
    return data


class ElfSizeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def elf(self, data, name="image"):
        path = self.root / name
        path.write_bytes(data)
        return size_report.Elf(path)

    def test_sections_do_not_charge_nobits_to_file_or_invent_crates(self):
        elf = self.elf(fixture())
        report = size_report.report(elf.path)
        self.assertEqual(report["alloc_file_bytes"], 40)
        self.assertEqual(report["alloc_zero_fill_bytes"], 80)
        self.assertEqual(report["alloc_file_bytes"] + report["non_alloc_and_headers_bytes"], len(elf.data))
        self.assertEqual(report["attribution"]["status"], "unavailable_no_sized_function_symbols")
        self.assertNotIn("crates", report["attribution"])
        with self.assertRaisesRegex(ValueError, "no sized function symbols"):
            size_report.report(elf.path, elf.path)

    def test_companion_matches_alloc_bytes_despite_extra_symbols(self):
        original = self.elf(fixture())
        companion = self.elf(fixture([("dnsmasq_rs::dns::run", 0x401000, 16)]), "companion")
        self.assertEqual(original.verify_companion(companion)["checked_sections"], 3)
        self.assertNotEqual(len(original.data), len(companion.data))

    def test_companion_rejects_same_size_different_text_and_address(self):
        original = self.elf(fixture())
        changed = self.elf(fixture(text=b"Y" * 32), "changed")
        with self.assertRaisesRegex(ValueError, "companion differs"):
            original.verify_companion(changed)
        data = fixture()
        shoff = struct.unpack_from("<Q", data, 40)[0]
        struct.pack_into("<Q", data, shoff + 64 + 16, 0x501000)
        moved = self.elf(data, "moved")
        with self.assertRaisesRegex(ValueError, "companion differs"):
            original.verify_companion(moved)

    def test_invalid_class_machine_truncation_and_section_table(self):
        for offset, replacement in ((4, b"\x01"), (5, b"\x02"), (18, b"\x3e\0")):
            data = fixture()
            data[offset:offset + len(replacement)] = replacement
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.elf(data)
        for data in (fixture()[:50], fixture()[:-1]):
            with self.assertRaisesRegex(ValueError, "exceeds file"):
                self.elf(data)
        data = fixture()
        struct.pack_into("<Q", data, 40, len(data) + 1)
        with self.assertRaisesRegex(ValueError, "section table exceeds file"):
            self.elf(data)

    def test_functions_reject_out_of_section_bounds_and_ignore_unsized(self):
        elf = self.elf(fixture([("bad", 0x401010, 33)]))
        with self.assertRaisesRegex(ValueError, "function exceeds"):
            elf.functions()
        elf = self.elf(fixture([("unsized", 0x401010, 0)]))
        self.assertEqual(elf.functions(), ([], 1))

    def test_alias_and_partial_overlap_are_counted_once(self):
        rows = [("core::fmt::one", 0x401000, 16),
                ("core::fmt::alias", 0x401000, 16),
                ("dnsmasq_rs::dns::two", 0x401008, 16)]
        elf = self.elf(fixture(rows))
        functions, _ = elf.functions()
        report = size_report.attribute(functions, {name: name for name, _, _ in rows}, elf.sections)
        self.assertEqual(report["attributed_function_bytes"], 24)
        self.assertEqual(report["unattributed_executable_bytes"], 8)
        self.assertEqual(report["alias_or_overlap_bytes"], 16)
        self.assertEqual({r["namespace"]: r["bytes"] for r in report["crates"]},
                         {"core": 8, "dnsmasq_rs": 8, size_report.AMBIGUOUS: 8})
        self.assertEqual(sum(r["bytes"] for r in report["modules"]), 24)
        self.assertEqual(len(report["largest_ranges_non_additive"]), 2)

    def test_namespace_uses_owner_not_trait_or_generic_argument(self):
        self.assertEqual(size_report.namespace("<dnsmasq_rs::Config as core::fmt::Debug>::fmt"),
                         ("dnsmasq_rs", "dnsmasq_rs::[root]"))
        self.assertEqual(size_report.namespace("core::ptr::drop_in_place<dnsmasq_rs::Config>"),
                         ("core", "core::ptr"))
        self.assertEqual(size_report.namespace("dnsmasq_rs::main::h1234567890abcdef"),
                         ("dnsmasq_rs", "dnsmasq_rs::[root]"))
        self.assertEqual(size_report.namespace("_RNvUnknown")[0], "[unresolved Rust]")
        self.assertEqual(size_report.namespace("memcpy")[0], "[C/assembly/unmangled]")


if __name__ == "__main__":
    unittest.main()
