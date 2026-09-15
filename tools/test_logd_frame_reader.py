"""Deterministic fragmented-stream checks for the benchmark reader helper."""
import itertools
import struct
import unittest
from unittest.mock import patch

import test_logd_stream_recovery as reader


def frame(message, index=0):
    fields = b"".join((reader.string("msg", message), reader.integer("id", index),
        reader.integer("priority", 0), reader.integer("source", 1),
        reader.message("time", 4, struct.pack(">Q", 1))))
    return struct.pack(">I", 4 + len(fields)) + fields


class FrameReaderTests(unittest.TestCase):
    def receive(self, chunks, count, timeout=3, eof=False):
        steps = [(chunk, False) for chunk in chunks]
        if eof:
            if steps:
                steps[-1] = (steps[-1][0], True)
            else:
                steps = [(b"", True)]
        ticks = (n * .001 for n in itertools.count())
        with patch.object(reader, "take", side_effect=itertools.chain(steps, itertools.repeat((b"", False)))), \
                patch.object(reader.select, "select", return_value=([], [], [])), \
                patch.object(reader.time, "monotonic", side_effect=ticks):
            return reader.receive_frames(7, count, timeout)

    def test_every_two_chunk_split_keeps_exact_bytes_and_fields(self):
        messages = [b"a\xff", b"second log body"]
        wire = frame(messages[0]) + frame(messages[1], 1)
        for split in range(1, len(wire)):
            with self.subTest(split=split):
                actual, closed = self.receive([wire[:split], wire[split:]], 2)
                self.assertEqual(actual, wire)
                self.assertFalse(closed)
                reader.assert_records(actual, messages)

    def test_byte_fragments_parse_each_header_once(self):
        messages = [b"x" * i for i in range(1, 17)]
        wire = b"".join(frame(value, i) for i, value in enumerate(messages))
        unpack = struct.unpack_from
        with patch.object(reader.struct, "unpack_from", wraps=unpack) as decode:
            actual, closed = self.receive([wire[i:i + 1] for i in range(len(wire))], len(messages), timeout=20)
            # A fragmented body does not cause its header, or any previous
            # complete frame, to be parsed a second time.
            self.assertEqual(decode.call_count, len(messages))
        self.assertEqual(actual, wire)
        self.assertFalse(closed)
        reader.assert_records(actual, messages)

    def test_coalesced_frames_and_clean_eof(self):
        wire = frame(b"first") + frame(b"second", 1)
        actual, closed = self.receive([wire], 2, eof=True)
        self.assertEqual(actual, wire)
        self.assertTrue(closed)
        reader.assert_records(actual, [b"first", b"second"])

    def test_padding_must_be_present_before_a_frame_is_complete(self):
        wire = struct.pack(">I", 5) + b"x\0\0\0"
        self.assertEqual(self.receive([wire[:5], wire[5:7], wire[7:]], 1), (wire, False))
        with self.assertRaisesRegex(AssertionError, "ended"):
            self.receive([wire[:-1]], 1, eof=True)

    def test_eof_does_not_accept_missing_or_truncated_frames(self):
        wire = frame(b"record")
        for chunks, count in [([], 1), ([wire], 2), ([wire[:3]], 1),
                              ([wire[:-1]], 1), ([wire + wire[:3]], 1),
                              ([wire + wire[:8]], 1)]:
            with self.subTest(length=sum(map(len, chunks)), count=count):
                with self.assertRaisesRegex(AssertionError, "ended"):
                    self.receive(chunks, count, eof=True)

    def test_timeout_does_not_accept_partial_tail_after_expected_count(self):
        wire = frame(b"record")
        for value in [b"", wire[:2], wire[:-1], wire + wire[:3]]:
            with self.subTest(length=len(value)):
                with self.assertRaisesRegex(AssertionError, "deadline"):
                    self.receive([value], 1, timeout=.01)

    def test_invalid_or_oversized_header_rejected_when_completed(self):
        for size in [0, 1, 3, 1048577, 0xffffffff]:
            header = struct.pack(">I", size)
            with self.subTest(size=size):
                with self.assertRaisesRegex(AssertionError, "invalid log frame size"):
                    self.receive([header[:1], header[1:3], header[3:]], 1)

    def test_extra_complete_frame_is_not_silently_accepted(self):
        with self.assertRaisesRegex(AssertionError, "more log frames"):
            self.receive([frame(b"one") + frame(b"two", 1)], 1)

    def test_final_validator_still_rejects_content_order_and_field_errors(self):
        valid = frame(b"first") + frame(b"second", 1)
        wrong_priority = valid.replace(reader.integer("priority", 0), reader.integer("priority", 1), 1)
        bad = [frame(b"wrong") + frame(b"second", 1),
               frame(b"second", 1) + frame(b"first"),
               frame(b"first") + frame(b"second", 0), wrong_priority]
        for wire in bad:
            with self.subTest(wire=wire):
                actual, closed = self.receive([wire], 2)
                self.assertFalse(closed)
                with self.assertRaises(AssertionError):
                    reader.assert_records(actual, [b"first", b"second"])


if __name__ == "__main__":
    unittest.main()
