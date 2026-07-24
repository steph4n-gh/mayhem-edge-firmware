# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


TOOLS_DIR = Path(__file__).resolve().parent.parent
MAKE_IMAGE_CHUNK = TOOLS_DIR / "make_image_chunk.py"
VERIFY_IMAGE_CHUNKS = TOOLS_DIR / "verify_image_chunks.py"
LZ4 = os.environ.get("MAYHEM_TEST_LZ4", "lz4")


def parse_frame(frame):
    if frame[:4] != bytes.fromhex("04224d18"):
        raise AssertionError("not a modern LZ4 frame")
    flags = frame[4]
    if flags & 0xC0 != 0x40:
        raise AssertionError("unsupported LZ4 frame version")
    header_size = 7
    if flags & 0x08:
        header_size += 8
    if flags & 0x01:
        header_size += 4

    block_word = struct.unpack_from("<I", frame, header_size)[0]
    if block_word == 0 or block_word & 0x80000000:
        raise AssertionError("test payload was not emitted as one compressed block")
    block_size = block_word & 0x7FFFFFFF
    block_start = header_size + 4
    block_end = block_start + block_size
    position = block_end
    if flags & 0x10:
        position += 4
    if struct.unpack_from("<I", frame, position)[0] != 0:
        raise AssertionError("compressed frame has more than one block")
    position += 4
    if flags & 0x04:
        position += 4
    if position != len(frame):
        raise AssertionError("unexpected bytes after LZ4 frame")
    return flags, frame[block_start:block_end]


def decompress_raw_block(source):
    output = bytearray()
    position = 0
    while position < len(source):
        token = source[position]
        position += 1

        literal_length = token >> 4
        if literal_length == 15:
            while True:
                extension = source[position]
                position += 1
                literal_length += extension
                if extension != 255:
                    break
        output += source[position:position + literal_length]
        position += literal_length
        if position == len(source):
            break

        offset = struct.unpack_from("<H", source, position)[0]
        position += 2
        if offset == 0 or offset > len(output):
            raise AssertionError("invalid LZ4 match offset")
        match_length = token & 0x0F
        if match_length == 15:
            while True:
                extension = source[position]
                position += 1
                match_length += extension
                if extension != 255:
                    break
        match_length += 4
        for _ in range(match_length):
            output.append(output[-offset])
    return bytes(output)


class Lz4ChunkPackagingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = (
            (b"HackRF Edge deterministic LZ4 compatibility\0" * 256)
            + (bytes(range(256)) * 32)
            + (b"IQIQ\x00\xff" * 1024)
        )

    def make_chunk(self, compression_args):
        with tempfile.TemporaryDirectory(prefix="mayhem-lz4-test-") as directory:
            directory = Path(directory)
            source = directory / "source.bin"
            frame_path = directory / "source.lz4"
            chunk_path = directory / "source.img"
            source.write_bytes(self.payload)
            subprocess.check_call(
                [LZ4, "-q", "-f", *compression_args, source, frame_path])
            subprocess.check_call(
                [sys.executable, MAKE_IMAGE_CHUNK, frame_path, "TEST", chunk_path])
            return frame_path.read_bytes(), chunk_path.read_bytes()

    def run_chunk_writer(self, frame, tag="TEST"):
        with tempfile.TemporaryDirectory(prefix="mayhem-lz4-invalid-") as directory:
            directory = Path(directory)
            frame_path = directory / "input.lz4"
            chunk_path = directory / "output.img"
            frame_path.write_bytes(frame)
            result = subprocess.run(
                [sys.executable, MAKE_IMAGE_CHUNK, frame_path, tag, chunk_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False)
            return result, chunk_path.exists()

    def verify_aggregate(self, image):
        with tempfile.TemporaryDirectory(prefix="mayhem-baseband-image-") as directory:
            image_path = Path(directory) / "baseband.img"
            image_path.write_bytes(image)
            return subprocess.run(
                [sys.executable, VERIFY_IMAGE_CHUNKS, image_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False)

    def check_chunk(self, frame, chunk, expect_frame_crc):
        flags, raw_block = parse_frame(frame)
        self.assertEqual(bool(flags & 0x04), expect_frame_crc)
        self.assertEqual(decompress_raw_block(raw_block), self.payload)

        self.assertEqual(chunk[:4], b"TEST")
        length, compressed_size = struct.unpack_from("<II", chunk, 4)
        self.assertEqual(length & 3, 0)
        self.assertEqual(len(chunk), 12 + length)
        self.assertEqual(compressed_size, len(raw_block))
        self.assertEqual(chunk[12:12 + compressed_size], raw_block)

        # firmware/application/lz4.S reads a final 16-bit match offset after
        # the raw block. The retained zero end marker makes that over-read a
        # harmless offset-zero self-copy; it must not be optimized away.
        self.assertEqual(chunk[12 + compressed_size:14 + compressed_size], b"\0\0")

    def test_upstream_default_frame(self):
        frame, chunk = self.make_chunk(["-9"])
        self.check_chunk(frame, chunk, expect_frame_crc=True)

    def test_edge_size_profile_frame(self):
        default_frame, _ = self.make_chunk(["-9"])
        frame, chunk = self.make_chunk(["-12", "--no-frame-crc"])
        self.check_chunk(frame, chunk, expect_frame_crc=False)
        self.assertLessEqual(len(frame), len(default_frame) - 4)

    def test_rejects_malformed_multiblock_and_uncompressed_frames(self):
        frame, _ = self.make_chunk(["-12", "--no-frame-crc"])
        flags, raw_block = parse_frame(frame)
        header_size = 15 if flags & 0x08 else 7
        first_block_end = header_size + 4 + len(raw_block)

        cases = []
        cases.append((b"BAD!" + frame[4:], "not a modern LZ4 frame"))
        cases.append((frame[:first_block_end] + struct.pack("<I", 1) +
                      b"\x00" + frame[first_block_end:], "multi-block"))
        uncompressed = bytearray(frame)
        block_word = struct.unpack_from("<I", uncompressed, header_size)[0]
        struct.pack_into("<I", uncompressed, header_size,
                         block_word | 0x80000000)
        cases.append((bytes(uncompressed), "uncompressed LZ4 blocks"))
        cases.append((frame[:-3], "missing its zero end marker"))

        for malformed, expected_error in cases:
            result, output_exists = self.run_chunk_writer(malformed)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected_error, result.stderr)
            self.assertFalse(output_exists)

    def test_rejects_invalid_tag_before_creating_output(self):
        frame, _ = self.make_chunk(["-12", "--no-frame-crc"])
        result, output_exists = self.run_chunk_writer(frame, "BAD")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("four non-NUL ASCII characters", result.stderr)
        self.assertFalse(output_exists)

    def test_aggregate_verifier_decodes_every_chunk_and_terminator(self):
        _, first = self.make_chunk(["-9"])
        _, second_test = self.make_chunk(["-12", "--no-frame-crc"])
        second = b"NEXT" + second_test[4:]
        aggregate = first + second + (b"\0" * 8)
        result = self.verify_aggregate(aggregate)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Verified 2 decoder-compatible", result.stdout)

        duplicate = first + first + (b"\0" * 8)
        result = self.verify_aggregate(duplicate)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate baseband image tag", result.stderr)

        result = self.verify_aggregate(aggregate[:-8])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing its terminator", result.stderr)

        corrupt = bytearray(aggregate)
        compressed_size = struct.unpack_from("<I", corrupt, 8)[0]
        corrupt[12 + compressed_size] = 1
        result = self.verify_aggregate(bytes(corrupt))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("zero decoder guard", result.stderr)


if __name__ == "__main__":
    unittest.main()
