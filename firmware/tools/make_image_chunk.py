#!/usr/bin/env python3

#
# Copyright (C) 2015 Jared Boone, ShareBrained Technology, Inc.
# Modified for HackRF Edge in 2026 by HackRF Edge contributors.
#
# This file is part of PortaPack.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#

"""Convert one decoder-compatible LZ4 frame into a PortaPack image chunk."""

from dataclasses import dataclass
from pathlib import Path
import struct
import sys


LZ4_FRAME_MAGIC = b"\x04\x22\x4d\x18"
LZ4_MAX_BLOCK_BYTES = {
    4: 64 * 1024,
    5: 256 * 1024,
    6: 1024 * 1024,
    7: 4 * 1024 * 1024,
}

USAGE = (
    "Usage: make_image_chunk.py <input.lz4> <four-character tag> <output.img>\n"
    "       make_image_chunk.py <terminator-output.img>"
)


@dataclass(frozen=True)
class Lz4Frame:
    body: bytes
    compressed_block: bytes
    decompressed: bytes
    content_checksum: bool


def _extended_length(source: bytes, position: int, value: int):
    if value != 15:
        return value, position
    while True:
        if position >= len(source):
            raise ValueError("truncated LZ4 length extension")
        extension = source[position]
        position += 1
        value += extension
        if extension != 255:
            return value, position


def decompress_lz4_block(source: bytes, maximum_output_bytes: int) -> bytes:
    """Decode the raw block using the subset consumed by application/lz4.S."""
    output = bytearray()
    position = 0
    while position < len(source):
        token = source[position]
        position += 1

        literal_length, position = _extended_length(
            source, position, token >> 4)
        literal_end = position + literal_length
        if literal_end > len(source):
            raise ValueError("LZ4 literal run exceeds the compressed block")
        output.extend(source[position:literal_end])
        position = literal_end
        if len(output) > maximum_output_bytes:
            raise ValueError("LZ4 block expands beyond its declared block maximum")
        if position == len(source):
            break

        if position + 2 > len(source):
            raise ValueError("truncated LZ4 match offset")
        offset = struct.unpack_from("<H", source, position)[0]
        position += 2
        if offset == 0 or offset > len(output):
            raise ValueError("invalid LZ4 match offset")

        match_length, position = _extended_length(
            source, position, token & 0x0F)
        match_length += 4
        if len(output) + match_length > maximum_output_bytes:
            raise ValueError("LZ4 block expands beyond its declared block maximum")
        for _ in range(match_length):
            output.append(output[-offset])

    if not source:
        raise ValueError("empty LZ4 compressed block")
    return bytes(output)


def parse_lz4_frame(frame: bytes) -> Lz4Frame:
    if len(frame) < 7 or frame[:4] != LZ4_FRAME_MAGIC:
        raise ValueError("input is not a modern LZ4 frame")

    flags = frame[4]
    block_descriptor = frame[5]
    if flags & 0xC0 != 0x40:
        raise ValueError("unsupported LZ4 frame version")
    if flags & 0x02:
        raise ValueError("LZ4 frame uses a reserved flag")
    if not flags & 0x20:
        raise ValueError("dependent LZ4 blocks are unsupported")
    if flags & 0x10:
        raise ValueError("LZ4 block checksums are unsupported")
    if flags & 0x01:
        raise ValueError("dictionary-backed LZ4 frames are unsupported")
    if block_descriptor & 0x8F:
        raise ValueError("invalid LZ4 block descriptor")

    block_size_code = (block_descriptor >> 4) & 0x07
    maximum_block_bytes = LZ4_MAX_BLOCK_BYTES.get(block_size_code)
    if maximum_block_bytes is None:
        raise ValueError("unsupported LZ4 maximum block size")

    position = 6
    declared_content_size = None
    if flags & 0x08:
        if position + 8 > len(frame):
            raise ValueError("truncated LZ4 content-size field")
        declared_content_size = struct.unpack_from("<Q", frame, position)[0]
        position += 8
    # Dictionary IDs were rejected above. The remaining descriptor byte is
    # the header checksum; link integrity is irrelevant after the descriptor
    # is stripped, while every semantic descriptor field is validated here.
    if position >= len(frame):
        raise ValueError("truncated LZ4 frame descriptor")
    position += 1

    if position + 4 > len(frame):
        raise ValueError("LZ4 frame has no block header")
    block_word = struct.unpack_from("<I", frame, position)[0]
    position += 4
    if block_word == 0:
        raise ValueError("LZ4 frame contains no compressed block")
    if block_word & 0x80000000:
        raise ValueError("uncompressed LZ4 blocks are unsupported by the device loader")

    compressed_size = block_word & 0x7FFFFFFF
    if compressed_size > maximum_block_bytes:
        raise ValueError("LZ4 compressed block exceeds its declared block maximum")
    block_end = position + compressed_size
    if block_end > len(frame):
        raise ValueError("truncated LZ4 compressed block")
    compressed_block = frame[position:block_end]
    position = block_end

    if position + 4 > len(frame):
        raise ValueError("LZ4 frame is missing its zero end marker")
    next_block = struct.unpack_from("<I", frame, position)[0]
    if next_block != 0:
        raise ValueError("multi-block LZ4 frames are unsupported by the device loader")
    position += 4

    content_checksum = bool(flags & 0x04)
    if content_checksum:
        if position + 4 > len(frame):
            raise ValueError("truncated LZ4 content checksum")
        position += 4
    if position != len(frame):
        raise ValueError("unexpected bytes after the LZ4 frame")

    decompressed = decompress_lz4_block(
        compressed_block, maximum_block_bytes)
    if (declared_content_size is not None and
            len(decompressed) != declared_content_size):
        raise ValueError(
            "LZ4 decompressed size does not match the frame content size")

    descriptor_bytes = block_end - compressed_size - 4
    body = frame[descriptor_bytes:]
    # The assembly decoder reads a final 16-bit offset after the declared raw
    # block. Retaining the zero end marker makes that read and four-byte
    # self-copy deterministic; it is a device-loader guard, not dead padding.
    if body[4 + compressed_size:6 + compressed_size] != b"\0\0":
        raise ValueError("LZ4 frame does not retain a zero decoder guard")
    return Lz4Frame(body, compressed_block, decompressed, content_checksum)


def make_chunk(frame: bytes, tag_text: str) -> bytes:
    try:
        tag = tag_text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("image tag must contain four ASCII characters") from error
    if len(tag) != 4 or b"\0" in tag:
        raise ValueError("image tag must contain four non-NUL ASCII characters")

    parsed = parse_lz4_frame(frame)
    body = bytearray(parsed.body)
    body.extend(b"\0" * ((-len(body)) & 3))
    # chunk_t::data starts after the block-size word. length is the distance
    # from data to the following chunk, so it excludes that first word.
    return tag + struct.pack("<I", len(body) - 4) + body


def main(argv) -> int:
    try:
        if len(argv) == 2:
            Path(argv[1]).write_bytes(b"\0" * 8)
            return 0
        if len(argv) != 4:
            raise ValueError(USAGE)
        frame = Path(argv[1]).read_bytes()
        output = make_chunk(frame, argv[2])
        Path(argv[3]).write_bytes(output)
        return 0
    except (OSError, ValueError) as error:
        print(f"make_image_chunk.py: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
