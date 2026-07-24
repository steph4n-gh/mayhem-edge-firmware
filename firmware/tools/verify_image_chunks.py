#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of PortaPack.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see LICENSE.GPL-2.0-or-later.

"""Validate every compressed chunk and terminator in a baseband image."""

from pathlib import Path
import struct
import sys

from make_image_chunk import decompress_lz4_block


def verify_image(image: bytes) -> int:
    position = 0
    tags = set()
    chunks = 0
    while True:
        if position + 8 > len(image):
            raise ValueError("baseband image is missing its terminator")
        tag = image[position:position + 4]
        length = struct.unpack_from("<I", image, position + 4)[0]
        if tag == b"\0" * 4:
            if length != 0:
                raise ValueError("baseband terminator has a nonzero length")
            position += 8
            if position != len(image):
                raise ValueError("baseband image has bytes after its terminator")
            return chunks

        if any(byte < 0x20 or byte > 0x7E for byte in tag):
            raise ValueError("baseband image contains a non-printable tag")
        if tag in tags:
            raise ValueError(f"duplicate baseband image tag {tag!r}")
        tags.add(tag)
        if length == 0 or length & 3:
            raise ValueError(f"chunk {tag!r} has an invalid aligned length")

        chunk_end = position + 12 + length
        if chunk_end > len(image):
            raise ValueError(f"chunk {tag!r} extends beyond the baseband image")
        compressed_size = struct.unpack_from("<I", image, position + 8)[0]
        if compressed_size == 0 or compressed_size > length:
            raise ValueError(f"chunk {tag!r} has an invalid compressed size")
        block_start = position + 12
        block_end = block_start + compressed_size
        guard = image[block_end:block_end + 2]
        if guard != b"\0\0":
            raise ValueError(f"chunk {tag!r} has no zero decoder guard")
        # All build profiles use an LZ4 maximum block size of at most 4 MiB.
        decompress_lz4_block(image[block_start:block_end], 4 * 1024 * 1024)

        chunks += 1
        position = chunk_end


def main(argv) -> int:
    if len(argv) != 2:
        print("Usage: verify_image_chunks.py <baseband.img>", file=sys.stderr)
        return 2
    try:
        chunks = verify_image(Path(argv[1]).read_bytes())
    except (OSError, ValueError) as error:
        print(f"verify_image_chunks.py: {error}", file=sys.stderr)
        return 2
    print(f"Verified {chunks} decoder-compatible baseband image chunks")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
