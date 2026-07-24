#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see LICENSE.GPL-2.0-or-later.
#

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SizeAssessment:
    remaining_bytes: int
    maintenance_warning: bool


def _validate_non_negative(name: str, value: Optional[int]) -> None:
    if value is not None and (not isinstance(value, int) or value < 0):
        raise ValueError(f"{name} must be a non-negative integer")


def assess_image_size(
        payload_bytes: int,
        spi_size: int,
        minimum_remaining_bytes: Optional[int] = None,
        maintenance_warning_bytes: Optional[int] = None,
        checksum_bytes: int = 4) -> SizeAssessment:
    """Validate aggregate image size and return its exact flash headroom."""
    _validate_non_negative("payload_bytes", payload_bytes)
    _validate_non_negative("spi_size", spi_size)
    _validate_non_negative("minimum_remaining_bytes", minimum_remaining_bytes)
    _validate_non_negative("maintenance_warning_bytes", maintenance_warning_bytes)
    _validate_non_negative("checksum_bytes", checksum_bytes)

    if (minimum_remaining_bytes is not None and
            maintenance_warning_bytes is not None and
            maintenance_warning_bytes < minimum_remaining_bytes):
        raise ValueError(
            "maintenance_warning_bytes must be at least minimum_remaining_bytes")

    remaining_bytes = spi_size - checksum_bytes - payload_bytes
    if remaining_bytes < 0:
        raise RuntimeError(
            "SPI flash image size of %d exceeds device size of %d bytes" %
            (payload_bytes + checksum_bytes, spi_size))

    if (minimum_remaining_bytes is not None and
            remaining_bytes < minimum_remaining_bytes):
        raise RuntimeError(
            "SPI flash image leaves %d bytes, below required minimum of %d bytes "
            "(image uses %d of %d bytes including checksum)" %
            (remaining_bytes, minimum_remaining_bytes,
             payload_bytes + checksum_bytes, spi_size))

    return SizeAssessment(
        remaining_bytes=remaining_bytes,
        maintenance_warning=(
            maintenance_warning_bytes is not None and
            remaining_bytes < maintenance_warning_bytes),
    )


def print_maintenance_warning(remaining_bytes: int, warning_bytes: int) -> None:
    banner = "!" * 79
    print(banner)
    print("!!! MAYHEM AGGREGATE FLASH MAINTENANCE WARNING !!!")
    print(
        f"Only {remaining_bytes} bytes remain; the maintenance threshold is "
        f"{warning_bytes} bytes.")
    print(
        "This pinned experimental artifact fits, but small source or toolchain "
        "changes may overflow flash.")
    print(banner)
