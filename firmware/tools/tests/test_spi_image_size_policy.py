#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path


TOOLS_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIRECTORY))

from spi_image_size_policy import assess_image_size  # noqa: E402
from spi_image_size_policy import print_maintenance_warning  # noqa: E402


class SpiImageSizePolicyTest(unittest.TestCase):
    def test_exact_capacity_preserves_existing_zero_headroom_behavior(self):
        assessment = assess_image_size(payload_bytes=1020, spi_size=1024)
        self.assertEqual(assessment.remaining_bytes, 0)
        self.assertFalse(assessment.maintenance_warning)

    def test_one_byte_over_capacity_hard_fails(self):
        with self.assertRaisesRegex(
                RuntimeError,
                "SPI flash image size of 1025 exceeds device size of 1024 bytes"):
            assess_image_size(payload_bytes=1021, spi_size=1024)

    def test_hard_minimum_is_inclusive(self):
        assessment = assess_image_size(
            payload_bytes=508,
            spi_size=1024,
            minimum_remaining_bytes=512,
        )
        self.assertEqual(assessment.remaining_bytes, 512)

    def test_one_byte_below_hard_minimum_fails(self):
        with self.assertRaisesRegex(
                RuntimeError,
                "leaves 511 bytes, below required minimum of 512 bytes"):
            assess_image_size(
                payload_bytes=509,
                spi_size=1024,
                minimum_remaining_bytes=512,
            )

    def test_warning_threshold_is_strict(self):
        at_threshold = assess_image_size(
            payload_bytes=1020,
            spi_size=17408,
            maintenance_warning_bytes=16384,
        )
        below_threshold = assess_image_size(
            payload_bytes=1021,
            spi_size=17408,
            maintenance_warning_bytes=16384,
        )
        self.assertFalse(at_threshold.maintenance_warning)
        self.assertTrue(below_threshold.maintenance_warning)

    def test_warning_threshold_cannot_be_below_hard_minimum(self):
        with self.assertRaisesRegex(
                ValueError,
                "maintenance_warning_bytes must be at least"):
            assess_image_size(
                payload_bytes=0,
                spi_size=1024,
                minimum_remaining_bytes=512,
                maintenance_warning_bytes=511,
            )

    def test_maintenance_warning_is_prominent_and_deterministic(self):
        output = StringIO()
        with redirect_stdout(output):
            print_maintenance_warning(860, 16384)

        lines = output.getvalue().splitlines()
        self.assertEqual(lines[0], "!" * 79)
        self.assertIn("AGGREGATE FLASH MAINTENANCE WARNING", lines[1])
        self.assertIn("Only 860 bytes remain", lines[2])
        self.assertEqual(lines[-1], "!" * 79)


if __name__ == "__main__":
    unittest.main()
