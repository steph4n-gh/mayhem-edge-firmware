#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock


TOOLS_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIRECTORY))

import export_external_apps as exporter  # noqa: E402
import verify_precision_rx_segmented_ppma as verifier  # noqa: E402


class PrecisionRxSegmentedPpmaVerifierTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.application_elf = self.root / "application.elf"
        self.m4_elf = self.root / "baseband_precision_rx.elf"
        self.m4_path = self.root / "PRX1.bin"
        self.ppma_path = self.root / "precision_rx.ppma"
        self.application_elf.write_bytes(b"synthetic application ELF")
        self.m4_elf.write_bytes(b"synthetic M4 ELF")
        self.m4 = bytes(range(32))
        self.m4_path.write_bytes(self.m4)

        self.main = bytearray(96)
        struct.pack_into("<I", self.main, 0, verifier.EXPECTED_MAIN_FAKE_BASE)
        struct.pack_into(
            "<I", self.main, 4, verifier.EXPECTED_MAIN_FAKE_BASE + 0x21
        )
        struct.pack_into(
            "<I", self.main, exporter.HEADER_VERSION_POSITION, 4
        )
        self.main[
            exporter.M4_APP_TAG_HEADER_POSITION:
            exporter.M4_APP_TAG_HEADER_POSITION + 4
        ] = b"PRX1"
        self.aux0 = bytes(16)
        self.aux1 = bytes(20)
        mappings = [
            (
                verifier.EXPECTED_MAIN_FAKE_BASE,
                verifier.M4_RUNTIME_BASE + len(self.m4),
                exporter.maximum_application_size,
            ),
            (
                verifier.EXPECTED_AUX0_FAKE_BASE,
                exporter.precision_rx_aux0_load_address,
                exporter.precision_rx_aux0_maximum_size,
            ),
            (
                verifier.EXPECTED_AUX1_FAKE_BASE,
                exporter.precision_rx_aux1_load_address,
                exporter.precision_rx_aux1_maximum_size,
            ),
        ]
        relocated_main = exporter.patch_image_mappings(
            "test-main", self.main, mappings
        )
        struct.pack_into(
            "<I",
            relocated_main,
            exporter.MEMORY_LOCATION_HEADER_POSITION,
            verifier.M4_RUNTIME_BASE + len(self.m4),
        )
        struct.pack_into(
            "<I",
            relocated_main,
            exporter.M4_APP_OFFSET_HEADER_POSITION,
            len(self.main),
        )
        relocated_main[
            exporter.BUILD_FINGERPRINT_HEADER_POSITION:
            exporter.BUILD_FINGERPRINT_HEADER_POSITION
            + exporter.BUILD_FINGERPRINT_SIZE
        ] = bytes.fromhex("0123456789abcdef")
        trailer = exporter.make_precision_rx_segmented_trailer(
            len(self.main), len(self.m4), len(self.aux0), len(self.aux1)
        )
        body = (
            bytes(relocated_main)
            + self.m4
            + self.aux0
            + self.aux1
            + trailer
        )
        ppma = body + struct.pack("<I", exporter.additive_checksum_word(body))
        self.ppma_path.write_bytes(ppma)

        self.sections = {
            verifier.MAIN_SECTION: (
                verifier.EXPECTED_MAIN_FAKE_BASE,
                len(self.main),
            ),
            verifier.AUX0_SECTION: (
                verifier.EXPECTED_AUX0_FAKE_BASE,
                len(self.aux0),
            ),
            verifier.AUX1_SECTION: (
                verifier.EXPECTED_AUX1_FAKE_BASE,
                len(self.aux1),
            ),
            verifier.UNWIND_GUARD_SECTION: (0, 0),
        }
        self.symbols = [
            (0x20009000, 0, "B", "__heap_base__"),
            (0x20010000, 0, "A", "__heap_end__"),
            (0x20009000, 0, "B", "_end"),
        ]
        self.geometry = {
            "version": verifier.GEOMETRY_VERSION,
            "m4_tag_word": int.from_bytes(b"PRX1", "little"),
            "main_bytes": len(self.main),
            "m4_bytes": len(self.m4),
            "aux0_bytes": len(self.aux0),
            "aux1_bytes": len(self.aux1),
            "trailer_bytes": exporter.PRECISION_RX_SEGMENTED_TRAILER.size,
            "checksum_bytes": exporter.CHECKSUM_SIZE,
            "image_bytes": (
                len(self.main)
                + len(self.m4)
                + len(self.aux0)
                + len(self.aux1)
            ),
            "file_bytes": len(ppma),
            "code_window_bytes": exporter.maximum_application_size,
            "m4_runtime_base": verifier.M4_RUNTIME_BASE,
            "m0_runtime_base": verifier.M4_RUNTIME_BASE + len(self.m4),
            "aux0_runtime_base": exporter.precision_rx_aux0_load_address,
            "aux0_max_bytes": exporter.precision_rx_aux0_maximum_size,
            "aux1_runtime_base": exporter.precision_rx_aux1_load_address,
            "aux1_max_bytes": exporter.precision_rx_aux1_maximum_size,
            "shared_memory_end": verifier.EXPECTED_AUX1_END,
            "main_fake_base": verifier.EXPECTED_MAIN_FAKE_BASE,
            "aux0_fake_base": verifier.EXPECTED_AUX0_FAKE_BASE,
            "aux1_fake_base": verifier.EXPECTED_AUX1_FAKE_BASE,
        }
        for field, symbol_name in verifier.GEOMETRY_SYMBOLS.items():
            self.symbols.append(
                (self.geometry[field], 0, "A", symbol_name)
            )
        for name in (
            "initialize_app",
            "write_exact",
            "reset_measurement_epoch",
            "PrecisionRxView::PrecisionRxView",
            "PrecisionRxView::~PrecisionRxView",
            "vtable for ui::external_app::precision_rx::PrecisionRxView",
        ):
            self.symbols.append(
                (verifier.EXPECTED_MAIN_FAKE_BASE, 4, "T", name)
            )
        for name in (
            "update_display() [clone .part.0]",
            "write_metadata",
            "set_capture_controls_locked",
        ):
            self.symbols.append(
                (verifier.EXPECTED_AUX0_FAKE_BASE, 4, "T", name)
            )
        for name in (
            "crc32c_update",
            "recover_snapshot_journal",
            "apply_sample_rate",
            "finish_sample_rate_change",
            "cancel_preparation",
            "reset_measurement_epoch",
            "on_status",
        ):
            self.symbols.append(
                (verifier.EXPECTED_AUX1_FAKE_BASE, 4, "T", name)
            )

    def args(self):
        return Namespace(
            elf=str(self.application_elf),
            ppma=str(self.ppma_path),
            m4=str(self.m4_path),
            m4_elf=str(self.m4_elf),
            objcopy="objcopy",
            objdump="objdump",
            nm="nm",
        )

    def verify(self, *, extracted_m4=None):
        section_bytes = {
            verifier.MAIN_SECTION: bytes(self.main),
            verifier.AUX0_SECTION: self.aux0,
            verifier.AUX1_SECTION: self.aux1,
        }

        def extract_section(_elf, _objcopy, section, _output):
            return section_bytes[section]

        with (
            mock.patch.object(
                verifier, "elf_sections", return_value=self.sections
            ),
            mock.patch.object(
                verifier, "elf_symbols", return_value=self.symbols
            ),
            mock.patch.object(
                verifier, "verify_direct_branches_are_segment_local"
            ),
            mock.patch.object(
                verifier, "extract_section", side_effect=extract_section
            ),
            mock.patch.object(
                verifier,
                "extract_binary",
                return_value=self.m4 if extracted_m4 is None else extracted_m4,
            ),
        ):
            return verifier.verify(self.args())

    def test_receipt_binds_every_artifact_and_has_no_calibration_debt(self):
        receipt = self.verify()
        self.assertEqual(receipt["result"], "PASS")
        self.assertEqual(receipt["contract"], verifier.RECEIPT_CONTRACT)
        self.assertEqual(
            receipt["contract"],
            "precision-rx-segmented-ppma-linked-v3",
        )
        self.assertEqual(
            receipt["artifact_bindings"]["application_elf"]["sha256"],
            hashlib.sha256(self.application_elf.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            receipt["artifact_bindings"]["m4_elf"]["sha256"],
            hashlib.sha256(self.m4_elf.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            receipt["artifact_bindings"]["m4_objcopied_raw"]["sha256"],
            receipt["artifact_bindings"]["supplied_prx1"]["sha256"],
        )
        self.assertEqual(
            receipt["artifact_bindings"]["relocated_sections"]["main"]["sha256"],
            receipt["artifact_bindings"]["ppma_sections"]["main"]["sha256"],
        )
        self.assertEqual(receipt["trailer"]["magic"], "PR12")
        self.assertEqual(receipt["trailer"]["version"], 2)
        self.assertEqual(receipt["trailer"]["trailer_size"], 40)
        self.assertEqual(receipt["ppma"]["header_version"], 4)
        self.assertEqual(
            receipt["ppma"]["cohort_fingerprint"], "0123456789abcdef"
        )
        self.assertEqual(receipt["ppma"]["additive_checksum"], 0)
        self.assertTrue(all(receipt["proofs"].values()))
        self.assertEqual(
            receipt["post_build_instruction_calibration_required"], []
        )

    def test_json_receipt_is_byte_deterministic(self):
        receipt = self.verify()
        first = self.root / "first.json"
        second = self.root / "second.json"
        verifier.write_json_atomic(first, receipt)
        verifier.write_json_atomic(second, receipt)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(json.loads(first.read_text(encoding="utf-8")), receipt)
        self.assertTrue(first.read_bytes().endswith(b"\n"))

    def test_rejects_supplied_prx1_that_does_not_equal_m4_elf_objcopy(self):
        with self.assertRaisesRegex(
            verifier.VerificationError, "objcopied M4 ELF"
        ):
            self.verify(extracted_m4=b"different")

    def test_rejects_missing_geometry_symbol(self):
        symbol_name = verifier.GEOMETRY_SYMBOLS["main_bytes"]
        self.symbols[:] = [
            symbol for symbol in self.symbols if symbol[3] != symbol_name
        ]
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "expected one geometry symbol",
        ):
            self.verify()

    def test_rejects_duplicate_geometry_symbol(self):
        symbol_name = verifier.GEOMETRY_SYMBOLS["main_bytes"]
        self.symbols.append(
            (self.geometry["main_bytes"], 0, "A", symbol_name)
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "expected one geometry symbol",
        ):
            self.verify()

    def test_rejects_non_absolute_geometry_symbol(self):
        symbol_name = verifier.GEOMETRY_SYMBOLS["main_bytes"]
        self.symbols[:] = [
            (
                address,
                size,
                "T" if name == symbol_name else kind,
                name,
            )
            for address, size, kind, name in self.symbols
        ]
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "expected absolute type 'A'",
        ):
            self.verify()

    def test_rejects_every_wrong_loader_geometry_value(self):
        original_symbols = list(self.symbols)
        for field, symbol_name in verifier.GEOMETRY_SYMBOLS.items():
            with self.subTest(field=field):
                self.symbols[:] = [
                    (
                        address ^ 1 if name == symbol_name else address,
                        size,
                        kind,
                        name,
                    )
                    for address, size, kind, name in original_symbols
                ]
                with self.assertRaises(verifier.VerificationError):
                    self.verify()
        self.symbols[:] = original_symbols

    def test_main_writes_json_only_after_a_successful_verification(self):
        receipt = self.verify()
        output = self.root / "receipt.json"
        with mock.patch.object(verifier, "verify", return_value=receipt):
            with redirect_stdout(io.StringIO()):
                result = verifier.main(
                    [
                        "--elf",
                        str(self.application_elf),
                        "--ppma",
                        str(self.ppma_path),
                        "--m4",
                        str(self.m4_path),
                        "--m4-elf",
                        str(self.m4_elf),
                        "--json-output",
                        str(output),
                    ]
                )
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), receipt)

        failed_output = self.root / "failed.json"
        with mock.patch.object(
            verifier,
            "verify",
            side_effect=verifier.VerificationError("injected"),
        ):
            with redirect_stderr(io.StringIO()):
                result = verifier.main(
                    [
                        "--elf",
                        str(self.application_elf),
                        "--ppma",
                        str(self.ppma_path),
                        "--m4",
                        str(self.m4_path),
                        "--json-output",
                        str(failed_output),
                    ]
                )
        self.assertEqual(result, 1)
        self.assertFalse(failed_output.exists())


if __name__ == "__main__":
    unittest.main()
