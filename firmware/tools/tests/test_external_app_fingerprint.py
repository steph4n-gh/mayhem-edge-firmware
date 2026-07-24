#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path
import hashlib
import struct
import sys
import unittest


TOOLS_DIRECTORY = Path(__file__).resolve().parents[1]
FIRMWARE_DIRECTORY = TOOLS_DIRECTORY.parent
sys.path.insert(0, str(TOOLS_DIRECTORY))

import export_external_apps as exporter  # noqa: E402


def blank_v4_image(size=exporter.APPLICATION_HEADER_SIZE):
    image = bytearray(size)
    image[exporter.HEADER_VERSION_POSITION:exporter.HEADER_VERSION_POSITION + 4] = (
        exporter.CURRENT_HEADER_VERSION.to_bytes(4, "little")
    )
    return image


class ExternalAppFingerprintTest(unittest.TestCase):
    def setUp(self):
        self.cohort_hash = bytes(range(20))
        self.baseband_image = b"baseband.img"

    def test_stamps_64_bit_prefix_and_closes_checksum(self):
        result = exporter.stamp_fingerprint_and_checksum(
            blank_v4_image(), self.cohort_hash, "test"
        )
        fingerprint_start = exporter.BUILD_FINGERPRINT_HEADER_POSITION
        fingerprint_end = fingerprint_start + exporter.BUILD_FINGERPRINT_SIZE

        self.assertEqual(
            result[fingerprint_start:fingerprint_end],
            self.cohort_hash[:exporter.BUILD_FINGERPRINT_SIZE],
        )
        self.assertEqual(exporter.additive_checksum_word(result), 0)
        self.assertEqual(
            len(result), exporter.APPLICATION_HEADER_SIZE + exporter.CHECKSUM_SIZE
        )

    def test_stamps_application_tail_and_rejects_nonzero_placeholder(self):
        application = b"firmware" + bytes(exporter.BUILD_FINGERPRINT_SIZE)
        result = exporter.stamp_application_fingerprint(application, self.cohort_hash)
        self.assertEqual(result[:-exporter.BUILD_FINGERPRINT_SIZE], b"firmware")
        self.assertEqual(
            result[-exporter.BUILD_FINGERPRINT_SIZE:],
            self.cohort_hash[:exporter.BUILD_FINGERPRINT_SIZE],
        )

        with self.assertRaisesRegex(ValueError, "placeholder is not zero"):
            exporter.stamp_application_fingerprint(
                b"firmware" + b"\0" * 7 + b"x", self.cohort_hash
            )

        with self.assertRaisesRegex(ValueError, "cannot be all zero"):
            exporter.stamp_application_fingerprint(
                application, bytes(exporter.BUILD_FINGERPRINT_SIZE)
            )

    def test_runtime_contract_rejects_zero_fingerprints(self):
        header_source = (
            FIRMWARE_DIRECTORY / "common" / "external_app.hpp"
        ).read_text(encoding="utf-8")
        self.assertIn("expected_bits != 0", header_source)
        self.assertIn("candidate.words[0] ^ expected.words[0]", header_source)
        self.assertIn("candidate.words[1] ^ expected.words[1]", header_source)

    def test_cohort_hash_covers_exact_prepared_bodies_and_is_order_stable(self):
        application = b"firmware" + bytes(exporter.BUILD_FINGERPRINT_SIZE)
        first = blank_v4_image(96)
        second = blank_v4_image(100)
        packaging = {"exporter": b"v1", "layout": b"v4"}

        baseline = exporter.derive_cohort_hash(
            application,
            self.baseband_image,
            {"z_app": second, "a_app": first},
            packaging,
        )
        reordered = exporter.derive_cohort_hash(
            application,
            self.baseband_image,
            {"a_app": first, "z_app": second},
            {"layout": b"v4", "exporter": b"v1"},
        )
        self.assertEqual(baseline, reordered)

        changed_body = bytearray(second)
        changed_body[-1] = 1
        self.assertNotEqual(
            baseline,
            exporter.derive_cohort_hash(
                application,
                self.baseband_image,
                {"a_app": first, "z_app": changed_body},
                packaging,
            ),
        )
        self.assertNotEqual(
            baseline,
            exporter.derive_cohort_hash(
                b"FirmWare" + bytes(exporter.BUILD_FINGERPRINT_SIZE),
                self.baseband_image,
                {"a_app": first, "z_app": second},
                packaging,
            ),
        )
        self.assertNotEqual(
            baseline,
            exporter.derive_cohort_hash(
                application,
                self.baseband_image,
                {"a_app": first, "z_app": second},
                {"exporter": b"v2", "layout": b"v4"},
            ),
        )

        changed_baseband = bytearray(self.baseband_image)
        changed_baseband[-1] ^= 1
        self.assertNotEqual(
            baseline,
            exporter.derive_cohort_hash(
                application,
                changed_baseband,
                {"a_app": first, "z_app": second},
                packaging,
            ),
        )

    def test_packaging_inputs_select_exact_p11_bytes_only_for_off_profile(self):
        off_inputs = exporter.packaging_source_inputs(
            FIRMWARE_DIRECTORY,
            precision_rx_segmented=False,
        )
        expected_p11 = {
            "export_external_apps.py": (
                15076,
                "4be475001a9fd521d9c5f8b574e1f87ec63881ff218b46f0db80744712f45e79",
            ),
            "external_app_info.py": (
                1065,
                "89430579316100e446b74c9b5b706f11ec47a633ecb2af8a30c795d1749fe6a3",
            ),
        }
        self.assertEqual(set(off_inputs), set(expected_p11))
        for name, (expected_size, expected_sha256) in expected_p11.items():
            self.assertEqual(len(off_inputs[name]), expected_size)
            self.assertEqual(
                hashlib.sha256(off_inputs[name]).hexdigest(),
                expected_sha256,
            )

        on_inputs = exporter.packaging_source_inputs(
            FIRMWARE_DIRECTORY,
            precision_rx_segmented=True,
        )
        self.assertEqual(
            on_inputs["export_external_apps.py"],
            Path(exporter.__file__).read_bytes(),
        )
        self.assertEqual(
            on_inputs["external_app_info.py"],
            (TOOLS_DIRECTORY / "external_app_info.py").read_bytes(),
        )
        self.assertEqual(
            on_inputs["precision_rx_segmented.ld"],
            (
                FIRMWARE_DIRECTORY
                / "application"
                / "external"
                / "precision_rx_segmented.ld"
            ).read_bytes(),
        )
        self.assertEqual(
            on_inputs["precision_rx_segmented_geometry.cmake"],
            (
                FIRMWARE_DIRECTORY
                / "application"
                / "external"
                / "precision_rx_segmented_geometry.cmake"
            ).read_bytes(),
        )
        self.assertEqual(
            on_inputs["precision_rx_segmented_geometry.hpp.in"],
            (
                FIRMWARE_DIRECTORY
                / "application"
                / "precision_rx_segmented_geometry.hpp.in"
            ).read_bytes(),
        )
        self.assertNotEqual(
            off_inputs["export_external_apps.py"],
            on_inputs["export_external_apps.py"],
        )
        self.assertNotEqual(
            off_inputs["external_app_info.py"],
            on_inputs["external_app_info.py"],
        )

    def test_rejects_v3_and_nonzero_placeholder(self):
        v3_image = blank_v4_image()
        v3_image[
            exporter.HEADER_VERSION_POSITION:exporter.HEADER_VERSION_POSITION + 4
        ] = (3).to_bytes(4, "little")
        with self.assertRaisesRegex(ValueError, "header version 3"):
            exporter.stamp_fingerprint_and_checksum(v3_image, self.cohort_hash, "v3")

        nonzero_placeholder = blank_v4_image()
        nonzero_placeholder[exporter.BUILD_FINGERPRINT_HEADER_POSITION] = 1
        with self.assertRaisesRegex(ValueError, "placeholder is not zero"):
            exporter.stamp_fingerprint_and_checksum(
                nonzero_placeholder, self.cohort_hash, "nonzero"
            )

    def test_32k_limit_includes_checksum_and_accepts_exact_boundary(self):
        exact = exporter.stamp_fingerprint_and_checksum(
            blank_v4_image(exporter.maximum_application_size - exporter.CHECKSUM_SIZE),
            self.cohort_hash,
            "exact",
        )
        self.assertEqual(len(exact), exporter.maximum_application_size)

        with self.assertRaisesRegex(ValueError, "cannot exceed 32 KiB"):
            exporter.stamp_fingerprint_and_checksum(
                blank_v4_image(
                    exporter.maximum_application_size
                    - exporter.CHECKSUM_SIZE
                    + 4
                ),
                self.cohort_hash,
                "oversize",
            )

    def test_fingerprint_is_stamped_after_address_relocation(self):
        image = blank_v4_image()
        fake_address_word = (0xADB10004).to_bytes(4, "little")
        cohort_hash = fake_address_word + b"ABCD" + self.cohort_hash[8:]

        relocated = exporter.patch_image(
            "test", image, 0xADB10000, 0x10080000
        )
        result = exporter.stamp_fingerprint_and_checksum(relocated, cohort_hash, "test")
        start = exporter.BUILD_FINGERPRINT_HEADER_POSITION
        self.assertEqual(result[start:start + 8], cohort_hash[:8])

    def test_segmented_flag_must_be_first_and_preserves_legacy_arguments(self):
        segmented, apps = exporter.parse_external_app_arguments(
            [exporter.SEGMENTED_PRECISION_RX_FLAG, "precision_rx", "scanner"]
        )
        self.assertTrue(segmented)
        self.assertEqual(apps, ["precision_rx", "scanner"])

        segmented, apps = exporter.parse_external_app_arguments(
            ["precision_rx", "scanner"]
        )
        self.assertFalse(segmented)
        self.assertEqual(apps, ["precision_rx", "scanner"])

        with self.assertRaisesRegex(ValueError, "must precede"):
            exporter.parse_external_app_arguments(
                ["precision_rx", exporter.SEGMENTED_PRECISION_RX_FLAG]
            )
        with self.assertRaisesRegex(ValueError, "empty"):
            exporter.parse_external_app_arguments(
                [exporter.SEGMENTED_PRECISION_RX_FLAG]
            )

    def test_segmented_precision_rx_uses_three_maps_and_never_relocates_m4(self):
        fake_main = 0xAE0D0000
        main = blank_v4_image(104)
        struct.pack_into("<I", main, exporter.EXTERNAL_APP_ENTRY_HEADER_POSITION,
                         fake_main + 0x59)
        main[
            exporter.M4_APP_TAG_HEADER_POSITION:
            exporter.M4_APP_TAG_HEADER_POSITION + 4
        ] = exporter.PRECISION_RX_M4_TAG.encode("ascii")
        struct.pack_into("<I", main, 88, exporter.precision_rx_aux0_fake_address)
        struct.pack_into("<I", main, 92, exporter.precision_rx_aux1_fake_address)

        # Deliberately make the opaque M4 bytes look like an M0 fake pointer.
        # Segmented preparation must append them without scanning or rewriting.
        m4 = struct.pack("<II", fake_main + 0x20, 0xA5A5A5A5)
        aux0 = struct.pack(
            "<III",
            fake_main + 0x21,
            exporter.precision_rx_aux0_fake_address,
            exporter.precision_rx_aux1_fake_address,
        )
        aux1 = struct.pack(
            "<III",
            fake_main + 0x25,
            exporter.precision_rx_aux0_fake_address,
            exporter.precision_rx_aux1_fake_address,
        )
        prepared = exporter.prepare_external_app(
            "/tmp",
            exporter.PRECISION_RX_APP_NAME,
            main,
            {exporter.PRECISION_RX_M4_TAG: m4},
            precision_rx_aux_images=(aux0, aux1),
        )
        trailer = exporter.decode_precision_rx_segmented_trailer(prepared)
        self.assertIsNotNone(trailer)
        self.assertEqual(trailer["main_size"], len(main))
        self.assertEqual(trailer["m4_size"], len(m4))
        self.assertEqual(trailer["aux0_size"], len(aux0))
        self.assertEqual(trailer["aux1_size"], len(aux1))

        runtime_main = 0x10080000 + len(m4)
        self.assertEqual(
            struct.unpack_from("<I", prepared, 0)[0],
            runtime_main,
        )
        self.assertEqual(
            struct.unpack_from(
                "<I", prepared, exporter.EXTERNAL_APP_ENTRY_HEADER_POSITION
            )[0],
            runtime_main + 0x59,
        )
        self.assertEqual(
            struct.unpack_from("<I", prepared, 88)[0],
            exporter.precision_rx_aux0_load_address,
        )
        self.assertEqual(
            struct.unpack_from("<I", prepared, 92)[0],
            exporter.precision_rx_aux1_load_address,
        )
        self.assertEqual(prepared[len(main):len(main) + len(m4)], m4)
        aux0_offset = len(main) + len(m4)
        self.assertEqual(
            struct.unpack_from("<I", prepared, aux0_offset)[0],
            runtime_main + 0x21,
        )
        self.assertEqual(
            struct.unpack_from("<I", prepared, aux0_offset + 4)[0],
            exporter.precision_rx_aux0_load_address,
        )
        self.assertEqual(
            struct.unpack_from("<I", prepared, aux0_offset + 8)[0],
            exporter.precision_rx_aux1_load_address,
        )
        aux1_offset = aux0_offset + len(aux0)
        self.assertEqual(
            struct.unpack_from("<I", prepared, aux1_offset)[0],
            runtime_main + 0x25,
        )
        self.assertEqual(
            struct.unpack_from("<I", prepared, aux1_offset + 4)[0],
            exporter.precision_rx_aux0_load_address,
        )
        self.assertEqual(
            struct.unpack_from("<I", prepared, aux1_offset + 8)[0],
            exporter.precision_rx_aux1_load_address,
        )

    def test_segmented_trailer_rejects_every_control_field_mutation(self):
        self.assertEqual(exporter.PRECISION_RX_SEGMENTED_TRAILER_VERSION, 2)
        body = (
            blank_v4_image(96)
            + bytes(32)
            + bytes(16)
            + bytes(20)
            + exporter.make_precision_rx_segmented_trailer(96, 32, 16, 20)
        )
        self.assertIsNotNone(
            exporter.decode_precision_rx_segmented_trailer(body)
        )

        trailer_offset = len(body) - exporter.PRECISION_RX_SEGMENTED_TRAILER.size
        original = list(
            exporter.PRECISION_RX_SEGMENTED_TRAILER.unpack_from(
                body, trailer_offset
            )
        )
        mutations = {
            0: original[0] ^ 1,  # magic
            1: original[1] + 1,  # version
            2: original[2] - 4,  # trailer size
            3: original[3] + 4,  # main
            4: original[4] + 4,  # M4
            5: original[5] + 4,  # aux0
            6: original[6] - 4,  # aux0 load address
            7: original[7] + 4,  # aux1
            8: original[8] - 4,  # aux1 load address
            9: original[9] + 4,  # image size
            10: 1,               # reserved
        }
        for index, replacement in mutations.items():
            with self.subTest(field=index):
                values = original.copy()
                values[index] = replacement
                mutated = bytearray(body)
                exporter.PRECISION_RX_SEGMENTED_TRAILER.pack_into(
                    mutated, trailer_offset, *values
                )
                self.assertIsNone(
                    exporter.decode_precision_rx_segmented_trailer(mutated)
                )

        oversized_aux0 = (
            blank_v4_image(96)
            + bytes(32)
            + bytes(exporter.precision_rx_aux0_maximum_size + 4)
            + bytes(16)
            + exporter.make_precision_rx_segmented_trailer(
                96,
                32,
                exporter.precision_rx_aux0_maximum_size + 4,
                16,
            )
        )
        self.assertIsNone(
            exporter.decode_precision_rx_segmented_trailer(oversized_aux0)
        )

        oversized_aux1 = (
            blank_v4_image(96)
            + bytes(32)
            + bytes(16)
            + bytes(exporter.precision_rx_aux1_maximum_size + 4)
            + exporter.make_precision_rx_segmented_trailer(
                96,
                32,
                16,
                exporter.precision_rx_aux1_maximum_size + 4,
            )
        )
        self.assertIsNone(
            exporter.decode_precision_rx_segmented_trailer(oversized_aux1)
        )

    def test_segmented_checksum_and_36k_ceiling_cover_trailer(self):
        body = (
            blank_v4_image(96)
            + bytes(32)
            + bytes(16)
            + bytes(20)
            + exporter.make_precision_rx_segmented_trailer(96, 32, 16, 20)
        )
        stamped = exporter.stamp_fingerprint_and_checksum(
            body,
            self.cohort_hash,
            exporter.PRECISION_RX_APP_NAME,
            maximum_file_size=exporter.precision_rx_segmented_maximum_file_size,
        )
        self.assertEqual(exporter.additive_checksum_word(stamped), 0)
        corrupted = bytearray(stamped)
        corrupted[-8] ^= 1
        self.assertNotEqual(exporter.additive_checksum_word(corrupted), 0)

        with self.assertRaisesRegex(ValueError, "36 KiB"):
            exporter.stamp_fingerprint_and_checksum(
                blank_v4_image(
                    exporter.precision_rx_segmented_maximum_file_size
                ),
                self.cohort_hash,
                exporter.PRECISION_RX_APP_NAME,
                maximum_file_size=(
                    exporter.precision_rx_segmented_maximum_file_size
                ),
            )

    def test_p14_loader_and_linker_enforce_segment_order_and_shared_memory_contract(self):
        loader_source = (
            FIRMWARE_DIRECTORY
            / "application"
            / "ui_external_items_menu_loader.cpp"
        ).read_text(encoding="utf-8")
        segmented_start = loader_source.index(
            "if (is_segmented_precision_rx)"
        )
        segmented_end = loader_source.index(
            "#else", segmented_start
        )
        segmented_body = loader_source[segmented_start:segmented_end]
        self.assertNotIn("trailer.", segmented_body)
        self.assertIn(
            "m4_offset != precision_rx_segmented_main_size",
            segmented_body,
        )
        self.assertIn(
            "m0_image_size = precision_rx_segmented_main_size",
            segmented_body,
        )
        self.assertIn(
            "m4_image_size = precision_rx_segmented_m4_size",
            segmented_body,
        )

        main_copy = loader_source.index(
            "app, application_information.memory_location, m0_image_size"
        )
        m4_copy = loader_source.index(
            "reinterpret_cast<void*>(precision_rx_segmented_m4_load_address)",
            main_copy,
        )
        aux0_copy = loader_source.index(
            "reinterpret_cast<void*>(precision_rx_segmented_aux0_load_address)",
            m4_copy,
        )
        aux1_copy = loader_source.index(
            "reinterpret_cast<void*>(precision_rx_segmented_aux1_load_address)",
            aux0_copy,
        )
        self.assertLess(main_copy, m4_copy)
        self.assertLess(m4_copy, aux0_copy)
        self.assertLess(aux0_copy, aux1_copy)
        for contract in (
            "precision_rx_bb_data_offset == 4200",
            "precision_rx_bb_data_size == 2496",
            "SharedMemory::m4_panic_context_reserved_bytes == 112",
            "sizeof(SharedMemory) == 6752",
            "precision_rx_aux0_load_address == 0x100890D8",
            "precision_rx_aux0_end_address == 0x10089A28",
            "precision_rx_aux1_load_address == 0x10089A60",
            "precision_rx_live_field_gap_size == 56",
            "precision_rx_aux1_end_address == 0x1008A000",
            "precision_rx_segmented_file_size == 36576",
            "precision_rx_segmented_image_size == 36532",
        ):
            self.assertIn(contract, loader_source)

        geometry_source = (
            FIRMWARE_DIRECTORY
            / "application"
            / "external"
            / "precision_rx_segmented_geometry.cmake"
        ).read_text(encoding="utf-8")
        for contract in (
            "PRECISION_RX_SEGMENTED_MAIN_SIZE 11304",
            "PRECISION_RX_SEGMENTED_M4_SIZE 21416",
            "PRECISION_RX_SEGMENTED_AUX0_SIZE 2372",
            "PRECISION_RX_SEGMENTED_AUX1_SIZE 1440",
            "PRECISION_RX_SEGMENTED_M0_LOAD_ADDRESS EQUAL 0x100853A8",
            "PRECISION_RX_SEGMENTED_IMAGE_SIZE EQUAL 36532",
            "PRECISION_RX_SEGMENTED_FILE_SIZE EQUAL 36576",
        ):
            self.assertIn(contract, geometry_source)

        linker_source = (
            FIRMWARE_DIRECTORY
            / "chibios-portapack"
            / "os"
            / "ports"
            / "GCC"
            / "ARMCMx"
            / "LPC43xx_M0"
            / "ld"
            / "LPC43xx_M0.ld"
        ).read_text(encoding="utf-8")
        self.assertIn("__heap_end__", linker_source)
        self.assertIn(": __ram_end__;", linker_source)
        self.assertNotIn("LD_EXTERNAL_APP_AUX_BASE", linker_source)

        segmented_linker_source = (
            FIRMWARE_DIRECTORY
            / "application"
            / "external"
            / "precision_rx_segmented.ld"
        ).read_text(encoding="utf-8")
        self.assertIn(
            ".external_app_precision_rx_unwind_guard",
            segmented_linker_source,
        )
        self.assertIn(
            "SIZEOF(.external_app_precision_rx_unwind_guard) == 0",
            segmented_linker_source,
        )
        self.assertIn(
            ".external_app_precision_rx_aux0 "
            "@PRECISION_RX_SEGMENTED_AUX0_FAKE_BASE@",
            segmented_linker_source,
        )
        self.assertIn(
            ".external_app_precision_rx_aux1 "
            "@PRECISION_RX_SEGMENTED_AUX1_FAKE_BASE@",
            segmented_linker_source,
        )
        self.assertIn(
            "SIZEOF(.external_app_precision_rx_aux0) <= "
            "@PRECISION_RX_SEGMENTED_AUX0_MAX_SIZE@",
            segmented_linker_source,
        )
        self.assertIn(
            "SIZEOF(.external_app_precision_rx_aux1) <= "
            "@PRECISION_RX_SEGMENTED_AUX1_MAX_SIZE@",
            segmented_linker_source,
        )
        self.assertIn(
            "__prx_p12_main_bytes = ABSOLUTE(",
            segmented_linker_source,
        )
        self.assertIn(
            "SIZEOF(.external_app_precision_rx) == __prx_p12_main_bytes",
            segmented_linker_source,
        )

        shared_source = (
            FIRMWARE_DIRECTORY / "common" / "portapack_shared_memory.hpp"
        ).read_text(encoding="utf-8")
        debug_source = (
            FIRMWARE_DIRECTORY / "baseband" / "debug.cpp"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "m4_panic_context_reserved_bytes = 112",
            shared_source,
        )
        self.assertIn("8 + sizeof(struct extctx)", debug_source)
        self.assertIn(
            "SharedMemory::m4_panic_context_reserved_bytes",
            debug_source,
        )

    def test_execution_boundary_checks_compatibility_before_copy(self):
        loader_source = (
            FIRMWARE_DIRECTORY
            / "application"
            / "ui_external_items_menu_loader.cpp"
        ).read_text(encoding="utf-8")
        prepare_start = loader_source.index(
            "static bool prepare_external_app"
        )
        prepare_end = loader_source.index(
            "void ExternalItemsMenuLoader::load_all_external_items_callback",
            prepare_start,
        )
        prepare_body = loader_source[prepare_start:prepare_end]

        compatibility_check = prepare_body.index("external_app_is_compatible")
        first_seek = prepare_body.index("app.seek(0)")
        checksum_check = prepare_body.index("checksum != EXT_APP_EXPECTED_CHECKSUM")
        first_copy = prepare_body.index(
            "read_exact(app, application_information.memory_location, m0_image_size)"
        )
        entry_assignment = prepare_body.index(
            "entry = application_information.externalAppEntry"
        )
        self.assertLess(compatibility_check, first_seek)
        self.assertLess(checksum_check, first_copy)
        self.assertLess(compatibility_check, first_copy)
        self.assertLess(compatibility_check, entry_assignment)
        self.assertIn("read_exact(app, checksum_buffer, bytes_to_read)", prepare_body)
        self.assertIn("result.value() != chunk_size", loader_source)
        self.assertIn("external_app_read_chunk_size = 4 * 1024", loader_source)
        self.assertIn("external_app_read_chunk_size <= 16 * 1024", loader_source)

        runner_start = loader_source.index(
            "bool ExternalItemsMenuLoader::run_external_app"
        )
        runner_end = loader_source.index(
            "bool ExternalItemsMenuLoader::run_standalone_app", runner_start
        )
        runner_body = loader_source[runner_start:runner_end]
        self.assertIn(
            "__attribute__((noinline)) static bool prepare_external_app",
            loader_source,
        )
        self.assertLess(
            runner_body.index("prepare_external_app(filePath, entry)"),
            runner_body.index("entry(nav)"),
        )
        self.assertNotIn("File app;", runner_body)

    def test_cdc_ui_commands_marshal_work_to_event_thread(self):
        shell_source = (
            FIRMWARE_DIRECTORY / "application" / "usb_serial_shell.cpp"
        ).read_text(encoding="utf-8")

        app_start = shell_source.index("static void cmd_appstart")
        app_end = shell_source.index("static void printAppInfo", app_start)
        app_body = shell_source[app_start:app_end]
        self.assertIn("request_app_start(argv[0])", app_body)
        self.assertNotIn("StartAppByName", app_body)
        self.assertNotIn("run_external_app", app_body)

        sd_start = shell_source.index("static void cmd_sd_over_usb")
        sd_end = shell_source.index("bool strEndsWith", sd_start)
        sd_body = shell_source[sd_start:sd_end]
        self.assertIn('request_app_start("sdusb")', sd_body)
        self.assertNotIn("getTopWidget", sd_body)
        self.assertNotIn("run_external_app", sd_body)

        flash_start = shell_source.index("static void cmd_flash")
        flash_end = shell_source.index("static void cmd_screenshot", flash_start)
        flash_body = shell_source[flash_start:flash_end]
        self.assertIn(
            "request_firmware_flash(path.native().c_str())", flash_body
        )
        self.assertNotIn("getTopWidget", flash_body)
        self.assertNotIn("FlashUtilityView", flash_body)

        event_source = (
            FIRMWARE_DIRECTORY / "application" / "event_m0.cpp"
        ).read_text(encoding="utf-8")

        app_request_start = event_source.index("EventDispatcher::request_app_start")
        app_request_end = event_source.index(
            "EventDispatcher::request_firmware_flash", app_request_start
        )
        app_request_body = event_source[app_request_start:app_request_end]
        self.assertIn(
            "request_shell_ui(start_app_on_event_thread, name)", app_request_body
        )

        flash_request_start = event_source.index(
            "EventDispatcher::request_firmware_flash"
        )
        flash_request_end = event_source.index("EventDispatcher::request_shell_ui")
        flash_request_body = event_source[
            flash_request_start:flash_request_end
        ]
        self.assertIn(
            "request_shell_ui(flash_firmware_on_event_thread, path)",
            flash_request_body,
        )

        request_start = event_source.index("EventDispatcher::request_shell_ui")
        request_end = event_source.index(
            "EventDispatcher::on_keyboard_event", request_start
        )
        request_body = event_source[request_start:request_end]
        self.assertIn("chThdSelf() == thread_event_loop", request_body)
        self.assertIn("chMtxLock(&shell_ui_mutex)", request_body)
        self.assertLess(
            request_body.index("pending_shell_ui_argument = argument"),
            request_body.index("pending_shell_ui_action = action"),
        )
        self.assertLess(
            request_body.index("pending_shell_ui_action = action"),
            request_body.index("events_flag(EVT_MASK_SHELL)"),
        )
        self.assertLess(
            request_body.index("events_flag(EVT_MASK_SHELL)"),
            request_body.index("chSemWait(&shell_ui_done)"),
        )
        self.assertIn("chMtxUnlock()", request_body)

        handler_start = event_source.index("EventDispatcher::handle_shell")
        handler_end = event_source.index(
            "EventDispatcher::touch_widget", handler_start
        )
        handler_body = event_source[handler_start:handler_end]
        self.assertLess(
            handler_body.index("shell_ui_action(top_widget, argument)"),
            handler_body.index("pending_shell_ui_action = nullptr"),
        )
        self.assertLess(
            handler_body.index("pending_shell_ui_action = nullptr"),
            handler_body.index("chSemSignal(&shell_ui_done)"),
        )

        launch_start = event_source.index("bool start_app_on_event_thread")
        launch_end = event_source.index(
            "EventDispatcher::EventDispatcher", launch_start
        )
        launch_body = event_source[launch_start:launch_end]
        self.assertLess(
            launch_body.index("StartAppByName"),
            launch_body.index("run_external_app"),
        )
        self.assertNotIn("path_from_string8", launch_body)
        self.assertLess(
            launch_body.index("nav->push<ui::FlashUtilityView>()"),
            launch_body.index("flash_view->flash_firmware"),
        )

    def test_build_contract_tracks_m4_inputs_and_keeps_zeroed_tail_slot(self):
        cmake_source = (
            FIRMWARE_DIRECTORY / "application" / "CMakeLists.txt"
        ).read_text(encoding="utf-8")
        baseband_cmake_source = (
            FIRMWARE_DIRECTORY / "baseband" / "CMakeLists.txt"
        ).read_text(encoding="utf-8")
        firmware_cmake_source = (
            FIRMWARE_DIRECTORY / "CMakeLists.txt"
        ).read_text(encoding="utf-8")
        linker_source = (
            FIRMWARE_DIRECTORY
            / "chibios-portapack"
            / "os"
            / "ports"
            / "GCC"
            / "ARMCMx"
            / "LPC43xx_M0"
            / "ld"
            / "LPC43xx_M0.ld"
        ).read_text(encoding="utf-8")

        self.assertIn("${BASEBAND_RAW_IMAGES}", cmake_source)
        self.assertIn("${baseband_BINARY_DIR}/baseband.img", cmake_source)
        self.assertIn("BASEBAND_RAW_IMAGES", baseband_cmake_source)
        self.assertLess(
            firmware_cmake_source.index("add_subdirectory(baseband)"),
            firmware_cmake_source.index("add_subdirectory(application)"),
        )
        self.assertIn(".build_cohort_fingerprint", linker_source)
        self.assertIn("LONG(0);", linker_source)


if __name__ == "__main__":
    unittest.main()
