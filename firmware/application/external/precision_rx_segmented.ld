/*
 * SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * P14 Precision RX auxiliary segments.
 *
 * The ordinary Precision RX image is linked in its legacy fake window at
 * 0xAE0D0000.  Keep the auxiliary fake addresses more than the Cortex-M0
 * Thumb-1 branch range away so GNU ld emits absolute-address veneers for
 * every main/auxiliary call.  The two auxiliary fake addresses preserve the
 * exact 0x988 spacing of their runtime slots, so direct branches between them
 * remain valid after relocation.  The exporter relocates aligned address
 * literals independently when all three segments move.
 */

.external_app_precision_rx_aux0 @PRECISION_RX_SEGMENTED_AUX0_FAKE_BASE@ : ALIGN(4) SUBALIGN(4)
{
    /*
     * This segment overlays the portion of SharedMemory::bb_data after the
     * 112-byte M4 panic-context mailbox. Precision RX otherwise leaves the
     * union unused. Keep related string-heavy helpers together so they share
     * veneers.
     */
    *(.rodata._ZN2ui12external_app12precision_rx15PrecisionRxView14update_displayEv.part.0*)
    *(.text._ZN2ui12external_app12precision_rx15PrecisionRxView14update_displayEv.part.0*)

    *(.rodata._ZN2ui12external_app12precision_rx15PrecisionRxView14write_metadataE*)
    *(.text._ZN2ui12external_app12precision_rx15PrecisionRxView14write_metadataE*)

    *(.text._ZN2ui12external_app12precision_rx15PrecisionRxView27set_capture_controls_lockedE*)

    . = ALIGN(4);
}

.external_app_precision_rx_aux1 @PRECISION_RX_SEGMENTED_AUX1_FAKE_BASE@ : ALIGN(4) SUBALIGN(4)
{
    /*
     * This segment occupies only the unused tail of the fixed 8 KiB shared
     * memory region.  The live fields between bb_data and this tail are never
     * overwritten.
     *
     * Only non-virtual helpers live in the auxiliary segments.  The PPMA
     * header, entry point, constructors, destructors, vtables, and
     * ownership-bearing capture writer methods remain in the main segment.
     */
    *(.text._ZN2ui12external_app12precision_rx12_GLOBAL__N_113crc32c_updateE*)
    *(.text._ZN2ui12external_app12precision_rx15PrecisionRxView14update_displayEv)

    *(.text._ZN2ui12external_app12precision_rx15PrecisionRxView24recover_snapshot_journalE*)
    *(.rodata._ZN2ui12external_app12precision_rx15PrecisionRxView17apply_sample_rateEv*)
    *(.text._ZN2ui12external_app12precision_rx15PrecisionRxView17apply_sample_rateEv*)

    *(.rodata._ZN2ui12external_app12precision_rx15PrecisionRxView25finish_sample_rate_changeE*)
    *(.text._ZN2ui12external_app12precision_rx15PrecisionRxView25finish_sample_rate_changeE*)

    *(.text._ZN2ui12external_app12precision_rx15PrecisionRxView18cancel_preparationEv)
    *(.text._ZN2ui12external_app12precision_rx15PrecisionRxView23reset_measurement_epochEv)

    *(.rodata._ZN2ui12external_app12precision_rx15PrecisionRxView12stop_captureEv.str2.2)

    *(.rodata._ZN2ui12external_app12precision_rx15PrecisionRxView9on_statusE*)
    *(.text._ZN2ui12external_app12precision_rx15PrecisionRxView9on_statusE*)

    . = ALIGN(4);
}

/*
 * PREL31 unwind records cannot be word-relocated after the two output
 * sections move independently.  This firmware is built without exceptions
 * and currently emits none; fail the link if toolchain flags ever change that
 * invariant instead of packaging a subtly invalid table.
 */
.external_app_precision_rx_unwind_guard 0xCE0D1000 :
{
    *(.ARM.extab*ui*external_app*precision_rx*)
    *(.ARM.exidx*ui*external_app*precision_rx*)
}

ASSERT(
    SIZEOF(.external_app_precision_rx_aux0) > 0,
    "Precision RX segmented PPMA auxiliary slot 0 is empty")
ASSERT(
    SIZEOF(.external_app_precision_rx_aux0) <= @PRECISION_RX_SEGMENTED_AUX0_MAX_SIZE@,
    "Precision RX segmented PPMA auxiliary slot 0 exceeds post-panic SharedMemory::bb_data")
ASSERT(
    SIZEOF(.external_app_precision_rx_aux1) > 0,
    "Precision RX segmented PPMA auxiliary slot 1 is empty")
ASSERT(
    SIZEOF(.external_app_precision_rx_aux1) <= @PRECISION_RX_SEGMENTED_AUX1_MAX_SIZE@,
    "Precision RX segmented PPMA auxiliary slot 1 exceeds shared-memory tail")
ASSERT(
    SIZEOF(.external_app_precision_rx_unwind_guard) == 0,
    "Precision RX segmented PPMA cannot relocate PREL31 unwind records")

/*
 * Zero-load-byte geometry contract. The legacy __prx_p12_* symbol names are
 * retained as the version-1 loader ABI; their exact P14 values are configured
 * from the single geometry authority above. GNU ld resolves the forward
 * main-section SIZEOF assertion after section allocation; the pinned
 * toolchain emits every symbol below as type A and objcopy emits no bytes for
 * them.
 */
__prx_p12_geometry_version = ABSOLUTE(@PRECISION_RX_SEGMENTED_GEOMETRY_VERSION@);
__prx_p12_m4_tag_word = ABSOLUTE(@PRECISION_RX_SEGMENTED_M4_TAG_WORD@);
__prx_p12_main_bytes = ABSOLUTE(@PRECISION_RX_SEGMENTED_MAIN_SIZE@);
__prx_p12_m4_bytes = ABSOLUTE(@PRECISION_RX_SEGMENTED_M4_SIZE@);
__prx_p12_aux0_bytes = ABSOLUTE(@PRECISION_RX_SEGMENTED_AUX0_SIZE@);
__prx_p12_aux1_bytes = ABSOLUTE(@PRECISION_RX_SEGMENTED_AUX1_SIZE@);
__prx_p12_trailer_bytes = ABSOLUTE(@PRECISION_RX_SEGMENTED_TRAILER_SIZE@);
__prx_p12_checksum_bytes = ABSOLUTE(@PRECISION_RX_SEGMENTED_CHECKSUM_SIZE@);
__prx_p12_image_bytes = ABSOLUTE(@PRECISION_RX_SEGMENTED_IMAGE_SIZE@);
__prx_p12_file_bytes = ABSOLUTE(@PRECISION_RX_SEGMENTED_FILE_SIZE@);

__prx_p12_code_window_bytes = ABSOLUTE(@PRECISION_RX_SEGMENTED_CODE_WINDOW_SIZE@);
__prx_p12_m4_runtime_base = ABSOLUTE(@PRECISION_RX_SEGMENTED_M4_LOAD_ADDRESS@);
__prx_p12_m0_runtime_base = ABSOLUTE(@PRECISION_RX_SEGMENTED_M0_LOAD_ADDRESS@);
__prx_p12_aux0_runtime_base = ABSOLUTE(@PRECISION_RX_SEGMENTED_AUX0_LOAD_ADDRESS@);
__prx_p12_aux0_max_bytes = ABSOLUTE(@PRECISION_RX_SEGMENTED_AUX0_MAX_SIZE@);
__prx_p12_aux1_runtime_base = ABSOLUTE(@PRECISION_RX_SEGMENTED_AUX1_LOAD_ADDRESS@);
__prx_p12_aux1_max_bytes = ABSOLUTE(@PRECISION_RX_SEGMENTED_AUX1_MAX_SIZE@);
__prx_p12_shared_memory_end = ABSOLUTE(@PRECISION_RX_SEGMENTED_SHARED_MEMORY_END@);

__prx_p12_main_fake_base = ABSOLUTE(@PRECISION_RX_SEGMENTED_MAIN_FAKE_BASE@);
__prx_p12_aux0_fake_base = ABSOLUTE(@PRECISION_RX_SEGMENTED_AUX0_FAKE_BASE@);
__prx_p12_aux1_fake_base = ABSOLUTE(@PRECISION_RX_SEGMENTED_AUX1_FAKE_BASE@);

ASSERT(
    ADDR(.external_app_precision_rx) == __prx_p12_main_fake_base,
    "Precision RX segmented main fake base differs from loader geometry")
ASSERT(
    SIZEOF(.external_app_precision_rx) == __prx_p12_main_bytes,
    "Precision RX segmented main size differs from loader geometry")
ASSERT(
    ADDR(.external_app_precision_rx_aux0) == __prx_p12_aux0_fake_base,
    "Precision RX segmented auxiliary slot 0 fake base differs from geometry")
ASSERT(
    SIZEOF(.external_app_precision_rx_aux0) == __prx_p12_aux0_bytes,
    "Precision RX segmented auxiliary slot 0 size differs from loader geometry")
ASSERT(
    ADDR(.external_app_precision_rx_aux1) == __prx_p12_aux1_fake_base,
    "Precision RX segmented auxiliary slot 1 fake base differs from geometry")
ASSERT(
    SIZEOF(.external_app_precision_rx_aux1) == __prx_p12_aux1_bytes,
    "Precision RX segmented auxiliary slot 1 size differs from loader geometry")

ASSERT(
    (__prx_p12_main_bytes | __prx_p12_m4_bytes |
     __prx_p12_aux0_bytes | __prx_p12_aux1_bytes) % 4 == 0,
    "Precision RX segmented image sizes are not word aligned")
ASSERT(
    __prx_p12_m0_runtime_base ==
        __prx_p12_m4_runtime_base + __prx_p12_m4_bytes,
    "Precision RX segmented M0 runtime base is not after M4")
ASSERT(
    __prx_p12_main_bytes + __prx_p12_m4_bytes <=
        __prx_p12_code_window_bytes,
    "Precision RX segmented main plus M4 exceeds code window")
ASSERT(
    __prx_p12_aux0_bytes <= __prx_p12_aux0_max_bytes,
    "Precision RX segmented auxiliary slot 0 exceeds runtime slot")
ASSERT(
    __prx_p12_aux1_bytes <= __prx_p12_aux1_max_bytes,
    "Precision RX segmented auxiliary slot 1 exceeds runtime slot")
ASSERT(
    __prx_p12_aux0_runtime_base + __prx_p12_aux0_max_bytes <
        __prx_p12_aux1_runtime_base,
    "Precision RX segmented auxiliary slots overlap live shared-memory fields")
ASSERT(
    __prx_p12_aux1_runtime_base + __prx_p12_aux1_max_bytes ==
        __prx_p12_shared_memory_end,
    "Precision RX segmented auxiliary slot 1 no longer ends at shared-memory end")
ASSERT(
    __prx_p12_aux1_fake_base - __prx_p12_aux0_fake_base ==
        __prx_p12_aux1_runtime_base - __prx_p12_aux0_runtime_base,
    "Precision RX segmented auxiliary fake/runtime spacing differs")
ASSERT(
    __prx_p12_image_bytes ==
        __prx_p12_main_bytes + __prx_p12_m4_bytes +
        __prx_p12_aux0_bytes + __prx_p12_aux1_bytes,
    "Precision RX segmented image-size sum differs")
ASSERT(
    __prx_p12_file_bytes ==
        __prx_p12_image_bytes + __prx_p12_trailer_bytes +
        __prx_p12_checksum_bytes,
    "Precision RX segmented file-size sum differs")
