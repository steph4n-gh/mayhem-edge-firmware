#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

"""Fail-closed linked verifier for the p12 segmented Precision RX PPMA."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

import export_external_apps as exporter


MAIN_SECTION = ".external_app_precision_rx"
AUX0_SECTION = ".external_app_precision_rx_aux0"
AUX1_SECTION = ".external_app_precision_rx_aux1"
UNWIND_GUARD_SECTION = ".external_app_precision_rx_unwind_guard"
EXPECTED_MAIN_FAKE_BASE = 0xAE0D0000
EXPECTED_AUX0_FAKE_BASE = exporter.precision_rx_aux0_fake_address
EXPECTED_AUX1_FAKE_BASE = exporter.precision_rx_aux1_fake_address
EXPECTED_AUX0_LOAD_BASE = 0x100890D8
EXPECTED_AUX0_END = 0x10089A28
EXPECTED_AUX1_LOAD_BASE = 0x10089A60
EXPECTED_AUX1_END = 0x1008A000
EXPECTED_LIVE_FIELD_GAP_SIZE = 56
EXPECTED_M4_PANIC_CONTEXT_RESERVED_SIZE = 112
M4_RUNTIME_BASE = 0x10080000
RECEIPT_CONTRACT = "precision-rx-segmented-ppma-linked-v3"
GEOMETRY_VERSION = 1
GEOMETRY_SYMBOLS = {
    "version": "__prx_p12_geometry_version",
    "m4_tag_word": "__prx_p12_m4_tag_word",
    "main_bytes": "__prx_p12_main_bytes",
    "m4_bytes": "__prx_p12_m4_bytes",
    "aux0_bytes": "__prx_p12_aux0_bytes",
    "aux1_bytes": "__prx_p12_aux1_bytes",
    "trailer_bytes": "__prx_p12_trailer_bytes",
    "checksum_bytes": "__prx_p12_checksum_bytes",
    "image_bytes": "__prx_p12_image_bytes",
    "file_bytes": "__prx_p12_file_bytes",
    "code_window_bytes": "__prx_p12_code_window_bytes",
    "m4_runtime_base": "__prx_p12_m4_runtime_base",
    "m0_runtime_base": "__prx_p12_m0_runtime_base",
    "aux0_runtime_base": "__prx_p12_aux0_runtime_base",
    "aux0_max_bytes": "__prx_p12_aux0_max_bytes",
    "aux1_runtime_base": "__prx_p12_aux1_runtime_base",
    "aux1_max_bytes": "__prx_p12_aux1_max_bytes",
    "shared_memory_end": "__prx_p12_shared_memory_end",
    "main_fake_base": "__prx_p12_main_fake_base",
    "aux0_fake_base": "__prx_p12_aux0_fake_base",
    "aux1_fake_base": "__prx_p12_aux1_fake_base",
}


class VerificationError(RuntimeError):
    pass


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def artifact_binding(path):
    path = Path(path)
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {
        "name": path.name,
        "size": size,
        "sha256": digest.hexdigest(),
    }


def byte_binding(name, data):
    return {
        "name": name,
        "size": len(data),
        "sha256": sha256_bytes(data),
    }


def write_json_atomic(path, value):
    path = Path(path)
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, separators=(",", ": "))
        + "\n"
    ).encode("utf-8")
    temporary = path.with_name(path.name + ".tmp")
    try:
        with temporary.open("wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run_tool(arguments):
    result = subprocess.run(
        arguments,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise VerificationError(
            f"{' '.join(arguments)} failed: {result.stderr.strip()}"
        )
    return result.stdout


def elf_sections(elf_path, objdump):
    output = run_tool([objdump, "-h", str(elf_path)])
    sections = {}
    pattern = re.compile(
        r"^\s*\d+\s+(\S+)\s+([0-9a-fA-F]+)\s+"
        r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if match:
            name, size, vma, _lma = match.groups()
            sections[name] = (int(vma, 16), int(size, 16))
    return sections


def elf_symbols(elf_path, nm):
    output = run_tool([nm, "-n", "-S", "-C", str(elf_path)])
    symbols = []
    pattern = re.compile(
        r"^([0-9a-fA-F]+)(?:\s+([0-9a-fA-F]+))?\s+"
        r"([A-Za-z])\s+(.*)$"
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if match:
            address, size, kind, name = match.groups()
            symbols.append(
                (int(address, 16), int(size, 16) if size else 0, kind, name)
            )
    return symbols


def unique_symbol_address(symbols, exact_name):
    matches = [address for address, _size, _kind, name in symbols
               if name == exact_name]
    if len(matches) != 1:
        raise VerificationError(
            f"expected one symbol {exact_name!r}, found {len(matches)}"
        )
    return matches[0]


def absolute_geometry(symbols):
    geometry = {}
    for field, exact_name in GEOMETRY_SYMBOLS.items():
        matches = [
            (address, kind)
            for address, _size, kind, name in symbols
            if name == exact_name
        ]
        if len(matches) != 1:
            raise VerificationError(
                f"expected one geometry symbol {exact_name!r}, "
                f"found {len(matches)}"
            )
        address, kind = matches[0]
        if kind != "A":
            raise VerificationError(
                f"geometry symbol {exact_name!r} has type {kind!r}, "
                "expected absolute type 'A'"
            )
        geometry[field] = address
    return geometry


def require_named_symbol_in_range(symbols, name_fragment, start, size):
    matches = [
        (address, name)
        for address, _symbol_size, _kind, name in symbols
        if name_fragment in name and start <= address < start + size
    ]
    if not matches:
        raise VerificationError(
            f"no symbol containing {name_fragment!r} is in "
            f"[{start:#x}, {start + size:#x})"
        )


def verify_direct_branches_are_segment_local(
    elf_path,
    objdump,
    section_name,
    allowed_ranges,
):
    output = run_tool([objdump, "-d", "-j", section_name, str(elf_path)])
    branch_pattern = re.compile(
        r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{4}\s+)+"
        r"(b(?:l|x|eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)?"
        r"(?:\.n|\.w)?)\s+([0-9a-fA-F]+)\s+<"
    )
    for line in output.splitlines():
        match = branch_pattern.match(line)
        if not match:
            continue
        target = int(match.group(2), 16)
        if not any(start <= target < start + size
                   for start, size in allowed_ranges):
            raise VerificationError(
                f"{section_name} has non-local direct branch target "
                f"{target:#x}: {line.strip()}"
            )


def extract_section(elf_path, objcopy, section_name, output_path):
    run_tool(
        [
            objcopy,
            "-O",
            "binary",
            f"--only-section={section_name}",
            str(elf_path),
            str(output_path),
        ]
    )
    return output_path.read_bytes()


def extract_binary(elf_path, objcopy, output_path):
    run_tool(
        [
            objcopy,
            "-O",
            "binary",
            str(elf_path),
            str(output_path),
        ]
    )
    return output_path.read_bytes()


def aligned_fake_words(data, base_offset=0):
    matches = []
    for offset in range(0, len(data), 4):
        value = struct.unpack_from("<I", data, offset)[0]
        if (
            EXPECTED_MAIN_FAKE_BASE <= value <
            EXPECTED_MAIN_FAKE_BASE + exporter.maximum_application_size
            or EXPECTED_AUX0_FAKE_BASE <= value <
            EXPECTED_AUX0_FAKE_BASE + exporter.precision_rx_aux0_maximum_size
            or EXPECTED_AUX1_FAKE_BASE <= value <
            EXPECTED_AUX1_FAKE_BASE + exporter.precision_rx_aux1_maximum_size
        ):
            matches.append((base_offset + offset, value))
    return matches


def verify(args):
    elf_path = Path(args.elf)
    ppma_path = Path(args.ppma)
    m4_path = Path(args.m4)
    m4_elf_argument = getattr(args, "m4_elf", None)
    m4_elf_path = (
        Path(m4_elf_argument)
        if m4_elf_argument
        else m4_path.with_name("baseband_precision_rx.elf")
    )
    ppma = ppma_path.read_bytes()
    m4 = m4_path.read_bytes()
    application_elf_binding = artifact_binding(elf_path)
    m4_elf_binding = artifact_binding(m4_elf_path)

    sections = elf_sections(elf_path, args.objdump)
    if (
        MAIN_SECTION not in sections
        or AUX0_SECTION not in sections
        or AUX1_SECTION not in sections
    ):
        raise VerificationError("linked ELF is missing a segmented PPMA section")

    symbols = elf_symbols(elf_path, args.nm)
    geometry = absolute_geometry(symbols)
    main_fake_base, linked_main_size = sections[MAIN_SECTION]
    aux0_fake_base, linked_aux0_size = sections[AUX0_SECTION]
    aux1_fake_base, linked_aux1_size = sections[AUX1_SECTION]

    if geometry["version"] != GEOMETRY_VERSION:
        raise VerificationError(
            f"geometry version is {geometry['version']}, "
            f"expected {GEOMETRY_VERSION}"
        )
    if geometry["m4_tag_word"] != int.from_bytes(b"PRX1", "little"):
        raise VerificationError("geometry M4 tag is not PRX1")
    if geometry["trailer_bytes"] != exporter.PRECISION_RX_SEGMENTED_TRAILER.size:
        raise VerificationError("geometry trailer size differs from exporter")
    if geometry["checksum_bytes"] != exporter.CHECKSUM_SIZE:
        raise VerificationError("geometry checksum size differs from exporter")
    if geometry["code_window_bytes"] != exporter.maximum_application_size:
        raise VerificationError("geometry code-window size differs from exporter")
    if geometry["m4_runtime_base"] != M4_RUNTIME_BASE:
        raise VerificationError("geometry M4 runtime base is invalid")
    if geometry["main_fake_base"] != EXPECTED_MAIN_FAKE_BASE:
        raise VerificationError("geometry main fake base is invalid")
    if geometry["aux0_fake_base"] != EXPECTED_AUX0_FAKE_BASE:
        raise VerificationError("geometry aux0 fake base is invalid")
    if geometry["aux1_fake_base"] != EXPECTED_AUX1_FAKE_BASE:
        raise VerificationError("geometry aux1 fake base is invalid")
    if geometry["aux0_runtime_base"] != EXPECTED_AUX0_LOAD_BASE:
        raise VerificationError("geometry aux0 runtime base is invalid")
    if geometry["aux0_max_bytes"] != exporter.precision_rx_aux0_maximum_size:
        raise VerificationError("geometry aux0 maximum differs from exporter")
    if geometry["aux1_runtime_base"] != EXPECTED_AUX1_LOAD_BASE:
        raise VerificationError("geometry aux1 runtime base is invalid")
    if geometry["aux1_max_bytes"] != exporter.precision_rx_aux1_maximum_size:
        raise VerificationError("geometry aux1 maximum differs from exporter")
    if geometry["shared_memory_end"] != EXPECTED_AUX1_END:
        raise VerificationError("geometry shared-memory end is invalid")

    if (
        main_fake_base != geometry["main_fake_base"]
        or linked_main_size != geometry["main_bytes"]
    ):
        raise VerificationError("linked main section differs from geometry")
    if (
        aux0_fake_base != geometry["aux0_fake_base"]
        or linked_aux0_size != geometry["aux0_bytes"]
    ):
        raise VerificationError("linked aux0 section differs from geometry")
    if (
        aux1_fake_base != geometry["aux1_fake_base"]
        or linked_aux1_size != geometry["aux1_bytes"]
    ):
        raise VerificationError("linked aux1 section differs from geometry")

    image_size_sum = (
        geometry["main_bytes"]
        + geometry["m4_bytes"]
        + geometry["aux0_bytes"]
        + geometry["aux1_bytes"]
    )
    if geometry["image_bytes"] != image_size_sum:
        raise VerificationError("geometry image-size sum is invalid")
    if geometry["file_bytes"] != (
        geometry["image_bytes"]
        + geometry["trailer_bytes"]
        + geometry["checksum_bytes"]
    ):
        raise VerificationError("geometry file-size sum is invalid")
    if (
        geometry["main_bytes"]
        | geometry["m4_bytes"]
        | geometry["aux0_bytes"]
        | geometry["aux1_bytes"]
    ) & 3:
        raise VerificationError("geometry image sizes are not word aligned")
    if geometry["main_bytes"] < exporter.APPLICATION_HEADER_SIZE:
        raise VerificationError("geometry main image is smaller than its header")
    if geometry["m4_bytes"] == 0:
        raise VerificationError("geometry M4 image is empty")
    if geometry["m0_runtime_base"] != (
        geometry["m4_runtime_base"] + geometry["m4_bytes"]
    ):
        raise VerificationError("geometry M0 runtime base is invalid")
    if (
        geometry["main_bytes"] + geometry["m4_bytes"]
        > geometry["code_window_bytes"]
    ):
        raise VerificationError("geometry main plus M4 exceeds code window")
    if not 0 < geometry["aux0_bytes"] <= geometry["aux0_max_bytes"]:
        raise VerificationError("geometry aux0 size exceeds runtime slot")
    if not 0 < geometry["aux1_bytes"] <= geometry["aux1_max_bytes"]:
        raise VerificationError("geometry aux1 size exceeds runtime slot")
    if (
        geometry["aux0_runtime_base"] + geometry["aux0_max_bytes"]
        >= geometry["aux1_runtime_base"]
    ):
        raise VerificationError("geometry auxiliary slots overlap live fields")
    if (
        geometry["aux1_runtime_base"] + geometry["aux1_max_bytes"]
        != geometry["shared_memory_end"]
    ):
        raise VerificationError("geometry aux1 slot does not end at shared-memory end")
    if (
        geometry["aux1_fake_base"] - geometry["aux0_fake_base"]
        != geometry["aux1_runtime_base"] - geometry["aux0_runtime_base"]
    ):
        raise VerificationError("geometry auxiliary fake/runtime spacing differs")

    if (
        exporter.precision_rx_m4_panic_context_reserved_size
        != EXPECTED_M4_PANIC_CONTEXT_RESERVED_SIZE
        or exporter.precision_rx_aux0_load_address != EXPECTED_AUX0_LOAD_BASE
        or (
            exporter.precision_rx_aux0_load_address
            + exporter.precision_rx_aux0_maximum_size
        ) != EXPECTED_AUX0_END
        or exporter.precision_rx_aux1_load_address != EXPECTED_AUX1_LOAD_BASE
        or (
            exporter.precision_rx_aux1_load_address
            - (
                exporter.precision_rx_aux0_load_address
                + exporter.precision_rx_aux0_maximum_size
            )
        ) != EXPECTED_LIVE_FIELD_GAP_SIZE
        or (
            exporter.precision_rx_aux1_load_address
            + exporter.precision_rx_aux1_maximum_size
        ) != EXPECTED_AUX1_END
    ):
        raise VerificationError(
            "segmented SharedMemory ABI or M4 panic-mailbox boundary changed"
        )
    if (
        geometry["aux0_runtime_base"] - aux0_fake_base
        != geometry["aux1_runtime_base"] - aux1_fake_base
    ):
        raise VerificationError(
            "auxiliary fake/runtime spacing does not preserve direct branches"
        )
    if (
        UNWIND_GUARD_SECTION in sections
        and sections[UNWIND_GUARD_SECTION][1] != 0
    ):
        raise VerificationError("Precision RX PREL31 unwind guard is non-empty")

    heap_base = unique_symbol_address(symbols, "__heap_base__")
    heap_end = unique_symbol_address(symbols, "__heap_end__")
    static_end = unique_symbol_address(symbols, "_end")
    if heap_end != 0x20010000:
        raise VerificationError(f"unexpected p12 heap end {heap_end:#x}")
    if not (static_end == heap_base <= heap_end):
        raise VerificationError(
            f"invalid heap/static bounds: end={static_end:#x}, "
            f"heap=[{heap_base:#x},{heap_end:#x})"
        )

    for name_fragment in (
        "update_display() [clone .part.0]",
        "write_metadata",
        "set_capture_controls_locked",
    ):
        require_named_symbol_in_range(
            symbols, name_fragment, aux0_fake_base, linked_aux0_size
        )
    for name_fragment in (
        "crc32c_update",
        "recover_snapshot_journal",
        "apply_sample_rate",
        "finish_sample_rate_change",
        "cancel_preparation",
        "reset_measurement_epoch",
        "on_status",
    ):
        require_named_symbol_in_range(
            symbols, name_fragment, aux1_fake_base, linked_aux1_size
        )
    for name_fragment in (
        "initialize_app",
        "write_exact",
        "reset_measurement_epoch",
        "PrecisionRxView::PrecisionRxView",
        "PrecisionRxView::~PrecisionRxView",
        "vtable for ui::external_app::precision_rx::PrecisionRxView",
    ):
        require_named_symbol_in_range(
            symbols, name_fragment, main_fake_base, linked_main_size
        )

    verify_direct_branches_are_segment_local(
        elf_path,
        args.objdump,
        MAIN_SECTION,
        [(main_fake_base, linked_main_size)],
    )
    auxiliary_ranges = [
        (aux0_fake_base, linked_aux0_size),
        (aux1_fake_base, linked_aux1_size),
    ]
    verify_direct_branches_are_segment_local(
        elf_path, args.objdump, AUX0_SECTION, auxiliary_ranges
    )
    verify_direct_branches_are_segment_local(
        elf_path, args.objdump, AUX1_SECTION, auxiliary_ranges
    )

    if len(ppma) != geometry["file_bytes"]:
        raise VerificationError(
            f"PPMA size is {len(ppma)}, expected geometry "
            f"{geometry['file_bytes']}"
        )
    if len(m4) != geometry["m4_bytes"]:
        raise VerificationError(
            f"supplied M4 size is {len(m4)}, expected geometry "
            f"{geometry['m4_bytes']}"
        )
    if exporter.additive_checksum_word(ppma) != 0:
        raise VerificationError("PPMA additive checksum is invalid")
    body = ppma[:-geometry["checksum_bytes"]]
    trailer = exporter.decode_precision_rx_segmented_trailer(body)
    if trailer is None:
        raise VerificationError("PPMA segmented trailer is invalid")
    expected_trailer = {
        "main_size": geometry["main_bytes"],
        "m4_size": geometry["m4_bytes"],
        "aux0_size": geometry["aux0_bytes"],
        "aux0_load_address": geometry["aux0_runtime_base"],
        "aux1_size": geometry["aux1_bytes"],
        "aux1_load_address": geometry["aux1_runtime_base"],
        "image_size": geometry["image_bytes"],
    }
    if trailer != expected_trailer:
        raise VerificationError("PPMA trailer differs from geometry")

    memory_location = struct.unpack_from(
        "<I", ppma, exporter.MEMORY_LOCATION_HEADER_POSITION
    )[0]
    entry = struct.unpack_from(
        "<I", ppma, exporter.EXTERNAL_APP_ENTRY_HEADER_POSITION
    )[0]
    m4_offset = struct.unpack_from(
        "<I", ppma, exporter.M4_APP_OFFSET_HEADER_POSITION
    )[0]
    expected_main_runtime = geometry["m0_runtime_base"]
    if memory_location != expected_main_runtime:
        raise VerificationError("PPMA main runtime address is invalid")
    if m4_offset != geometry["main_bytes"]:
        raise VerificationError("PPMA m4_app_offset is invalid")
    if ppma[
        exporter.M4_APP_TAG_HEADER_POSITION:
        exporter.M4_APP_TAG_HEADER_POSITION + 4
    ] != struct.pack("<I", geometry["m4_tag_word"]):
        raise VerificationError("PPMA M4 tag is not PRX1")
    if (
        (entry & 1) == 0
        or not expected_main_runtime <= (entry & ~1) <
        expected_main_runtime + geometry["main_bytes"]
    ):
        raise VerificationError("PPMA entry is outside M0 main")
    fingerprint_start = exporter.BUILD_FINGERPRINT_HEADER_POSITION
    fingerprint_end = fingerprint_start + exporter.BUILD_FINGERPRINT_SIZE
    header_version = struct.unpack_from(
        "<I", ppma, exporter.HEADER_VERSION_POSITION
    )[0]
    if header_version != exporter.CURRENT_HEADER_VERSION:
        raise VerificationError(
            f"PPMA header version is {header_version}, "
            f"expected {exporter.CURRENT_HEADER_VERSION}"
        )
    if not any(ppma[fingerprint_start:fingerprint_end]):
        raise VerificationError("PPMA cohort fingerprint is zero")

    main_end = geometry["main_bytes"]
    m4_end = main_end + geometry["m4_bytes"]
    aux0_end = m4_end + geometry["aux0_bytes"]
    aux1_end = aux0_end + geometry["aux1_bytes"]
    trailer_end = aux1_end + geometry["trailer_bytes"]
    if (
        aux1_end != geometry["image_bytes"]
        or trailer_end != len(body)
        or trailer_end + geometry["checksum_bytes"] != len(ppma)
    ):
        raise VerificationError("PPMA segment boundaries differ from geometry")
    if ppma[main_end:m4_end] != m4:
        raise VerificationError("PPMA M4 bytes differ from supplied M4")
    fake_words = (
        aligned_fake_words(ppma[:main_end])
        + aligned_fake_words(ppma[m4_end:aux0_end], base_offset=m4_end)
        + aligned_fake_words(ppma[aux0_end:aux1_end], base_offset=aux0_end)
    )
    if fake_words:
        offset, value = fake_words[0]
        raise VerificationError(
            f"unrelocated fake address {value:#x} at PPMA offset {offset:#x}"
        )

    with tempfile.TemporaryDirectory() as temporary_directory:
        temporary = Path(temporary_directory)
        linked_main = extract_section(
            elf_path, args.objcopy, MAIN_SECTION, temporary / "main.bin"
        )
        linked_aux0 = extract_section(
            elf_path, args.objcopy, AUX0_SECTION, temporary / "aux0.bin"
        )
        linked_aux1 = extract_section(
            elf_path, args.objcopy, AUX1_SECTION, temporary / "aux1.bin"
        )
        objcopied_m4 = extract_binary(
            m4_elf_path, args.objcopy, temporary / "m4.bin"
        )
    if objcopied_m4 != m4:
        raise VerificationError(
            "supplied PRX1 does not equal the objcopied M4 ELF"
        )
    mappings = [
        (
            main_fake_base,
            expected_main_runtime,
            geometry["code_window_bytes"],
        ),
        (
            aux0_fake_base,
            geometry["aux0_runtime_base"],
            geometry["aux0_max_bytes"],
        ),
        (
            aux1_fake_base,
            geometry["aux1_runtime_base"],
            geometry["aux1_max_bytes"],
        ),
    ]
    expected_main = exporter.patch_image_mappings(
        "linked-main", linked_main, mappings
    )
    struct.pack_into(
        "<I",
        expected_main,
        exporter.MEMORY_LOCATION_HEADER_POSITION,
        expected_main_runtime,
    )
    struct.pack_into(
        "<I",
        expected_main,
        exporter.M4_APP_OFFSET_HEADER_POSITION,
        geometry["main_bytes"],
    )
    expected_main[fingerprint_start:fingerprint_end] = ppma[
        fingerprint_start:fingerprint_end
    ]
    expected_aux0 = exporter.patch_image_mappings(
        "linked-aux0", linked_aux0, mappings
    )
    expected_aux1 = exporter.patch_image_mappings(
        "linked-aux1", linked_aux1, mappings
    )
    if bytes(expected_main) != ppma[:main_end]:
        raise VerificationError("PPMA main is not the exact relocated ELF section")
    if bytes(expected_aux0) != ppma[m4_end:aux0_end]:
        raise VerificationError("PPMA aux0 is not the exact relocated ELF section")
    if bytes(expected_aux1) != ppma[aux0_end:aux1_end]:
        raise VerificationError("PPMA aux1 is not the exact relocated ELF section")

    if artifact_binding(elf_path) != application_elf_binding:
        raise VerificationError("application ELF changed during verification")
    if artifact_binding(m4_elf_path) != m4_elf_binding:
        raise VerificationError("M4 ELF changed during verification")
    if ppma_path.read_bytes() != ppma:
        raise VerificationError("PPMA changed during verification")
    if m4_path.read_bytes() != m4:
        raise VerificationError("supplied PRX1 changed during verification")

    fingerprint = ppma[fingerprint_start:fingerprint_end]
    checksum_word = struct.unpack_from(
        "<I", ppma, len(ppma) - geometry["checksum_bytes"]
    )[0]
    raw_sections = {
        "main": byte_binding(MAIN_SECTION, linked_main),
        "aux0": byte_binding(AUX0_SECTION, linked_aux0),
        "aux1": byte_binding(AUX1_SECTION, linked_aux1),
    }
    relocated_sections = {
        "main": byte_binding("precision_rx.main.relocated", bytes(expected_main)),
        "aux0": byte_binding("precision_rx.aux0.relocated", bytes(expected_aux0)),
        "aux1": byte_binding("precision_rx.aux1.relocated", bytes(expected_aux1)),
    }
    ppma_sections = {
        "main": byte_binding("precision_rx.ppma.main", ppma[:main_end]),
        "m4": byte_binding("precision_rx.ppma.m4", ppma[main_end:m4_end]),
        "aux0": byte_binding(
            "precision_rx.ppma.aux0", ppma[m4_end:aux0_end]
        ),
        "aux1": byte_binding(
            "precision_rx.ppma.aux1", ppma[aux0_end:aux1_end]
        ),
        "trailer": byte_binding(
            "precision_rx.ppma.trailer",
            body[-exporter.PRECISION_RX_SEGMENTED_TRAILER.size:],
        ),
    }
    receipt = {
        "contract": RECEIPT_CONTRACT,
        "result": "PASS",
        "artifact_bindings": {
            "application_elf": application_elf_binding,
            "m4_elf": m4_elf_binding,
            "m4_objcopied_raw": byte_binding(
                "baseband_precision_rx.objcopy.bin", objcopied_m4
            ),
            "supplied_prx1": byte_binding(m4_path.name, m4),
            "ppma": byte_binding(ppma_path.name, ppma),
            "ppma_body": byte_binding(ppma_path.name + ".body", body),
            "application_objcopied_sections": raw_sections,
            "relocated_sections": relocated_sections,
            "ppma_sections": ppma_sections,
        },
        "linked_sections": {
            "main": {
                "name": MAIN_SECTION,
                "fake_base": f"0x{main_fake_base:08x}",
                "runtime_base": f"0x{expected_main_runtime:08x}",
                "size": linked_main_size,
            },
            "aux0": {
                "name": AUX0_SECTION,
                "fake_base": f"0x{aux0_fake_base:08x}",
                "runtime_base": (
                    f"0x{geometry['aux0_runtime_base']:08x}"
                ),
                "maximum_size": geometry["aux0_max_bytes"],
                "size": linked_aux0_size,
            },
            "aux1": {
                "name": AUX1_SECTION,
                "fake_base": f"0x{aux1_fake_base:08x}",
                "runtime_base": (
                    f"0x{geometry['aux1_runtime_base']:08x}"
                ),
                "maximum_size": geometry["aux1_max_bytes"],
                "size": linked_aux1_size,
            },
        },
        "heap": {
            "base": f"0x{heap_base:08x}",
            "end": f"0x{heap_end:08x}",
            "static_end": f"0x{static_end:08x}",
            "bytes": heap_end - heap_base,
        },
        "loader_geometry": {
            field: (
                f"0x{value:08x}"
                if field.endswith("_base")
                or field.endswith("_word")
                or field == "shared_memory_end"
                else value
            )
            for field, value in geometry.items()
        },
        "ppma": {
            "size": len(ppma),
            "geometry_size": geometry["file_bytes"],
            "maximum_size": exporter.precision_rx_segmented_maximum_file_size,
            "header_version": header_version,
            "cohort_fingerprint": fingerprint.hex(),
            "memory_location": f"0x{memory_location:08x}",
            "entry": f"0x{entry:08x}",
            "m4_tag": exporter.PRECISION_RX_M4_TAG,
            "m4_app_offset": m4_offset,
            "checksum_word": f"0x{checksum_word:08x}",
            "additive_checksum": 0,
        },
        "trailer": {
            "magic": "PR12",
            "version": exporter.PRECISION_RX_SEGMENTED_TRAILER_VERSION,
            "trailer_size": exporter.PRECISION_RX_SEGMENTED_TRAILER.size,
            "main_size": trailer["main_size"],
            "m4_size": trailer["m4_size"],
            "aux0_size": trailer["aux0_size"],
            "aux0_load_address": f"0x{trailer['aux0_load_address']:08x}",
            "aux1_size": trailer["aux1_size"],
            "aux1_load_address": f"0x{trailer['aux1_load_address']:08x}",
            "image_size": trailer["image_size"],
            "reserved": 0,
        },
        "headroom_bytes": {
            "ppma_file": (
                exporter.precision_rx_segmented_maximum_file_size - len(ppma)
            ),
            "main_plus_m4": (
                geometry["code_window_bytes"] -
                (geometry["main_bytes"] + geometry["m4_bytes"])
            ),
            "aux0": (
                geometry["aux0_max_bytes"] - geometry["aux0_bytes"]
            ),
            "aux1": (
                geometry["aux1_max_bytes"] - geometry["aux1_bytes"]
            ),
        },
        "verification_evidence": {
            "unrelocated_fake_address_words": [],
            "unwind_guard": {
                "name": UNWIND_GUARD_SECTION,
                "size": (
                    sections[UNWIND_GUARD_SECTION][1]
                    if UNWIND_GUARD_SECTION in sections
                    else 0
                ),
            },
            "direct_branch_locality_sections": [
                MAIN_SECTION,
                AUX0_SECTION,
                AUX1_SECTION,
            ],
            "byte_comparisons": {
                "m4_objcopy_equals_supplied_prx1": True,
                "ppma_m4_equals_supplied_prx1": True,
                "main_equals_relocated_application_section": True,
                "aux0_equals_relocated_application_section": True,
                "aux1_equals_relocated_application_section": True,
            },
        },
        "proofs": {
            "input_artifacts_stable_during_verification": True,
            "m4_objcopy_equals_supplied_prx1": True,
            "ppma_m4_equals_supplied_prx1": True,
            "ppma_sections_equal_relocated_elf_sections": True,
            "segmented_trailer_exact_v2": True,
            "header_and_entry_bounds_valid": True,
            "additive_checksum_valid": True,
            "cohort_fingerprint_nonzero": True,
            "no_unrelocated_fake_addresses": True,
            "unwind_guard_empty": True,
            "direct_branches_segment_local": True,
            "shared_memory_abi_exact": True,
            "loader_geometry_symbols_absolute_and_exact": True,
        },
        "post_build_instruction_calibration_required": [],
    }
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", required=True)
    parser.add_argument("--ppma", required=True)
    parser.add_argument("--m4", required=True)
    parser.add_argument(
        "--m4-elf",
        help=(
            "M4 ELF to bind and objcopy (defaults to "
            "baseband_precision_rx.elf beside --m4)"
        ),
    )
    parser.add_argument("--json-output")
    parser.add_argument("--objcopy", default="arm-none-eabi-objcopy")
    parser.add_argument("--objdump", default="arm-none-eabi-objdump")
    parser.add_argument("--nm", default="arm-none-eabi-nm")
    args = parser.parse_args(argv)
    try:
        receipt = verify(args)
        if args.json_output:
            write_json_atomic(args.json_output, receipt)
    except (OSError, ValueError, VerificationError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        "PASS segmented Precision RX PPMA: "
        f"main={receipt['trailer']['main_size']} "
        f"m4={receipt['trailer']['m4_size']} "
        f"aux0={receipt['trailer']['aux0_size']} "
        f"aux1={receipt['trailer']['aux1_size']} "
        f"file={receipt['ppma']['size']} "
        f"heap={receipt['heap']['bytes']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
