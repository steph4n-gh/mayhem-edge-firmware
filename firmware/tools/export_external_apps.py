#!/usr/bin/env python3

#
# Copyright (C) 2023 Bernd Herzog
# Copyright (C) 2024 Mark Thompson
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

import hashlib
import os
import struct
import subprocess
import sys

from external_app_info import external_apps_address_end
from external_app_info import external_apps_address_start
from external_app_info import maximum_application_size
from external_app_info import precision_rx_aux0_fake_address
from external_app_info import precision_rx_aux0_load_address
from external_app_info import precision_rx_aux0_maximum_size
from external_app_info import precision_rx_aux1_fake_address
from external_app_info import precision_rx_aux1_load_address
from external_app_info import precision_rx_aux1_maximum_size
from external_app_info import precision_rx_m4_panic_context_reserved_size
from external_app_info import precision_rx_segmented_maximum_file_size


usage_message = """
PortaPack external app image creator
This script is used in the build process and should never be run manually.
See firmware/application/CMakeLists.txt > COMMAND ${EXPORT_EXTERNAL_APP_IMAGES}

Usage: <command> <project source dir> <binary dir> <cmake objcopy path> <baseband.img path> [--precision-rx-segmented] <list of external image prefixes>
"""

CURRENT_HEADER_VERSION = 0x00000004
BUILD_FINGERPRINT_SIZE = 8
APPLICATION_FINGERPRINT_POSITION_FROM_END = BUILD_FINGERPRINT_SIZE

MEMORY_LOCATION_HEADER_POSITION = 0
EXTERNAL_APP_ENTRY_HEADER_POSITION = 4
HEADER_VERSION_POSITION = 8
BUILD_FINGERPRINT_HEADER_POSITION = 12
M4_APP_TAG_HEADER_POSITION = 80
M4_APP_OFFSET_HEADER_POSITION = 84
APPLICATION_HEADER_SIZE = 88
CHECKSUM_SIZE = 4
COHORT_HASH_DOMAIN = b"portapack-mayhem-ppma-v4-cohort\0"

SEGMENTED_PRECISION_RX_FLAG = "--precision-rx-segmented"
PRECISION_RX_APP_NAME = "precision_rx"
PRECISION_RX_M4_TAG = "PRX1"
PRECISION_RX_AUX0_SECTION = ".external_app_precision_rx_aux0"
PRECISION_RX_AUX1_SECTION = ".external_app_precision_rx_aux1"
PRECISION_RX_SEGMENTED_TRAILER_MAGIC = int.from_bytes(b"PR12", "little")
# Version 2 is the two-auxiliary-slot layout; reject the earlier private
# one-slot version instead of interpreting its shorter trailer ambiguously.
PRECISION_RX_SEGMENTED_TRAILER_VERSION = 2
PRECISION_RX_SEGMENTED_TRAILER = struct.Struct("<IHHIIIIIIII")


def read_image(path):
    with open(path, "rb") as image_file:
        return image_file.read()


def write_image_atomic(data, path):
    temporary_path = path + ".tmp"
    try:
        with open(temporary_path, "wb") as image_file:
            image_file.write(data)
        os.replace(temporary_path, path)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def application_fingerprint_start(image_data):
    if len(image_data) < APPLICATION_FINGERPRINT_POSITION_FROM_END:
        raise ValueError("application binary is too small for its fingerprint slot")
    return len(image_data) - APPLICATION_FINGERPRINT_POSITION_FROM_END


def validate_application_fingerprint_placeholder(image_data):
    fingerprint_start = application_fingerprint_start(image_data)
    if any(image_data[fingerprint_start:]):
        raise ValueError("application fingerprint placeholder is not zero")


def cohort_fingerprint(cohort_hash):
    if len(cohort_hash) < BUILD_FINGERPRINT_SIZE:
        raise ValueError("cohort hash is too short for a 64-bit fingerprint")
    fingerprint = cohort_hash[:BUILD_FINGERPRINT_SIZE]
    if not any(fingerprint):
        raise ValueError("cohort fingerprint cannot be all zero")
    return fingerprint


def stamp_application_fingerprint(image_data, cohort_hash):
    """Stamp the final in-image placeholder with the raw cohort-hash prefix."""
    image_data = bytearray(image_data)
    validate_application_fingerprint_placeholder(image_data)
    fingerprint_start = application_fingerprint_start(image_data)
    image_data[fingerprint_start:] = cohort_fingerprint(cohort_hash)
    return image_data


def stamp_application_binary(binary_dir, cohort_hash):
    application_path = os.path.join(binary_dir, "application.bin")
    stamped_image = stamp_application_fingerprint(
        read_image(application_path), cohort_hash
    )
    write_image_atomic(stamped_image, application_path)


def update_cohort_hash(digest, name, payload):
    """Add one unambiguous, length-framed component to the cohort hash."""
    encoded_name = name.encode("utf-8")
    digest.update(struct.pack("<I", len(encoded_name)))
    digest.update(encoded_name)
    digest.update(struct.pack("<Q", len(payload)))
    digest.update(payload)


def derive_cohort_hash(
    application_image,
    baseband_image,
    prepared_external_apps,
    packaging_inputs,
):
    """Cover the exact firmware and zero-fingerprint deployable app bodies."""
    validate_application_fingerprint_placeholder(application_image)

    digest = hashlib.sha1()
    digest.update(COHORT_HASH_DOMAIN)
    update_cohort_hash(digest, "application-bin-zero-slot", application_image)
    # External apps may request built-in SPI basebands that are not appended to
    # their PPMA body, so the exact aggregate baseband image is part of the
    # compatibility cohort too.
    update_cohort_hash(digest, "baseband-img", baseband_image)
    for name in sorted(packaging_inputs):
        update_cohort_hash(digest, f"packaging:{name}", packaging_inputs[name])
    for app_name in sorted(prepared_external_apps):
        app_image = prepared_external_apps[app_name]
        fingerprint_end = BUILD_FINGERPRINT_HEADER_POSITION + BUILD_FINGERPRINT_SIZE
        if len(app_image) < APPLICATION_HEADER_SIZE:
            raise ValueError(f"application {app_name} has a truncated header")
        if any(app_image[BUILD_FINGERPRINT_HEADER_POSITION:fingerprint_end]):
            raise ValueError(f"application {app_name} fingerprint placeholder is not zero")
        update_cohort_hash(digest, f"ppma-body:{app_name}", app_image)
    cohort_hash = digest.digest()
    cohort_fingerprint(cohort_hash)
    return cohort_hash


def packaging_source_inputs(project_source_dir=None, precision_rx_segmented=False):
    if not precision_rx_segmented:
        # P12-feature-OFF is a byte-compatibility profile. Feed the exact P11
        # exporter/info source bytes into the unchanged cohort algorithm.
        from prxq0011_cohort_inputs import packaging_source_inputs as p11_inputs

        return p11_inputs()

    tools_directory = os.path.dirname(os.path.abspath(__file__))
    inputs = {
        "export_external_apps.py": read_image(__file__),
        "external_app_info.py": read_image(
            os.path.join(tools_directory, "external_app_info.py")
        ),
    }
    if precision_rx_segmented:
        if project_source_dir is None:
            raise ValueError("segmented Precision RX packaging requires the project source directory")
        inputs["precision_rx_segmented.ld"] = read_image(
            os.path.join(
                project_source_dir,
                "application",
                "external",
                "precision_rx_segmented.ld",
            )
        )
        inputs["precision_rx_segmented_geometry.cmake"] = read_image(
            os.path.join(
                project_source_dir,
                "application",
                "external",
                "precision_rx_segmented_geometry.cmake",
            )
        )
        inputs["precision_rx_segmented_geometry.hpp.in"] = read_image(
            os.path.join(
                project_source_dir,
                "application",
                "precision_rx_segmented_geometry.hpp.in",
            )
        )
    return inputs


def patch_image_mappings(path, image_data, mappings, include_mapping_bases=True):
    """Relocate aligned absolute words under disjoint [start, start+size) maps."""
    image_data = bytearray(image_data)
    if len(image_data) % 4:
        padding_size = 4 - (len(image_data) % 4)
        print(
            "External App image file:",
            path,
            "size is not divisible by 4; padding by",
            padding_size,
            "bytes",
        )
        image_data.extend(b"\x00" * padding_size)

    ordered_mappings = sorted(mappings)
    for index, (search_address, _replace_address, mapping_size) in enumerate(
        ordered_mappings
    ):
        if mapping_size <= 0:
            raise ValueError("External app relocation mapping must be non-empty")
        if index != 0:
            previous_address, _previous_replace, previous_size = ordered_mappings[
                index - 1
            ]
            if search_address < previous_address + previous_size:
                raise ValueError("External app relocation mappings overlap")

    external_application_image = bytearray()
    for offset in range(0, len(image_data), 4):
        snippet = image_data[offset:offset + 4]
        value = int.from_bytes(snippet, byteorder="little")

        relocated_value = None
        for search_address, replace_address, mapping_size in ordered_mappings:
            lower_bound_matches = (
                value >= search_address
                if include_mapping_bases
                else value > search_address
            )
            if lower_bound_matches and value < search_address + mapping_size:
                relative_address = value - search_address
                relocated_value = replace_address + relative_address
                break

        if relocated_value is None:
            external_application_image.extend(snippet)
            if (
                external_apps_address_start <= value < external_apps_address_end
                and (value & 0xFFFF) < maximum_application_size
            ):
                print(
                    "WARNING: External code address",
                    hex(value),
                    "at offset",
                    hex(offset),
                    "in",
                    path,
                )
        else:
            external_application_image.extend(
                relocated_value.to_bytes(4, byteorder="little")
            )

    return external_application_image


def patch_image(path, image_data, search_address, replace_address):
    # Legacy compatibility wrapper: external.ld gives every app one fake,
    # non-overlapping 32 KiB window.
    return patch_image_mappings(
        path,
        image_data,
        [(search_address, replace_address, maximum_application_size)],
        include_mapping_bases=False,
    )


def additive_checksum_word(image_data):
    if len(image_data) % 4:
        raise ValueError("External app image is not 32-bit aligned")

    checksum = sum(
        struct.unpack_from("<I", image_data, offset)[0]
        for offset in range(0, len(image_data), 4)
    )
    return (-checksum) & 0xFFFFFFFF


def make_precision_rx_segmented_trailer(
    main_size,
    m4_size,
    aux0_size,
    aux1_size,
):
    image_size = main_size + m4_size + aux0_size + aux1_size
    return PRECISION_RX_SEGMENTED_TRAILER.pack(
        PRECISION_RX_SEGMENTED_TRAILER_MAGIC,
        PRECISION_RX_SEGMENTED_TRAILER_VERSION,
        PRECISION_RX_SEGMENTED_TRAILER.size,
        main_size,
        m4_size,
        aux0_size,
        precision_rx_aux0_load_address,
        aux1_size,
        precision_rx_aux1_load_address,
        image_size,
        0,
    )


def decode_precision_rx_segmented_trailer(image_data):
    if len(image_data) < PRECISION_RX_SEGMENTED_TRAILER.size:
        return None
    values = PRECISION_RX_SEGMENTED_TRAILER.unpack_from(
        image_data, len(image_data) - PRECISION_RX_SEGMENTED_TRAILER.size
    )
    (
        magic,
        version,
        trailer_size,
        main_size,
        m4_size,
        aux0_size,
        aux0_load_address,
        aux1_size,
        aux1_load_address,
        image_size,
        reserved,
    ) = values
    if (
        magic != PRECISION_RX_SEGMENTED_TRAILER_MAGIC
        or version != PRECISION_RX_SEGMENTED_TRAILER_VERSION
        or trailer_size != PRECISION_RX_SEGMENTED_TRAILER.size
        or reserved != 0
    ):
        return None
    if image_size != len(image_data) - PRECISION_RX_SEGMENTED_TRAILER.size:
        return None
    if main_size + m4_size + aux0_size + aux1_size != image_size:
        return None
    if (
        main_size < APPLICATION_HEADER_SIZE
        or main_size & 3
        or m4_size == 0
        or m4_size & 3
        or aux0_size == 0
        or aux0_size & 3
        or aux1_size == 0
        or aux1_size & 3
    ):
        return None
    if main_size + m4_size > maximum_application_size:
        return None
    if aux0_size > precision_rx_aux0_maximum_size:
        return None
    if aux0_load_address != precision_rx_aux0_load_address:
        return None
    if aux1_size > precision_rx_aux1_maximum_size:
        return None
    if aux1_load_address != precision_rx_aux1_load_address:
        return None
    return {
        "main_size": main_size,
        "m4_size": m4_size,
        "aux0_size": aux0_size,
        "aux0_load_address": aux0_load_address,
        "aux1_size": aux1_size,
        "aux1_load_address": aux1_load_address,
        "image_size": image_size,
    }


def stamp_fingerprint_and_checksum(
    image_data,
    cohort_hash,
    app_name,
    maximum_file_size=maximum_application_size,
):
    image_data = bytearray(image_data)
    if len(image_data) < APPLICATION_HEADER_SIZE:
        raise ValueError(f"application {app_name} has a truncated header")

    header_version = struct.unpack_from("<I", image_data, HEADER_VERSION_POSITION)[0]
    if header_version != CURRENT_HEADER_VERSION:
        raise ValueError(
            f"application {app_name} has header version {header_version}, expected {CURRENT_HEADER_VERSION}"
        )

    fingerprint_end = BUILD_FINGERPRINT_HEADER_POSITION + BUILD_FINGERPRINT_SIZE
    if any(image_data[BUILD_FINGERPRINT_HEADER_POSITION:fingerprint_end]):
        raise ValueError(f"application {app_name} fingerprint placeholder is not zero")
    image_data[BUILD_FINGERPRINT_HEADER_POSITION:fingerprint_end] = cohort_fingerprint(cohort_hash)

    final_size = len(image_data) + CHECKSUM_SIZE
    if final_size > maximum_file_size:
        limit_kib = maximum_file_size // 1024
        raise ValueError(
            f"application {app_name} cannot exceed {limit_kib} KiB: {final_size} bytes used"
        )

    image_data.extend(additive_checksum_word(image_data).to_bytes(4, "little"))
    if additive_checksum_word(image_data) != 0:
        raise AssertionError("External app additive checksum did not close to zero")
    return image_data


def extract_elf_section(binary_dir, cmake_objcopy, section_name, output_name):
    application_elf = os.path.join(binary_dir, "application.elf")
    himg = os.path.join(binary_dir, output_name)
    print(f"Extracting application ELF section {section_name}")
    subprocess.run(
        [
            cmake_objcopy,
            "-v",
            "-O",
            "binary",
            f"--only-section={section_name}",
            application_elf,
            himg,
        ],
        check=True,
    )
    return read_image(himg)


def extract_external_app(binary_dir, cmake_objcopy, external_image_prefix):
    external_application_image = extract_elf_section(
        binary_dir,
        cmake_objcopy,
        f".external_app_{external_image_prefix}",
        f"external_app_{external_image_prefix}.himg",
    )
    if len(external_application_image) < APPLICATION_HEADER_SIZE:
        raise ValueError(f"application {external_image_prefix} has a truncated header")
    return external_application_image


def extract_precision_rx_aux(
    binary_dir,
    cmake_objcopy,
    section_name,
    output_name,
    maximum_size,
):
    aux_image = extract_elf_section(
        binary_dir,
        cmake_objcopy,
        section_name,
        output_name,
    )
    if len(aux_image) == 0:
        raise ValueError(f"Precision RX auxiliary image {section_name} is empty")
    if len(aux_image) > maximum_size:
        raise ValueError(
            f"Precision RX auxiliary image {section_name} exceeds "
            f"{maximum_size} bytes"
        )
    if len(aux_image) % 4:
        raise ValueError(
            f"Precision RX auxiliary image {section_name} size is not divisible by 4"
        )
    return aux_image


def decode_m4_tag(external_application_image, external_image_prefix):
    chunk_data = external_application_image[
        M4_APP_TAG_HEADER_POSITION:M4_APP_TAG_HEADER_POSITION + 4
    ]
    if chunk_data == b"\0\0\0\0":
        return None
    try:
        return chunk_data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(
            f"application {external_image_prefix} has an invalid M4 image tag"
        ) from error


def collect_external_app_inputs(
    binary_dir,
    cmake_objcopy,
    external_apps,
    precision_rx_segmented=False,
):
    external_images = {}
    m4_payloads = {}
    for external_app in external_apps:
        external_image = extract_external_app(
            binary_dir, cmake_objcopy, external_app
        )
        external_images[external_app] = external_image
        chunk_tag = decode_m4_tag(external_image, external_app)
        if chunk_tag is None or chunk_tag in m4_payloads:
            continue

        m4_path = os.path.join(binary_dir, "..", "baseband", f"{chunk_tag}.bin")
        m4_image = read_image(m4_path)
        if len(m4_image) % 4:
            raise ValueError(f"M4 image {chunk_tag} size is not divisible by 4")
        m4_payloads[chunk_tag] = m4_image

    precision_rx_aux_images = None
    if precision_rx_segmented:
        if PRECISION_RX_APP_NAME not in external_images:
            raise ValueError("segmented Precision RX packaging requires precision_rx")
        precision_rx_aux_images = (
            extract_precision_rx_aux(
                binary_dir,
                cmake_objcopy,
                PRECISION_RX_AUX0_SECTION,
                "external_app_precision_rx_aux0.himg",
                precision_rx_aux0_maximum_size,
            ),
            extract_precision_rx_aux(
                binary_dir,
                cmake_objcopy,
                PRECISION_RX_AUX1_SECTION,
                "external_app_precision_rx_aux1.himg",
                precision_rx_aux1_maximum_size,
            ),
        )
    return external_images, m4_payloads, precision_rx_aux_images


def prepare_external_app(
    binary_dir,
    external_image_prefix,
    external_application_image,
    m4_payloads,
    precision_rx_aux_images=None,
):
    himg = os.path.join(binary_dir, f"external_app_{external_image_prefix}.himg")
    print(f"Creating external application image for {external_image_prefix}")

    chunk_tag = decode_m4_tag(external_application_image, external_image_prefix)
    entry_address = int.from_bytes(
        external_application_image[
            EXTERNAL_APP_ENTRY_HEADER_POSITION:EXTERNAL_APP_ENTRY_HEADER_POSITION + 4
        ],
        byteorder="little",
    )
    search_address = entry_address & 0xFFFF0000

    if (
        external_image_prefix == PRECISION_RX_APP_NAME
        and precision_rx_aux_images is not None
    ):
        if chunk_tag != PRECISION_RX_M4_TAG:
            raise ValueError(
                f"segmented Precision RX requires M4 tag {PRECISION_RX_M4_TAG}"
            )
        m4_image = m4_payloads[chunk_tag]
        main_size = len(external_application_image)
        m4_size = len(m4_image)
        aux0_image, aux1_image = precision_rx_aux_images
        aux0_size = len(aux0_image)
        aux1_size = len(aux1_image)
        if main_size % 4:
            raise ValueError("Precision RX main image size is not divisible by 4")
        if main_size + m4_size > maximum_application_size:
            raise ValueError(
                "Precision RX M0 main plus M4 image exceeds the 32 KiB code window: "
                f"{main_size + m4_size} bytes used"
            )

        replace_address = 0x10080000 + m4_size
        mappings = [
            (search_address, replace_address, maximum_application_size),
            (
                precision_rx_aux0_fake_address,
                precision_rx_aux0_load_address,
                precision_rx_aux0_maximum_size,
            ),
            (
                precision_rx_aux1_fake_address,
                precision_rx_aux1_load_address,
                precision_rx_aux1_maximum_size,
            ),
        ]
        relocated_main = patch_image_mappings(
            himg,
            external_application_image,
            mappings,
        )
        relocated_aux0 = patch_image_mappings(
            os.path.join(binary_dir, "external_app_precision_rx_aux0.himg"),
            aux0_image,
            mappings,
        )
        relocated_aux1 = patch_image_mappings(
            os.path.join(binary_dir, "external_app_precision_rx_aux1.himg"),
            aux1_image,
            mappings,
        )
        relocated_main[
            M4_APP_OFFSET_HEADER_POSITION:M4_APP_OFFSET_HEADER_POSITION + 4
        ] = main_size.to_bytes(4, byteorder="little")
        relocated_main[
            MEMORY_LOCATION_HEADER_POSITION:MEMORY_LOCATION_HEADER_POSITION + 4
        ] = replace_address.to_bytes(4, byteorder="little")

        trailer = make_precision_rx_segmented_trailer(
            main_size,
            m4_size,
            aux0_size,
            aux1_size,
        )
        segmented_image = (
            relocated_main + m4_image + relocated_aux0 + relocated_aux1 + trailer
        )
        if decode_precision_rx_segmented_trailer(segmented_image) is None:
            raise AssertionError("Precision RX segmented trailer failed self-validation")
        return segmented_image

    if chunk_tag is None:
        replace_address = 0x10080000
        external_application_image = patch_image(
            himg, external_application_image, search_address, replace_address
        )
    else:
        m4_image = m4_payloads[chunk_tag]

        app_image_len = len(external_application_image)
        external_application_image += m4_image
        replace_address = 0x10080000 + len(m4_image)
        external_application_image = patch_image(
            himg, external_application_image, search_address, replace_address
        )
        external_application_image[
            M4_APP_OFFSET_HEADER_POSITION:M4_APP_OFFSET_HEADER_POSITION + 4
        ] = app_image_len.to_bytes(4, byteorder="little")

    external_application_image[
        MEMORY_LOCATION_HEADER_POSITION:MEMORY_LOCATION_HEADER_POSITION + 4
    ] = replace_address.to_bytes(4, byteorder="little")

    return external_application_image


def export_external_app(
    binary_dir,
    external_image_prefix,
    cohort_hash,
    prepared_external_application,
):
    print(f"Writing external application image for {external_image_prefix}")

    maximum_file_size = maximum_application_size
    if external_image_prefix == PRECISION_RX_APP_NAME:
        trailer = decode_precision_rx_segmented_trailer(
            prepared_external_application
        )
        if trailer is not None:
            encoded_m4_offset = struct.unpack_from(
                "<I",
                prepared_external_application,
                M4_APP_OFFSET_HEADER_POSITION,
            )[0]
            if encoded_m4_offset != trailer["main_size"]:
                raise ValueError(
                    "Precision RX segmented main size does not match m4_app_offset"
                )
            maximum_file_size = precision_rx_segmented_maximum_file_size

    # The cohort hash was derived from this exact relocated, M4-appended body
    # while its fingerprint bytes were zero. Stamp only after that pass.
    external_application_image = stamp_fingerprint_and_checksum(
        prepared_external_application,
        cohort_hash,
        external_image_prefix,
        maximum_file_size=maximum_file_size,
    )
    write_image_atomic(
        external_application_image,
        os.path.join(binary_dir, f"{external_image_prefix}.ppma"),
    )


def parse_external_app_arguments(external_apps):
    external_apps = list(external_apps)
    precision_rx_segmented = False
    if external_apps and external_apps[0] == SEGMENTED_PRECISION_RX_FLAG:
        precision_rx_segmented = True
        external_apps = external_apps[1:]
    if SEGMENTED_PRECISION_RX_FLAG in external_apps:
        raise ValueError(
            f"{SEGMENTED_PRECISION_RX_FLAG} must precede the external app list"
        )
    if not external_apps:
        raise ValueError("external app list is empty")
    return precision_rx_segmented, external_apps


def main(argv=None):
    argv = sys.argv if argv is None else argv
    if len(argv) < 5:
        print(usage_message)
        return 2

    (
        _,
        project_source_dir,
        binary_dir,
        cmake_objcopy,
        baseband_image_path,
        *external_apps,
    ) = argv
    try:
        precision_rx_segmented, external_apps = parse_external_app_arguments(
            external_apps
        )

        application_image = read_image(os.path.join(binary_dir, "application.bin"))
        baseband_image = read_image(baseband_image_path)
        validate_application_fingerprint_placeholder(application_image)
        external_images, m4_payloads, precision_rx_aux_images = collect_external_app_inputs(
            binary_dir,
            cmake_objcopy,
            external_apps,
            precision_rx_segmented=precision_rx_segmented,
        )
        prepared_external_apps = {
            external_app: prepare_external_app(
                binary_dir,
                external_app,
                external_images[external_app],
                m4_payloads,
                precision_rx_aux_images=(
                    precision_rx_aux_images
                    if external_app == PRECISION_RX_APP_NAME
                    else None
                ),
            )
            for external_app in external_apps
        }
        cohort_hash = derive_cohort_hash(
            application_image,
            baseband_image,
            prepared_external_apps,
            packaging_source_inputs(
                project_source_dir,
                precision_rx_segmented=precision_rx_segmented,
            ),
        )
        for external_app in external_apps:
            export_external_app(
                binary_dir,
                external_app,
                cohort_hash,
                prepared_external_apps[external_app],
            )
        stamp_application_binary(binary_dir, cohort_hash)
        print(
            "External app cohort fingerprint: "
            f"{cohort_hash[:BUILD_FINGERPRINT_SIZE].hex()}"
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
