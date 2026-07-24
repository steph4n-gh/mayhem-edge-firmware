/*
 * Copyright (C) 2023 Bernd Herzog
 *
 * This file is part of PortaPack.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef __EXTERNAL_APPS_H__
#define __EXTERNAL_APPS_H__

#include "ch.h"
#include "ui_navigation.hpp"
#include "spi_image.hpp"
#include "standalone_app.hpp"

#include <cstddef>
#include <cstdint>

#define CURRENT_HEADER_VERSION 0x00000004
#define MIN_HEADER_VERSION_FOR_CHECKSUM 0x00000002

constexpr size_t EXTERNAL_APP_MAX_FILE_SIZE = 32 * 1024;
constexpr size_t EXTERNAL_APP_CHECKSUM_SIZE = sizeof(uint32_t);

struct external_app_fingerprint_t {
    uint32_t words[2];
};

static_assert(sizeof(external_app_fingerprint_t) == 8, "External app fingerprint must be 64 bits");

extern "C" const external_app_fingerprint_t __external_app_build_fingerprint;

typedef void (*externalAppEntry_t)(ui::NavigationView& nav);

struct application_information_t {
    uint8_t* memory_location;
    externalAppEntry_t externalAppEntry;
    uint32_t header_version;
    external_app_fingerprint_t build_fingerprint;

    uint8_t app_name[16];
    uint8_t bitmap_data[32];
    uint32_t icon_color;
    app_location_t menu_location;
    int32_t desired_menu_position;

    portapack::spi_flash::image_tag_t m4_app_tag;
    uint32_t m4_app_offset;
};

inline bool external_app_fingerprint_matches(
    const external_app_fingerprint_t& candidate,
    const external_app_fingerprint_t& expected) {
    const auto expected_bits = expected.words[0] | expected.words[1];
    // Equality with a non-zero expected value also proves that the candidate
    // is non-zero, so a second OR reduction is redundant.
    return expected_bits != 0 &&
           ((candidate.words[0] ^ expected.words[0]) |
            (candidate.words[1] ^ expected.words[1])) == 0;
}

inline bool external_app_is_compatible(const application_information_t& application_information) {
    return application_information.header_version == CURRENT_HEADER_VERSION &&
           external_app_fingerprint_matches(
               application_information.build_fingerprint,
               __external_app_build_fingerprint);
}

#if UINTPTR_MAX == UINT32_MAX
static_assert(offsetof(application_information_t, header_version) == 8, "Unexpected PPMA header layout");
static_assert(offsetof(application_information_t, build_fingerprint) == 12, "Unexpected PPMA fingerprint offset");
static_assert(offsetof(application_information_t, m4_app_tag) == 80, "Unexpected PPMA M4 tag offset");
static_assert(offsetof(application_information_t, m4_app_offset) == 84, "Unexpected PPMA M4 offset offset");
static_assert(sizeof(application_information_t) == 88, "Unexpected PPMA header size");
#endif

#endif /*__EXTERNAL_APPS_H__*/
