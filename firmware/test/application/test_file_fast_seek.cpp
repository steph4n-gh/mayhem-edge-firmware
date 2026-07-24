/*
 * Copyright (C) 2026 HackRF Edge contributors
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
 */

#include "doctest.h"
#include "file.hpp"

#include <array>

TEST_SUITE_BEGIN("Bounded FatFs fast seek");

TEST_CASE("a bounded multi-fragment CLMT is structurally valid") {
    const std::array<DWORD, 8> table{{
        6U, 3U, 2U, 5U, 20U, 0U, 0U, 0U}};

    CHECK(file_detail::bounded_fast_seek_table_valid(
        table.data(), table.size()));
}

TEST_CASE("malformed bounded CLMTs fail closed") {
    const std::array<DWORD, 8> valid{{
        6U, 3U, 2U, 5U, 20U, 0U, 0U, 0U}};

    auto too_short = valid;
    too_short[0] = 2U;
    CHECK_FALSE(file_detail::bounded_fast_seek_table_valid(
        too_short.data(), too_short.size()));

    auto odd_used_count = valid;
    odd_used_count[0] = 5U;
    CHECK_FALSE(file_detail::bounded_fast_seek_table_valid(
        odd_used_count.data(), odd_used_count.size()));

    auto missing_terminator = valid;
    missing_terminator[5] = 1U;
    CHECK_FALSE(file_detail::bounded_fast_seek_table_valid(
        missing_terminator.data(), missing_terminator.size()));

    auto zero_length_fragment = valid;
    zero_length_fragment[3] = 0U;
    CHECK_FALSE(file_detail::bounded_fast_seek_table_valid(
        zero_length_fragment.data(), zero_length_fragment.size()));

    auto invalid_first_cluster = valid;
    invalid_first_cluster[4] = 1U;
    CHECK_FALSE(file_detail::bounded_fast_seek_table_valid(
        invalid_first_cluster.data(), invalid_first_cluster.size()));

    CHECK_FALSE(file_detail::bounded_fast_seek_table_valid(nullptr, 8U));
    CHECK_FALSE(file_detail::bounded_fast_seek_table_valid(
        valid.data(), 3U));
}

TEST_CASE("a CLMT reporting more entries than its capacity fails closed") {
    const std::array<DWORD, 4> table{{6U, 3U, 2U, 0U}};

    CHECK_FALSE(file_detail::bounded_fast_seek_table_valid(
        table.data(), table.size()));
}

TEST_SUITE_END();
