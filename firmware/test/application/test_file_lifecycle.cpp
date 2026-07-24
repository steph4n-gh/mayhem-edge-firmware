/*
 * Copyright (C) 2026 HackRF Edge contributors.
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

#include "doctest.h"
#include "fatfs_test_fixture.hpp"
#include "file.hpp"

#include <array>
#include <initializer_list>
#include <string>

namespace {

constexpr auto capture_pattern =
    u"/CAPTURES/PRX_20260724T120000_??.*";

void check_calls(
    const std::initializer_list<fatfs_test::Call> expected) {
    const auto& actual = fatfs_test::state().calls;
    REQUIRE(actual.size() == expected.size());
    size_t index = 0;
    for (const auto call : expected) {
        CHECK(actual[index] == call);
        ++index;
    }
}

} /* namespace */

TEST_SUITE_BEGIN("File lifecycle");

TEST_CASE("result-suffix allocator starts at zero in an empty directory") {
    fatfs_test::reset();

    const auto path = next_filename_matching_pattern(
        capture_pattern,
        u".C8");

    CHECK(path == std::filesystem::path{
                      u"/CAPTURES/PRX_20260724T120000_00.C8"});
    CHECK(fatfs_test::state().find_path == u"/CAPTURES");
    CHECK(
        fatfs_test::state().find_pattern ==
        u"PRX_20260724T120000_??.*");
}

TEST_CASE("every Precision RX artifact suffix reserves its ordinal") {
    const std::array<const char16_t*, 6> artifact_suffixes{{
        u".C8",
        u".SHORT.C8",
        u".STOP.C8",
        u".LOSS.C8",
        u".PRX",
        u".C8.PART",
    }};

    for (const auto* const suffix : artifact_suffixes) {
        fatfs_test::reset();
        fatfs_test::state().directory_entries = {
            std::u16string{u"PRX_20260724T120000_00"} + suffix};

        const auto path = next_filename_matching_pattern(
            capture_pattern,
            u".C8");

        CHECK(path == std::filesystem::path{
                          u"/CAPTURES/PRX_20260724T120000_01.C8"});
    }
}

TEST_CASE("mixed terminal artifacts advance past the greatest ordinal") {
    fatfs_test::reset();
    fatfs_test::state().directory_entries = {
        u"PRX_20260724T120000_03.STOP.C8",
        u"PRX_20260724T120000_01.SHORT.C8",
        u"PRX_20260724T120000_04.C8.PART",
        u"PRX_20260724T120000_02.LOSS.C8",
        u"PRX_20260724T120000_00.C8",
        u"PRX_20260724T120000_04.PRX",
    };

    const auto path = next_filename_matching_pattern(
        capture_pattern,
        u".C8");

    CHECK(path == std::filesystem::path{
                      u"/CAPTURES/PRX_20260724T120000_05.C8"});
}

TEST_CASE("exhausted result-suffix ordinal returns an empty path") {
    fatfs_test::reset();
    fatfs_test::state().directory_entries = {
        u"PRX_20260724T120000_99.LOSS.C8"};

    const auto path = next_filename_matching_pattern(
        capture_pattern,
        u".C8");

    CHECK(path.empty());
}

TEST_CASE("result-suffix allocator rejects a pattern without an ordinal") {
    fatfs_test::reset();

    const auto path = next_filename_matching_pattern(
        u"/CAPTURES/PRX_FIXED.*",
        u".C8");

    CHECK(path.empty());
    CHECK(fatfs_test::state().calls.empty());
}

TEST_CASE("finish_new_file syncs and closes a complete file") {
    fatfs_test::reset();
    File file;

    const bool complete = finish_new_file(
        file,
        u"/CAPTURES/PRX_00.PRX",
        true);

    CHECK(complete);
    check_calls({
        fatfs_test::Call::Sync,
        fatfs_test::Call::Close});
    CHECK(fatfs_test::state().unlinked_paths.empty());
}

TEST_CASE("finish_new_file closes and removes incomplete contents") {
    fatfs_test::reset();
    File file;

    const bool complete = finish_new_file(
        file,
        u"/CAPTURES/PRX_00.PRX",
        false);

    CHECK_FALSE(complete);
    check_calls({
        fatfs_test::Call::Close,
        fatfs_test::Call::Unlink});
    REQUIRE(fatfs_test::state().unlinked_paths.size() == 1);
    CHECK(
        fatfs_test::state().unlinked_paths.front() ==
        u"/CAPTURES/PRX_00.PRX");
}

TEST_CASE("finish_new_file removes contents after a sync failure") {
    fatfs_test::reset();
    fatfs_test::state().sync_result = FR_DISK_ERR;
    File file;

    const bool complete = finish_new_file(
        file,
        u"/CAPTURES/PRX_00.PRX",
        true);

    CHECK_FALSE(complete);
    check_calls({
        fatfs_test::Call::Sync,
        fatfs_test::Call::Close,
        fatfs_test::Call::Unlink});
    REQUIRE(fatfs_test::state().unlinked_paths.size() == 1);
    CHECK(
        fatfs_test::state().unlinked_paths.front() ==
        u"/CAPTURES/PRX_00.PRX");
}

TEST_CASE("rename_file forwards paths and FatFS failures") {
    fatfs_test::reset();
    const std::filesystem::path work_path{
        u"/CAPTURES/PRX_00.C8.PART"};
    const std::filesystem::path final_path{
        u"/CAPTURES/PRX_00.SHORT.C8"};

    CHECK(rename_file(work_path, final_path).ok());
    check_calls({fatfs_test::Call::Rename});
    REQUIRE(fatfs_test::state().rename_calls.size() == 1);
    CHECK(
        fatfs_test::state().rename_calls.front().from ==
        work_path.native());
    CHECK(
        fatfs_test::state().rename_calls.front().to ==
        final_path.native());

    fatfs_test::reset();
    fatfs_test::state().rename_result = FR_DISK_ERR;
    const auto error = rename_file(work_path, final_path);
    CHECK_FALSE(error.ok());
    CHECK(error.code() == FR_DISK_ERR);
    check_calls({fatfs_test::Call::Rename});
}

TEST_SUITE_END();
