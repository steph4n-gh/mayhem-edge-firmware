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
#include "../../application/external/precision_rx/precision_rx_capture_writer.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace {

class FaultInjectingFile {
   public:
    using Error = File::Error;
    using Offset = File::Offset;
    using Size = File::Size;

    template <typename T>
    using Result = File::Result<T>;

    Optional<Error> create_new(const std::filesystem::path&) {
        ++create_calls;
        if (fail_create != FR_OK) {
            return Error{fail_create};
        }
        data.clear();
        offset = 0;
        return {};
    }

    Result<Offset> seek(const Offset new_offset) {
        ++seek_calls;
        if (sticky_error) {
            return Error{FR_DISK_ERR};
        }
        if (fail_seek_call != 0 && seek_calls == fail_seek_call) {
            sticky_error = true;
            return Error{FR_BAD_SEEK};
        }

        const auto previous = offset;
        if (new_offset > data.size()) {
            data.resize(static_cast<size_t>(new_offset));
        }
        offset = new_offset;
        if (cancel_after_seek_call != 0 &&
            seek_calls == cancel_after_seek_call && cancel_target) {
            *cancel_target = true;
        }
        return static_cast<Offset>(previous);
    }

    Optional<Error> enable_bounded_fast_seek(
        DWORD* const table,
        const size_t table_entries) {
        ++fast_seek_calls;
        fast_seek_table = table;
        fast_seek_table_entries = table_entries;
        if (fail_fast_seek != FR_OK) {
            return Error{fail_fast_seek};
        }
        if (!table || table_entries < 4U) {
            return Error{FR_INVALID_PARAMETER};
        }
        const size_t required_entries = 2U + 2U * fast_seek_fragments;
        table[0] = static_cast<DWORD>(required_entries);
        if (required_entries > table_entries) {
            return Error{FR_NOT_ENOUGH_CORE};
        }
        for (size_t fragment = 0; fragment < fast_seek_fragments; ++fragment) {
            table[1U + fragment * 2U] = 1U;
            table[2U + fragment * 2U] =
                static_cast<DWORD>(2U + fragment * 2U);
        }
        table[required_entries - 1U] = 0U;
        return {};
    }

    void disable_fast_seek() {
        ++disable_fast_seek_calls;
        fast_seek_table = nullptr;
    }

    Result<Offset> truncate() {
        ++truncate_calls;
        if (sticky_error) {
            return Error{FR_DISK_ERR};
        }
        if (fail_truncate_call != 0 && truncate_calls == fail_truncate_call) {
            return Error{FR_DISK_ERR};
        }

        data.resize(static_cast<size_t>(offset));
        return static_cast<Offset>(offset);
    }

    Result<Size> write(const void* source, const Size bytes) {
        ++write_calls;
        largest_write_size = std::max(largest_write_size, bytes);
        last_write_size = bytes;
        const bool fail_this_write =
            fail_write_call != 0 && write_calls == fail_write_call;
        const auto accepted = fail_this_write
                                  ? std::min(bytes, partial_write_error_bytes)
                                  : bytes;
        const auto new_offset = offset + accepted;
        if (new_offset > data.size()) {
            data.resize(static_cast<size_t>(new_offset));
        }
        std::memcpy(
            data.data() + static_cast<size_t>(offset),
            source,
            static_cast<size_t>(accepted));
        offset = new_offset;

        if (cancel_after_write_call != 0 &&
            write_calls == cancel_after_write_call && cancel_target) {
            *cancel_target = true;
        }

        if (fail_this_write) {
            sticky_error = true;
            return Error{fail_write_error};
        }
        return static_cast<Size>(accepted);
    }

    Optional<Error> sync() {
        ++sync_calls;
        if (fail_sync_call != 0 && sync_calls == fail_sync_call) {
            return Error{FR_DISK_ERR};
        }
        return {};
    }

    void clear_error() {
        ++clear_error_calls;
        sticky_error = false;
    }

    std::vector<uint8_t> data{};
    Offset offset{0};
    Size partial_write_error_bytes{0};
    FRESULT fail_create{FR_OK};
    FRESULT fail_write_error{FR_DISK_ERR};
    size_t fail_write_call{0};
    size_t cancel_after_write_call{0};
    size_t cancel_after_seek_call{0};
    bool volatile* cancel_target{nullptr};
    bool sticky_error{false};
    FRESULT fail_fast_seek{FR_OK};
    size_t fast_seek_fragments{1U};
    size_t fail_seek_call{0};
    size_t fail_truncate_call{0};
    size_t fail_sync_call{0};
    size_t create_calls{0};
    size_t seek_calls{0};
    size_t truncate_calls{0};
    size_t write_calls{0};
    size_t sync_calls{0};
    size_t clear_error_calls{0};
    size_t fast_seek_calls{0};
    size_t disable_fast_seek_calls{0};
    DWORD* fast_seek_table{nullptr};
    size_t fast_seek_table_entries{0};
    Size largest_write_size{0};
    Size last_write_size{0};
};

using TestWriter =
    ui::external_app::precision_rx::BasicPrecisionRxCaptureWriter<
        FaultInjectingFile,
        false>;
using FastTestWriter =
    ui::external_app::precision_rx::BasicPrecisionRxCaptureWriter<
        FaultInjectingFile,
        true>;

} /* namespace */

TEST_SUITE_BEGIN("Precision RX capture writer");

TEST_CASE("capture geometry separates the limit from an aligned guard reservation") {
    constexpr uint32_t sample_rate_hz = 1'000'000U;
    constexpr auto limit = precision_rx::capture_limit_bytes(sample_rate_hz);
    constexpr auto reserve = precision_rx::capture_reserve_bytes(sample_rate_hz);

    static_assert(
        precision_rx::capture_write_size == 8U * 1024U,
        "capture blocks must use one two-descriptor SD transaction");
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
    static_assert(
        precision_rx::capture_local_buffer_count == 9U &&
            precision_rx::capture_spill_buffer_count == 2U &&
            precision_rx::capture_buffer_count == 9U &&
            precision_rx::capture_total_buffer_count == 11U &&
            precision_rx::capture_stream_bytes == 72U * 1024U &&
            precision_rx::capture_spill_stream_bytes == 16U * 1024U &&
            precision_rx::capture_total_stream_bytes == 88U * 1024U,
        "p10 must bind nine M4 and two M0 transfer blocks");
#elif defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC)
    static_assert(
        precision_rx::capture_local_buffer_count == 8U &&
            precision_rx::capture_spill_buffer_count == 3U &&
            precision_rx::capture_buffer_count == 8U &&
            precision_rx::capture_total_buffer_count == 11U &&
            precision_rx::capture_stream_bytes == 64U * 1024U &&
            precision_rx::capture_spill_stream_bytes == 24U * 1024U &&
            precision_rx::capture_total_stream_bytes == 88U * 1024U,
        "p9 must append exactly three M0-owned transfer blocks");
#else
    static_assert(
        precision_rx::capture_local_buffer_count == 8U &&
            precision_rx::capture_spill_buffer_count == 0U &&
            precision_rx::capture_buffer_count == 8U &&
            precision_rx::capture_total_buffer_count == 8U &&
            precision_rx::capture_stream_bytes == 64U * 1024U &&
            precision_rx::capture_total_stream_bytes == 64U * 1024U,
        "normal builds must retain the reviewed 64 KiB pool");
#endif
    static_assert(precision_rx::capture_total_stream_bytes == 88U * 1024U ||
                      precision_rx::capture_total_stream_bytes == 64U * 1024U,
                  "capture pool must use a reviewed geometry");
    static_assert(limit == 32'000'000U, "16 seconds of complex8 data expected");
    static_assert(reserve >= 36'000'000U, "at least 18 seconds must be reserved");
    static_assert(
        reserve % precision_rx::capture_write_size == 0,
        "reservation must be write-block aligned");
    static_assert(
        reserve % precision_rx::capture_scrub_write_size == 0,
        "reservation must be scrub-write aligned");
    CHECK(reserve > limit);
    CHECK_EQ(reserve, 36'003'840U);
    CHECK_EQ(reserve / precision_rx::capture_scrub_write_size, 8'790);
    CHECK_EQ(
        precision_rx::capture_reserve_bytes(2'000'000U),
        72'007'680U);
    CHECK_EQ(
        precision_rx::capture_reserve_bytes(2'000'000U) /
            precision_rx::capture_scrub_write_size,
        17'580);
}

TEST_CASE("preparation diagnostics preserve stage, extended errors, and field bounds") {
    CHECK_EQ(
        precision_rx::capture_preparation_diagnostic(
            precision_rx::CapturePreparationStage::Map,
            FR_NOT_ENOUGH_CORE,
            258U),
        301'700'258U);
    CHECK_EQ(
        precision_rx::capture_preparation_diagnostic(
            precision_rx::CapturePreparationStage::Rewind,
            FR_BAD_SEEK),
        525'800'000U);
    CHECK_EQ(
        precision_rx::capture_preparation_diagnostic(
            precision_rx::CapturePreparationStage::Reserve,
            FR_UNEXPECTED,
            100'000U),
        225'999'999U);
}

TEST_CASE("create reserves and final sync truncates to wholly written data") {
    TestWriter writer{};
    const auto create_error = writer.create(u"/CAPTURES/TEST.C8", 32);
    REQUIRE_FALSE(create_error.is_valid());
    CHECK(writer.prepared());
    CHECK(
        writer.preparation_stage() ==
        precision_rx::CapturePreparationStage::None);
    CHECK_EQ(writer.file().data.size(), 32);
    CHECK_EQ(writer.file().offset, 0);
    CHECK_EQ(writer.file().sync_calls, 1);
    CHECK_EQ(writer.bytes_written(), 0);
    CHECK(std::all_of(
        writer.file().data.begin(),
        writer.file().data.end(),
        [](uint8_t byte) { return byte == 0; }));

    const uint8_t payload[]{1, 2, 3, 4};
    const auto write_result = writer.write(payload, sizeof(payload));
    REQUIRE(write_result.is_ok());
    CHECK_EQ(write_result.value(), sizeof(payload));

    const auto sync_error = writer.sync();
    REQUIRE_FALSE(sync_error.is_valid());
    CHECK(writer.finalized());
    CHECK_EQ(writer.file().data.size(), sizeof(payload));
    CHECK_EQ(writer.file().sync_calls, 2);

    const auto second_sync_error = writer.sync();
    CHECK_FALSE(second_sync_error.is_valid());
    CHECK_EQ(writer.file().sync_calls, 2);
}

TEST_CASE("preallocation zero-fills through bounded multi-sector writes") {
    constexpr auto reserve =
        precision_rx::capture_scrub_write_size * 2U + 17U;
    static_assert(
        precision_rx::capture_scrub_write_size == 4U * 1024U,
        "preparation must not depend on a large temporary buffer");
    static_assert(
        precision_rx::preparation_thread_usable_stack_size == 6U * 1024U,
        "preparation worker needs 4 KiB scrub storage plus 2 KiB stack");
    static_assert(
        precision_rx::preparation_thread_working_area_size ==
            THD_WA_SIZE(precision_rx::preparation_thread_usable_stack_size),
        "working area must add ChibiOS thread overhead to usable stack");

    TestWriter writer{};
    const auto create_error =
        writer.create(u"/CAPTURES/TEST.C8.PART", reserve);

    REQUIRE_FALSE(create_error.is_valid());
    CHECK(writer.prepared());
    CHECK_EQ(writer.file().data.size(), reserve);
    CHECK_EQ(writer.file().write_calls, 3);
    CHECK_EQ(
        writer.file().largest_write_size,
        precision_rx::capture_scrub_write_size);
    CHECK_EQ(writer.file().last_write_size, 17);
    CHECK(std::all_of(
        writer.file().data.begin(),
        writer.file().data.end(),
        [](uint8_t byte) { return byte == 0; }));
}

TEST_CASE("metadata-only reservation avoids payload writes and enables bounded fast seek") {
    constexpr File::Size reserve = precision_rx::capture_write_size * 3U;
    FastTestWriter writer{};

    const auto create_error =
        writer.create(u"/CAPTURES/FAST.C8.PART", reserve);

    REQUIRE_FALSE(create_error.is_valid());
    CHECK(writer.prepared());
    CHECK_EQ(writer.file().data.size(), reserve);
    CHECK_EQ(writer.file().offset, 0);
    CHECK_EQ(writer.file().write_calls, 0);
    CHECK_EQ(writer.file().fast_seek_calls, 1);
    CHECK_EQ(writer.file().fast_seek_table_entries, 256);
    CHECK_NE(writer.file().fast_seek_table, nullptr);
    CHECK_EQ(writer.file().sync_calls, 1);
    CHECK_EQ(writer.file().seek_calls, 2);
}

TEST_CASE("bounded metadata-only reservation accepts multiple fragments") {
    FaultInjectingFile file{};
    file.fast_seek_fragments = 127U;
    FastTestWriter writer{std::move(file)};

    const auto create_error = writer.create(
        u"/CAPTURES/FRAGMENTED.C8.PART",
        precision_rx::capture_write_size * 3U);

    REQUIRE_FALSE(create_error.is_valid());
    CHECK(writer.prepared());
    CHECK_EQ(writer.file().fast_seek_calls, 1);
    CHECK_EQ(writer.file().fast_seek_table[0], 256U);
    CHECK_EQ(writer.file().fast_seek_table[255], 0U);
}

TEST_CASE("over-capacity metadata-only reservation fails closed and rolls back") {
    FaultInjectingFile file{};
    file.fast_seek_fragments = 128U;
    FastTestWriter writer{std::move(file)};

    const auto create_error = writer.create(
        u"/CAPTURES/FRAGMENTED.C8.PART",
        precision_rx::capture_write_size * 3U);

    REQUIRE(create_error.is_valid());
    CHECK_EQ(create_error->code(), FR_NOT_ENOUGH_CORE);
    CHECK(
        writer.preparation_stage() ==
        precision_rx::CapturePreparationStage::Map);
    CHECK_EQ(writer.preparation_detail(), 258U);
    CHECK_FALSE(writer.prepared());
    CHECK_EQ(writer.file().write_calls, 0);
    CHECK_EQ(writer.file().fast_seek_calls, 1);
    CHECK_EQ(writer.file().data.size(), 0);
    CHECK_EQ(writer.file().offset, 0);
    CHECK_EQ(writer.file().truncate_calls, 1);
    CHECK_EQ(writer.file().sync_calls, 1);
}

TEST_CASE("metadata-only sync failure rolls back the allocated extent") {
    FaultInjectingFile file{};
    file.fail_sync_call = 1;
    FastTestWriter writer{std::move(file)};

    const auto create_error = writer.create(
        u"/CAPTURES/SYNCFAIL.C8.PART",
        precision_rx::capture_write_size * 3U);

    REQUIRE(create_error.is_valid());
    CHECK_EQ(create_error->code(), FR_DISK_ERR);
    CHECK(
        writer.preparation_stage() ==
        precision_rx::CapturePreparationStage::Sync);
    CHECK_FALSE(writer.prepared());
    CHECK_EQ(writer.file().write_calls, 0);
    CHECK_EQ(writer.file().fast_seek_calls, 1);
    CHECK_EQ(writer.file().data.size(), 0);
    CHECK_EQ(writer.file().truncate_calls, 1);
    CHECK_EQ(writer.file().sync_calls, 2);
}

TEST_CASE("metadata-only rewind failure clears sticky state and rolls back") {
    FaultInjectingFile file{};
    file.fail_seek_call = 2;
    FastTestWriter writer{std::move(file)};

    const auto create_error = writer.create(
        u"/CAPTURES/REWINDFAIL.C8.PART",
        precision_rx::capture_write_size * 3U);

    REQUIRE(create_error.is_valid());
    CHECK_EQ(create_error->code(), FR_BAD_SEEK);
    CHECK(
        writer.preparation_stage() ==
        precision_rx::CapturePreparationStage::Rewind);
    CHECK_FALSE(writer.prepared());
    CHECK_FALSE(writer.file().sticky_error);
    CHECK_EQ(writer.file().write_calls, 0);
    CHECK_EQ(writer.file().fast_seek_calls, 1);
    CHECK_EQ(writer.file().data.size(), 0);
    CHECK_EQ(writer.file().offset, 0);
    CHECK_EQ(writer.file().clear_error_calls, 1);
    CHECK_EQ(writer.file().truncate_calls, 1);
    CHECK_EQ(writer.file().sync_calls, 2);
}

TEST_CASE("metadata-only cancellation after allocation rolls back without mapping") {
    bool volatile cancel_requested = false;
    FaultInjectingFile file{};
    file.cancel_after_seek_call = 1;
    file.cancel_target = &cancel_requested;
    FastTestWriter writer{std::move(file)};

    const auto create_error = writer.create(
        u"/CAPTURES/CANCEL.C8.PART",
        precision_rx::capture_write_size * 3U,
        &cancel_requested);

    REQUIRE_FALSE(create_error.is_valid());
    CHECK(writer.prepared());
    CHECK(writer.finalized());
    CHECK_EQ(writer.file().write_calls, 0);
    CHECK_EQ(writer.file().fast_seek_calls, 0);
    CHECK_EQ(writer.file().data.size(), 0);
    CHECK_EQ(writer.file().truncate_calls, 1);
    CHECK_EQ(writer.file().sync_calls, 1);
}

TEST_CASE("a partial failed write is discarded during finalization") {
    FaultInjectingFile file{};
    file.fail_write_call = 2;
    file.partial_write_error_bytes = 3;
    TestWriter writer{std::move(file)};
    REQUIRE_FALSE(writer.create(u"/CAPTURES/TEST.C8", 32).is_valid());

    const uint8_t payload[]{1, 2, 3, 4, 5, 6, 7, 8};
    const auto write_result = writer.write(payload, sizeof(payload));
    REQUIRE(write_result.is_error());
    CHECK_EQ(writer.bytes_written(), 0);
    CHECK_EQ(writer.file().offset, 3);

    const auto sync_error = writer.sync();
    REQUIRE_FALSE(sync_error.is_valid());
    CHECK_EQ(writer.file().data.size(), 0);
    CHECK_EQ(writer.file().clear_error_calls, 1);
}

TEST_CASE("a scrub write failure is rolled back without becoming prepared") {
    FaultInjectingFile file{};
    file.fail_write_call = 2;
    file.partial_write_error_bytes = 3;
    TestWriter writer{std::move(file)};

    const auto create_error = writer.create(
        u"/CAPTURES/TEST.C8.PART",
        precision_rx::capture_write_size + 32);
    REQUIRE(create_error.is_valid());
    CHECK_EQ(create_error->code(), FR_DISK_ERR);
    CHECK(
        writer.preparation_stage() ==
        precision_rx::CapturePreparationStage::Reserve);
    CHECK_EQ(writer.preparation_detail(), 1U);
    CHECK_FALSE(writer.prepared());
    CHECK_EQ(writer.bytes_written(), 0);
    CHECK_EQ(writer.file().data.size(), 0);
    CHECK_EQ(writer.file().clear_error_calls, 1);
    CHECK_EQ(writer.file().write_calls, 2);
}

TEST_CASE("preparation cancellation between scrub blocks rolls back the extent") {
    bool volatile cancel_requested = false;
    FaultInjectingFile file{};
    file.cancel_after_write_call = 1;
    file.cancel_target = &cancel_requested;
    TestWriter writer{std::move(file)};

    const auto create_error = writer.create(
        u"/CAPTURES/TEST.C8.PART",
        precision_rx::capture_write_size + 32,
        &cancel_requested);
    REQUIRE_FALSE(create_error.is_valid());
    CHECK(writer.prepared());
    CHECK(writer.finalized());
    CHECK_EQ(writer.bytes_written(), 0);
    CHECK_EQ(writer.file().data.size(), 0);
    CHECK_EQ(writer.file().write_calls, 1);
}

TEST_CASE("exclusive create failure preserves an existing orphan") {
    FaultInjectingFile file{};
    file.data = {9, 8, 7, 6};
    file.offset = file.data.size();
    file.fail_create = FR_EXIST;
    TestWriter writer{std::move(file)};

    const auto create_error = writer.create(
        u"/CAPTURES/EXISTING.C8.PART",
        precision_rx::capture_write_size);
    REQUIRE(create_error.is_valid());
    CHECK_EQ(create_error->code(), FR_EXIST);
    CHECK(
        writer.preparation_stage() ==
        precision_rx::CapturePreparationStage::Create);
    CHECK_EQ(writer.file().data, std::vector<uint8_t>({9, 8, 7, 6}));
    CHECK_EQ(writer.file().write_calls, 0);
    CHECK_EQ(writer.file().seek_calls, 0);
    CHECK_EQ(writer.file().truncate_calls, 0);
    CHECK_EQ(writer.file().sync_calls, 0);
}

TEST_CASE("cancellation reports a rollback sync failure and retains PART state") {
    bool volatile cancel_requested = false;
    FaultInjectingFile file{};
    file.cancel_after_write_call = 1;
    file.cancel_target = &cancel_requested;
    file.fail_sync_call = 1;
    TestWriter writer{std::move(file)};

    const auto create_error = writer.create(
        u"/CAPTURES/TEST.C8.PART",
        precision_rx::capture_write_size + 32,
        &cancel_requested);
    REQUIRE(create_error.is_valid());
    CHECK_EQ(create_error->code(), FR_DISK_ERR);
    CHECK_FALSE(writer.prepared());
    CHECK_FALSE(writer.finalized());
    CHECK_EQ(writer.file().write_calls, 1);
    CHECK_EQ(writer.file().truncate_calls, 1);
}

TEST_CASE("preparation preserves the original media error when rollback fails") {
    FaultInjectingFile file{};
    file.fail_write_call = 2;
    file.fail_write_error = FR_DENIED;
    file.partial_write_error_bytes = 3;
    file.fail_truncate_call = 1;
    TestWriter writer{std::move(file)};

    const auto create_error = writer.create(
        u"/CAPTURES/TEST.C8.PART",
        precision_rx::capture_write_size + 32);
    REQUIRE(create_error.is_valid());
    CHECK_EQ(create_error->code(), FR_DENIED);
    CHECK_FALSE(writer.prepared());
    CHECK_GT(writer.file().data.size(), 0);
}

TEST_CASE("finalization retains only wholly committed capture blocks") {
    FaultInjectingFile file{};
    file.fail_write_call = 3;
    file.partial_write_error_bytes = 3;
    TestWriter writer{std::move(file)};
    REQUIRE_FALSE(writer.create(u"/CAPTURES/TEST.C8.PART", 32).is_valid());

    const uint8_t committed[]{1, 2, 3, 4};
    REQUIRE(writer.write(committed, sizeof(committed)).is_ok());
    const uint8_t failed[]{5, 6, 7, 8, 9, 10};
    REQUIRE(writer.write(failed, sizeof(failed)).is_error());
    CHECK_EQ(writer.bytes_written(), sizeof(committed));

    REQUIRE_FALSE(writer.sync().is_valid());
    CHECK_EQ(writer.file().data, std::vector<uint8_t>({1, 2, 3, 4}));
}

TEST_CASE("preallocation sync failure cleans up the temporary extent") {
    FaultInjectingFile file{};
    file.fail_sync_call = 1;
    TestWriter writer{std::move(file)};

    const auto create_error = writer.create(u"/CAPTURES/TEST.C8", 32);
    REQUIRE(create_error.is_valid());
    CHECK_EQ(create_error->code(), FR_DISK_ERR);
    CHECK_FALSE(writer.prepared());
    CHECK_EQ(writer.file().data.size(), 0);
    CHECK_EQ(writer.file().offset, 0);
    CHECK_EQ(writer.file().truncate_calls, 1);
    CHECK_EQ(writer.file().sync_calls, 2);
}

TEST_CASE("sticky preallocation seek failure is cleared before cleanup") {
    FaultInjectingFile file{};
    file.fail_seek_call = 1;
    TestWriter writer{std::move(file)};

    const auto create_error = writer.create(u"/CAPTURES/TEST.C8", 32);
    REQUIRE(create_error.is_valid());
    CHECK_EQ(create_error->code(), FR_BAD_SEEK);
    CHECK_FALSE(writer.prepared());
    CHECK_FALSE(writer.file().sticky_error);
    CHECK_EQ(writer.file().data.size(), 0);
    CHECK_EQ(writer.file().offset, 0);
    CHECK_EQ(writer.file().clear_error_calls, 1);
    CHECK_EQ(writer.file().truncate_calls, 1);
}

TEST_CASE("truncate and final sync errors are surfaced") {
    SUBCASE("truncate failure") {
        FaultInjectingFile file{};
        file.fail_truncate_call = 1;
        TestWriter writer{std::move(file)};
        REQUIRE_FALSE(writer.create(u"/CAPTURES/TEST.C8", 32).is_valid());

        const auto error = writer.sync();
        REQUIRE(error.is_valid());
        CHECK_EQ(error->code(), FR_DISK_ERR);
        CHECK_FALSE(writer.finalized());
    }

    SUBCASE("sync failure") {
        FaultInjectingFile file{};
        file.fail_sync_call = 2;
        TestWriter writer{std::move(file)};
        REQUIRE_FALSE(writer.create(u"/CAPTURES/TEST.C8", 32).is_valid());

        const auto error = writer.sync();
        REQUIRE(error.is_valid());
        CHECK_EQ(error->code(), FR_DISK_ERR);
        CHECK_FALSE(writer.finalized());
    }
}

TEST_CASE("writes beyond the preallocated guard are rejected without touching the file") {
    TestWriter writer{};
    REQUIRE_FALSE(writer.create(u"/CAPTURES/TEST.C8", 8).is_valid());

    const uint8_t payload[]{1, 2, 3, 4, 5, 6, 7, 8};
    REQUIRE(writer.write(payload, sizeof(payload)).is_ok());
    const auto offset_before_rejection = writer.file().offset;
    const auto writes_before_rejection = writer.file().write_calls;

    const uint8_t extra = 9;
    const auto overflow_result = writer.write(&extra, sizeof(extra));
    REQUIRE(overflow_result.is_error());
    CHECK_EQ(overflow_result.error().code(), FR_DISK_FULL);
    CHECK_EQ(writer.file().offset, offset_before_rejection);
    CHECK_EQ(writer.file().write_calls, writes_before_rejection);
}

TEST_SUITE_END();
