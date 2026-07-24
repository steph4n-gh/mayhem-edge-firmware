/*
 * Copyright (C) 2026 HackRF Edge contributors
 *
 * This file is part of PortaPack.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */

#include "doctest.h"
#include "../../application/external/precision_rx/precision_rx_capture_acceptance.hpp"
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
#include "../../application/external/precision_rx/precision_rx_journal_recovery.hpp"
#endif

#include <array>
#include <cstring>
#include <cstdint>

namespace {

namespace capture_acceptance = ui::external_app::precision_rx;

static_assert(
    capture_acceptance::known_continuity_flag_mask == 0x0000028dU,
    "frozen Edge ABI continuity mask changed");
static_assert(
    capture_acceptance::loss_continuity_flag_mask == 0x0000000cU,
    "capture loss mask changed");
static_assert(
    capture_acceptance::acceptable_continuity_flag_mask == 0x00000281U,
    "known non-loss continuity mask changed");

capture_acceptance::CaptureAcceptanceEvidence clean_evidence() {
    return {
        true,
        4,
        4,
        1'000,
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
        9'192,
#else
        2'000,
#endif
        16'384,
        16'384,
        0,
        7,
        7,
        0,
        capture_acceptance::continuity_flag_stream_start,
        0,
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
        PrecisionRxCaptureTerminalReason::TargetReached,
        16'384,
#endif
    };
}

}  // namespace

TEST_SUITE_BEGIN("Precision RX capture acceptance");

TEST_CASE("clean authoritative evidence is accepted") {
    CHECK(capture_acceptance::capture_is_acceptable(clean_evidence()));
}

#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
TEST_CASE("clean prefixes remain explicit but are never promoted as full captures") {
    auto pressure = clean_evidence();
    pressure.terminal_reason =
        PrecisionRxCaptureTerminalReason::StoragePressure;
    CHECK(capture_acceptance::capture_prefix_is_acceptable(pressure));
    CHECK_FALSE(capture_acceptance::capture_is_acceptable(pressure));

    auto requested = clean_evidence();
    requested.terminal_reason =
        PrecisionRxCaptureTerminalReason::RequestedStop;
    CHECK(capture_acceptance::capture_prefix_is_acceptable(requested));
    CHECK_FALSE(capture_acceptance::capture_is_acceptable(requested));
}

TEST_CASE("target completion is exact and cannot accept a short or overshoot") {
    auto evidence = clean_evidence();
    --evidence.file_bytes_written;
    --evidence.input_bytes_offered;
    CHECK_FALSE(capture_acceptance::capture_is_acceptable(evidence));

    evidence = clean_evidence();
    evidence.target_bytes -= 2U;
    CHECK_FALSE(capture_acceptance::capture_is_acceptable(evidence));

    evidence = clean_evidence();
    ++evidence.stop_input_tick;
    CHECK_FALSE(capture_acceptance::capture_is_acceptable(evidence));
}
#endif

TEST_CASE("each scalar evidence failure rejects the capture") {
    auto evidence = clean_evidence();

    SUBCASE("invalid authoritative evidence") {
        evidence.valid = false;
    }
    SUBCASE("no generated reports") {
        evidence.status_reports_generated = 0;
    }
    SUBCASE("no retained snapshots") {
        evidence.retained_snapshot_count = 0;
    }
    SUBCASE("empty tick interval") {
        evidence.stop_input_tick = evidence.start_input_tick;
    }
    SUBCASE("reversed tick interval") {
        evidence.stop_input_tick = evidence.start_input_tick - 1;
    }
    SUBCASE("empty file") {
        evidence.file_bytes_written = 0;
        evidence.input_bytes_offered = 0;
    }
    SUBCASE("file shorter than offered input") {
        --evidence.file_bytes_written;
    }
    SUBCASE("file longer than offered input") {
        ++evidence.file_bytes_written;
    }
    SUBCASE("stream FIFO dropped bytes") {
        evidence.stream_fifo_bytes_dropped = 1;
    }
    SUBCASE("input sample loss increased") {
        ++evidence.stop_dropped_input_samples;
    }
    SUBCASE("input loss counters are inconsistent") {
        --evidence.stop_dropped_input_samples;
    }
    SUBCASE("status reports are missing") {
        evidence.status_reports_missing = 1;
    }

    CHECK_FALSE(capture_acceptance::capture_is_acceptable(evidence));
}

TEST_CASE("known non-loss continuity flags remain acceptable") {
    constexpr uint32_t benign_flags =
        capture_acceptance::continuity_flag_stream_start |
        capture_acceptance::continuity_flag_config_changed |
        capture_acceptance::continuity_flag_clock_reset;
    auto evidence = clean_evidence();
    evidence.aggregate_continuity_flags = benign_flags;
    evidence.aggregate_capture_continuity_flags = benign_flags;

    CHECK(capture_acceptance::capture_is_acceptable(evidence));
}

TEST_CASE("each known loss bit rejects either continuity aggregate") {
    constexpr uint32_t loss_flags[]{
        capture_acceptance::continuity_flag_discontinuity,
        capture_acceptance::continuity_flag_dropped_input,
    };

    for (const uint32_t loss_flag : loss_flags) {
        auto evidence = clean_evidence();
        evidence.aggregate_continuity_flags = loss_flag;
        CHECK_FALSE(capture_acceptance::capture_is_acceptable(evidence));

        evidence = clean_evidence();
        evidence.aggregate_capture_continuity_flags = loss_flag;
        CHECK_FALSE(capture_acceptance::capture_is_acceptable(evidence));
    }
}

TEST_CASE("every unknown continuity bit fails closed in either aggregate") {
    for (uint32_t bit = 1; bit != 0; bit <<= 1) {
        if ((bit & capture_acceptance::known_continuity_flag_mask) != 0) {
            continue;
        }

        auto evidence = clean_evidence();
        evidence.aggregate_continuity_flags = bit;
        CHECK_FALSE(capture_acceptance::capture_is_acceptable(evidence));

        evidence = clean_evidence();
        evidence.aggregate_capture_continuity_flags = bit;
        CHECK_FALSE(capture_acceptance::capture_is_acceptable(evidence));
    }
}

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
TEST_CASE("valid snapshot journal records remain in their authoritative ring") {
    std::array<PrecisionRxSnapshotRecord,
               precision_rx::capture_snapshot_journal_capacity>
        snapshots{};
    PrecisionRxCaptureEvidence evidence{};
    evidence.update_sequence = 2;
    evidence.valid = true;
    evidence.final_stream_epoch = 7;
    evidence.final_report_sequence = 17;
    evidence.status_reports_generated = 3;

    for (uint32_t sequence = 15; sequence <= 17; ++sequence) {
        auto& snapshot =
            snapshots[precision_rx::capture_snapshot_journal_slot(sequence)];
        const uint64_t step = sequence - 14U;
        snapshot.first_input_tick = step * 100U;
        snapshot.next_input_tick = (step + 1U) * 100U;
        snapshot.dropped_input_samples = 6U + step;
        snapshot.capture_bytes_received = step * 1000U;
        snapshot.capture_bytes_dropped = step == 3U ? 100U : step * 20U;
        snapshot.stream_epoch = 7;
        snapshot.report_sequence = sequence;
    }

    const auto original = snapshots;
    const auto recovery = capture_acceptance::validate_snapshot_journal(
        snapshots,
        evidence,
        {100U, 400U, 3000U, 100U, 9U});
    CHECK_EQ(recovery.retained_count, 3U);
    CHECK_EQ(recovery.head, 2U);
    CHECK_EQ(recovery.missing_count, 0U);
    CHECK_EQ(
        std::memcmp(snapshots.data(), original.data(), sizeof(snapshots)), 0);
}

TEST_CASE("full snapshot journal remains chronological across sequence wrap") {
    constexpr size_t capacity =
        precision_rx::capture_snapshot_journal_capacity;
    std::array<PrecisionRxSnapshotRecord, capacity> snapshots{};
    PrecisionRxCaptureEvidence evidence{};
    evidence.update_sequence = 2;
    evidence.valid = true;
    evidence.final_stream_epoch = 9;
    evidence.final_report_sequence = 3U;
    evidence.status_reports_generated = (uint64_t{1} << 32U) + 4U;

    for (size_t index = 0; index < capacity; ++index) {
        const uint32_t sequence =
            precision_rx::capture_snapshot_journal_sequence(
                evidence.final_report_sequence, capacity, index);
        auto& snapshot =
            snapshots[precision_rx::capture_snapshot_journal_slot(sequence)];
        const uint64_t step = index + 1U;
        snapshot.first_input_tick = step * 100U;
        snapshot.next_input_tick = (step + 1U) * 100U;
        snapshot.dropped_input_samples = 19U + step;
        snapshot.capture_bytes_received = step * 1000U;
        snapshot.capture_bytes_dropped = step * 10U;
        snapshot.stream_epoch = 9;
        snapshot.report_sequence = sequence;
    }

    const auto recovery = capture_acceptance::validate_snapshot_journal(
        snapshots,
        evidence,
        {100U, 1700U, 16000U, 160U, 35U});
    CHECK_EQ(recovery.retained_count, capacity);
    CHECK_EQ(recovery.head, 4U);
    CHECK_EQ(recovery.missing_count, 0U);

    for (size_t index = 0; index < capacity; ++index) {
        const uint32_t sequence =
            precision_rx::capture_snapshot_journal_sequence(
                evidence.final_report_sequence, capacity, index);
        const auto& snapshot =
            snapshots[precision_rx::capture_snapshot_journal_slot(sequence)];
        CHECK_EQ(snapshot.report_sequence, sequence);
        CHECK_EQ(snapshot.first_input_tick, (index + 1U) * 100U);
    }
    CHECK_EQ(snapshots[4U].report_sequence, 0xfffffff4U);
    CHECK_EQ(snapshots[3U].report_sequence, 3U);

    snapshots[precision_rx::capture_snapshot_journal_slot(0xffffffffU)]
        .report_sequence = 0U;
    const auto rejected = capture_acceptance::validate_snapshot_journal(
        snapshots,
        evidence,
        {100U, 1700U, 16000U, 160U, 35U});
    CHECK_EQ(rejected.retained_count, 0U);
    CHECK_EQ(rejected.head, 0U);
    CHECK_EQ(rejected.missing_count, capacity);
}

TEST_CASE("any missing or corrupt snapshot journal record fails closed") {
    std::array<PrecisionRxSnapshotRecord,
               precision_rx::capture_snapshot_journal_capacity>
        clean{};
    PrecisionRxCaptureEvidence evidence{};
    evidence.update_sequence = 2;
    evidence.valid = true;
    evidence.final_stream_epoch = 7;
    evidence.final_report_sequence = 17;
    evidence.status_reports_generated = 3;
    for (uint32_t sequence = 15; sequence <= 17; ++sequence) {
        auto& snapshot =
            clean[precision_rx::capture_snapshot_journal_slot(sequence)];
        const uint64_t step = sequence - 14U;
        snapshot.first_input_tick = step * 100U;
        snapshot.next_input_tick = (step + 1U) * 100U;
        snapshot.dropped_input_samples = 6U + step;
        snapshot.capture_bytes_received = step * 1000U;
        snapshot.capture_bytes_dropped = step == 3U ? 100U : step * 20U;
        snapshot.stream_epoch = 7;
        snapshot.report_sequence = sequence;
    }

    SUBCASE("middle record is missing") {
        clean[precision_rx::capture_snapshot_journal_slot(16U)] = {};
    }
    SUBCASE("record timing is discontinuous") {
        clean[precision_rx::capture_snapshot_journal_slot(16U)]
            .first_input_tick++;
    }
    SUBCASE("record counters exceed final evidence") {
        clean[precision_rx::capture_snapshot_journal_slot(16U)]
            .capture_bytes_received = 3001U;
    }
    SUBCASE("evidence seqlock is unstable") {
        evidence.update_sequence = 3;
    }
    SUBCASE("final record does not close the capture") {
        clean[precision_rx::capture_snapshot_journal_slot(17U)]
            .next_input_tick--;
    }

    const auto recovery = capture_acceptance::validate_snapshot_journal(
        clean,
        evidence,
        {100U, 400U, 3000U, 100U, 9U});
    CHECK_EQ(recovery.retained_count, 0U);
    CHECK_EQ(recovery.head, 0U);
    CHECK_EQ(recovery.missing_count, 3U);
}
#endif

TEST_SUITE_END();
