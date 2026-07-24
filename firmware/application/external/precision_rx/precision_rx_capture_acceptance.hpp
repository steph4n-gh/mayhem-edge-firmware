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

#ifndef __PRECISION_RX_CAPTURE_ACCEPTANCE_H__
#define __PRECISION_RX_CAPTURE_ACCEPTANCE_H__

#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
#include "message.hpp"
#endif

#include <cstdint>

namespace ui::external_app::precision_rx {

/* Values intentionally match edge_frame_flag_v1 in the frozen Edge ABI. */
constexpr uint32_t continuity_flag_stream_start = uint32_t{1} << 0;
constexpr uint32_t continuity_flag_discontinuity = uint32_t{1} << 2;
constexpr uint32_t continuity_flag_dropped_input = uint32_t{1} << 3;
constexpr uint32_t continuity_flag_config_changed = uint32_t{1} << 7;
constexpr uint32_t continuity_flag_clock_reset = uint32_t{1} << 9;

constexpr uint32_t known_continuity_flag_mask =
    continuity_flag_stream_start |
    continuity_flag_discontinuity |
    continuity_flag_dropped_input |
    continuity_flag_config_changed |
    continuity_flag_clock_reset;
constexpr uint32_t loss_continuity_flag_mask =
    continuity_flag_discontinuity | continuity_flag_dropped_input;
constexpr uint32_t acceptable_continuity_flag_mask =
    known_continuity_flag_mask & ~loss_continuity_flag_mask;

struct CaptureAcceptanceEvidence {
    bool valid{false};
    uint64_t status_reports_generated{0};
    uint64_t retained_snapshot_count{0};
    uint64_t start_input_tick{0};
    uint64_t stop_input_tick{0};
    uint64_t file_bytes_written{0};
    uint64_t input_bytes_offered{0};
    uint64_t stream_fifo_bytes_dropped{0};
    uint64_t start_dropped_input_samples{0};
    uint64_t stop_dropped_input_samples{0};
    uint64_t status_reports_missing{0};
    uint32_t aggregate_continuity_flags{0};
    uint32_t aggregate_capture_continuity_flags{0};
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
    PrecisionRxCaptureTerminalReason terminal_reason{
        PrecisionRxCaptureTerminalReason::Unspecified};
    uint64_t target_bytes{0};
#endif
};

constexpr bool continuity_flags_are_acceptable(const uint32_t flags) {
    return (flags & ~acceptable_continuity_flag_mask) == 0;
}

/*
 * Governs LOSS versus SAVED after file, metadata, and publication operations
 * have already succeeded.  Unknown continuity bits fail closed so a newer ABI
 * cannot silently weaken the integrity claim made by SAVED.
 */
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
constexpr bool capture_prefix_is_acceptable(
    const CaptureAcceptanceEvidence& evidence) {
    return evidence.valid &&
           evidence.status_reports_generated != 0 &&
           evidence.retained_snapshot_count != 0 &&
           evidence.stop_input_tick > evidence.start_input_tick &&
           evidence.file_bytes_written != 0 &&
           evidence.input_bytes_offered == evidence.file_bytes_written &&
           evidence.stream_fifo_bytes_dropped == 0 &&
           evidence.stop_dropped_input_samples ==
               evidence.start_dropped_input_samples &&
           evidence.status_reports_missing == 0 &&
           continuity_flags_are_acceptable(
               evidence.aggregate_continuity_flags |
               evidence.aggregate_capture_continuity_flags);
}

constexpr bool capture_is_acceptable(
    const CaptureAcceptanceEvidence& evidence) {
    return capture_prefix_is_acceptable(evidence) &&
           evidence.terminal_reason ==
               PrecisionRxCaptureTerminalReason::TargetReached &&
           evidence.target_bytes != 0 &&
           evidence.file_bytes_written == evidence.target_bytes &&
           (evidence.stop_input_tick - evidence.start_input_tick) * 2U ==
               evidence.target_bytes;
}
#else
constexpr bool capture_is_acceptable(
    const CaptureAcceptanceEvidence& evidence) {
    return evidence.valid &&
           evidence.status_reports_generated != 0 &&
           evidence.retained_snapshot_count != 0 &&
           evidence.stop_input_tick > evidence.start_input_tick &&
           evidence.file_bytes_written != 0 &&
           evidence.input_bytes_offered == evidence.file_bytes_written &&
           evidence.stream_fifo_bytes_dropped == 0 &&
           evidence.stop_dropped_input_samples ==
               evidence.start_dropped_input_samples &&
           evidence.status_reports_missing == 0 &&
           continuity_flags_are_acceptable(
               evidence.aggregate_continuity_flags |
               evidence.aggregate_capture_continuity_flags);
}
#endif

}  // namespace ui::external_app::precision_rx

#endif /*__PRECISION_RX_CAPTURE_ACCEPTANCE_H__*/
