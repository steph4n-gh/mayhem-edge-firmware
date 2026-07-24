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

#ifndef __PRECISION_RX_JOURNAL_RECOVERY_H__
#define __PRECISION_RX_JOURNAL_RECOVERY_H__

#include "message.hpp"
#include "precision_rx_evidence.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace ui::external_app::precision_rx {

struct SnapshotJournalBounds {
    uint64_t start_input_tick;
    uint64_t stop_input_tick;
    uint64_t offered_bytes;
    uint64_t fifo_dropped_bytes;
    uint64_t stop_dropped_input_samples;
};

struct SnapshotJournalRecovery {
    size_t retained_count;
    size_t head;
    size_t missing_count;
};

/*
 * The p11 lease profile cannot afford a second 16-record working copy in the
 * 32 KiB PPMA flash package. Validate the authoritative ring in place instead.
 * A fully coherent ring retains every normal record; any inconsistency drops
 * the entire recovered set so capture acceptance fails closed with LOSS.
 */
template <size_t Capacity>
SnapshotJournalRecovery validate_snapshot_journal(
    const std::array<PrecisionRxSnapshotRecord, Capacity>& snapshots,
    const PrecisionRxCaptureEvidence& evidence,
    const SnapshotJournalBounds& bounds) {
    static_assert(Capacity == ::precision_rx::capture_snapshot_journal_capacity);
    const size_t expected_count =
        ::precision_rx::capture_snapshot_journal_retained(
            evidence.status_reports_generated);
    const SnapshotJournalRecovery rejected{0U, 0U, expected_count};
    if (!evidence.valid || (evidence.update_sequence & 1U) != 0U)
        return rejected;

    const PrecisionRxSnapshotRecord* previous = nullptr;
    for (size_t index = 0; index < expected_count; ++index) {
        const uint32_t expected_sequence =
            ::precision_rx::capture_snapshot_journal_sequence(
                evidence.final_report_sequence, expected_count, index);
        const auto& snapshot =
            snapshots[::precision_rx::capture_snapshot_journal_slot(
                expected_sequence)];
        const bool record_valid =
            snapshot.stream_epoch == evidence.final_stream_epoch &&
            snapshot.report_sequence == expected_sequence &&
            snapshot.first_input_tick >= bounds.start_input_tick &&
            snapshot.next_input_tick > snapshot.first_input_tick &&
            snapshot.capture_bytes_dropped <=
                snapshot.capture_bytes_received &&
            (!previous ||
             (snapshot.first_input_tick == previous->next_input_tick &&
              snapshot.dropped_input_samples >=
                  previous->dropped_input_samples &&
              snapshot.capture_bytes_received >=
                  previous->capture_bytes_received &&
              snapshot.capture_bytes_dropped >=
                  previous->capture_bytes_dropped));
        if (!record_valid)
            return rejected;
        previous = &snapshot;
    }

    if (expected_count != 0U &&
        (previous->next_input_tick != bounds.stop_input_tick ||
         previous->dropped_input_samples !=
             bounds.stop_dropped_input_samples ||
         previous->capture_bytes_received != bounds.offered_bytes ||
         previous->capture_bytes_dropped != bounds.fifo_dropped_bytes)) {
        return rejected;
    }

    const size_t head = expected_count == 0U
                            ? 0U
                            : ::precision_rx::capture_snapshot_journal_slot(
                                  evidence.final_report_sequence + 1U);
    return {expected_count, head, 0U};
}

}  // namespace ui::external_app::precision_rx

#endif /*__PRECISION_RX_JOURNAL_RECOVERY_H__*/
