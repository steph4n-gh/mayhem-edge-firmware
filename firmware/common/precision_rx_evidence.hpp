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

#ifndef __PRECISION_RX_EVIDENCE_H__
#define __PRECISION_RX_EVIDENCE_H__

#include <cstddef>
#include <cstdint>

namespace precision_rx {

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC) || \
    defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
constexpr uint32_t capture_duration_seconds = 16U;
constexpr uint32_t complex8_bytes_per_sample = 2U;
constexpr size_t capture_closing_reserve_buffers = 2U;

constexpr uint64_t capture_target_samples(const uint32_t sample_rate_hz) {
    return static_cast<uint64_t>(sample_rate_hz) * capture_duration_seconds;
}

constexpr uint64_t capture_target_bytes(const uint32_t sample_rate_hz) {
    return capture_target_samples(sample_rate_hz) * complex8_bytes_per_sample;
}
#endif

/*
 * The p9 diagnostic retains a 64 KiB M4 allocation and loans three checked
 * 8 KiB buffers from M0 shared SRAM.  The p10 hybrid geometry instead retains
 * nine M4-local buffers and loans two M0 buffers; its Precision-RX-only 8 KiB
 * DMA ring pays for the ninth local descriptor without increasing total M4
 * demand.  Both layouts expose one eleven-descriptor cross-core pool.  The
 * card-ready probe runs before M0 dequeues a descriptor, so all eleven blocks
 * absorb that measured latency; the shorter transfer phase then runs with one
 * descriptor held.
 */
constexpr size_t capture_write_size = 8U * 1024U;
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
constexpr size_t capture_local_buffer_count = 9U;
#else
constexpr size_t capture_local_buffer_count = 8U;
#endif
#if defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC)
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
constexpr size_t capture_spill_buffer_count = 2U;
#else
constexpr size_t capture_spill_buffer_count = 3U;
#endif
#else
constexpr size_t capture_spill_buffer_count = 0U;
#endif
/* CaptureConfig retains the M4-local count; total includes the M0 loan. */
constexpr size_t capture_buffer_count = capture_local_buffer_count;
constexpr size_t capture_total_buffer_count =
    capture_local_buffer_count + capture_spill_buffer_count;
constexpr size_t capture_local_stream_bytes =
    capture_write_size * capture_local_buffer_count;
constexpr size_t capture_spill_stream_bytes =
    capture_write_size * capture_spill_buffer_count;
constexpr size_t capture_stream_bytes = capture_local_stream_bytes;
constexpr size_t capture_total_stream_bytes =
    capture_write_size * capture_total_buffer_count;
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
static_assert(capture_local_stream_bytes == 72U * 1024U);
static_assert(capture_spill_buffer_count == 2U);
static_assert(capture_total_buffer_count == 11U);
static_assert(capture_spill_stream_bytes == 16U * 1024U);
static_assert(capture_total_stream_bytes == 88U * 1024U);
#elif defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC)
static_assert(capture_local_stream_bytes == 64U * 1024U);
static_assert(capture_spill_buffer_count == 3U);
static_assert(capture_total_buffer_count == 11U);
static_assert(capture_spill_stream_bytes == 24U * 1024U);
static_assert(capture_total_stream_bytes == 88U * 1024U);
#else
static_assert(capture_local_stream_bytes == 64U * 1024U);
static_assert(capture_total_buffer_count == 8U);
static_assert(capture_spill_stream_bytes == 0U);
static_assert(capture_total_stream_bytes == 64U * 1024U);
#endif

/*
 * Sequence numbers are uint32_t and deliberately wrap.  A report belongs to
 * the capture when walking backwards from the final generated sequence reaches
 * it in fewer steps than the number of reports generated for that capture.
 */
constexpr bool report_in_capture_interval(
    bool evidence_valid,
    uint32_t evidence_stream_epoch,
    uint32_t final_report_sequence,
    uint64_t reports_generated,
    uint32_t report_stream_epoch,
    uint32_t report_sequence) {
    return evidence_valid && reports_generated != 0 &&
           report_stream_epoch == evidence_stream_epoch &&
           static_cast<uint64_t>(
               static_cast<uint32_t>(final_report_sequence - report_sequence)) <
               reports_generated;
}

/*
 * M4 owns an authoritative last-sixteen journal while capture is active.
 * Application-queue status messages are live display only; the journal makes
 * stop-time queue contention incapable of creating or hiding capture
 * evidence.  Sequence-derived slots avoid a second cross-core index and stay
 * correct across uint32_t wrap.
 */
constexpr size_t capture_snapshot_journal_capacity = 16U;
static_assert(
    (capture_snapshot_journal_capacity &
     (capture_snapshot_journal_capacity - 1U)) == 0U,
    "snapshot journal capacity must be a power of two");

constexpr size_t capture_snapshot_journal_retained(
    const uint64_t reports_generated) {
    return reports_generated < capture_snapshot_journal_capacity
               ? static_cast<size_t>(reports_generated)
               : capture_snapshot_journal_capacity;
}

constexpr uint32_t capture_snapshot_journal_sequence(
    const uint32_t final_report_sequence,
    const size_t retained_count,
    const size_t chronological_index) {
    return final_report_sequence -
           static_cast<uint32_t>(retained_count - chronological_index - 1U);
}

constexpr size_t capture_snapshot_journal_slot(const uint32_t report_sequence) {
    return report_sequence & (capture_snapshot_journal_capacity - 1U);
}

}  // namespace precision_rx

#endif /*__PRECISION_RX_EVIDENCE_H__*/
