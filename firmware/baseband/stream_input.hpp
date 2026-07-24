/*
 * Copyright (C) 2016 Jared Boone, ShareBrained Technology, Inc.
 * Modified for HackRF Edge in 2026 by HackRF Edge contributors.
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

#ifndef __STREAM_INPUT_H__
#define __STREAM_INPUT_H__

#include "message.hpp"
#include "fifo.hpp"

#include <cstdint>
#include <cstddef>
#include <array>
#include <memory>

#if !defined(STREAM_INPUT_BUFFER_COUNT_MAX_LOG2)
#define STREAM_INPUT_BUFFER_COUNT_MAX_LOG2 3
#endif

static_assert(
    STREAM_INPUT_BUFFER_COUNT_MAX_LOG2 == 3 ||
        STREAM_INPUT_BUFFER_COUNT_MAX_LOG2 == 4,
    "StreamInput supports only the upstream 8-slot or Precision RX private 16-slot capacity");

class StreamInput {
   public:
    StreamInput(CaptureConfig* const config);
    StreamInput(size_t write_size, size_t buffer_count);

    StreamInput(const StreamInput&) = delete;
    StreamInput(StreamInput&&) = delete;
    StreamInput& operator=(const StreamInput&) = delete;
    StreamInput& operator=(StreamInput&&) = delete;

    /*
     * Rebind retained storage without allocation.  The caller acknowledges
     * the open separately, after crossing any required real-time boundary.
     */
    bool rebind(CaptureConfig* config);
    bool acknowledge_open();
    size_t write(const void* const data, const size_t length);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    bool try_write_exact(
        const void* data,
        size_t length,
        size_t reserve_empty_buffers);
#endif
    bool seal();
    bool drained() const;
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    uint8_t* dma_loan_buffer();
    bool unbind_if_drained();
    bool force_unbind_after_abort();
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    bool abort_unacknowledged_open_after_dma_fault(
        CaptureConfig* expected_config);
    bool signal_bound_capture_abort_after_dma_fault();
#endif
    bool unbound() const { return config == nullptr && sealed_; }
#endif

   private:
    /*
     * Precision RX compiles private capacity for sixteen slots. p9 binds eight
     * M4-local plus three M0-owned descriptors; p10 binds nine plus two. The
     * larger array retains the reviewed M4 object layout.
     */
    static constexpr size_t buffer_count_max_log2 =
        STREAM_INPUT_BUFFER_COUNT_MAX_LOG2;
    static constexpr size_t buffer_count_max = 1U << buffer_count_max_log2;

    FIFO<StreamBuffer*> fifo_buffers_empty;
    FIFO<StreamBuffer*> fifo_buffers_full;
    std::array<StreamBuffer, buffer_count_max> buffers{};
    /* FIFO indices gate access; producer/consumer slots are written by in(). */
    std::array<StreamBuffer*, buffer_count_max> buffers_empty;
    std::array<StreamBuffer*, buffer_count_max> buffers_full;
    StreamBuffer* active_buffer{nullptr};
    /* Unbound retained storage is inert until a successful rebind. */
    bool sealed_{true};
    /* Reusable geometry occupies the legacy object's former padding bytes. */
    uint8_t buffer_count_{0};
    uint16_t write_size_{0};
    CaptureConfig* config{nullptr};
    std::unique_ptr<uint8_t[]> data{};
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    void release_dma_loan();
#endif
};

#endif /*__STREAM_INPUT_H__*/
