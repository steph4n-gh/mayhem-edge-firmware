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

#include "stream_input.hpp"

#include "precision_rx_evidence.hpp"
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
#include "precision_rx_dma_lease.hpp"
#endif

#if defined(__arm__) && STREAM_INPUT_BUFFER_COUNT_MAX_LOG2 == 4
static_assert(sizeof(StreamInput) == 0x170U);
#endif

#if defined(__arm__)
#define HACKRF_EDGE_STRINGIFY_IMPL(value) #value
#define HACKRF_EDGE_STRINGIFY(value) HACKRF_EDGE_STRINGIFY_IMPL(value)
/* Absolute metadata: proves the linked implementation's private geometry. */
__asm__(
    ".global hackrf_edge_stream_input_impl_buffer_count_log2\n"
    ".type hackrf_edge_stream_input_impl_buffer_count_log2, %object\n"
    ".set hackrf_edge_stream_input_impl_buffer_count_log2, "
    HACKRF_EDGE_STRINGIFY(STREAM_INPUT_BUFFER_COUNT_MAX_LOG2) "\n"
    ".size hackrf_edge_stream_input_impl_buffer_count_log2, 1\n");
#undef HACKRF_EDGE_STRINGIFY
#undef HACKRF_EDGE_STRINGIFY_IMPL
#endif

#if !defined(STREAM_INPUT_HOST_TEST)
#include "lpc43xx_cpp.hpp"
using namespace lpc43xx;
#endif

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
#define HACKRF_EDGE_PRX_LINK_SHAPE \
    __attribute__((noinline, noclone, optimize("Os")))
#else
#define HACKRF_EDGE_PRX_LINK_SHAPE
#endif

StreamInput::StreamInput(CaptureConfig* const config)
    : fifo_buffers_empty{buffers_empty.data(), buffer_count_max_log2},
      fifo_buffers_full{buffers_full.data(), buffer_count_max_log2},
      sealed_{false},
      buffer_count_{0},
      write_size_{0},
      config{config},
      data{std::make_unique<uint8_t[]>(config->write_size * config->buffer_count)} {
    config->baseband_producer_sealed = false;
    config->application_abort_requested = false;
    config->baseband_open_succeeded = false;
    config->fifo_buffers_empty = &fifo_buffers_empty;
    config->fifo_buffers_full = &fifo_buffers_full;

    for (size_t i = 0; i < config->buffer_count; ++i) {
        buffers[i] = {&(data.get()[i * config->write_size]), config->write_size};
        fifo_buffers_empty.in(&buffers[i]);
    }
    config->baseband_open_succeeded = true;
}

HACKRF_EDGE_PRX_LINK_SHAPE
StreamInput::StreamInput(
    const size_t write_size,
    const size_t buffer_count)
    : fifo_buffers_empty{buffers_empty.data(), buffer_count_max_log2},
      fifo_buffers_full{buffers_full.data(), buffer_count_max_log2},
      buffer_count_{static_cast<uint8_t>(
          buffer_count <= buffer_count_max ? buffer_count : 0)},
      write_size_{static_cast<uint16_t>(
          write_size <= 0xffffU ? write_size : 0)},
      data{
          write_size != 0 && write_size <= 0xffffU && buffer_count != 0 &&
                  buffer_count <= buffer_count_max
              ? std::make_unique<uint8_t[]>(write_size * buffer_count)
              : nullptr} {
}

/* Capture setup is cold; optimize it for the constrained PRX package. */
__attribute__((optimize("Os"))) bool StreamInput::rebind(CaptureConfig* const next_config) {
#if !defined(STREAM_INPUT_HOST_TEST)
    /* Acquire the M0-published config and shared-SRAM loan before inspection. */
    __DMB();
#endif
#if defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC) && \
    !defined(STREAM_INPUT_HOST_TEST)
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
    constexpr size_t local_buffer_count = 9U;
    constexpr size_t supplemental_count = 2U;
    constexpr uintptr_t spill_bytes = 16U * 1024U;
#else
    constexpr size_t local_buffer_count = 8U;
    constexpr size_t supplemental_count = 3U;
    constexpr uintptr_t spill_bytes = 24U * 1024U;
#endif
    constexpr size_t total_buffer_count = 11U;
    constexpr size_t transfer_bytes = 8U * 1024U;
    auto* const supplemental = next_config
        ? static_cast<uint8_t*>(
              next_config->precision_rx_evidence.supplemental_buffer_data)
        : nullptr;
    auto* const snapshot_journal = next_config
        ? next_config->precision_rx_final_report
        : nullptr;
    const uintptr_t supplemental_begin =
        reinterpret_cast<uintptr_t>(supplemental);
    const uintptr_t journal_begin =
        reinterpret_cast<uintptr_t>(snapshot_journal);
    constexpr uintptr_t m0_shared_begin = 0x20000000U;
    constexpr uintptr_t m0_shared_end = 0x20010000U;
    constexpr uintptr_t journal_bytes =
        precision_rx::capture_snapshot_journal_capacity *
        sizeof(PrecisionRxSnapshotRecord);
    static_assert(journal_bytes == 1664U);
    constexpr uintptr_t m0_spill_last_begin = m0_shared_end - spill_bytes;
    constexpr uintptr_t m0_journal_last_begin = m0_shared_end - journal_bytes;
    const bool spill_range_invalid =
        supplemental_begin < m0_shared_begin ||
        supplemental_begin > m0_spill_last_begin ||
        (supplemental_begin & (alignof(uint32_t) - 1U)) != 0U;
    const bool journal_range_invalid =
        journal_begin < m0_shared_begin ||
        journal_begin > m0_journal_last_begin ||
        (journal_begin & (alignof(PrecisionRxSnapshotRecord) - 1U)) != 0U;
    const bool shared_ranges_overlap =
        !spill_range_invalid && !journal_range_invalid &&
        supplemental_begin < journal_begin + journal_bytes &&
        journal_begin < supplemental_begin + spill_bytes;
    const bool geometry_invalid =
        !next_config || !data ||
        next_config->supplemental_buffer_count != supplemental_count ||
        spill_range_invalid || journal_range_invalid || shared_ranges_overlap;
#elif defined(STREAM_INPUT_HOST_TEST)
    const size_t next_buffer_count = next_config ? next_config->buffer_count : 0U;
    const size_t supplemental_count =
        next_config ? next_config->supplemental_buffer_count : buffer_count_max;
    const size_t total_buffer_count = next_buffer_count + supplemental_count;
    auto* const supplemental = next_config
        ? static_cast<uint8_t*>(
              next_config->precision_rx_evidence.supplemental_buffer_data)
        : nullptr;
    const uintptr_t supplemental_begin =
        reinterpret_cast<uintptr_t>(supplemental);
    const bool supplemental_range_invalid =
        supplemental_count != 0U &&
        (supplemental_begin & (alignof(uint32_t) - 1U)) != 0U;
    const bool geometry_invalid =
        !next_config || !data || write_size_ == 0 || buffer_count_ == 0 ||
        buffer_count_ > buffer_count_max ||
        next_config->write_size != write_size_ ||
        next_buffer_count != buffer_count_ ||
        supplemental_count > buffer_count_max - next_buffer_count ||
        total_buffer_count > buffer_count_max ||
        (supplemental_count != 0U && supplemental == nullptr) ||
        supplemental_range_invalid;
#else
    const size_t total_buffer_count = buffer_count_;
    auto* const supplemental = static_cast<uint8_t*>(nullptr);
    const bool geometry_invalid =
        !next_config || !data || write_size_ == 0 || buffer_count_ == 0 ||
        buffer_count_ > buffer_count_max ||
        next_config->write_size != write_size_ ||
        next_config->buffer_count != buffer_count_ ||
        next_config->supplemental_buffer_count != 0U;
#endif
    if (geometry_invalid) {
        config = nullptr;
        fifo_buffers_empty.reset();
        fifo_buffers_full.reset();
        active_buffer = nullptr;
        sealed_ = true;
        if (next_config) {
            next_config->baseband_open_succeeded = false;
            next_config->fifo_buffers_empty = nullptr;
            next_config->fifo_buffers_full = nullptr;
        }
        return false;
    }

    config = next_config;
    fifo_buffers_empty.reset();
    fifo_buffers_full.reset();
    active_buffer = nullptr;
    sealed_ = false;

    config->baseband_bytes_received = 0;
    config->baseband_bytes_dropped = 0;
    config->baseband_producer_sealed = false;
    config->application_abort_requested = false;
    config->baseband_open_succeeded = false;
    config->fifo_buffers_empty = &fifo_buffers_empty;
    config->fifo_buffers_full = &fifo_buffers_full;

    /*
     * reset() makes every stale FIFO slot unreachable.  Each live descriptor
     * is replaced below before its pointer is enqueued, and FIFO::in() writes
     * the backing pointer slot before advancing the visible index.  Clearing
     * all maximum-capacity storage here is therefore redundant and, at the
     * sixteen-buffer geometry, expands into a large unrolled M4 code block.
     */
#if defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC) && \
    !defined(STREAM_INPUT_HOST_TEST)
    uint8_t* storage = data.get();
    for (size_t i = 0; i < total_buffer_count; ++i) {
        if (i == local_buffer_count)
            storage = supplemental;
        buffers[i] = {storage, transfer_bytes};
        storage += transfer_bytes;
        fifo_buffers_empty.in(&buffers[i]);
    }
#else
    for (size_t i = 0; i < total_buffer_count; ++i) {
        uint8_t* const storage =
            i < buffer_count_
                ? &(data.get()[i * write_size_])
                : &(supplemental[(i - buffer_count_) * write_size_]);
        buffers[i] = {storage, write_size_};
        fifo_buffers_empty.in(&buffers[i]);
    }
#endif
    return true;
}

HACKRF_EDGE_PRX_LINK_SHAPE
bool StreamInput::acknowledge_open() {
    if (!config) {
        return false;
    }
    config->baseband_open_succeeded = true;
    return true;
}

HACKRF_EDGE_PRX_LINK_SHAPE
size_t StreamInput::write(const void* const data, const size_t length) {
    if (sealed_) {
        return 0;
    }
    const uint8_t* p = static_cast<const uint8_t*>(data);
    size_t written = 0;

    while (written < length) {
        if (!active_buffer) {
            // We need an empty buffer...
            if (!fifo_buffers_empty.out(active_buffer)) {
                // ...but none are available. Samples were dropped.
                break;
            }
        }

        const auto remaining = length - written;
        written += active_buffer->write(&p[written], remaining);

        if (active_buffer->is_full()) {
            if (!fifo_buffers_full.in(active_buffer)) {
                // FIFO is full of buffers, there's no place for this one.
                // Bail out of the loop, and try submitting the buffer in the
                // next pass.
                // This should never happen if the number of buffers is less
                // than the capacity of the FIFO.
                break;
            }
            active_buffer = nullptr;
#if !defined(STREAM_INPUT_HOST_TEST)
            creg::m4txevent::assert_event();
#endif
        }
    }

    config->baseband_bytes_received += length;
    config->baseband_bytes_dropped += (length - written);

    return written;
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
HACKRF_EDGE_PRX_LINK_SHAPE
bool StreamInput::try_write_exact(
    const void* const source,
    const size_t length,
    const size_t reserve_empty_buffers) {
    /*
     * The complete-block caller has already proved source != nullptr and
     * 0 < length.  An unbound stream is always sealed, so that single state
     * test also protects write()'s config access without duplicating the hot
     * caller's invariants here.
     */
    if (sealed_) {
        return false;
    }

    const size_t active_free =
        active_buffer ? active_buffer->capacity() - active_buffer->size() : 0U;
    /*
     * Precision RX submits one DMA quantum, always smaller than a capture
     * descriptor.  Such a write can consume at most one new descriptor:
     * either it fits the active tail or one empty slot must remain available
     * beyond the closing reserve.
     */
    if (length > static_cast<size_t>(write_size_) ||
        (length > active_free &&
         fifo_buffers_empty.len() <= reserve_empty_buffers)) {
        return false;
    }

    return write(source, length) == length;
}
#endif

HACKRF_EDGE_PRX_LINK_SHAPE
bool StreamInput::seal() {
    if (!config) {
        return false;
    }
    if (sealed_) {
        return true;
    }

    /*
     * A partial producer block is data, not the terminal marker. Publish it
     * first and wait for a recycled buffer before appending the zero-length
     * sentinel. This gives M0 one unambiguous in-band end-of-stream record and
     * avoids racing a separately published flag against the FIFO indices.
     */
    /*
     * The M0 consumer may already be sleeping in BufferExchange::get(). The
     * empty sentinel both occupies the FIFO before the event and remains
     * recognizable after it is dequeued, independent of flag publication.
     */
    const bool terminal = !active_buffer || active_buffer->is_empty();
    if (!active_buffer && !fifo_buffers_empty.out(active_buffer)) {
        return false;
    }
    if (!fifo_buffers_full.in(active_buffer)) {
        return false;
    }

    active_buffer = nullptr;
    if (terminal) {
        sealed_ = true;
        config->baseband_producer_sealed = true;
    }
#if !defined(STREAM_INPUT_HOST_TEST)
    creg::m4txevent::assert_event();
#endif
    return terminal;
}

HACKRF_EDGE_PRX_LINK_SHAPE
bool StreamInput::drained() const {
#if defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC) && \
    !defined(STREAM_INPUT_HOST_TEST)
    constexpr size_t bound_buffer_count = 11U;
#else
    const size_t bound_buffer_count =
        config ? config->buffer_count + config->supplemental_buffer_count : 0U;
#endif
    return config && sealed_ && fifo_buffers_full.is_empty() &&
           fifo_buffers_empty.len() == bound_buffer_count;
}

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
uint8_t* StreamInput::dma_loan_buffer() {
    constexpr size_t index = precision_rx::dma_lease::loan_local_buffer_index;
    uint8_t* const base = data.get();
    if (!unbound() || !base) {
        return nullptr;
    }
    return &base[index * precision_rx::capture_write_size];
}

__attribute__((noinline, noclone, optimize("Os")))
void StreamInput::release_dma_loan() {
    config = nullptr;
    fifo_buffers_empty.reset();
    fifo_buffers_full.reset();
    active_buffer = nullptr;
    sealed_ = true;
#if !defined(STREAM_INPUT_HOST_TEST)
    /* Publish the completed reclamation before descriptors can be re-leased. */
    __asm__ volatile("" ::: "memory");
    __DMB();
    __asm__ volatile("" ::: "memory");
#endif
}

__attribute__((optimize("Os"))) bool StreamInput::unbind_if_drained() {
    if (!drained()) {
        return false;
    }
#if !defined(STREAM_INPUT_HOST_TEST)
    /* Acquire the M0-published FIFO indices before reclaiming their storage. */
    __asm__ volatile("" ::: "memory");
    __DMB();
    __asm__ volatile("" ::: "memory");
#endif
    release_dma_loan();
    return true;
}

__attribute__((optimize("Os"))) bool StreamInput::force_unbind_after_abort() {
    CaptureConfig* const bound_config = config;
    if (!bound_config || !bound_config->application_abort_requested ||
        bound_config->baseband_open_succeeded) {
        return false;
    }
#if !defined(STREAM_INPUT_HOST_TEST)
    /*
     * M0 publishes false only after BufferExchange teardown.  The volatile
     * false load above is the observation; acquire after it, before reclaim.
     */
    __asm__ volatile("" ::: "memory");
    __DMB();
    __asm__ volatile("" ::: "memory");
#endif
    release_dma_loan();
    return true;
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
bool StreamInput::abort_unacknowledged_open_after_dma_fault(
    CaptureConfig* const expected_config) {
    CaptureConfig* const bound_config = config;
    if (!bound_config)
        return unbound();
    if (bound_config != expected_config ||
        bound_config->baseband_open_succeeded)
        return false;

    /*
     * The fatal DMA worker has published quiescence, and OPEN has not been
     * acknowledged, before this method may be called. M0 cannot construct its
     * BufferExchange until the synchronous OPEN message returns successfully,
     * so no consumer can retain a live FIFO descriptor here.
     */
    bound_config->application_abort_requested = true;
#if !defined(STREAM_INPUT_HOST_TEST)
    __DMB();
#endif
    release_dma_loan();
    bound_config->fifo_buffers_empty = nullptr;
    bound_config->fifo_buffers_full = nullptr;
    return true;
}

__attribute__((noinline, noclone, optimize("Os")))
bool StreamInput::signal_bound_capture_abort_after_dma_fault() {
    CaptureConfig* const bound_config = config;
    if (!bound_config)
        return false;

    /*
     * Do not forge baseband_open_succeeded=false here: that byte belongs to
     * M0 and is published only after BufferExchange destruction. Instead,
     * publish an explicit aborted+sealed condition and wake its consumer.
     */
    bound_config->application_abort_requested = true;
    bound_config->baseband_producer_sealed = true;
#if !defined(STREAM_INPUT_HOST_TEST)
    __DMB();
    creg::m4txevent::assert_event();
#endif
    return true;
}
#endif
#endif

#undef HACKRF_EDGE_PRX_LINK_SHAPE
