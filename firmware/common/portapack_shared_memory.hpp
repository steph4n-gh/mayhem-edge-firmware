/*
 * Copyright (C) 2015 Jared Boone, ShareBrained Technology, Inc.
 * Copyright (C) 2016 Furrtek
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

#ifndef __PORTAPACK_SHARED_MEMORY_H__
#define __PORTAPACK_SHARED_MEMORY_H__

#include <cstdint>
#include <cstddef>

#include "message_queue.hpp"

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
namespace precision_rx {
namespace dma_telemetry {

/*
 * P15 keeps the SharedMemory ABI fixed by packing the durable quiesce-failure
 * reason into the high nibble of the existing transition-failure word. The
 * remaining 28 bits retain a saturating lifetime failure count.
 */
enum class QuiesceFailure : uint32_t {
    None = 0,
    CounterUnavailable = 1,
    ActiveDrainTimeout = 2,
    DmaErrorBeforeHalt = 3,
    DmaErrorDuringDrain = 4,
    DmaErrorAfterDrain = 5,
    DmaErrorAfterDisable = 6,
    ChannelDisabled = 7,
    ActiveReassertedAfterGate = 8,
};

constexpr uint32_t quiesce_failure_shift = 28U;
constexpr uint32_t transition_failure_count_mask =
    (uint32_t{1U} << quiesce_failure_shift) - 1U;
constexpr uint32_t quiesce_failure_mask =
    ~transition_failure_count_mask;

constexpr uint32_t transition_failure_count(const uint32_t encoded) {
    return encoded & transition_failure_count_mask;
}

constexpr QuiesceFailure quiesce_failure(const uint32_t encoded) {
    return static_cast<QuiesceFailure>(
        (encoded & quiesce_failure_mask) >> quiesce_failure_shift);
}

constexpr uint32_t with_quiesce_failure(
    const uint32_t encoded,
    const QuiesceFailure reason) {
    return transition_failure_count(encoded) |
           (static_cast<uint32_t>(reason) << quiesce_failure_shift);
}

constexpr uint32_t increment_transition_failure(const uint32_t encoded) {
    const uint32_t count = transition_failure_count(encoded);
    return (encoded & quiesce_failure_mask) |
           (count == transition_failure_count_mask ? count : count + 1U);
}

static_assert(
    static_cast<uint32_t>(QuiesceFailure::ActiveReassertedAfterGate) < 16U);
static_assert(
    increment_transition_failure(
        with_quiesce_failure(0U, QuiesceFailure::ActiveDrainTimeout)) ==
    0x20000001U);
static_assert(
    increment_transition_failure(0x2fffffffU) == 0x2fffffffU);

}  // namespace dma_telemetry
}  // namespace precision_rx
#endif

struct JammerChannel {
    bool enabled;
    uint64_t center;
    uint32_t width;
    uint32_t duration;
};

struct HopperChannel {
    bool enabled;
    uint64_t center;
    uint32_t width;
    uint32_t duration;
};

struct ToneDef {
    uint32_t delta;
    uint32_t duration;
};

struct ToneData {
    ToneDef tone_defs[32];
    uint32_t silence;
    uint8_t message[256];
};

/* NOTE: These structures must be located in the same location in both M4 and M0 binaries */
struct SharedMemory {
    static constexpr size_t application_queue_k = 11;
    static constexpr size_t app_local_queue_k = 11;
    // bb_data doubles as the M4 hard-fault context mailbox. Segmented
    // Precision RX code may use only bytes after this reserved prefix.
    static constexpr size_t m4_panic_context_reserved_bytes = 112;

    uint8_t application_queue_data[1 << application_queue_k]{0};
    uint8_t app_local_queue_data[1 << app_local_queue_k]{0};
    const Message* volatile baseband_message{nullptr};
    MessageQueue application_queue{application_queue_data, application_queue_k};
    MessageQueue app_local_queue{app_local_queue_data, app_local_queue_k};

    char m4_panic_msg[32]{0};

    union {
        ToneData tones_data;
        struct {
            JammerChannel jammer_channels[80];
            HopperChannel hopper_channels[24];
        } dummy_seperate;
        uint8_t data[512];
    } bb_data{{{{0, 0}}, 0, {0}}};

    // Set by the M4 to indicate that the baseband app is ready.
    bool volatile baseband_ready{false};
    void clear_baseband_ready() { baseband_ready = false; }
    void set_baseband_ready() { baseband_ready = true; }

    uint8_t volatile request_m4_performance_counter{0};
    uint8_t volatile m4_performance_counter{0};
    uint16_t volatile m4_stack_usage{0};
    uint32_t volatile m4_heap_usage{0};
    uint16_t volatile m4_buffer_missed{0};
    uint8_t volatile radio_tx_drain{0};  // to indicate the baseband thread to drain the tx buffer, and wait for it, before radio::disable()
#ifdef PRALINE
    // Phase 0 instrumentation counters for PRALINE radio debugging
    uint32_t volatile m4_dma_xfr_count{0};    // DMA transfer_complete() calls
    uint32_t volatile m4_dma_wait_count{0};   // wait_for_buffer() calls
    uint32_t volatile m4_baseband_loops{0};   // Main loop iterations
    uint8_t volatile m4_streaming_marker{0};  // Proves streaming_enable() called
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    /*
     * Appended p12 Precision RX telemetry. Keep the legacy prefix unchanged so
     * unrelated M4 images remain layout-compatible when this private profile
     * is enabled only for the Precision RX baseband image.
     */
    uint32_t volatile m4_dma_missed_lifetime{0};
    uint32_t volatile m4_dma_tc_total{0};
    uint32_t volatile m4_dma_queue_dropped{0};
    uint32_t volatile m4_dma_reuse_dropped{0};
    uint32_t volatile m4_dma_error_dropped{0};
    uint32_t volatile m4_dma_boundary_discarded{0};
    uint32_t volatile m4_dma_rate_hz{0};
    uint32_t volatile m4_dma_transaction_id{0};
    uint32_t volatile m4_dma_transition_failures{0};
    uint8_t volatile m4_dma_queue_depth{0};
    uint8_t volatile m4_dma_queue_high_water{0};
    uint8_t volatile m4_dma_phase{0};
    uint8_t volatile m4_dma_rate_state{0};
#endif
};

extern SharedMemory& shared_memory;

#endif /*__PORTAPACK_SHARED_MEMORY_H__*/
