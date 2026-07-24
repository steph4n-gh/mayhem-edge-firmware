/*
 * Copyright (C) 2014 Jared Boone, ShareBrained Technology, Inc.
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

#include "baseband_thread.hpp"

#include "dsp_types.hpp"

#include "baseband.hpp"
#include "baseband_sgpio.hpp"
#include "baseband_dma.hpp"

#include "rssi.hpp"
#include "i2s.hpp"
using namespace lpc43xx;

#include "portapack_shared_memory.hpp"

#include "utility.hpp"

#include <array>

static baseband::SGPIO baseband_sgpio;

WORKING_AREA(baseband_thread_wa, 4096);

Thread* BasebandThread::thread = nullptr;
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
#define HACKRF_EDGE_PRX_LINK_SHAPE \
    __attribute__((noinline, noclone, optimize("Os")))
bool BasebandThread::precision_rx_worker_quiesced_ = true;

void BasebandThread::publish_precision_rx_worker_quiesced(
    const bool quiesced) {
    chSysLock();
    precision_rx_worker_quiesced_ = quiesced;
    __DMB();
    chSysUnlock();
}
#else
#define HACKRF_EDGE_PRX_LINK_SHAPE
#endif

HACKRF_EDGE_PRX_LINK_SHAPE
BasebandThread::BasebandThread(
    uint32_t sampling_rate,
    BasebandProcessor* const baseband_processor,
    baseband::Direction direction,
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    baseband::sample_t* const precision_rx_dma_loan,
#endif
    bool auto_start,
    tprio_t priority)
    : baseband_processor_{baseband_processor},
      direction_{direction},
      sampling_rate_{sampling_rate},
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
      precision_rx_dma_loan_{precision_rx_dma_loan},
#endif
      priority_{priority} {
    if (auto_start) start();
}

BasebandThread::~BasebandThread() {
    if (thread) {
        chThdTerminate(thread);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        /*
         * Publish termination first, then durably wake any normal or paused
         * waiter without touching SGPIO, DMA E, descriptors, or ownership.
         * The worker owns the terminal H -> ACTIVE-clear -> gate -> E
         * transaction below; exceptional callers retain fail_close_precision_rx.
         */
        baseband::dma::wake_precision_rx_worker_for_shutdown();
#endif
        chThdWait(thread);
        thread = nullptr;
    }
}

void BasebandThread::start() {
    if (!thread) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        publish_precision_rx_worker_quiesced(false);
#endif
        thread = chThdCreateStatic(
            baseband_thread_wa, sizeof(baseband_thread_wa),
            priority_, ThreadBase::fn, this);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        if (!thread)
            publish_precision_rx_worker_quiesced(true);
#endif
    }
}

void BasebandThread::set_sampling_rate(uint32_t new_sampling_rate) {
    sampling_rate_ = new_sampling_rate;
}

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
bool BasebandThread::set_precision_rx_capture_geometry(const bool capture) {
#if !defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    baseband_sgpio.streaming_disable();
#endif
    chSysLock();
    const bool configured =
        baseband::dma::set_precision_rx_capture_geometry(capture);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    bool gate_opened = false;
    if (configured) {
        baseband::dma::enable_precision_rx();
        /*
         * Keep the fatal-latch test and SGPIO restart in one system-locked
         * interval. A failed HALT never closed the gate, so only a successful
         * geometry restart is permitted to touch HOST_DISABLE here.
         */
        if (!baseband::dma::precision_rx_dma_faulted_locked())
            gate_opened =
                baseband::dma::open_precision_rx_sgpio_gate_locked();
    }
    chSysUnlock();
    return configured && gate_opened;
#else
    chSysUnlock();
    if (configured) {
        baseband::dma::enable_precision_rx();
    }
    /* On timeout the lower layer cleared H without ever clearing E. */
    baseband_sgpio.streaming_enable();
    return configured;
#endif
}
#endif

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
bool BasebandThread::prepare_precision_rx_rate_change() {
    chSysLock();
    const bool paused = baseband::dma::pause_precision_rx_rate_change();
    chSysUnlock();
    return paused;
}

__attribute__((noinline, noclone, optimize("Os")))
bool BasebandThread::resume_precision_rx_rate_change() {
    chSysLock();
    const bool resumed = baseband::dma::resume_precision_rx_rate_change();
    const bool gate_opened =
        resumed &&
        baseband::dma::open_precision_rx_sgpio_gate_locked();
    chSysUnlock();
    return resumed && gate_opened;
}

bool BasebandThread::precision_rx_rate_pause_armed() const {
    return baseband::dma::precision_rx_rate_pause_armed();
}

bool BasebandThread::precision_rx_rate_paused() const {
    return baseband::dma::precision_rx_rate_paused();
}

bool BasebandThread::precision_rx_dma_faulted_locked() const {
    return baseband::dma::precision_rx_dma_faulted_locked();
}

bool BasebandThread::precision_rx_dma_faulted() const {
    return baseband::dma::precision_rx_dma_faulted();
}

bool BasebandThread::begin_precision_rx_rate_state_update() const {
    return baseband::dma::begin_precision_rx_rate_state_update();
}

void BasebandThread::end_precision_rx_rate_state_update() const {
    baseband::dma::end_precision_rx_rate_state_update();
}

bool BasebandThread::precision_rx_worker_quiesced() const {
    chSysLock();
    const bool quiesced = precision_rx_worker_quiesced_;
    chSysUnlock();
    return quiesced;
}

__attribute__((noinline, noclone, optimize("Os")))
void BasebandThread::fail_close_precision_rx() {
    baseband_sgpio.streaming_disable();
    baseband::dma::stop_precision_rx_for_shutdown();
}
#endif

void BasebandThread::run() {
    baseband_sgpio.init();
    baseband::dma::init();

    const auto baseband_buffer =
        std::make_unique<std::array<baseband::sample_t, baseband::dma::buffer_samples>>();
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    if (!baseband::dma::configure_precision_rx_lease(
            baseband_buffer->data(), precision_rx_dma_loan_)) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        publish_precision_rx_worker_quiesced(true);
#endif
        return;
    }
#else
    baseband::dma::configure(baseband_buffer->data(), direction());
#endif
    // baseband::dma::allocate(4, 2048);

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    baseband_sgpio.configure(baseband::Direction::Receive);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    chSysLock();
    baseband::dma::enable_precision_rx();
    if (!baseband::dma::precision_rx_dma_faulted_locked())
        baseband::dma::open_precision_rx_sgpio_gate_locked();
    chSysUnlock();
#else
    baseband::dma::enable_precision_rx();
#endif
#else
    baseband_sgpio.configure(direction());
    baseband::dma::enable(direction());
#endif
#if !defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    baseband_sgpio.streaming_enable();
#endif
#ifdef PRALINE
    shared_memory.m4_streaming_marker = 0xAA;  // Phase 0 instrumentation
#endif
    uint8_t buffer_drained = 0;  // to count how many dma buffers we already emptied
    while (!chThdShouldTerminate()) {
#ifdef PRALINE
        shared_memory.m4_baseband_loops++;  // Phase 0 instrumentation
#endif

        // TODO: Place correct sampling rate into buffer returned here:
        const auto buffer_tmp = baseband::dma::wait_for_buffer();
        if (buffer_tmp) {
            buffer_c8_t buffer{
                buffer_tmp.p, buffer_tmp.count, sampling_rate_};

            if (shared_memory.request_m4_performance_counter == 0x02) {
                uint8_t max = shared_memory.m4_performance_counter;
                for (size_t i = 0; i < buffer_tmp.count; i++) {
                    int8_t a = buffer_tmp.p[i].real();
                    if (a < 0)
                        a = -a;

                    if (a > max)
                        max = a;
                }

                shared_memory.m4_performance_counter = max;
            }

            if (baseband_processor_) {
                if (shared_memory.radio_tx_drain == 0) {  // only generate if not draining.
                    baseband_processor_->execute(buffer);
                }
            }
            if (shared_memory.radio_tx_drain == 1) {
                buffer_drained++;
                if (buffer_drained >= 4) {             // We have 4 buffers, so after draining 4 we should be safe to disable.
                    shared_memory.radio_tx_drain = 0;  // Clear the drain request to allow normal operation to resume.
                    buffer_drained = 0;
                }
            }
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
            baseband::dma::release_buffer();
#endif
        }
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        else if (baseband::dma::precision_rx_dma_faulted()) {
            baseband_sgpio.streaming_disable();
            break;
        }
#endif
    }
    shared_memory.radio_tx_drain = 0;
    i2s::i2s0::tx_mute();
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    if (!baseband::dma::quiesce_precision_rx_for_shutdown()) {
        /*
         * Never reclaim the local ring or the processor-owned loan while an
         * AHB write may still complete. A stuck ACTIVE bit is an unrecoverable
         * hardware invariant failure, so halt before either owner unwinds.
         */
        chSysHalt();
    }
    publish_precision_rx_worker_quiesced(true);
#else
    baseband::dma::disable();
    baseband_sgpio.streaming_disable();
#endif
}

#undef HACKRF_EDGE_PRX_LINK_SHAPE
