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

#include "buffer_exchange.hpp"

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC) && \
    defined(LPC43XX_M0)
#include "portapack_shared_memory.hpp"
#endif

#if defined(__arm__) && defined(LPC43XX_M0) && \
    defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
__asm__(
    ".global hackrf_edge_precision_rx_m0_fault_watchdog_ms\n"
    ".type hackrf_edge_precision_rx_m0_fault_watchdog_ms, %object\n"
    ".set hackrf_edge_precision_rx_m0_fault_watchdog_ms, 10\n"
    ".size hackrf_edge_precision_rx_m0_fault_watchdog_ms, 1\n");
#endif

BufferExchange* BufferExchange::obj{nullptr};

BufferExchange::BufferExchange(
    CaptureConfig* const config)  // : config_capture { config }
{
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    config_capture = config;
#endif
    obj = this;
    // In capture mode, baseband wants empty buffers, app waits for full buffers
    fifo_buffers_for_baseband = config->fifo_buffers_empty;
    fifo_buffers_for_application = config->fifo_buffers_full;
}

BufferExchange::BufferExchange(
    ReplayConfig* const config)  // : config_replay { config }
{
    obj = this;
    // In replay mode, baseband wants full buffers, app waits for empty buffers
    fifo_buffers_for_baseband = config->fifo_buffers_full;
    fifo_buffers_for_application = config->fifo_buffers_empty;
}

BufferExchange::~BufferExchange() {
    obj = nullptr;
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    config_capture = nullptr;
#endif
    fifo_buffers_for_baseband = nullptr;
    fifo_buffers_for_application = nullptr;
}

StreamBuffer* BufferExchange::get(FIFO<StreamBuffer*>* fifo) {
    while (true) {
        /*
         * Lock before the empty check so an M4 event cannot arrive between
         * that check and publication of the sleeping thread. Otherwise the
         * one terminal seal event can be lost and leave capture shutdown
         * asleep forever with a full buffer waiting.
         */
        chSysLock();
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC) && \
    defined(LPC43XX_M0)
        const bool precision_capture =
            direction == CAPTURE && config_capture &&
            config_capture->precision_rx_final_report != nullptr;
        if (precision_capture) {
            __DMB();
            if (shared_memory.m4_dma_rate_state == 5U) {
                config_capture->application_abort_requested = true;
                __DMB();
                thread = nullptr;
                chSysUnlock();
                return nullptr;
            }
        }
#endif
        StreamBuffer* p{nullptr};
        fifo->out(p);

        if (p) {
            thread = nullptr;
            chSysUnlock();
            return p;
        }

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        if (direction == CAPTURE && config_capture &&
            config_capture->application_abort_requested &&
            config_capture->baseband_producer_sealed) {
            thread = nullptr;
            chSysUnlock();
            return nullptr;
        }
#endif

        // Put thread to sleep, woken up by M4 IRQ
        thread = chThdSelf();
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC) && \
    defined(LPC43XX_M0)
        if (precision_capture) {
            chSchGoSleepTimeoutS(
                THD_STATE_SUSPENDED, MS2ST(10));
            /*
             * wakeup_isr() may already have cleared this pointer. Clear it
             * again while locked after both event wake and timeout so no ISR
             * can retain a stale CaptureThread address.
             */
            thread = nullptr;
            __DMB();
            if (shared_memory.m4_dma_rate_state == 5U) {
                config_capture->application_abort_requested = true;
                __DMB();
                chSysUnlock();
                return nullptr;
            }
        } else {
            chSchGoSleepS(THD_STATE_SUSPENDED);
            thread = nullptr;
        }
#else
        chSchGoSleepS(THD_STATE_SUSPENDED);
#endif
        chSysUnlock();
    }
}

StreamBuffer* BufferExchange::get_prefill(FIFO<StreamBuffer*>* fifo) {
    StreamBuffer* p{nullptr};
    fifo->out(p);

    return p;
}
