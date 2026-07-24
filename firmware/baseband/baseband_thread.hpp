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

#ifndef __BASEBAND_THREAD_H__
#define __BASEBAND_THREAD_H__

#include "thread_base.hpp"
#include "message.hpp"
#include "baseband_processor.hpp"

#include <ch.h>

/* NB: Because ThreadBase threads start when then are initialized (by default),
 * they should be the last members in a Processor class to ensure the rest of the
 * members are fully initialized before data handling starts. If the Procressor
 * needs to do additional initialization (in its ctor), set 'auto_start' to false
 * and manually call 'start()' on the thread. */

class BasebandThread : public ThreadBase {
   public:
    BasebandThread(
        uint32_t sampling_rate,
        BasebandProcessor* const baseband_processor,
        baseband::Direction direction,
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        baseband::sample_t* precision_rx_dma_loan,
#endif
        bool auto_start = true,
        tprio_t priority = (NORMALPRIO + 20));
    ~BasebandThread();

    BasebandThread(const BasebandThread&) = delete;
    BasebandThread(BasebandThread&&) = delete;
    BasebandThread& operator=(const BasebandThread&) = delete;
    BasebandThread& operator=(BasebandThread&&) = delete;

    void start() override;

    // This getter should die, it's just here to leak information to code that
    // isn't in the right place to begin with.
    baseband::Direction direction() const {
        return direction_;
    }

    void set_sampling_rate(uint32_t new_sampling_rate);
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    bool set_precision_rx_capture_geometry(bool capture);
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    bool prepare_precision_rx_rate_change();
    bool resume_precision_rx_rate_change();
    bool precision_rx_rate_pause_armed() const;
    bool precision_rx_rate_paused() const;
    bool precision_rx_dma_faulted_locked() const;
    bool precision_rx_dma_faulted() const;
    bool begin_precision_rx_rate_state_update() const;
    void end_precision_rx_rate_state_update() const;
    bool precision_rx_worker_quiesced() const;
    void fail_close_precision_rx();
#endif

   private:
    static Thread* thread;
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    static bool precision_rx_worker_quiesced_;
    static void publish_precision_rx_worker_quiesced(bool quiesced);
#endif

    BasebandProcessor* baseband_processor_;
    baseband::Direction direction_;
    uint32_t sampling_rate_;
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    baseband::sample_t* precision_rx_dma_loan_;
#endif
    const tprio_t priority_;

    void run() override;
};

#endif /*__BASEBAND_THREAD_H__*/
