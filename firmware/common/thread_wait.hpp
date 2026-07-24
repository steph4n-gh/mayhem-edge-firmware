/*
 * Copyright (C) 2016 Jared Boone, ShareBrained Technology, Inc.
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

#ifndef __THREAD_WAIT_H__
#define __THREAD_WAIT_H__

#include <ch.h>
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
#include <cstdint>
#endif

class ThreadWait {
   public:
    int sleep();
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    /*
     * The caller already holds the ChibiOS system lock. This primitive lets a
     * producer queue be checked and the waiter installed in one critical
     * section, eliminating the empty-check/sleep race.
     */
    int sleep_locked(uint8_t volatile* armed = nullptr);
#endif
    bool wake_from_interrupt(const int value);
    void reset() { thread_to_wake = nullptr; }
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    bool is_waiting_locked() const { return thread_to_wake != nullptr; }
#endif

   private:
    Thread* thread_to_wake{nullptr};
};

#endif /*__THREAD_WAIT_H__*/
