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

#include "thread_wait.hpp"

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
#include "hal.h"
#endif

int ThreadWait::sleep() {
    chSysLock();
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    const auto result = sleep_locked();
#else
    thread_to_wake = chThdSelf();
    chSchGoSleepS(THD_STATE_SUSPENDED);
    const auto result = chThdSelf()->p_u.rdymsg;
#endif
    chSysUnlock();
    return result;
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
int ThreadWait::sleep_locked(uint8_t volatile* const armed) {
    thread_to_wake = chThdSelf();
    if (armed) {
        /*
         * Publish the ordinary waiter before declaring a paused DMA worker
         * armed. A subsequent first terminal-count IRQ can therefore only
         * enqueue and wake a fully installed waiter.
         */
        __DMB();
        *armed = 1U;
        __DMB();
    }
    chSchGoSleepS(THD_STATE_SUSPENDED);
    return chThdSelf()->p_u.rdymsg;
}
#endif

bool ThreadWait::wake_from_interrupt(const int value) {
    if (thread_to_wake) {
        thread_to_wake->p_u.rdymsg = value;
        chSchReadyI(thread_to_wake);
        thread_to_wake = nullptr;
        return true;
    } else {
        return false;
    }
}
