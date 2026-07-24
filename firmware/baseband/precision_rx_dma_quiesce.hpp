/*
 * Copyright (C) 2026 HackRF Edge contributors
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

#ifndef __PRECISION_RX_DMA_QUIESCE_H__
#define __PRECISION_RX_DMA_QUIESCE_H__

#include <cstdint>

namespace precision_rx {
namespace dma_quiesce {

/*
 * PL080 HALT is published while SGPIO requests remain live, then ACTIVE is
 * allowed to drain before the SGPIO gate and channel E bit are closed. Ten
 * milliseconds covers more than four complete 2048-sample monitor descriptors
 * at the minimum 1 Msps rate while remaining far below the outer 100 ms
 * rate-transaction deadline.
 */
constexpr uint32_t control_active_drain_timeout_us = 10'000U;

constexpr uint32_t control_active_drain_timeout_ticks(
    const uint32_t counter_frequency_hz) {
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(counter_frequency_hz) *
             control_active_drain_timeout_us +
         999'999U) /
        1'000'000U);
}

constexpr uint32_t descriptor_ticks(
    const uint32_t descriptor_samples,
    const uint32_t sample_rate_hz,
    const uint32_t counter_frequency_hz) {
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(descriptor_samples) *
             counter_frequency_hz +
         sample_rate_hz - 1U) /
        sample_rate_hz);
}

/*
 * Unsigned subtraction makes the comparison safe across one 32-bit counter
 * wrap.  The reviewed timeout is many orders of magnitude below a full wrap.
 */
constexpr bool control_active_drain_deadline_reached(
    const uint32_t start,
    const uint32_t now,
    const uint32_t timeout_ticks) {
    return static_cast<uint32_t>(now - start) >= timeout_ticks;
}

static_assert(
    control_active_drain_timeout_ticks(200'000'000U) == 2'000'000U);
static_assert(
    descriptor_ticks(2'048U, 1'000'000U, 200'000'000U) == 409'600U);
static_assert(
    control_active_drain_timeout_ticks(200'000'000U) <
    (uint32_t{1U} << 31U));

}  // namespace dma_quiesce
}  // namespace precision_rx

#endif /*__PRECISION_RX_DMA_QUIESCE_H__*/
