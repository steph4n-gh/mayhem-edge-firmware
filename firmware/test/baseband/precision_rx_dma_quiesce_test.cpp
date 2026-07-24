/*
 * Copyright (C) 2026 HackRF Edge contributors.
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

#include "doctest.h"

#include <cstdint>

#include "precision_rx_dma_lease.hpp"
#include "precision_rx_dma_quiesce.hpp"
#include "portapack_shared_memory.hpp"

namespace {

namespace quiesce = precision_rx::dma_quiesce;
namespace lease = precision_rx::dma_lease;

constexpr uint32_t minimum_sample_rate_hz = 1'000'000U;
constexpr uint32_t rate_control_timeout_us = 100'000U;
constexpr uint32_t m4_counter_frequency_hz = 200'000'000U;
constexpr uint32_t slowest_monitor_descriptor_us =
    static_cast<uint32_t>(
        (static_cast<uint64_t>(lease::monitor_transfer_samples) *
             1'000'000U +
         minimum_sample_rate_hz - 1U) /
        minimum_sample_rate_hz);
constexpr uint32_t slowest_monitor_descriptor_ticks =
    quiesce::descriptor_ticks(
        lease::monitor_transfer_samples,
        minimum_sample_rate_hz,
        m4_counter_frequency_hz);

}  // namespace

TEST_CASE("Precision RX control ACTIVE drain has a reviewed DWT budget") {
    CHECK(quiesce::control_active_drain_timeout_us == 10'000U);
    CHECK(
        quiesce::control_active_drain_timeout_ticks(
            m4_counter_frequency_hz) ==
        2'000'000U);
    CHECK(slowest_monitor_descriptor_ticks == 409'600U);
    CHECK(
        quiesce::control_active_drain_timeout_ticks(
            m4_counter_frequency_hz) >
        slowest_monitor_descriptor_ticks);
    CHECK(slowest_monitor_descriptor_us == 2'048U);
    CHECK(
        quiesce::control_active_drain_timeout_us <
        rate_control_timeout_us);
}

TEST_CASE("Precision RX control ACTIVE drain deadline is exact") {
    constexpr uint32_t start = 100U;
    constexpr uint32_t timeout = 2'000'000U;

    CHECK_FALSE(quiesce::control_active_drain_deadline_reached(
        start, start + timeout - 1U, timeout));
    CHECK(quiesce::control_active_drain_deadline_reached(
        start, start + timeout, timeout));
    CHECK(quiesce::control_active_drain_deadline_reached(
        start, start + timeout + 1U, timeout));
}

TEST_CASE("Precision RX control ACTIVE drain deadline survives counter wrap") {
    constexpr uint32_t timeout = 2'000'000U;
    constexpr uint32_t start = 0xfff0'0000U;
    constexpr uint32_t before =
        static_cast<uint32_t>(start + timeout - 1U);
    constexpr uint32_t at =
        static_cast<uint32_t>(start + timeout);

    static_assert(timeout < (uint32_t{1U} << 31U));
    static_assert(before == 0x000e'847fU);
    static_assert(at == 0x000e'8480U);
    CHECK_FALSE(quiesce::control_active_drain_deadline_reached(
        start, before, timeout));
    CHECK(quiesce::control_active_drain_deadline_reached(
        start, at, timeout));
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
TEST_CASE("Precision RX quiesce reason shares a saturating failure word") {
    using precision_rx::dma_telemetry::QuiesceFailure;
    using precision_rx::dma_telemetry::increment_transition_failure;
    using precision_rx::dma_telemetry::quiesce_failure;
    using precision_rx::dma_telemetry::transition_failure_count;
    using precision_rx::dma_telemetry::transition_failure_count_mask;
    using precision_rx::dma_telemetry::with_quiesce_failure;

    const uint32_t timeout = with_quiesce_failure(
        41U, QuiesceFailure::ActiveDrainTimeout);
    CHECK(transition_failure_count(timeout) == 41U);
    CHECK(quiesce_failure(timeout) == QuiesceFailure::ActiveDrainTimeout);

    const uint32_t incremented = increment_transition_failure(timeout);
    CHECK(transition_failure_count(incremented) == 42U);
    CHECK(
        quiesce_failure(incremented) ==
        QuiesceFailure::ActiveDrainTimeout);

    const uint32_t saturated = with_quiesce_failure(
        transition_failure_count_mask,
        QuiesceFailure::CounterUnavailable);
    CHECK(increment_transition_failure(saturated) == saturated);
}
#endif
