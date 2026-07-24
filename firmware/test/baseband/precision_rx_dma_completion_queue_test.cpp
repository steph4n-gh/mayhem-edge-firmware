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
#include <limits>

#include "precision_rx_dma_completion_queue.hpp"

namespace {

using Completion = baseband::dma::PrecisionRxDmaCompletion;

void check_completion(
    const Completion& completion,
    const std::size_t descriptor_index,
    const uint32_t completion_sequence) {
    CHECK(completion.descriptor_index == descriptor_index);
    CHECK(completion.completion_sequence == completion_sequence);
}

} /* namespace */

TEST_CASE("Precision RX DMA completion queue preserves FIFO order at depth three") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;

    CHECK(queue.capacity() == 3U);
    CHECK(queue.empty());
    CHECK(queue.size() == 0U);
    CHECK(queue.high_water_mark() == 0U);

    CHECK(queue.push({0U, 10U}).accepted);
    CHECK(queue.push({1U, 11U}).accepted);
    CHECK(queue.push({2U, 12U}).accepted);
    CHECK(queue.size() == 3U);
    CHECK(queue.high_water_mark() == 3U);

    Completion completion{};
    REQUIRE(queue.pop(completion));
    check_completion(completion, 0U, 10U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 1U, 11U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 2U, 12U);
    CHECK(queue.empty());
    CHECK_FALSE(queue.pop(completion));
}

TEST_CASE("Precision RX DMA completion queue preserves FIFO order across ring wrap") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;
    Completion completion{};

    queue.push({0U, 20U});
    queue.push({1U, 21U});
    REQUIRE(queue.pop(completion));
    check_completion(completion, 0U, 20U);

    queue.push({2U, 22U});
    queue.push({3U, 23U});
    REQUIRE(queue.pop(completion));
    check_completion(completion, 1U, 21U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 2U, 22U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 3U, 23U);
}

TEST_CASE("Precision RX DMA completion queue rejects a full producer without eviction") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;

    queue.push({0U, 30U});
    queue.push({1U, 31U});
    queue.push({2U, 32U});
    const auto result = queue.push({3U, 33U});

    REQUIRE_FALSE(result.accepted);
    CHECK(queue.size() == 3U);
    CHECK(queue.high_water_mark() == 3U);

    Completion completion{};
    REQUIRE(queue.pop(completion));
    check_completion(completion, 0U, 30U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 1U, 31U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 2U, 32U);
}

TEST_CASE("Precision RX DMA completion queue high-water mark tracks retained depth") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;
    Completion completion{};

    queue.push({0U, 40U});
    queue.push({1U, 41U});
    CHECK(queue.high_water_mark() == 2U);
    REQUIRE(queue.pop(completion));
    CHECK(queue.size() == 1U);
    CHECK(queue.high_water_mark() == 2U);
    queue.push({2U, 42U});
    CHECK(queue.high_water_mark() == 2U);
    queue.push({3U, 43U});
    CHECK(queue.high_water_mark() == 3U);
}

TEST_CASE("Precision RX DMA completion queue stores uint32 sequence wrap unchanged") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;
    const auto maximum = std::numeric_limits<uint32_t>::max();

    queue.push({2U, maximum - 1U});
    queue.push({3U, maximum});
    queue.push({0U, 0U});

    Completion completion{};
    REQUIRE(queue.pop(completion));
    check_completion(completion, 2U, maximum - 1U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 3U, maximum);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 0U, 0U);
}

TEST_CASE("Precision RX DMA completion queue reset clears depth and history") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;

    queue.push({0U, 50U});
    queue.push({1U, 51U});
    REQUIRE(queue.high_water_mark() == 2U);
    queue.reset();

    CHECK(queue.empty());
    CHECK(queue.size() == 0U);
    CHECK(queue.high_water_mark() == 0U);

    Completion completion{};
    CHECK_FALSE(queue.pop(completion));
    CHECK(queue.push({2U, 52U}).accepted);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 2U, 52U);
}

TEST_CASE("Precision RX DMA lifetime counters saturate instead of wrapping") {
    volatile uint32_t value = std::numeric_limits<uint32_t>::max() - 1U;

    baseband::dma::precision_rx_dma_saturating_increment(value);
    CHECK(value == std::numeric_limits<uint32_t>::max());
    baseband::dma::precision_rx_dma_saturating_increment(value);
    CHECK(value == std::numeric_limits<uint32_t>::max());
}

TEST_CASE("Precision RX DMA reuse begins at exactly three later completions") {
    using baseband::dma::precision_rx_dma_descriptor_reused;

    CHECK_FALSE(precision_rx_dma_descriptor_reused(102U, 100U, 3U));
    CHECK(precision_rx_dma_descriptor_reused(103U, 100U, 3U));
    CHECK(precision_rx_dma_descriptor_reused(0U, UINT32_MAX - 2U, 3U));
}

TEST_CASE("Precision RX ISR fail-closes one completion before in-flight reuse") {
    using baseband::dma::precision_rx_dma_claim_too_late;
    using baseband::dma::precision_rx_dma_descriptor_reused;
    using baseband::dma::precision_rx_dma_in_flight_must_fail_close;

    CHECK_FALSE(precision_rx_dma_in_flight_must_fail_close(
        101U, 100U, 3U));
    CHECK(precision_rx_dma_in_flight_must_fail_close(
        102U, 100U, 3U));
    CHECK(precision_rx_dma_claim_too_late(
        102U, 100U, 3U));
    CHECK_FALSE(precision_rx_dma_descriptor_reused(
        102U, 100U, 3U));
    CHECK(precision_rx_dma_descriptor_reused(
        103U, 100U, 3U));

    CHECK_FALSE(precision_rx_dma_in_flight_must_fail_close(
        UINT32_MAX, UINT32_MAX - 1U, 3U));
    CHECK(precision_rx_dma_in_flight_must_fail_close(
        0U, UINT32_MAX - 1U, 3U));
}

TEST_CASE("Precision RX producer sees the oldest claim at its fail-close age") {
    using baseband::dma::precision_rx_dma_claim_too_late;

    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;
    queue.push({0U, 100U});
    queue.push({1U, 101U});
    queue.push({2U, 102U});

    Completion completion{};
    REQUIRE(queue.peek(completion));
    check_completion(completion, 0U, 100U);
    REQUIRE(precision_rx_dma_claim_too_late(
        102U, completion.completion_sequence, 3U));

    /*
     * The production fast ISR gates at n+2 before it attempts to publish that
     * completion. Existing FIFO ownership remains unchanged for deferred
     * fail-close accounting.
     */
    REQUIRE(queue.pop(completion));
    check_completion(completion, 0U, 100U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 1U, 101U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 2U, 102U);
}

TEST_CASE("Precision RX queue retains an ISR completion before the worker checks") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;
    Completion completion{};

    CHECK(queue.push({1U, 60U}).accepted);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 1U, 60U);
    CHECK(queue.empty());
}

TEST_CASE("Precision RX queue retains an ISR completion after the worker arms") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;
    Completion completion{};

    /* Empty check/arm happens before the ISR; the queue is the durable wake. */
    CHECK_FALSE(queue.pop(completion));
    CHECK(queue.push({2U, 61U}).accepted);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 2U, 61U);
}

TEST_CASE("Precision RX queue retains multiple IRQs while the worker is awake") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;

    CHECK(queue.push({0U, 70U}).accepted);
    CHECK(queue.push({1U, 71U}).accepted);
    CHECK(queue.push({2U, 72U}).accepted);
    CHECK(queue.size() == 3U);
    CHECK(queue.high_water_mark() == 3U);

    Completion completion{};
    REQUIRE(queue.pop(completion));
    check_completion(completion, 0U, 70U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 1U, 71U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 2U, 72U);
}

TEST_CASE("Precision RX boundary reset excludes old-ring completions") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;

    queue.push({0U, 80U});
    queue.push({1U, 81U});
    queue.reset();
    queue.push({2U, 1U});

    Completion completion{};
    REQUIRE(queue.pop(completion));
    check_completion(completion, 2U, 1U);
    CHECK_FALSE(queue.pop(completion));
}

TEST_CASE("Precision RX one-shot backlog probe reports exact retained depth") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;
    Completion completion{};

    CHECK_FALSE(queue.pop(completion));
    queue.push({0U, 90U});
    queue.push({1U, 91U});
    CHECK(queue.size() == 2U);
    CHECK(queue.high_water_mark() == 2U);
    CHECK(queue.push({2U, 92U}).accepted);
    CHECK(queue.size() == 3U);
    CHECK(queue.high_water_mark() == 3U);

    REQUIRE(queue.pop(completion));
    check_completion(completion, 0U, 90U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 1U, 91U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 2U, 92U);
}

TEST_CASE("Precision RX SPSC producer and consumer interleave without changing ownership") {
    baseband::dma::PrecisionRxDmaCompletionQueue<3> queue;
    Completion completion{};

    REQUIRE(queue.push({0U, 200U}).accepted);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 0U, 200U);

    REQUIRE(queue.push({1U, 201U}).accepted);
    REQUIRE(queue.push({2U, 202U}).accepted);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 1U, 201U);

    REQUIRE(queue.push({3U, 203U}).accepted);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 2U, 202U);
    REQUIRE(queue.pop(completion));
    check_completion(completion, 3U, 203U);
    CHECK(queue.empty());
}
