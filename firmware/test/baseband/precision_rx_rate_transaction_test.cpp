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

#include "precision_rx_rate_transaction.hpp"

namespace {

namespace transaction = precision_rx::rate_transaction;
using Event = transaction::Event;
using State = transaction::State;

/*
 * This is only a caller adapter: the state decision remains the exact
 * production reducer used by PrecisionRxProcessor.
 */
bool apply(State& state, const Event event) {
    const auto transition = transaction::reduce(state, event);
    if (transition.accepted)
        state = transition.next;
    return transition.accepted;
}

} /* namespace */

TEST_CASE("Precision RX bootstrap and COMMIT publish RUN only after the first matching block") {
    State state = State::Bootstrap;

    REQUIRE(apply(state, Event::BootstrapPrepared));
    CHECK(state == State::PausedArmed);
    REQUIRE(apply(state, Event::CommitRequested));
    CHECK(state == State::Resuming);

    CHECK_FALSE(transaction::first_block_matches_commit(
        state, true, 2'000'000U, 4'000'000U));
    CHECK(transaction::first_block_matches_commit(
        state, true, 4'000'000U, 4'000'000U));
    REQUIRE(apply(state, Event::FirstBlockApplied));
    CHECK(state == State::Running);
}

TEST_CASE("Precision RX PREPARE and COMMIT success follows the production state machine") {
    State state = State::Running;

    REQUIRE(apply(state, Event::PrepareRequested));
    CHECK(state == State::PrepareRequested);
    REQUIRE(apply(state, Event::PrepareSucceeded));
    CHECK(state == State::PausedArmed);
    REQUIRE(apply(state, Event::CommitRequested));
    CHECK(state == State::Resuming);
    REQUIRE(apply(state, Event::FirstBlockApplied));
    CHECK(state == State::Running);
}

TEST_CASE("Precision RX healthy PREPARE halt timeout restores unchanged RUN") {
    State state = State::Running;

    REQUIRE(apply(state, Event::PrepareRequested));
    CHECK(
        transaction::prepare_timeout_action(false, false) ==
        transaction::PrepareTimeoutAction::RestoreRunning);
    REQUIRE(apply(state, Event::PrepareHaltRestored));
    CHECK(state == State::Running);
}

TEST_CASE("Precision RX raced PREPARE timeout or DMA fault requires explicit fail-close") {
    CHECK(
        transaction::prepare_timeout_action(true, false) ==
        transaction::PrepareTimeoutAction::FailClosed);
    CHECK(
        transaction::prepare_timeout_action(false, true) ==
        transaction::PrepareTimeoutAction::FailClosed);
    CHECK(
        transaction::prepare_timeout_action(true, true) ==
        transaction::PrepareTimeoutAction::FailClosed);

    State state = State::PrepareRequested;
    REQUIRE(apply(state, Event::Fatal));
    CHECK(state == State::Fault);
}

TEST_CASE("Precision RX arm timeout fails closed from PAUSED") {
    State state = State::PausedArmed;

    REQUIRE(apply(state, Event::Fatal));
    CHECK(state == State::Fault);
}

TEST_CASE("Precision RX COMMIT timeout rearms PAUSED and ABORT restores the old rate") {
    State state = State::PausedArmed;

    REQUIRE(apply(state, Event::CommitRequested));
    REQUIRE(apply(state, Event::ResumeRearmed));
    CHECK(state == State::PausedArmed);

    REQUIRE(apply(state, Event::AbortRequested));
    CHECK(state == State::Resuming);
    CHECK(transaction::first_block_matches_commit(
        state, true, 2'000'000U, 2'000'000U));
    REQUIRE(apply(state, Event::FirstBlockApplied));
    CHECK(state == State::Running);
}

TEST_CASE("Precision RX ABORT timeout can rearm once and then fail closed") {
    State state = State::PausedArmed;

    REQUIRE(apply(state, Event::AbortRequested));
    REQUIRE(apply(state, Event::ResumeRearmed));
    CHECK(state == State::PausedArmed);
    REQUIRE(apply(state, Event::AbortRequested));
    REQUIRE(apply(state, Event::Fatal));
    CHECK(state == State::Fault);
}

TEST_CASE("Precision RX rejects stale and out-of-order transaction events") {
    State state = State::Running;

    CHECK_FALSE(apply(state, Event::CommitRequested));
    CHECK_FALSE(apply(state, Event::AbortRequested));
    CHECK_FALSE(apply(state, Event::PrepareSucceeded));
    CHECK_FALSE(apply(state, Event::FirstBlockApplied));
    CHECK(state == State::Running);

    REQUIRE(apply(state, Event::PrepareRequested));
    CHECK_FALSE(apply(state, Event::CommitRequested));
    CHECK_FALSE(apply(state, Event::AbortRequested));
    CHECK(state == State::PrepareRequested);

    REQUIRE(apply(state, Event::PrepareSucceeded));
    REQUIRE(apply(state, Event::CommitRequested));
    CHECK_FALSE(apply(state, Event::CommitRequested));
    CHECK_FALSE(apply(state, Event::AbortRequested));
    CHECK_FALSE(apply(state, Event::PrepareRequested));
    CHECK(state == State::Resuming);
}

TEST_CASE("Precision RX first-new-rate guard excludes stale labels and incomplete configuration") {
    constexpr uint32_t old_rate_hz = 2'000'000U;
    constexpr uint32_t new_rate_hz = 8'000'000U;

    CHECK_FALSE(transaction::first_block_matches_commit(
        State::PausedArmed, true, new_rate_hz, new_rate_hz));
    CHECK_FALSE(transaction::first_block_matches_commit(
        State::Resuming, false, new_rate_hz, new_rate_hz));
    CHECK_FALSE(transaction::first_block_matches_commit(
        State::Resuming, true, old_rate_hz, new_rate_hz));
    CHECK_FALSE(transaction::first_block_matches_commit(
        State::Resuming, true, new_rate_hz, 0U));
    CHECK(transaction::first_block_matches_commit(
        State::Resuming, true, new_rate_hz, new_rate_hz));
}

TEST_CASE("Precision RX lifetime loss survives configure rate and geometry boundaries") {
    transaction::LifetimeLossObservation losses;
    losses.initialize_before_dma(7U);
    State state = State::Running;

    /* configure(current rate) */
    CHECK(losses.observed() == 7U);
    uint32_t delta = UINT32_MAX;
    REQUIRE(losses.consume(7U, delta));
    CHECK(delta == 0U);

    /* PREPARE/rate COMMIT */
    REQUIRE(apply(state, Event::PrepareRequested));
    REQUIRE(apply(state, Event::PrepareSucceeded));
    REQUIRE(apply(state, Event::CommitRequested));
    CHECK(losses.observed() == 7U);
    REQUIRE(losses.consume(9U, delta));
    CHECK(delta == 2U);
    REQUIRE(apply(state, Event::FirstBlockApplied));

    /* Capture geometry HALT/restart */
    CHECK(losses.observed() == 9U);
    REQUIRE(losses.consume(9U, delta));
    CHECK(delta == 0U);
    REQUIRE(losses.consume(10U, delta));
    CHECK(delta == 1U);
    CHECK(losses.observed() == 10U);
}

TEST_CASE("Precision RX lifetime observation fails closed on producer decrease") {
    transaction::LifetimeLossObservation losses{UINT32_MAX - 1U};
    uint32_t delta = 0U;

    REQUIRE(losses.consume(UINT32_MAX, delta));
    CHECK(delta == 1U);
    CHECK_FALSE(losses.consume(2U, delta));
    CHECK(delta == 0U);
    CHECK(losses.observed() == UINT32_MAX);
}
