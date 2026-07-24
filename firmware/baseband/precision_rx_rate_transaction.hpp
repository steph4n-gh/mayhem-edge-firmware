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

#ifndef __PRECISION_RX_RATE_TRANSACTION_H__
#define __PRECISION_RX_RATE_TRANSACTION_H__

#include <cstdint>

namespace precision_rx {
namespace rate_transaction {

/*
 * These values are a cross-core telemetry contract. Keep them synchronized
 * with the strings rendered by the M0 sysinfo command.
 */
enum class State : uint8_t {
    Bootstrap = 0,
    Running = 1,
    PrepareRequested = 2,
    PausedArmed = 3,
    Resuming = 4,
    Fault = 5,
};

/*
 * Events name the only legal state-machine edges. Hardware work happens
 * outside this reducer; callers publish an event only after the associated
 * gate/HALT/waiter or first-completion invariant has been established.
 */
enum class Event : uint8_t {
    BootstrapPrepared,
    PrepareRequested,
    PrepareSucceeded,
    PrepareHaltRestored,
    CommitRequested,
    AbortRequested,
    ResumeRearmed,
    FirstBlockApplied,
    Fatal,
};

enum class PrepareTimeoutAction : uint8_t {
    RestoreRunning,
    FailClosed,
};

struct Transition {
    State next;
    bool accepted;
};

/*
 * Convert state equality to a data dependency rather than condition-code
 * predication. State has an 8-bit underlying type, so only a zero XOR can
 * underflow this unsigned subtraction and set bit 31. Besides remaining
 * constexpr for host tests, this keeps the linked transaction proof free of
 * Thumb IT blocks that would hide one of the reducer's control-flow edges.
 */
constexpr bool state_matches(
    const State current,
    const State expected) noexcept {
    const uint32_t difference =
        static_cast<uint8_t>(current) ^ static_cast<uint8_t>(expected);
    return ((difference - 1U) >> 31U) != 0U;
}

constexpr Transition reduce(
    const State current,
    const Event event) noexcept {
    switch (event) {
        case Event::BootstrapPrepared:
            return {
                State::PausedArmed,
                state_matches(current, State::Bootstrap)};

        case Event::PrepareRequested:
            return {
                State::PrepareRequested,
                state_matches(current, State::Running)};

        case Event::PrepareSucceeded:
            return {
                State::PausedArmed,
                state_matches(current, State::PrepareRequested)};

        case Event::PrepareHaltRestored:
            return {
                State::Running,
                state_matches(current, State::PrepareRequested)};

        case Event::CommitRequested:
        case Event::AbortRequested:
            return {
                State::Resuming,
                state_matches(current, State::PausedArmed)};

        case Event::ResumeRearmed:
            return {
                State::PausedArmed,
                state_matches(current, State::Resuming)};

        case Event::FirstBlockApplied:
            return {
                State::Running,
                state_matches(current, State::Resuming)};

        case Event::Fatal:
            return {
                State::Fault,
                true};
    }

    return {State::Fault, false};
}

/*
 * A dispatcher timeout may race the worker. If the emergency PREPARE did not
 * pause and no DMA fault latched, BasebandThread has restored the unchanged
 * old ring and SGPIO gate, so rejecting in RUN is safe. Every other outcome
 * must explicitly fail-close before publishing FAULT.
 */
constexpr PrepareTimeoutAction prepare_timeout_action(
    const bool emergency_pause_succeeded,
    const bool dma_faulted) noexcept {
    return !emergency_pause_succeeded && !dma_faulted
               ? PrepareTimeoutAction::RestoreRunning
               : PrepareTimeoutAction::FailClosed;
}

constexpr bool first_block_matches_commit(
    const State state,
    const bool configuration_applied,
    const uint32_t block_rate_hz,
    const uint32_t target_rate_hz) noexcept {
    return state == State::Resuming &&
           configuration_applied &&
           target_rate_hz != 0U &&
           block_rate_hz == target_rate_hz;
}

/*
 * The observation baseline is initialized once before BasebandThread starts.
 * No configure/rate/geometry API is exposed, so those operations cannot
 * silently rebase a lifetime loss that still needs to be reported.
 */
class LifetimeLossObservation {
   public:
    constexpr LifetimeLossObservation() noexcept = default;

    constexpr explicit LifetimeLossObservation(
        const uint32_t initial) noexcept
        : observed_{initial} {
    }

    void initialize_before_dma(const uint32_t initial) noexcept {
        observed_ = initial;
    }

    bool consume(
        const uint32_t current,
        uint32_t& delta) noexcept {
        /*
         * The producer saturates and has no generation token, so a decrease
         * cannot be distinguished from corruption or an unauthorized reset.
         * Do not rebase it: the live caller must fail closed.
         */
        if (current < observed_) {
            delta = 0U;
            return false;
        }
        delta = current - observed_;
        observed_ = current;
        return true;
    }

    constexpr uint32_t observed() const noexcept {
        return observed_;
    }

   private:
    uint32_t observed_{};
};

} /* namespace rate_transaction */
} /* namespace precision_rx */

#endif /*__PRECISION_RX_RATE_TRANSACTION_H__*/
