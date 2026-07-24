/*
 * Copyright (C) 2026 HackRF Edge contributors
 *
 * This file is part of PortaPack.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */

#ifndef __PRECISION_RX_CAPTURE_BOUNDARY_H__
#define __PRECISION_RX_CAPTURE_BOUNDARY_H__

#include <cstdint>

namespace precision_rx {

struct CaptureBoundaryPoint {
    uint64_t input_tick{0};
    uint64_t dropped_input_samples{0};
};

enum class CaptureOpenAction : uint8_t {
    Prepare,
    Begin,
    Reject,
};

struct CaptureOpenBoundary {
    CaptureOpenAction action{CaptureOpenAction::Reject};
    CaptureBoundaryPoint capture_start{};

    constexpr bool prepares() const {
        return action == CaptureOpenAction::Prepare;
    }

    constexpr bool acknowledges_open() const {
        return action == CaptureOpenAction::Begin;
    }
};

/*
 * The state machine deliberately owns no counters.  Boundary B returns the
 * caller's current counters as the authoritative inclusive capture start, so
 * a subsequent OPEN cannot inherit stale values from an earlier capture.
 */
class CaptureBoundaryState {
   public:
    constexpr CaptureOpenBoundary advance_open(
        const CaptureBoundaryPoint current) {
        switch (phase_) {
            case Phase::Idle:
                phase_ = Phase::Prepared;
                return {CaptureOpenAction::Prepare, {}};

            case Phase::Prepared:
                phase_ = Phase::Active;
                return {CaptureOpenAction::Begin, current};

            case Phase::Active:
                return {CaptureOpenAction::Reject, {}};
        }
        return {CaptureOpenAction::Reject, {}};
    }

    constexpr bool active() const {
        return phase_ == Phase::Active;
    }

    constexpr bool end_capture() {
        const bool was_active = active();
        phase_ = Phase::Idle;
        return was_active;
    }

    constexpr void cancel_open() {
        phase_ = Phase::Idle;
    }

   private:
    enum class Phase : uint8_t {
        Idle,
        Prepared,
        Active,
    };

    Phase phase_{Phase::Idle};
};

static_assert(
    sizeof(CaptureBoundaryState) == sizeof(uint8_t),
    "capture boundary state must remain one byte");

constexpr bool capture_interval_has_input_loss(
    const CaptureBoundaryPoint start,
    const CaptureBoundaryPoint stop) {
    return stop.dropped_input_samples != start.dropped_input_samples;
}

}  // namespace precision_rx

#endif /*__PRECISION_RX_CAPTURE_BOUNDARY_H__*/
