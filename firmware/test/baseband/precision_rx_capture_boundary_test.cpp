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

#include "precision_rx_capture_boundary.hpp"
#include "precision_rx_metrics.hpp"

#include "doctest.h"

#include <array>

TEST_CASE("Precision RX OPEN brackets setup loss before the capture boundary") {
    precision_rx::CaptureBoundaryState boundary_state;
    precision_rx::MetricsAccumulator metrics;
    metrics.configure(1'000'000, 7);

    const auto boundary_a = boundary_state.advance_open({
        metrics.input_tick(),
        metrics.dropped_input_samples(),
    });
    CHECK(boundary_a.prepares());
    CHECK_FALSE(boundary_a.acknowledges_open());
    CHECK_FALSE(boundary_state.active());

    /* One 2,048-sample DMA transfer is missed while OPEN is prepared. */
    metrics.mark_input_drop(2'048);
    const auto boundary_b = boundary_state.advance_open({
        metrics.input_tick(),
        metrics.dropped_input_samples(),
    });
    CHECK_FALSE(boundary_b.prepares());
    CHECK(boundary_b.acknowledges_open());
    CHECK(boundary_state.active());
    CHECK(boundary_b.capture_start.input_tick == 2'048);
    CHECK(boundary_b.capture_start.dropped_input_samples == 2'048);
    metrics.begin_capture_interval();

    metrics.mark_input_drop(2'048);
    const precision_rx::CaptureBoundaryPoint lossy_stop{
        metrics.input_tick(),
        metrics.dropped_input_samples(),
    };
    CHECK(precision_rx::capture_interval_has_input_loss(
        boundary_b.capture_start,
        lossy_stop));
    CHECK(boundary_state.end_capture());
    CHECK_FALSE(boundary_state.active());

    /* A later capture starts from its own boundary and inherits no old loss. */
    const auto next_boundary_a = boundary_state.advance_open(lossy_stop);
    CHECK(next_boundary_a.prepares());
    CHECK_FALSE(next_boundary_a.acknowledges_open());

    std::array<complex8_t, 16> clean_samples{};
    CHECK_FALSE(metrics.observe_block(clean_samples.data(), clean_samples.size()));
    const precision_rx::CaptureBoundaryPoint clean_start{
        metrics.input_tick(),
        metrics.dropped_input_samples(),
    };
    const auto next_boundary_b = boundary_state.advance_open(clean_start);
    CHECK(next_boundary_b.acknowledges_open());
    CHECK(next_boundary_b.capture_start.input_tick == clean_start.input_tick);
    CHECK(next_boundary_b.capture_start.dropped_input_samples ==
          clean_start.dropped_input_samples);
    metrics.begin_capture_interval();

    CHECK_FALSE(metrics.observe_block(clean_samples.data(), clean_samples.size()));
    const precision_rx::CaptureBoundaryPoint clean_stop{
        metrics.input_tick(),
        metrics.dropped_input_samples(),
    };
    CHECK_FALSE(precision_rx::capture_interval_has_input_loss(
        next_boundary_b.capture_start,
        clean_stop));
    CHECK(boundary_state.end_capture());
    CHECK_FALSE(boundary_state.active());
}

TEST_CASE("Precision RX failed preparation returns OPEN to idle") {
    precision_rx::CaptureBoundaryState boundary_state;
    CHECK(boundary_state.advance_open({1, 0}).prepares());

    boundary_state.cancel_open();
    CHECK_FALSE(boundary_state.active());
    CHECK(boundary_state.advance_open({2, 0}).prepares());
    CHECK(boundary_state.advance_open({3, 0}).acknowledges_open());
    CHECK(boundary_state.active());
}
