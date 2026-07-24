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

#include "precision_rx_metrics.hpp"
#include "precision_rx_evidence.hpp"

#include "doctest.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <vector>

namespace {

struct Sample {
    int8_t i;
    int8_t q;
    int8_t real() const { return i; }
    int8_t imag() const { return q; }
};

std::vector<Sample> tone(
    uint32_t sample_rate,
    double frequency_hz,
    size_t count,
    int amplitude = 96,
    int dc_i = 0,
    int dc_q = 0) {
    constexpr double pi = 3.14159265358979323846;
    std::vector<Sample> samples;
    samples.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        const double phase = 2.0 * pi * frequency_hz * index / sample_rate;
        samples.push_back({
            static_cast<int8_t>(dc_i + std::lround(amplitude * std::cos(phase))),
            static_cast<int8_t>(dc_q + std::lround(amplitude * std::sin(phase))),
        });
    }
    return samples;
}

Sample mixed_reference_sample(uint64_t index) {
    static constexpr std::array<Sample, 8> tone_octants{{
        {96, 0},
        {68, 68},
        {0, 96},
        {-68, 68},
        {-96, 0},
        {-68, -68},
        {0, -96},
        {68, -68},
    }};
    static constexpr std::array<Sample, 8> rail_cases{{
        {-128, -128},
        {-126, 0},
        {-125, 125},
        {0, 126},
        {125, -125},
        {126, 0},
        {127, 127},
        {0, -126},
    }};

    switch ((index / 257U) % 5U) {
        case 0:
            return {32, -16};
        case 1:
            return tone_octants[index % tone_octants.size()];
        case 2: {
            uint32_t value = static_cast<uint32_t>(index);
            value ^= value >> 16;
            value *= 0x7feb352dU;
            value ^= value >> 15;
            value *= 0x846ca68bU;
            value ^= value >> 16;
            return {
                static_cast<int8_t>(static_cast<int32_t>(value & 0xffU) - 128),
                static_cast<int8_t>(static_cast<int32_t>((value >> 8) & 0xffU) - 128),
            };
        }
        case 3:
            return rail_cases[index % rail_cases.size()];
        default:
            return {0, 0};
    }
}

void check_accumulator_state_equal(
    const precision_rx::MetricsAccumulator& scalar,
    const precision_rx::MetricsAccumulator& fast) {
    CHECK(fast.input_tick() == scalar.input_tick());
    CHECK(fast.dropped_input_samples() == scalar.dropped_input_samples());
    CHECK(fast.stream_epoch() == scalar.stream_epoch());
    CHECK(fast.analysis_stride() == scalar.analysis_stride());
}

void check_snapshot_equal(
    const precision_rx::MetricsSnapshot& scalar,
    const precision_rx::MetricsSnapshot& fast) {
    CHECK(fast.stream_epoch == scalar.stream_epoch);
    CHECK(fast.report_sequence == scalar.report_sequence);
    CHECK(fast.continuity_flags == scalar.continuity_flags);
    CHECK(fast.capture_continuity_flags == scalar.capture_continuity_flags);
    CHECK(fast.metric_quality_flags == scalar.metric_quality_flags);
    CHECK(fast.input_sample_rate_hz == scalar.input_sample_rate_hz);
    CHECK(fast.analysis_stride == scalar.analysis_stride);
    CHECK(fast.first_input_tick == scalar.first_input_tick);
    CHECK(fast.next_input_tick == scalar.next_input_tick);
    CHECK(fast.dropped_input_samples == scalar.dropped_input_samples);
    CHECK(fast.analyzed_sample_count == scalar.analyzed_sample_count);
    CHECK(fast.sampled_clip_count == scalar.sampled_clip_count);
    CHECK(fast.mean_i_q8 == scalar.mean_i_q8);
    CHECK(fast.mean_q_q8 == scalar.mean_q_q8);
    CHECK(fast.rms_dbfs_x10 == scalar.rms_dbfs_x10);
    CHECK(fast.robust_rms_dbfs_x10 == scalar.robust_rms_dbfs_x10);
    CHECK(fast.peak_dbfs_x10 == scalar.peak_dbfs_x10);
    CHECK(fast.carrier_offset_hz_x10 == scalar.carrier_offset_hz_x10);
    CHECK(fast.carrier_delta_hz_per_s_x10 == scalar.carrier_delta_hz_per_s_x10);
    CHECK(fast.coherence_ppm == scalar.coherence_ppm);
    CHECK(fast.gain_advice == scalar.gain_advice);
}

void observe_equivalent_block(
    precision_rx::MetricsAccumulator& scalar,
    precision_rx::MetricsAccumulator& fast,
    uint64_t& source_index,
    size_t count) {
    std::vector<Sample> scalar_samples;
    std::vector<complex8_t> fast_samples;
    scalar_samples.reserve(count);
    fast_samples.reserve(count);
    for (size_t offset = 0; offset < count; ++offset) {
        const Sample sample = mixed_reference_sample(source_index + offset);
        scalar_samples.push_back(sample);
        fast_samples.emplace_back(sample.i, sample.q);
    }
    source_index += count;

    const bool scalar_due = scalar.observe_block(scalar_samples.data(), count);
    const bool fast_due = fast.observe_block(fast_samples.data(), count);
    CHECK(fast_due == scalar_due);
    check_accumulator_state_equal(scalar, fast);
}

}  // namespace

TEST_CASE("precision bounded divider matches native quotient and remainder") {
    constexpr std::array<uint64_t, 8> numerators{{
        0U,
        1U,
        UINT32_MAX,
        uint64_t{1U} << 32U,
        (uint64_t{1U} << 32U) + 1U,
        0x0123456789abcdefULL,
        UINT64_MAX - 1U,
        UINT64_MAX,
    }};
    constexpr std::array<uint32_t, 7> denominators{{
        1U,
        2U,
        3U,
        20U,
        100U,
        100'003U,
        UINT32_MAX,
    }};

    for (const uint64_t numerator : numerators) {
        for (const uint32_t denominator : denominators) {
            uint32_t remainder = UINT32_MAX;
            const uint64_t quotient =
                precision_rx::test_divide_u64_by_u32(
                    numerator, denominator, remainder);
            CHECK_EQ(quotient, numerator / denominator);
            CHECK_EQ(remainder, numerator % denominator);
        }
    }
}

TEST_CASE("precision metrics preserve input time and initial epoch evidence") {
    precision_rx::MetricsAccumulator accumulator;
    accumulator.configure(2'000'000, 7);
    std::vector<Sample> samples(200'000, {0, 0});

    CHECK(accumulator.observe_block(samples.data(), samples.size()));
    precision_rx::MetricsSnapshot snapshot;
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK(snapshot.stream_epoch == 7);
    CHECK(snapshot.report_sequence == 0);
    CHECK(snapshot.first_input_tick == 0);
    CHECK(snapshot.next_input_tick == 200'000);
    CHECK(snapshot.analysis_stride == 2);
    CHECK(snapshot.analyzed_sample_count == 100'000);
    CHECK(snapshot.rms_dbfs_x10 == -1200);
    CHECK((snapshot.continuity_flags & precision_rx::STREAM_START) != 0);
    CHECK((snapshot.continuity_flags & precision_rx::CLOCK_RESET) != 0);
    CHECK((snapshot.metric_quality_flags & precision_rx::ALIAS_LIMITED) != 0);
}

TEST_CASE("precision metrics report DC, level, clipping, and advisory gain") {
    precision_rx::MetricsAccumulator accumulator;
    accumulator.configure(1'000, 1);
    std::vector<Sample> dc(100, {32, -16});
    REQUIRE(accumulator.observe_block(dc.data(), dc.size()));
    precision_rx::MetricsSnapshot snapshot;
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK(snapshot.mean_i_q8 == 32 * 256);
    CHECK(snapshot.mean_q_q8 == -16 * 256);
    CHECK(snapshot.rms_dbfs_x10 > -130);
    CHECK(snapshot.rms_dbfs_x10 < -100);
    CHECK(snapshot.sampled_clip_count == 0);
    CHECK(snapshot.gain_advice == precision_rx::GainAdvice::Hold);

    accumulator.configure(1'000, 2);
    std::vector<Sample> clipped(100, {127, 0});
    REQUIRE(accumulator.observe_block(clipped.data(), clipped.size()));
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK(snapshot.sampled_clip_count == 100);
    CHECK((snapshot.metric_quality_flags & precision_rx::SAMPLED_CLIPPING) != 0);
    CHECK(snapshot.gain_advice == precision_rx::GainAdvice::Reduce);
}

TEST_CASE("precision metrics estimate a coherent carrier in physical hertz") {
    constexpr uint32_t sample_rate = 1'000'000;
    auto samples = tone(sample_rate, 125'000.0, sample_rate / 10);
    precision_rx::MetricsAccumulator accumulator;
    accumulator.configure(sample_rate, 3);
    REQUIRE(accumulator.observe_block(samples.data(), samples.size()));
    precision_rx::MetricsSnapshot snapshot;
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK((snapshot.metric_quality_flags & precision_rx::CARRIER_VALID) != 0);
    CHECK(snapshot.coherence_ppm > 990'000);
    CHECK(snapshot.carrier_offset_hz_x10 == doctest::Approx(1'250'000).epsilon(0.002));
    CHECK((snapshot.metric_quality_flags & precision_rx::DRIFT_VALID) == 0);

    REQUIRE(accumulator.observe_block(samples.data(), samples.size()));
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK((snapshot.metric_quality_flags & precision_rx::DRIFT_VALID) != 0);
    CHECK(snapshot.carrier_delta_hz_per_s_x10 == doctest::Approx(0).epsilon(0.002));
}

TEST_CASE("precision carrier removes DC before phase and coherence estimates") {
    constexpr uint32_t sample_rate = 1'000'000;
    auto samples = tone(sample_rate, 125'000.0, sample_rate / 10, 32, 64, -24);
    precision_rx::MetricsAccumulator accumulator;
    accumulator.configure(sample_rate, 5);
    REQUIRE(accumulator.observe_block(samples.data(), samples.size()));
    precision_rx::MetricsSnapshot snapshot;
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK((snapshot.metric_quality_flags & precision_rx::CARRIER_VALID) != 0);
    CHECK(snapshot.carrier_offset_hz_x10 == doctest::Approx(1'250'000).epsilon(0.005));

    accumulator.configure(sample_rate, 6);
    std::vector<Sample> dc(sample_rate / 10, {64, -24});
    REQUIRE(accumulator.observe_block(dc.data(), dc.size()));
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK((snapshot.metric_quality_flags & precision_rx::CARRIER_VALID) == 0);
}

TEST_CASE("precision metrics bound work at high sample rates") {
    precision_rx::MetricsAccumulator accumulator;
    accumulator.configure(20'000'000, 4);
    std::vector<Sample> samples(2'000'000, {1, 1});
    REQUIRE(accumulator.observe_block(samples.data(), samples.size()));
    precision_rx::MetricsSnapshot snapshot;
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK(snapshot.analysis_stride == 20);
    CHECK(snapshot.analyzed_sample_count == 100'000);
    CHECK(snapshot.next_input_tick == 2'000'000);
}

TEST_CASE("precision metrics advance logical time across known input loss") {
    precision_rx::MetricsAccumulator accumulator;
    accumulator.configure(1'000, 9);
    accumulator.mark_input_drop(37);
    std::vector<Sample> samples(100, {1, 0});
    REQUIRE(accumulator.observe_block(samples.data(), samples.size()));
    precision_rx::MetricsSnapshot snapshot;
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK((snapshot.continuity_flags & precision_rx::DISCONTINUITY) != 0);
    CHECK((snapshot.continuity_flags & precision_rx::DROPPED_INPUT) != 0);
    CHECK(snapshot.dropped_input_samples == 37);
    CHECK(snapshot.next_input_tick == 137);

    accumulator.configure(1'000, 10);
    REQUIRE(accumulator.observe_block(samples.data(), samples.size()));
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK(snapshot.stream_epoch == 10);
    CHECK(snapshot.report_sequence == 0);
    CHECK(snapshot.first_input_tick == 0);
}

TEST_CASE("precision gain advice uses sampled rails and release dwell") {
    precision_rx::MetricsAccumulator accumulator;
    accumulator.configure(1'000, 11);
    std::vector<Sample> sparse_rails(100, {1, 0});
    sparse_rails[0] = {126, 0};
    REQUIRE(accumulator.observe_block(sparse_rails.data(), sparse_rails.size()));
    precision_rx::MetricsSnapshot snapshot;
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK(snapshot.sampled_clip_count == 1);
    CHECK(snapshot.gain_advice == precision_rx::GainAdvice::Reduce);

    accumulator.configure(1'000, 12);
    std::vector<Sample> weak(100, {1, 0});
    for (size_t report = 0; report < 4; ++report) {
        REQUIRE(accumulator.observe_block(weak.data(), weak.size()));
        REQUIRE(accumulator.take_snapshot(snapshot));
        CHECK(snapshot.gain_advice == precision_rx::GainAdvice::Hold);
    }
    REQUIRE(accumulator.observe_block(weak.data(), weak.size()));
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK(snapshot.gain_advice == precision_rx::GainAdvice::Increase);
}

TEST_CASE("precision robust level discards the highest five percent") {
    precision_rx::MetricsAccumulator accumulator;
    accumulator.configure(1'000, 13);
    std::vector<Sample> impulsive(100, {0, 0});
    for (size_t index = 95; index < impulsive.size(); ++index) {
        impulsive[index] = {125, 125};
    }
    REQUIRE(accumulator.observe_block(impulsive.data(), impulsive.size()));
    precision_rx::MetricsSnapshot snapshot;
    REQUIRE(accumulator.take_snapshot(snapshot));
    CHECK(snapshot.sampled_clip_count == 0);
    CHECK(snapshot.rms_dbfs_x10 > -105);
    CHECK(snapshot.robust_rms_dbfs_x10 == -1200);
    CHECK(snapshot.gain_advice == precision_rx::GainAdvice::Hold);
}

TEST_CASE("precision capture interval discards pre-open partials and flushes the tail") {
    precision_rx::MetricsAccumulator accumulator;
    accumulator.configure(1'000, 14);
    std::vector<Sample> before_open(50, {80, 0});
    CHECK_FALSE(accumulator.observe_block(before_open.data(), before_open.size()));

    accumulator.begin_capture_interval();
    std::vector<Sample> capture_tail(25, {4, -2});
    CHECK_FALSE(accumulator.observe_block(capture_tail.data(), capture_tail.size()));
    precision_rx::MetricsSnapshot snapshot;
    REQUIRE(accumulator.take_snapshot(snapshot, true));
    CHECK(snapshot.first_input_tick == 50);
    CHECK(snapshot.next_input_tick == 75);
    CHECK(snapshot.analyzed_sample_count == 25);
    CHECK(snapshot.mean_i_q8 == 4 * 256);
    CHECK(snapshot.mean_q_q8 == -2 * 256);
    CHECK((snapshot.continuity_flags & precision_rx::STREAM_START) != 0);
    CHECK_FALSE(accumulator.take_snapshot(snapshot, true));
}

TEST_CASE("precision capture interval baselines pre-open loss and preserves post-open loss") {
    precision_rx::MetricsAccumulator accumulator;
    accumulator.configure(1'000, 15);
    accumulator.mark_input_drop(37);

    accumulator.begin_capture_interval();
    const uint64_t start_tick = accumulator.input_tick();
    const uint64_t start_dropped = accumulator.dropped_input_samples();
    CHECK(start_tick == 37);
    CHECK(start_dropped == 37);

    std::vector<Sample> first_block(25, {7, -3});
    CHECK_FALSE(accumulator.observe_block(first_block.data(), first_block.size()));
    precision_rx::MetricsSnapshot clean_snapshot;
    REQUIRE(accumulator.take_snapshot(clean_snapshot, true));
    CHECK(clean_snapshot.first_input_tick == start_tick);
    CHECK(clean_snapshot.next_input_tick == start_tick + first_block.size());
    CHECK(clean_snapshot.dropped_input_samples == start_dropped);
    CHECK((clean_snapshot.continuity_flags & precision_rx::STREAM_START) != 0);
    CHECK((clean_snapshot.continuity_flags & precision_rx::DISCONTINUITY) == 0);
    CHECK((clean_snapshot.continuity_flags & precision_rx::DROPPED_INPUT) == 0);

    accumulator.mark_input_drop(5);
    std::vector<Sample> second_block(10, {-4, 2});
    CHECK_FALSE(accumulator.observe_block(second_block.data(), second_block.size()));
    precision_rx::MetricsSnapshot loss_snapshot;
    REQUIRE(accumulator.take_snapshot(loss_snapshot, true));
    CHECK(loss_snapshot.first_input_tick == clean_snapshot.next_input_tick);
    CHECK(loss_snapshot.next_input_tick ==
          clean_snapshot.next_input_tick + 5 + second_block.size());
    CHECK(loss_snapshot.dropped_input_samples == start_dropped + 5);
    CHECK((loss_snapshot.continuity_flags & precision_rx::DISCONTINUITY) != 0);
    CHECK((loss_snapshot.continuity_flags & precision_rx::DROPPED_INPUT) != 0);
}

TEST_CASE("precision C8 block fast path exactly matches scalar semantics") {
    static constexpr std::array<uint32_t, 7> sample_rates{{
        1'000'000,
        2'000'000,
        4'000'000,
        8'000'000,
        10'000'000,
        16'000'000,
        20'000'000,
    }};
    static constexpr std::array<size_t, 9> block_sizes{{
        1,
        17,
        2'048,
        3,
        4'095,
        257,
        8'191,
        63,
        1'027,
    }};

    /* This explicit member-pointer type guarantees that the C8 overload is present. */
    bool (precision_rx::MetricsAccumulator::*const c8_fast_path)(
        const complex8_t*, size_t) =
        &precision_rx::MetricsAccumulator::observe_block;
    CHECK(c8_fast_path != nullptr);

    for (const uint32_t sample_rate : sample_rates) {
        INFO("sample_rate=", sample_rate);
        precision_rx::MetricsAccumulator scalar;
        precision_rx::MetricsAccumulator fast;
        const uint32_t epoch = 100U + sample_rate / 1'000'000U;
        scalar.configure(sample_rate, epoch);
        fast.configure(sample_rate, epoch);
        check_accumulator_state_equal(scalar, fast);

        std::vector<Sample> scalar_probe(1, {7, -9});
        std::vector<complex8_t> fast_probe(1, complex8_t{7, -9});
        CHECK_FALSE(scalar.observe_block(nullptr, 1));
        CHECK_FALSE((fast.*c8_fast_path)(nullptr, 1));
        CHECK(scalar.observe_block(scalar_probe.data(), 0) ==
              (fast.*c8_fast_path)(fast_probe.data(), 0));
        check_accumulator_state_equal(scalar, fast);

        uint64_t source_index = 0;
        size_t block_index = 0;
        uint32_t reports_seen = 0;
        const uint64_t input_tick_target =
            static_cast<uint64_t>(sample_rate) / 5U + 12'345U;

        while (scalar.input_tick() < input_tick_target) {
            if (block_index == 1U) {
                scalar.mark_input_drop(1);
                fast.mark_input_drop(1);
                check_accumulator_state_equal(scalar, fast);
            } else if (block_index == 4U) {
                const uint64_t drop = scalar.analysis_stride() + 3U;
                scalar.mark_input_drop(drop);
                fast.mark_input_drop(drop);
                check_accumulator_state_equal(scalar, fast);
            } else if (block_index == 11U) {
                const uint64_t drop = scalar.analysis_stride() * 3U - 1U;
                scalar.mark_input_drop(drop);
                fast.mark_input_drop(drop);
                check_accumulator_state_equal(scalar, fast);
            }

            const uint64_t remaining = input_tick_target - scalar.input_tick();
            const size_t count = static_cast<size_t>(std::min<uint64_t>(
                block_sizes[block_index % block_sizes.size()],
                remaining));
            observe_equivalent_block(scalar, fast, source_index, count);

            precision_rx::MetricsSnapshot scalar_snapshot;
            precision_rx::MetricsSnapshot fast_snapshot;
            const bool scalar_taken = scalar.take_snapshot(scalar_snapshot);
            const bool fast_taken = fast.take_snapshot(fast_snapshot);
            CHECK(fast_taken == scalar_taken);
            if (scalar_taken && fast_taken) {
                ++reports_seen;
                check_snapshot_equal(scalar_snapshot, fast_snapshot);
            }
            ++block_index;
        }
        CHECK(reports_seen >= 2U);

        scalar.begin_capture_interval();
        fast.begin_capture_interval();
        check_accumulator_state_equal(scalar, fast);

        /* Exercise a partial stride, a discontinuity, and a forced tail. */
        observe_equivalent_block(
            scalar,
            fast,
            source_index,
            scalar.analysis_stride() + 1U);
        const uint64_t tail_drop = scalar.analysis_stride() * 2U + 1U;
        scalar.mark_input_drop(tail_drop);
        fast.mark_input_drop(tail_drop);
        observe_equivalent_block(
            scalar,
            fast,
            source_index,
            scalar.analysis_stride() * 13U + 5U);

        precision_rx::MetricsSnapshot scalar_tail;
        precision_rx::MetricsSnapshot fast_tail;
        const bool scalar_tail_taken = scalar.take_snapshot(scalar_tail, true);
        const bool fast_tail_taken = fast.take_snapshot(fast_tail, true);
        REQUIRE(fast_tail_taken == scalar_tail_taken);
        REQUIRE(scalar_tail_taken);
        check_snapshot_equal(scalar_tail, fast_tail);
        CHECK((fast_tail.continuity_flags & precision_rx::DISCONTINUITY) != 0);
        CHECK((fast_tail.continuity_flags & precision_rx::DROPPED_INPUT) != 0);

        CHECK_FALSE(scalar.take_snapshot(scalar_tail, true));
        CHECK_FALSE(fast.take_snapshot(fast_tail, true));
    }
}

TEST_CASE("precision capture evidence rejects pre- and post-capture reports") {
    constexpr uint32_t epoch = 23;
    constexpr uint32_t final_sequence = 104;
    constexpr uint64_t generated = 5;
    CHECK(precision_rx::report_in_capture_interval(
        true, epoch, final_sequence, generated, epoch, 100));
    CHECK(precision_rx::report_in_capture_interval(
        true, epoch, final_sequence, generated, epoch, 104));
    CHECK_FALSE(precision_rx::report_in_capture_interval(
        true, epoch, final_sequence, generated, epoch, 99));
    CHECK_FALSE(precision_rx::report_in_capture_interval(
        true, epoch, final_sequence, generated, epoch, 105));
    CHECK_FALSE(precision_rx::report_in_capture_interval(
        true, epoch, final_sequence, generated, epoch + 1, 104));
    CHECK_FALSE(precision_rx::report_in_capture_interval(
        false, epoch, final_sequence, generated, epoch, 104));
}

TEST_CASE("precision capture evidence handles uint32 sequence wrap") {
    constexpr uint32_t epoch = 24;
    CHECK(precision_rx::report_in_capture_interval(
        true, epoch, 1, 4, epoch, 0xfffffffeU));
    CHECK(precision_rx::report_in_capture_interval(
        true, epoch, 1, 4, epoch, 1));
    CHECK_FALSE(precision_rx::report_in_capture_interval(
        true, epoch, 1, 4, epoch, 0xfffffffdU));
    CHECK_FALSE(precision_rx::report_in_capture_interval(
        true, epoch, 1, 4, epoch, 2));
}

TEST_CASE("precision capture snapshot journal retains every short capture report") {
    CHECK_EQ(precision_rx::capture_snapshot_journal_retained(0U), 0U);
    CHECK_EQ(precision_rx::capture_snapshot_journal_retained(1U), 1U);
    CHECK_EQ(precision_rx::capture_snapshot_journal_retained(15U), 15U);

    constexpr uint32_t final_sequence = 104U;
    constexpr size_t retained = 5U;
    for (size_t index = 0; index < retained; ++index) {
        CHECK_EQ(
            precision_rx::capture_snapshot_journal_sequence(
                final_sequence, retained, index),
            100U + static_cast<uint32_t>(index));
    }
}

TEST_CASE("precision capture snapshot journal caps long captures at sixteen") {
    constexpr size_t capacity =
        precision_rx::capture_snapshot_journal_capacity;
    CHECK_EQ(precision_rx::capture_snapshot_journal_retained(16U), capacity);
    CHECK_EQ(precision_rx::capture_snapshot_journal_retained(17U), capacity);
    CHECK_EQ(
        precision_rx::capture_snapshot_journal_retained(1ULL << 40U),
        capacity);

    constexpr uint32_t final_sequence = 104U;
    for (size_t index = 0; index < capacity; ++index) {
        CHECK_EQ(
            precision_rx::capture_snapshot_journal_sequence(
                final_sequence, capacity, index),
            89U + static_cast<uint32_t>(index));
    }
}

TEST_CASE("precision capture snapshot journal sequences cross uint32 wrap") {
    constexpr uint32_t final_sequence = 2U;
    constexpr size_t retained = 5U;
    constexpr std::array<uint32_t, retained> expected{{
        0xfffffffeU,
        0xffffffffU,
        0U,
        1U,
        2U,
    }};

    for (size_t index = 0; index < retained; ++index) {
        CHECK_EQ(
            precision_rx::capture_snapshot_journal_sequence(
                final_sequence, retained, index),
            expected[index]);
    }
}

TEST_CASE("precision capture snapshot journal maps sequences to ring slots") {
    constexpr size_t capacity =
        precision_rx::capture_snapshot_journal_capacity;
    for (uint32_t sequence = 0U; sequence < 2U * capacity; ++sequence) {
        CHECK_EQ(
            precision_rx::capture_snapshot_journal_slot(sequence),
            static_cast<size_t>(sequence % capacity));
    }
    CHECK_EQ(
        precision_rx::capture_snapshot_journal_slot(0xffffffffU),
        capacity - 1U);
}
