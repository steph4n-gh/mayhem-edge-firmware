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

#ifndef __PRECISION_RX_METRICS_H__
#define __PRECISION_RX_METRICS_H__

#include <array>
#include <cstddef>
#include <cstdint>

#include "complex.hpp"

namespace precision_rx {

#if defined(STREAM_INPUT_HOST_TEST)
uint64_t test_divide_u64_by_u32(
    uint64_t numerator,
    uint32_t denominator,
    uint32_t& remainder);
#endif

/* Values intentionally match edge_frame_flag_v1 in the frozen Edge ABI. */
enum ContinuityFlag : uint32_t {
    STREAM_START = uint32_t{1} << 0,
    DISCONTINUITY = uint32_t{1} << 2,
    DROPPED_INPUT = uint32_t{1} << 3,
    CONFIG_CHANGED = uint32_t{1} << 7,
    CLOCK_RESET = uint32_t{1} << 9,
};

enum MetricQualityFlag : uint32_t {
    CARRIER_VALID = uint32_t{1} << 0,
    DRIFT_VALID = uint32_t{1} << 1,
    SAMPLED_CLIPPING = uint32_t{1} << 2,
    ALIAS_LIMITED = uint32_t{1} << 3,
    ANALOG_ALIAS_RISK = uint32_t{1} << 4,
};

enum class GainAdvice : int8_t {
    Reduce = -1,
    Hold = 0,
    Increase = 1,
};

struct MetricsSnapshot {
    uint32_t stream_epoch{0};
    uint32_t report_sequence{0};
    uint32_t continuity_flags{0};
    uint32_t capture_continuity_flags{0};
    uint32_t metric_quality_flags{0};
    uint32_t input_sample_rate_hz{0};
    uint32_t analysis_stride{1};
    uint64_t first_input_tick{0};
    uint64_t next_input_tick{0};
    uint64_t dropped_input_samples{0};
    uint32_t analyzed_sample_count{0};
    uint32_t sampled_clip_count{0};
    int32_t mean_i_q8{0};
    int32_t mean_q_q8{0};
    int32_t rms_dbfs_x10{-1200};
    int32_t robust_rms_dbfs_x10{-1200};
    int32_t peak_dbfs_x10{-1200};
    int32_t carrier_offset_hz_x10{0};
    int32_t carrier_delta_hz_per_s_x10{0};
    uint32_t coherence_ppm{0};
    GainAdvice gain_advice{GainAdvice::Hold};
};

class MetricsAccumulator {
   public:
    static constexpr uint32_t analysis_rate_limit_hz = 1'000'000;
    static constexpr uint32_t reports_per_second = 10;

    void configure(uint32_t input_sample_rate_hz, uint32_t stream_epoch);
    void begin_capture_interval();
    void mark_input_drop(uint64_t dropped_sample_count);

    /*
     * Production C8 path.  Keeping the block accumulators in locals avoids
     * paying an out-of-line call and member loads/stores for every selected
     * sample.  The generic overload below remains the scalar reference path
     * used by host tests and by non-C8 callers.
     */
    bool observe_block(const complex8_t* __restrict samples, size_t count);

    template <typename Sample>
    bool observe_block(const Sample* samples, size_t count) {
        if (!samples || input_sample_rate_hz_ == 0) {
            return false;
        }

        size_t index = stride_countdown_;
        for (; index < count; index += analysis_stride_) {
            const int8_t i = static_cast<int8_t>(samples[index].real());
            const int8_t q = static_cast<int8_t>(samples[index].imag());
            observe_selected_sample(i, q);
        }
        stride_countdown_ = static_cast<uint32_t>(index - count);
        input_tick_ += count;
        return snapshot_due();
    }

    bool take_snapshot(MetricsSnapshot& snapshot, bool force = false);

    uint64_t input_tick() const { return input_tick_; }
    uint64_t dropped_input_samples() const { return dropped_input_samples_; }
    uint32_t stream_epoch() const { return stream_epoch_; }
    uint32_t analysis_stride() const { return analysis_stride_; }

   private:
    void observe_selected_sample(int8_t i, int8_t q);
    bool snapshot_due() const;
    void clear_report_accumulators();

    uint32_t input_sample_rate_hz_{0};
    uint32_t stream_epoch_{0};
    uint32_t report_sequence_{0};
    uint32_t analysis_stride_{1};
    uint32_t stride_countdown_{0};
    uint64_t input_tick_{0};
    uint64_t report_first_tick_{0};
    uint64_t report_interval_ticks_{1};
    uint32_t pending_continuity_flags_{0};
    uint64_t dropped_input_samples_{0};

    int64_t sum_i_{0};
    int64_t sum_q_{0};
    uint64_t energy_sum_{0};
    uint32_t peak_energy_{0};
    uint32_t analyzed_count_{0};
    uint32_t clip_count_{0};
    static constexpr size_t robust_histogram_bins = 32;
    std::array<uint32_t, robust_histogram_bins> energy_histogram_counts_{};
    std::array<uint64_t, robust_histogram_bins> energy_histogram_sums_{};

    bool have_previous_sample_{false};
    int32_t previous_i_{0};
    int32_t previous_q_{0};
    int64_t cross_real_sum_{0};
    int64_t cross_imag_sum_{0};
    int64_t previous_pair_sum_i_{0};
    int64_t previous_pair_sum_q_{0};
    int64_t current_pair_sum_i_{0};
    int64_t current_pair_sum_q_{0};
    uint64_t previous_pair_energy_sum_{0};
    uint64_t current_pair_energy_sum_{0};
    uint32_t pair_count_{0};

    bool have_previous_carrier_{false};
    float previous_carrier_hz_{0.0f};
    uint64_t release_dwell_ticks_{0};
};

}  // namespace precision_rx

#endif /*__PRECISION_RX_METRICS_H__*/
