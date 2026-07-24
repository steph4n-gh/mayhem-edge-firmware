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

#include <algorithm>
#include <cmath>
#include <limits>

#if defined(__arm__) && defined(__NEWLIB__) && \
    defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
/*
 * energy_to_dbfs_x10 excludes newlib log10f's non-positive error domain
 * before calling this numerically identical IEEE-754 kernel.  Avoiding the
 * wrapper keeps its otherwise-unused errno/reentrancy machinery out of M4.
 */
extern "C" float __ieee754_log10f(float);
#endif

namespace precision_rx {
namespace {

#if defined(__arm__)
#define PRECISION_RX_SIZE_OPT __attribute__((optimize("Os")))
#else
#define PRECISION_RX_SIZE_OPT
#endif
#if defined(__arm__) && \
    defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
#define PRECISION_RX_P12_LINK_SHAPE \
    __attribute__((noinline, noclone, optimize("Os")))
#else
#define PRECISION_RX_P12_LINK_SHAPE PRECISION_RX_SIZE_OPT
#endif

constexpr float pi = 3.14159265358979323846f;
constexpr float c8_full_scale_energy = 128.0f * 128.0f;
constexpr uint32_t robust_power_numerator = 95;
constexpr uint32_t robust_power_denominator = 100;
constexpr int32_t target_rms_low_dbfs_x10 = -219;
constexpr int32_t target_rms_high_dbfs_x10 = -105;

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC) || \
    defined(STREAM_INPUT_HOST_TEST)
/*
 * The generic ARM EABI 64-bit divider costs more than the entire bounded
 * operation below. Division is confined to loss accounting and the 10 Hz
 * report path, so a fixed 64-step restoring divider is both deterministic
 * and comfortably outside the per-sample loops.
 */
__attribute__((noinline, noclone, optimize("Os")))
uint64_t divide_u64_by_u32(
    const uint64_t numerator,
    const uint32_t denominator,
    uint32_t* const remainder_out = nullptr) {
    if (denominator == 0U) {
        if (remainder_out)
            *remainder_out = 0U;
        return 0U;
    }

    uint32_t words[] = {
        static_cast<uint32_t>(numerator >> 32U),
        static_cast<uint32_t>(numerator)};
    uint64_t quotient = 0U;
    uint32_t remainder = 0U;
    for (uint32_t word : words) {
        for (uint32_t bit = 0U; bit < 32U; ++bit) {
            const bool carry = (remainder & 0x80000000U) != 0U;
            remainder =
                (remainder << 1U) | (word >> 31U);
            word <<= 1U;
            quotient <<= 1U;
            if (carry || remainder >= denominator) {
                remainder -= denominator;
                quotient |= 1U;
            }
        }
    }
    if (remainder_out)
        *remainder_out = remainder;
    return quotient;
}

PRECISION_RX_SIZE_OPT uint64_t scale_u64_by_ratio(
    const uint64_t value,
    const uint32_t numerator,
    const uint32_t denominator) {
    uint32_t remainder = 0U;
    const uint64_t whole =
        divide_u64_by_u32(value, denominator, &remainder);
    const uint64_t fractional = divide_u64_by_u32(
        static_cast<uint64_t>(remainder) * numerator,
        denominator);
    return whole * numerator + fractional;
}
#endif

PRECISION_RX_SIZE_OPT int32_t clamp_round_i32(float value) {
    if (value >= static_cast<float>(std::numeric_limits<int32_t>::max())) {
        return std::numeric_limits<int32_t>::max();
    }
    if (value <= static_cast<float>(std::numeric_limits<int32_t>::min())) {
        return std::numeric_limits<int32_t>::min();
    }
    return static_cast<int32_t>(std::lround(value));
}

PRECISION_RX_SIZE_OPT int32_t energy_to_dbfs_x10(float energy) {
    if (energy <= 0.0f) {
        return -1200;
    }
#if defined(__arm__) && defined(__NEWLIB__) && \
    defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    const float log10_energy =
        __ieee754_log10f(energy / c8_full_scale_energy);
#else
    const float log10_energy =
        std::log10(energy / c8_full_scale_energy);
#endif
    return std::max<int32_t>(
        -1200,
        clamp_round_i32(100.0f * log10_energy));
}

}  // namespace

#if defined(STREAM_INPUT_HOST_TEST)
uint64_t test_divide_u64_by_u32(
    const uint64_t numerator,
    const uint32_t denominator,
    uint32_t& remainder) {
    return divide_u64_by_u32(
        numerator, denominator, &remainder);
}
#endif

PRECISION_RX_SIZE_OPT void MetricsAccumulator::configure(
    uint32_t input_sample_rate_hz,
    uint32_t stream_epoch) {
    input_sample_rate_hz_ = input_sample_rate_hz;
    stream_epoch_ = stream_epoch;
    report_sequence_ = 0;
    analysis_stride_ = std::max<uint32_t>(
        1,
        (input_sample_rate_hz + analysis_rate_limit_hz - 1) / analysis_rate_limit_hz);
    report_interval_ticks_ = std::max<uint64_t>(
        1,
        static_cast<uint64_t>(input_sample_rate_hz) / reports_per_second);
    stride_countdown_ = 0;
    input_tick_ = 0;
    report_first_tick_ = 0;
    pending_continuity_flags_ = STREAM_START | CLOCK_RESET | CONFIG_CHANGED;
    dropped_input_samples_ = 0;
    have_previous_sample_ = false;
    have_previous_carrier_ = false;
    previous_carrier_hz_ = 0.0f;
    release_dwell_ticks_ = 0;
    clear_report_accumulators();
}

PRECISION_RX_P12_LINK_SHAPE
void MetricsAccumulator::begin_capture_interval() {
    clear_report_accumulators();
    report_first_tick_ = input_tick_;
    pending_continuity_flags_ = STREAM_START;
    have_previous_sample_ = false;
    have_previous_carrier_ = false;
    release_dwell_ticks_ = 0;
}

PRECISION_RX_SIZE_OPT void MetricsAccumulator::mark_input_drop(
    uint64_t dropped_sample_count) {
    if (dropped_sample_count == 0) {
        return;
    }
    pending_continuity_flags_ |= DISCONTINUITY | DROPPED_INPUT;
    dropped_input_samples_ += dropped_sample_count;

    if (dropped_sample_count <= stride_countdown_) {
        stride_countdown_ -= static_cast<uint32_t>(dropped_sample_count);
    } else {
        const uint64_t samples_after_next = dropped_sample_count - stride_countdown_;
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        uint32_t remainder = 0U;
        divide_u64_by_u32(
            samples_after_next, analysis_stride_, &remainder);
        stride_countdown_ =
            remainder == 0U ? 0U : analysis_stride_ - remainder;
#else
        stride_countdown_ = static_cast<uint32_t>(
            (analysis_stride_ - (samples_after_next % analysis_stride_)) % analysis_stride_);
#endif
    }
    input_tick_ += dropped_sample_count;
    have_previous_sample_ = false;
    have_previous_carrier_ = false;
}

bool MetricsAccumulator::observe_block(
    const complex8_t* __restrict samples,
    size_t count) {
    if (!samples || input_sample_rate_hz_ == 0) {
        return false;
    }

    /*
     * Analyze production C8 buffers in three bounded-register passes.  In
     * particular, do not call observe_selected_sample() here: on the M4 that
     * call used to save/restore a large register set for every selected C8
     * sample and made a 1 Msps analysis stream miss every other DMA buffer.
     *
     * The first pass collects I/Q sums.  The second collects energy, peak,
     * clipping, and the robust histogram.  The third collects only adjacent
     * cross products.  Pair sums and energies are then derived algebraically
     * from the block moments, first and last samples, and the optional sample
     * preceding this block.  Separating the moments keeps each Cortex-M4
     * inner loop register-resident; rereading a 4 KiB DMA buffer is cheaper
     * than spilling the full report state for every selected sample.
     */
    const size_t first_index = stride_countdown_;
    if (first_index >= count) {
        stride_countdown_ = static_cast<uint32_t>(first_index - count);
        input_tick_ += count;
        return snapshot_due();
    }

    const uint32_t stride = analysis_stride_;
    const uint32_t block_sample_count = static_cast<uint32_t>(
        1U + (count - 1U - first_index) / stride);
    const size_t last_index =
        first_index + static_cast<size_t>(block_sample_count - 1U) * stride;
    const int32_t first_i = samples[first_index].real();
    const int32_t first_q = samples[first_index].imag();
    const int32_t last_i = samples[last_index].real();
    const int32_t last_q = samples[last_index].imag();
    const uint32_t first_energy = static_cast<uint32_t>(
        first_i * first_i + first_q * first_q);
    const uint32_t last_energy = static_cast<uint32_t>(
        last_i * last_i + last_q * last_q);

    int64_t block_sum_i = 0;
    int64_t block_sum_q = 0;
    for (size_t index = first_index; index < count; index += stride) {
        block_sum_i += samples[index].real();
        block_sum_q += samples[index].imag();
    }

    uint64_t block_energy_sum = 0;
    uint32_t block_peak_energy = 0;
    uint32_t block_clip_count = 0;
    for (size_t index = first_index; index < count; index += stride) {
        const int32_t i = samples[index].real();
        const int32_t q = samples[index].imag();
        const uint32_t energy = static_cast<uint32_t>(i * i + q * q);

        block_energy_sum += energy;
        block_peak_energy = std::max(block_peak_energy, energy);

        const size_t energy_bin = std::min<size_t>(
            robust_histogram_bins - 1,
            energy >> 10);
        ++energy_histogram_counts_[energy_bin];
        energy_histogram_sums_[energy_bin] += energy;

        if (i <= -126 || i >= 126 || q <= -126 || q >= 126) {
            ++block_clip_count;
        }
    }

    sum_i_ += block_sum_i;
    sum_q_ += block_sum_q;
    energy_sum_ += block_energy_sum;
    peak_energy_ = std::max(peak_energy_, block_peak_energy);
    analyzed_count_ += block_sample_count;
    clip_count_ += block_clip_count;

    const bool had_previous_sample = have_previous_sample_;
    const int32_t preceding_i = previous_i_;
    const int32_t preceding_q = previous_q_;
    const uint32_t preceding_energy = static_cast<uint32_t>(
        preceding_i * preceding_i + preceding_q * preceding_q);
    int32_t pair_previous_i = preceding_i;
    int32_t pair_previous_q = preceding_q;
    bool have_pair_previous = had_previous_sample;
    int64_t block_cross_real_sum = 0;
    int64_t block_cross_imag_sum = 0;
    for (size_t index = first_index; index < count; index += stride) {
        const int32_t i = samples[index].real();
        const int32_t q = samples[index].imag();
        if (have_pair_previous) {
            block_cross_real_sum +=
                static_cast<int64_t>(pair_previous_i) * i +
                static_cast<int64_t>(pair_previous_q) * q;
            block_cross_imag_sum +=
                static_cast<int64_t>(pair_previous_i) * q -
                static_cast<int64_t>(pair_previous_q) * i;
        }
        pair_previous_i = i;
        pair_previous_q = q;
        have_pair_previous = true;
    }
    cross_real_sum_ += block_cross_real_sum;
    cross_imag_sum_ += block_cross_imag_sum;

    if (had_previous_sample) {
        previous_pair_sum_i_ += preceding_i + block_sum_i - last_i;
        previous_pair_sum_q_ += preceding_q + block_sum_q - last_q;
        current_pair_sum_i_ += block_sum_i;
        current_pair_sum_q_ += block_sum_q;
        previous_pair_energy_sum_ +=
            preceding_energy + block_energy_sum - last_energy;
        current_pair_energy_sum_ += block_energy_sum;
        pair_count_ += block_sample_count;
    } else {
        previous_pair_sum_i_ += block_sum_i - last_i;
        previous_pair_sum_q_ += block_sum_q - last_q;
        current_pair_sum_i_ += block_sum_i - first_i;
        current_pair_sum_q_ += block_sum_q - first_q;
        previous_pair_energy_sum_ += block_energy_sum - last_energy;
        current_pair_energy_sum_ += block_energy_sum - first_energy;
        pair_count_ += block_sample_count - 1U;
    }

    previous_i_ = last_i;
    previous_q_ = last_q;
    have_previous_sample_ = true;

    const size_t next_index =
        first_index + static_cast<size_t>(block_sample_count) * stride;
    stride_countdown_ = static_cast<uint32_t>(next_index - count);
    input_tick_ += count;
    return snapshot_due();
}

PRECISION_RX_SIZE_OPT void MetricsAccumulator::observe_selected_sample(
    int8_t i_raw,
    int8_t q_raw) {
    const int32_t i = i_raw;
    const int32_t q = q_raw;
    const uint32_t energy = static_cast<uint32_t>(i * i + q * q);
    sum_i_ += i;
    sum_q_ += q;
    energy_sum_ += energy;
    peak_energy_ = std::max(peak_energy_, energy);
    ++analyzed_count_;
    const size_t energy_bin = std::min<size_t>(
        robust_histogram_bins - 1,
        energy >> 10);
    ++energy_histogram_counts_[energy_bin];
    energy_histogram_sums_[energy_bin] += energy;
    /* SatTime's 0.98 rail threshold maps to component magnitude 126 in C8. */
    if (i <= -126 || i >= 126 || q <= -126 || q >= 126) {
        ++clip_count_;
    }

    if (have_previous_sample_) {
        cross_real_sum_ += static_cast<int64_t>(previous_i_) * i +
                           static_cast<int64_t>(previous_q_) * q;
        cross_imag_sum_ += static_cast<int64_t>(previous_i_) * q -
                           static_cast<int64_t>(previous_q_) * i;
        const uint32_t previous_energy = static_cast<uint32_t>(
            previous_i_ * previous_i_ + previous_q_ * previous_q_);
        previous_pair_sum_i_ += previous_i_;
        previous_pair_sum_q_ += previous_q_;
        current_pair_sum_i_ += i;
        current_pair_sum_q_ += q;
        previous_pair_energy_sum_ += previous_energy;
        current_pair_energy_sum_ += energy;
        ++pair_count_;
    }
    previous_i_ = i;
    previous_q_ = q;
    have_previous_sample_ = true;
}

PRECISION_RX_SIZE_OPT bool MetricsAccumulator::snapshot_due() const {
    return analyzed_count_ != 0 &&
           input_tick_ - report_first_tick_ >= report_interval_ticks_;
}

PRECISION_RX_SIZE_OPT bool MetricsAccumulator::take_snapshot(
    MetricsSnapshot& snapshot,
    bool force) {
    if (analyzed_count_ == 0 || (!force && !snapshot_due())) {
        return false;
    }

    snapshot = {};
    snapshot.stream_epoch = stream_epoch_;
    snapshot.report_sequence = report_sequence_++;
    snapshot.continuity_flags = pending_continuity_flags_;
    snapshot.input_sample_rate_hz = input_sample_rate_hz_;
    snapshot.analysis_stride = analysis_stride_;
    snapshot.first_input_tick = report_first_tick_;
    snapshot.next_input_tick = input_tick_;
    snapshot.dropped_input_samples = dropped_input_samples_;
    snapshot.analyzed_sample_count = analyzed_count_;
    snapshot.sampled_clip_count = clip_count_;
    snapshot.mean_i_q8 = clamp_round_i32(
        static_cast<float>(sum_i_) * 256.0f / analyzed_count_);
    snapshot.mean_q_q8 = clamp_round_i32(
        static_cast<float>(sum_q_) * 256.0f / analyzed_count_);
    snapshot.rms_dbfs_x10 = energy_to_dbfs_x10(
        static_cast<float>(energy_sum_) / analyzed_count_);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    static_assert(
        robust_power_numerator == 95U &&
        robust_power_denominator == 100U);
    /* ceil(95*n/100) == n - floor(n/20), without a wide multiply. */
    const uint32_t robust_sample_count =
        analyzed_count_ - analyzed_count_ / 20U;
#else
    const uint32_t robust_sample_count = static_cast<uint32_t>(
        (static_cast<uint64_t>(analyzed_count_) * robust_power_numerator +
         robust_power_denominator - 1) /
        robust_power_denominator);
#endif
    uint32_t robust_samples_remaining = robust_sample_count;
    uint64_t robust_energy_sum = 0;
    for (size_t bin = 0; bin < robust_histogram_bins && robust_samples_remaining; ++bin) {
        const uint32_t bin_count = energy_histogram_counts_[bin];
        const uint32_t take = std::min(bin_count, robust_samples_remaining);
        if (take == bin_count) {
            robust_energy_sum += energy_histogram_sums_[bin];
        } else if (take != 0) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
            robust_energy_sum += scale_u64_by_ratio(
                energy_histogram_sums_[bin], take, bin_count);
#else
            robust_energy_sum +=
                energy_histogram_sums_[bin] * take / bin_count;
#endif
        }
        robust_samples_remaining -= take;
    }
    snapshot.robust_rms_dbfs_x10 = energy_to_dbfs_x10(
        static_cast<float>(robust_energy_sum) / robust_sample_count);
    snapshot.peak_dbfs_x10 = energy_to_dbfs_x10(peak_energy_);

    if (clip_count_ != 0) {
        snapshot.metric_quality_flags |= SAMPLED_CLIPPING;
    }
    if (analysis_stride_ != 1) {
        snapshot.metric_quality_flags |= ALIAS_LIMITED;
    }
    if (input_sample_rate_hz_ < 1'750'000) {
        snapshot.metric_quality_flags |= ANALOG_ALIAS_RISK;
    }

    const int64_t covariance_real_n =
        cross_real_sum_ * pair_count_ -
        previous_pair_sum_i_ * current_pair_sum_i_ -
        previous_pair_sum_q_ * current_pair_sum_q_;
    const int64_t covariance_imag_n =
        cross_imag_sum_ * pair_count_ -
        previous_pair_sum_i_ * current_pair_sum_q_ +
        previous_pair_sum_q_ * current_pair_sum_i_;
    const int64_t previous_variance_n =
        static_cast<int64_t>(previous_pair_energy_sum_ * pair_count_) -
        previous_pair_sum_i_ * previous_pair_sum_i_ -
        previous_pair_sum_q_ * previous_pair_sum_q_;
    const int64_t current_variance_n =
        static_cast<int64_t>(current_pair_energy_sum_ * pair_count_) -
        current_pair_sum_i_ * current_pair_sum_i_ -
        current_pair_sum_q_ * current_pair_sum_q_;
    const float covariance_real = static_cast<float>(covariance_real_n);
    const float covariance_imag = static_cast<float>(covariance_imag_n);
    /*
     * The 100 ms, 1 Msps-bounded analysis interval keeps the squared
     * covariance well below FLT_MAX.  The normalized std::hypot path adds a
     * large double-precision helper on Cortex-M4 without providing useful
     * overflow protection for this bounded domain.
     */
    const float covariance_power =
        covariance_real * covariance_real +
        covariance_imag * covariance_imag;
    const float variance_product =
        static_cast<float>(std::max<int64_t>(0, previous_variance_n)) *
        static_cast<float>(std::max<int64_t>(0, current_variance_n));
    const float coherence = variance_product <= 0.0f
                                ? 0.0f
                                : std::min<float>(
                                      1.0f,
                                      std::sqrt(covariance_power / variance_product));
    snapshot.coherence_ppm = static_cast<uint32_t>(std::lround(coherence * 1'000'000.0f));

    const bool carrier_valid = pair_count_ >= 8 && snapshot.coherence_ppm >= 200'000;
    if (carrier_valid) {
        snapshot.metric_quality_flags |= CARRIER_VALID;
        const float phase_per_observation = std::atan2(
            static_cast<float>(covariance_imag_n),
            static_cast<float>(covariance_real_n));
        const float carrier_hz = phase_per_observation * input_sample_rate_hz_ /
                                 (2.0f * pi * analysis_stride_);
        snapshot.carrier_offset_hz_x10 = clamp_round_i32(carrier_hz * 10.0f);

        const float elapsed_seconds = static_cast<float>(
            snapshot.next_input_tick - snapshot.first_input_tick) /
            input_sample_rate_hz_;
        if (have_previous_carrier_ && elapsed_seconds > 0.0f) {
            snapshot.metric_quality_flags |= DRIFT_VALID;
            snapshot.carrier_delta_hz_per_s_x10 = clamp_round_i32(
                (carrier_hz - previous_carrier_hz_) / elapsed_seconds * 10.0f);
        }
        previous_carrier_hz_ = carrier_hz;
        have_previous_carrier_ = true;
    } else {
        have_previous_carrier_ = false;
    }

    /*
     * Advisory-only port of SatTime RobustAgcConfig for HackRF:
     * 0.1% sampled rail contact or robust RMS above -10.5 dBFS attacks
     * immediately; a non-zero robust RMS below -21.9 dBFS must persist for
     * 0.5 seconds before release. The deadband is the hysteresis region.
     */
    const bool rail_attack =
        static_cast<uint64_t>(snapshot.sampled_clip_count) * 1000U >
        snapshot.analyzed_sample_count;
    const bool power_attack =
        snapshot.robust_rms_dbfs_x10 > target_rms_high_dbfs_x10;
    const bool release =
        snapshot.robust_rms_dbfs_x10 > -1200 &&
        snapshot.robust_rms_dbfs_x10 < target_rms_low_dbfs_x10;
    const uint64_t report_ticks = snapshot.next_input_tick - snapshot.first_input_tick;
    if (rail_attack || power_attack) {
        release_dwell_ticks_ = 0;
        snapshot.gain_advice = GainAdvice::Reduce;
    } else if (release &&
               (snapshot.continuity_flags & DISCONTINUITY) == 0) {
        release_dwell_ticks_ = std::min<uint64_t>(
            release_dwell_ticks_ + report_ticks,
            input_sample_rate_hz_);
        snapshot.gain_advice =
            release_dwell_ticks_ >= input_sample_rate_hz_ / 2
                ? GainAdvice::Increase
                : GainAdvice::Hold;
    } else {
        release_dwell_ticks_ = 0;
        snapshot.gain_advice = GainAdvice::Hold;
    }

    pending_continuity_flags_ = 0;
    report_first_tick_ = input_tick_;
    clear_report_accumulators();
    return true;
}

PRECISION_RX_SIZE_OPT void MetricsAccumulator::clear_report_accumulators() {
    sum_i_ = 0;
    sum_q_ = 0;
    energy_sum_ = 0;
    peak_energy_ = 0;
    analyzed_count_ = 0;
    clip_count_ = 0;
    energy_histogram_counts_.fill(0);
    energy_histogram_sums_.fill(0);
    cross_real_sum_ = 0;
    cross_imag_sum_ = 0;
    previous_pair_sum_i_ = 0;
    previous_pair_sum_q_ = 0;
    current_pair_sum_i_ = 0;
    current_pair_sum_q_ = 0;
    previous_pair_energy_sum_ = 0;
    current_pair_energy_sum_ = 0;
    pair_count_ = 0;
}

#undef PRECISION_RX_SIZE_OPT
#undef PRECISION_RX_P12_LINK_SHAPE

}  // namespace precision_rx
