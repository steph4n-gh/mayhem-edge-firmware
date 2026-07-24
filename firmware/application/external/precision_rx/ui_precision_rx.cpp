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

#include "ui_precision_rx.hpp"

#include "baseband_api.hpp"
#include "event_m0.hpp"
#include "io_file.hpp"
#include "portapack.hpp"
#include "precision_rx_capture_acceptance.hpp"
#include "precision_rx_capture_writer.hpp"
#include "precision_rx_evidence.hpp"
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
#include "precision_rx_journal_recovery.hpp"
#endif
#include "receiver_model.hpp"
#include "rtc_time.hpp"
#include "string_format.hpp"
#include "ui_painter.hpp"
#include "ui_spectrum.hpp"

#include <algorithm>
#include <limits>

using namespace portapack;

namespace ui::external_app::precision_rx {
namespace {

std::string tenths(int32_t value) {
    const int64_t wide = value;
    const uint64_t magnitude = static_cast<uint64_t>(wide < 0 ? -wide : wide);
    return (wide < 0 ? "-" : "") + to_string_dec_uint(magnitude / 10) + "." +
           to_string_dec_uint(magnitude % 10);
}

#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
struct SidecarHeaderV2 {
    uint64_t center_frequency_hz;
    uint64_t capture_start_input_tick;
    uint64_t capture_stop_input_tick;
    uint64_t start_dropped_input_samples;
    uint64_t stop_dropped_input_samples;
    uint64_t input_bytes_offered;
    uint64_t stream_fifo_bytes_dropped;
    uint64_t stream_bytes_accepted;
    uint64_t file_bytes_written;
    uint64_t accepted_bytes_not_written;
    uint64_t status_reports_generated;
    uint64_t status_reports_missing;
    uint32_t magic;
    uint32_t version;
    uint32_t header_bytes;
    uint32_t record_bytes;
    uint32_t sample_format;
    uint32_t input_sample_rate_hz;
    uint32_t lna_gain_db;
    uint32_t vga_gain_db;
    uint32_t rf_amp_enabled;
    uint32_t file_write_error;
    uint32_t file_error_code;
    uint32_t aggregate_continuity_flags;
    uint32_t aggregate_capture_continuity_flags;
    uint32_t aggregate_metric_quality_flags;
    uint32_t retained_record_count;
    uint32_t retained_record_capacity;
    uint32_t final_stream_epoch;
    uint32_t final_report_sequence;
    int32_t minimum_rms_dbfs_x10;
    int32_t minimum_robust_rms_dbfs_x10;
    int32_t maximum_robust_rms_dbfs_x10;
    int32_t maximum_peak_dbfs_x10;
    int32_t minimum_carrier_mod_hz_x10;
    int32_t maximum_carrier_mod_hz_x10;
    uint32_t minimum_coherence_ppm;
    uint32_t valid_carrier_report_count;
    uint32_t terminal_reason;
    uint32_t capture_target_input_samples;
    uint32_t records_crc32c;
    uint32_t header_crc32c;
};

static_assert(sizeof(SidecarHeaderV2) == 216, "PRX2 header wire size changed");
#else
struct SidecarHeaderV1 {
    uint64_t center_frequency_hz;
    uint64_t capture_start_input_tick;
    uint64_t capture_stop_input_tick;
    uint64_t start_dropped_input_samples;
    uint64_t stop_dropped_input_samples;
    uint64_t input_bytes_offered;
    uint64_t stream_fifo_bytes_dropped;
    uint64_t stream_bytes_accepted;
    uint64_t file_bytes_written;
    uint64_t accepted_bytes_not_written;
    uint64_t status_reports_generated;
    uint64_t status_reports_missing;
    uint32_t magic;
    uint32_t version;
    uint32_t header_bytes;
    uint32_t record_bytes;
    uint32_t sample_format;
    uint32_t input_sample_rate_hz;
    uint32_t lna_gain_db;
    uint32_t vga_gain_db;
    uint32_t rf_amp_enabled;
    uint32_t file_write_error;
    uint32_t file_error_code;
    uint32_t aggregate_continuity_flags;
    uint32_t aggregate_capture_continuity_flags;
    uint32_t aggregate_metric_quality_flags;
    uint32_t retained_record_count;
    uint32_t retained_record_capacity;
    uint32_t final_stream_epoch;
    uint32_t final_report_sequence;
    int32_t minimum_rms_dbfs_x10;
    int32_t minimum_robust_rms_dbfs_x10;
    int32_t maximum_robust_rms_dbfs_x10;
    int32_t maximum_peak_dbfs_x10;
    int32_t minimum_carrier_mod_hz_x10;
    int32_t maximum_carrier_mod_hz_x10;
    uint32_t minimum_coherence_ppm;
    uint32_t valid_carrier_report_count;
    uint32_t records_crc32c;
    uint32_t header_crc32c;
};

static_assert(sizeof(SidecarHeaderV1) == 208, "PRX header wire size changed");
#endif

uint32_t crc32c_update(uint32_t crc, const void* data, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    while (size--) {
        crc ^= *bytes++;
        for (uint_fast8_t bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0x82f63b78U & (0U - (crc & 1U)));
        }
    }
    return crc;
}

bool write_exact(File& file, const void* data, size_t size) {
    const auto result = file.write(data, size);
    return result.is_ok() && result.value() == size;
}

#if !defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
void cross_core_evidence_fence() {
    __asm__ volatile("" ::: "memory");
    __DMB();
    __asm__ volatile("" ::: "memory");
}

struct CaptureEvidenceInterval {
    bool valid{false};
    uint32_t stream_epoch{0};
    uint32_t final_report_sequence{0};
    uint64_t status_reports_generated{0};
};

CaptureEvidenceInterval read_capture_evidence_interval(
    const PrecisionRxCaptureEvidence& source) {
    const auto& evidence =
        static_cast<const volatile PrecisionRxCaptureEvidence&>(source);
    CaptureEvidenceInterval interval{};
    while (true) {
        const uint32_t sequence_before = evidence.update_sequence;
        if ((sequence_before & 1U) != 0) {
            continue;
        }
        cross_core_evidence_fence();
        interval.valid = evidence.valid;
        interval.stream_epoch = evidence.final_stream_epoch;
        interval.final_report_sequence = evidence.final_report_sequence;
        interval.status_reports_generated = evidence.status_reports_generated;
        cross_core_evidence_fence();
        const uint32_t sequence_after = evidence.update_sequence;
        if (sequence_before == sequence_after) {
            return interval;
        }
    }
}
#endif

}  // namespace

#if defined(__arm__) && \
    defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
__asm__(
    ".global hackrf_edge_precision_rx_journal_fail_closed_recovery\n"
    ".type hackrf_edge_precision_rx_journal_fail_closed_recovery, %object\n"
    ".set hackrf_edge_precision_rx_journal_fail_closed_recovery, 1\n"
    ".size hackrf_edge_precision_rx_journal_fail_closed_recovery, 1\n");
#endif

PrecisionRxView::PrecisionRxView(NavigationView& nav)
    : nav_{nav} {
    baseband::run_prepared_image(portapack::memory::map::m4_code.base());

    add_children({
        &field_frequency_,
        &field_frequency_step_,
        &field_rf_amp_,
        &field_lna_,
        &field_vga_,
        &labels_,
        &options_sample_rate_,
        &button_capture_,
        &text_state_,
        &text_epoch_,
        &text_tick_,
        &text_levels_,
        &text_dc_,
        &text_carrier_,
        &text_drift_,
        &text_coherence_,
        &text_loss_,
        &text_gain_,
        &text_evidence_,
    });

    field_frequency_step_.set_by_value(receiver_model.frequency_step());
    field_frequency_step_.on_change = [this](size_t, OptionsField::value_t value) {
        receiver_model.set_frequency_step(value);
        field_frequency_.set_step(value);
    };
    field_frequency_.updated = [this](rf::Frequency) {
        if (capture_phase_ != CapturePhase::Idle) {
            stop_capture();
        }
        reset_measurement_epoch();
    };
    field_rf_amp_.on_change = [this](int32_t value) {
        if (capture_phase_ != CapturePhase::Idle) {
            stop_capture();
        }
        receiver_model.set_rf_amp(value);
        reset_measurement_epoch();
    };
    field_lna_.on_change = [this](int32_t value) {
        if (capture_phase_ != CapturePhase::Idle) {
            stop_capture();
        }
        receiver_model.set_lna(value);
        reset_measurement_epoch();
    };
    field_vga_.on_change = [this](int32_t value) {
        if (capture_phase_ != CapturePhase::Idle) {
            stop_capture();
        }
        receiver_model.set_vga(value);
        reset_measurement_epoch();
    };

    options_sample_rate_.set_by_nearest_value(sample_rate_);
    sample_rate_ = options_sample_rate_.selected_index_value();
    options_sample_rate_.on_change = [this](size_t, OptionsField::value_t value) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        sample_rate_ = value;
        if (restoring_sample_rate_option_) {
            return;
        }
#endif
        if (capture_phase_ != CapturePhase::Idle) {
            stop_capture();
        }
#if !defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        sample_rate_ = value;
#endif
        apply_sample_rate();
    };

    button_capture_.on_select = [this](Button&) {
        switch (capture_phase_) {
            case CapturePhase::Idle:
                start_capture();
                break;
            case CapturePhase::Capturing:
            case CapturePhase::Preparing:
                stop_capture();
                break;
            case CapturePhase::Stopping:
                break;
        }
    };

    receiver_model.set_squelch_level(0);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    portapack::set_antenna_bias(false);
#endif
    receiver_model.enable();
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    committed_sample_rate_ = receiver_model.sampling_rate();
#endif
    apply_sample_rate();
}

PrecisionRxView::~PrecisionRxView() {
    if (capture_phase_ != CapturePhase::Idle) {
        stop_capture();
    }
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    if (rate_faulted_) {
        /* Fault teardown is RF-first and carries an explicit M4 fail-close. */
        (void)baseband::shutdown_precision_rx_after_rate_fault();
    } else {
        /*
         * Keep the RF/SGPIO request source live until M4 completes its
         * H -> ACTIVE-clear -> gate -> E shutdown and acknowledges exit.
         */
        baseband::shutdown();
        receiver_model.disable();
    }
#else
    receiver_model.disable();
    baseband::shutdown();
#endif
}

void PrecisionRxView::focus() {
    field_frequency_.focus();
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
bool PrecisionRxView::apply_sample_rate() {
    return finish_sample_rate_change(
        baseband::set_precision_rx(sample_rate_));
}

bool PrecisionRxView::reset_measurement_epoch() {
    return apply_sample_rate();
}

bool PrecisionRxView::finish_sample_rate_change(
    const baseband::PrecisionRxRateResult result) {
    using Result = baseband::PrecisionRxRateResult;
    if (result == Result::Applied) {
        committed_sample_rate_ = sample_rate_;
        committed_sample_rate_index_ =
            options_sample_rate_.selected_index();
        text_state_.set("ARMED");
        return true;
    }

    restoring_sample_rate_option_ = true;
    options_sample_rate_.set_selected_index(
        committed_sample_rate_index_, false);
    restoring_sample_rate_option_ = false;
    if (result != Result::Fatal) {
        text_state_.set("RATE ERR");
        return false;
    }

    rate_faulted_ = true;
    (void)baseband::shutdown_precision_rx_after_rate_fault();
    set_capture_controls_locked(true);
    button_capture_.set_focusable(false);
    text_state_.set("RESET REQ");
    return false;
}
#else
void PrecisionRxView::apply_sample_rate() {
    receiver_model.set_sampling_rate(sample_rate_);
    receiver_model.set_baseband_bandwidth(filter_bandwidth_for_sampling_rate(sample_rate_));
    baseband::set_precision_rx(sample_rate_);
    text_state_.set("ARMED");
}

void PrecisionRxView::reset_measurement_epoch() {
    baseband::set_precision_rx(sample_rate_);
}
#endif

void PrecisionRxView::on_status(const PrecisionRxStatusMessage& status) {
    if (capture_phase_ == CapturePhase::Preparing && !capture_thread_ &&
        preparation_done_) {
        finish_preparation();
    }

    /* Completion messages are best-effort; status cadence is the fallback. */
    if (capture_thread_ && capture_thread_->done()) {
        stop_capture();
    }

    if (capture_phase_ == CapturePhase::Preparing && capture_thread_ &&
        capture_thread_->started()) {
        capture_phase_ = CapturePhase::Capturing;
        button_capture_.set_text("STOP");
        text_state_.set("CAPTURE");
    }

    latest_status_.stream_epoch = status.stream_epoch;
    latest_status_.report_sequence = status.report_sequence;
    latest_status_.continuity_flags = status.continuity_flags;
    latest_status_.capture_continuity_flags = status.capture_continuity_flags;
    latest_status_.metric_quality_flags = status.metric_quality_flags;
    latest_status_.input_sample_rate_hz = status.input_sample_rate_hz;
    latest_status_.analysis_stride = status.analysis_stride;
    latest_status_.first_input_tick = status.first_input_tick;
    latest_status_.next_input_tick = status.next_input_tick;
    latest_status_.dropped_input_samples = status.dropped_input_samples;
    latest_status_.analyzed_sample_count = status.analyzed_sample_count;
    latest_status_.sampled_clip_count = status.sampled_clip_count;
    latest_status_.mean_i_q8 = status.mean_i_q8;
    latest_status_.mean_q_q8 = status.mean_q_q8;
    latest_status_.rms_dbfs_x10 = status.rms_dbfs_x10;
    latest_status_.robust_rms_dbfs_x10 = status.robust_rms_dbfs_x10;
    latest_status_.peak_dbfs_x10 = status.peak_dbfs_x10;
    latest_status_.carrier_offset_hz_x10 = status.carrier_offset_hz_x10;
    latest_status_.carrier_delta_hz_per_s_x10 = status.carrier_delta_hz_per_s_x10;
    latest_status_.coherence_ppm = status.coherence_ppm;
    latest_status_.gain_advice = status.gain_advice;
    latest_status_.capture_bytes_received = status.capture_bytes_received;
    latest_status_.capture_bytes_dropped = status.capture_bytes_dropped;
    have_status_ = true;
#if !defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
    CaptureEvidenceInterval capture_interval{};
    if (capture_thread_ && capture_thread_->started()) {
        capture_interval = read_capture_evidence_interval(
            capture_thread_->state().precision_rx_evidence);
    }
    const bool status_in_active_capture =
        capture_thread_ && capture_thread_->started() &&
        ::precision_rx::report_in_capture_interval(
            capture_interval.valid,
            capture_interval.stream_epoch,
            capture_interval.final_report_sequence,
            capture_interval.status_reports_generated,
            status.stream_epoch,
            status.report_sequence) &&
        status.next_input_tick > capture_thread_->state().baseband_start_input_tick;
#endif
    /* Live queue delivery drives the display only; M4 owns capture evidence. */
    update_display();
#if !defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
    if (status_in_active_capture && capture_limit_bytes_ != 0 &&
        status.capture_bytes_received >= capture_limit_bytes_) {
        stop_capture();
    }
#endif
}

void PrecisionRxView::update_display() {
    if (!have_status_) {
        return;
    }
    text_epoch_.set(to_string_dec_uint(latest_status_.stream_epoch) + "/" +
                    to_string_dec_uint(latest_status_.report_sequence));
    text_tick_.set(to_string_dec_uint(latest_status_.next_input_tick));
    text_levels_.set(tenths(latest_status_.rms_dbfs_x10) + "/" +
                     tenths(latest_status_.peak_dbfs_x10) + " dBFS");
    text_dc_.set(tenths(latest_status_.mean_i_q8 * 10 / 256) + "/" +
                 tenths(latest_status_.mean_q_q8 * 10 / 256));

    constexpr uint32_t carrier_valid_flag = uint32_t{1} << 0;
    constexpr uint32_t drift_valid_flag = uint32_t{1} << 1;
    constexpr uint32_t alias_limited_flag = uint32_t{1} << 3;
    constexpr uint32_t analog_alias_risk_flag = uint32_t{1} << 4;
    if ((latest_status_.metric_quality_flags & carrier_valid_flag) != 0) {
        std::string carrier = tenths(latest_status_.carrier_offset_hz_x10);
        if ((latest_status_.metric_quality_flags & alias_limited_flag) != 0) {
            carrier = "MOD " + carrier;
        } else if ((latest_status_.metric_quality_flags & analog_alias_risk_flag) != 0) {
            carrier = "RISK " + carrier;
        }
        text_carrier_.set(carrier);
        if ((latest_status_.metric_quality_flags & drift_valid_flag) != 0) {
            text_drift_.set(tenths(latest_status_.carrier_delta_hz_per_s_x10));
        } else {
            text_drift_.set("UNRES");
        }
    } else {
        text_carrier_.set("UNRES");
        text_drift_.set("UNRES");
    }
    text_coherence_.set(
        tenths(static_cast<int32_t>(latest_status_.coherence_ppm / 1000)) + "%");
    text_loss_.set(to_string_dec_uint(latest_status_.sampled_clip_count) + "/" +
                   to_string_dec_uint(latest_status_.dropped_input_samples) + "/" +
                   to_string_dec_uint(latest_status_.capture_bytes_dropped));

    if (latest_status_.gain_advice < 0) {
        text_gain_.set("REDUCE");
    } else if (latest_status_.gain_advice > 0) {
        text_gain_.set("INCREASE");
    } else {
        text_gain_.set("HOLD");
    }

    std::string evidence = "D" + to_string_dec_uint(latest_status_.analysis_stride);
    if ((latest_status_.metric_quality_flags & alias_limited_flag) != 0) {
        const uint32_t effective_rate_hz =
            latest_status_.input_sample_rate_hz / latest_status_.analysis_stride;
        evidence += " MOD" + to_string_dec_uint(effective_rate_hz / 1000) + "k";
    } else if ((latest_status_.metric_quality_flags & analog_alias_risk_flag) != 0) {
        evidence += " A-RISK";
    } else {
        evidence += " RAW";
    }
    text_evidence_.set(evidence);
}

void PrecisionRxView::start_capture() {
    if (sample_rate_ > capture_rate_limit_hz) {
        text_state_.set("SR>2M");
        return;
    }

    rtc::RTC datetime{};
    rtc_time::now(datetime);
    const std::string capture_stem =
        "PRX_" +
        to_string_dec_uint(datetime.year(), 4, '0') +
        to_string_dec_uint(datetime.month(), 2, '0') +
        to_string_dec_uint(datetime.day(), 2, '0') + "T" +
        to_string_dec_uint(datetime.hour(), 2, '0') +
        to_string_dec_uint(datetime.minute(), 2, '0') +
        to_string_dec_uint(datetime.second(), 2, '0');
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
    capture_path_ = next_filename_matching_pattern(
        std::filesystem::path(u"/CAPTURES") / (capture_stem + "_??.*"),
        u".C8");
#else
    capture_path_ = next_filename_matching_pattern(
        std::filesystem::path(u"/CAPTURES") / (capture_stem + "_??.C8"));
#endif
    if (capture_path_.empty()) {
        text_state_.set("NAME ERR");
        return;
    }

    constexpr size_t part_suffix_char_count = 5;
    std::array<char16_t, 64> work_path_chars{};
    const auto& capture_path_chars = capture_path_.native();
    if (capture_path_chars.size() + part_suffix_char_count >=
        work_path_chars.size()) {
        capture_path_ = {};
        text_state_.set("NAME ERR");
        return;
    }
    auto work_path_end = std::copy(
        capture_path_chars.begin(),
        capture_path_chars.end(),
        work_path_chars.begin());
    std::copy_n(u".PART", part_suffix_char_count, work_path_end);
    capture_work_path_ = std::filesystem::path{
        static_cast<const char16_t*>(work_path_chars.data())};
    if (std::filesystem::file_exists(capture_work_path_)) {
        capture_path_ = {};
        capture_work_path_ = {};
        text_state_.set("NAME ERR");
        return;
    }

    capture_center_frequency_hz_ = receiver_model.target_frequency();
    capture_sample_rate_hz_ = sample_rate_;
    capture_lna_gain_db_ = receiver_model.lna();
    capture_vga_gain_db_ = receiver_model.vga();
    capture_rf_amp_enabled_ = receiver_model.rf_amp();
    capture_thread_error_code_ = 0;
    capture_limit_bytes_ = ::precision_rx::capture_limit_bytes(sample_rate_);
    snapshots_ = {};
    snapshot_head_ = 0;
    snapshot_count_ = 0;
    capture_report_count_ = 0;
    capture_missing_report_count_ = 0;
    final_capture_stream_epoch_ = 0;
    final_capture_report_sequence_ = 0;
    aggregate_continuity_flags_ = 0;
    aggregate_capture_continuity_flags_ = 0;
    aggregate_metric_quality_flags_ = 0;
    aggregate_min_rms_dbfs_x10_ = std::numeric_limits<int32_t>::max();
    aggregate_min_robust_rms_dbfs_x10_ = std::numeric_limits<int32_t>::max();
    aggregate_max_robust_rms_dbfs_x10_ = std::numeric_limits<int32_t>::min();
    aggregate_max_peak_dbfs_x10_ = std::numeric_limits<int32_t>::min();
    aggregate_min_carrier_hz_x10_ = 0;
    aggregate_max_carrier_hz_x10_ = 0;
    aggregate_min_coherence_ppm_ = 0;
    aggregate_valid_carrier_reports_ = 0;

    capture_phase_ = CapturePhase::Preparing;
    set_capture_controls_locked(true);
    button_capture_.focus();
    button_capture_.set_text("CANCEL");
    text_state_.set("PREP");
    /* The worker runs above the UI priority, so publish PREP deterministically. */
    Painter painter;
    button_capture_.paint(painter);
    text_state_.paint(painter);

    preparation_cancel_requested_ = false;
    preparation_done_ = false;
    preparation_error_code_ = 0;
    capture_work_path_owned_ = false;
    capture_writer_ = std::make_unique<PrecisionRxCaptureWriter>();
    preparation_thread_ = chThdCreateFromHeap(
        nullptr,
        ::precision_rx::preparation_thread_working_area_size,
        NORMALPRIO + 10,
        PrecisionRxView::preparation_thread_fn,
        this);
    if (!preparation_thread_) {
        preparation_error_code_ =
            ::precision_rx::capture_preparation_diagnostic(
                ::precision_rx::CapturePreparationStage::Worker,
                FR_NOT_ENOUGH_CORE);
        preparation_done_ = true;
        finish_preparation();
    }
}

msg_t PrecisionRxView::preparation_thread_fn(void* const context) {
    auto& view = *static_cast<PrecisionRxView*>(context);
    const auto error = view.capture_writer_->create(
        view.capture_work_path_,
        ::precision_rx::capture_reserve_bytes(view.capture_sample_rate_hz_),
        &view.preparation_cancel_requested_);
    view.preparation_error_code_ =
        error.is_valid()
            ? ::precision_rx::capture_preparation_diagnostic(
                  view.capture_writer_->preparation_stage(),
                  error.value().code(),
                  view.capture_writer_->preparation_detail())
            : 0;
    __DMB();
    view.preparation_done_ = true;

    CaptureThreadDoneMessage message{};
    EventDispatcher::send_message(message);
    return 0;
}

void PrecisionRxView::finish_preparation() {
    if (!preparation_done_) {
        return;
    }
    if (preparation_thread_) {
        chThdWait(preparation_thread_);
        preparation_thread_ = nullptr;
    }
    __DMB();

    capture_work_path_owned_ =
        capture_writer_ && capture_writer_->created();
    const bool cancelled = preparation_cancel_requested_;
    const bool preparation_error = preparation_error_code_ != 0;
    if (cancelled || preparation_error) {
        capture_writer_.reset();
        if (cancelled && !preparation_error && capture_work_path_owned_ &&
            !capture_work_path_.empty()) {
            (void)delete_file(capture_work_path_);
        }
        capture_path_ = {};
        capture_work_path_ = {};
        capture_work_path_owned_ = false;
        capture_limit_bytes_ = 0;
        capture_phase_ = CapturePhase::Idle;
        set_capture_controls_locked(false);
        button_capture_.set_text("CAPTURE");
        if (preparation_error) {
            text_state_.set(to_string_dec_uint(preparation_error_code_));
        } else {
            text_state_.set("ARMED");
        }
        return;
    }

    /*
     * SD reservation intentionally runs before capture. Start a fresh stream
     * epoch afterward so any PREP-era DMA contention remains visible in the
     * prior epoch and cannot contaminate the capture boundary.
     */
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    if (!reset_measurement_epoch()) {
        capture_writer_.reset();
        if (capture_work_path_owned_ && !capture_work_path_.empty()) {
            (void)delete_file(capture_work_path_);
        }
        capture_path_ = {};
        capture_work_path_ = {};
        capture_work_path_owned_ = false;
        capture_limit_bytes_ = 0;
        capture_phase_ = CapturePhase::Idle;
        if (!rate_faulted_) {
            set_capture_controls_locked(false);
            button_capture_.set_text("CAPTURE");
        }
        return;
    }
#else
    reset_measurement_epoch();
#endif
    capture_thread_ = std::make_unique<CaptureThread>(
        std::move(capture_writer_),
        ::precision_rx::capture_write_size,
        ::precision_rx::capture_buffer_count,
        []() {
            CaptureThreadDoneMessage message{};
            EventDispatcher::send_message(message);
        },
        [](File::Error error) {
            CaptureThreadDoneMessage message{error.code()};
            EventDispatcher::send_message(message);
        },
        true,
        snapshots_.data());
    if (!capture_thread_->worker_created()) {
        capture_thread_error_code_ = FR_NOT_ENOUGH_CORE;
        stop_capture();
    }
}

void PrecisionRxView::cancel_preparation() {
    preparation_cancel_requested_ = true;
    if (preparation_thread_) {
        chThdWait(preparation_thread_);
        preparation_thread_ = nullptr;
    }
    preparation_done_ = true;
    finish_preparation();
}

void PrecisionRxView::stop_capture() {
    if (capture_phase_ == CapturePhase::Preparing && !capture_thread_) {
        cancel_preparation();
        return;
    }
    if (!capture_thread_) {
        return;
    }

    capture_phase_ = CapturePhase::Stopping;
    capture_thread_->stop();
    if (capture_thread_->error_code() != 0) {
        capture_thread_error_code_ = capture_thread_->error_code();
    }

    if (!capture_thread_->started()) {
        const bool preparation_error = capture_thread_error_code_ != 0;
        capture_thread_.reset();
        /* Delete only a cleanly cancelled PART that this attempt owns. */
        if (!preparation_error && capture_work_path_owned_ &&
            !capture_work_path_.empty()) {
            (void)delete_file(capture_work_path_);
        }
        capture_path_ = {};
        capture_work_path_ = {};
        capture_work_path_owned_ = false;
        capture_limit_bytes_ = 0;
        capture_phase_ = CapturePhase::Idle;
        set_capture_controls_locked(false);
        button_capture_.set_text("CAPTURE");
        text_state_.set(preparation_error ? "SD ERROR" : "ARMED");
        return;
    }

    /* Pair the M4 evidence publication fence before copying shared state. */
    __DMB();
    const auto& final_state = capture_thread_->state();
    const uint64_t offered_bytes = final_state.baseband_bytes_received;
    const uint64_t fifo_dropped_bytes = final_state.baseband_bytes_dropped;
    const uint64_t start_input_tick = final_state.baseband_start_input_tick;
    const uint64_t stop_input_tick = final_state.baseband_stop_input_tick;
    const uint64_t start_dropped_input_samples =
        final_state.baseband_start_dropped_input_samples;
    const uint64_t stop_dropped_input_samples =
        final_state.baseband_stop_dropped_input_samples;
    const auto capture_evidence = final_state.precision_rx_evidence;
    const uint64_t file_bytes = capture_thread_->file_bytes_written();
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
    const uint64_t target_bytes = capture_limit_bytes_;
#endif
    const bool file_error =
        capture_thread_->write_error() || capture_thread_error_code_ != 0;
    capture_thread_.reset();

    final_capture_stream_epoch_ = capture_evidence.final_stream_epoch;
    final_capture_report_sequence_ = capture_evidence.final_report_sequence;
    if (capture_evidence.valid) {
        capture_report_count_ = capture_evidence.status_reports_generated;
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        const SnapshotJournalBounds journal_bounds{
            start_input_tick,
            stop_input_tick,
            offered_bytes,
            fifo_dropped_bytes,
            stop_dropped_input_samples,
        };
        recover_snapshot_journal(capture_evidence, journal_bounds);
#else
        recover_snapshot_journal(
            capture_evidence,
            start_input_tick,
            stop_input_tick,
            offered_bytes,
            fifo_dropped_bytes,
            stop_dropped_input_samples);
#endif
        aggregate_continuity_flags_ =
            capture_evidence.aggregate_continuity_flags;
        aggregate_capture_continuity_flags_ =
            capture_evidence.aggregate_capture_continuity_flags;
        aggregate_metric_quality_flags_ =
            capture_evidence.aggregate_metric_quality_flags;
        aggregate_min_rms_dbfs_x10_ = capture_evidence.minimum_rms_dbfs_x10;
        aggregate_min_robust_rms_dbfs_x10_ =
            capture_evidence.minimum_robust_rms_dbfs_x10;
        aggregate_max_robust_rms_dbfs_x10_ =
            capture_evidence.maximum_robust_rms_dbfs_x10;
        aggregate_max_peak_dbfs_x10_ = capture_evidence.maximum_peak_dbfs_x10;
        aggregate_min_carrier_hz_x10_ =
            capture_evidence.minimum_carrier_mod_hz_x10;
        aggregate_max_carrier_hz_x10_ =
            capture_evidence.maximum_carrier_mod_hz_x10;
        aggregate_min_coherence_ppm_ =
            capture_evidence.minimum_coherence_ppm;
        aggregate_valid_carrier_reports_ =
            capture_evidence.valid_carrier_report_count;
    }

    if (fifo_dropped_bytes != 0) {
        aggregate_capture_continuity_flags_ |= loss_continuity_flag_mask;
    }
    if (stop_dropped_input_samples > start_dropped_input_samples) {
        aggregate_continuity_flags_ |= loss_continuity_flag_mask;
    }

#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
    const CaptureAcceptanceEvidence acceptance{
        capture_evidence.valid,
        capture_report_count_,
        snapshot_count_,
        start_input_tick,
        stop_input_tick,
        file_bytes,
        offered_bytes,
        fifo_dropped_bytes,
        start_dropped_input_samples,
        stop_dropped_input_samples,
        capture_missing_report_count_,
        aggregate_continuity_flags_,
        aggregate_capture_continuity_flags_,
        capture_evidence.terminal_reason,
        target_bytes,
    };
    const bool prefix_ok = capture_prefix_is_acceptable(acceptance);
    const bool saved = capture_is_acceptable(acceptance);
    if (!saved && !capture_path_.empty()) {
        if (prefix_ok &&
            capture_evidence.terminal_reason ==
                PrecisionRxCaptureTerminalReason::StoragePressure) {
            capture_path_.replace_extension(u".SHORT.C8");
        } else if (
            prefix_ok &&
            capture_evidence.terminal_reason ==
                PrecisionRxCaptureTerminalReason::RequestedStop) {
            capture_path_.replace_extension(u".STOP.C8");
        } else {
            capture_path_.replace_extension(u".LOSS.C8");
        }
    }

    const bool metadata_ok =
        !file_error && !capture_path_.empty() &&
        write_metadata(
            offered_bytes,
            fifo_dropped_bytes,
            file_bytes,
            start_input_tick,
            stop_input_tick,
            start_dropped_input_samples,
            stop_dropped_input_samples,
            file_error,
            capture_evidence.terminal_reason);
    /* Publish the data name last; a final data file therefore has a sidecar. */
    const bool publication_ok =
        metadata_ok && !capture_work_path_.empty() &&
        rename_file(capture_work_path_, capture_path_).ok();
    if (metadata_ok && !publication_ok) {
        auto metadata_path = capture_path_;
        metadata_path.replace_extension(u".PRX");
        (void)delete_file(metadata_path);
    }
    capture_path_ = {};
    capture_work_path_ = {};
    capture_work_path_owned_ = false;
    capture_limit_bytes_ = 0;
    capture_phase_ = CapturePhase::Idle;
    set_capture_controls_locked(false);
    button_capture_.set_text("CAPTURE");
    if (file_error) {
        text_state_.set("SD ERROR");
    } else if (!metadata_ok) {
        text_state_.set("META ERR");
    } else if (!publication_ok) {
        text_state_.set("PUB ERR");
    } else if (saved) {
        text_state_.set("SAVED");
    } else if (
        prefix_ok &&
        capture_evidence.terminal_reason ==
            PrecisionRxCaptureTerminalReason::StoragePressure) {
        text_state_.set("CARD SLOW");
    } else if (
        prefix_ok &&
        capture_evidence.terminal_reason ==
            PrecisionRxCaptureTerminalReason::RequestedStop) {
        text_state_.set("STOPPED");
    } else {
        text_state_.set("LOSS");
    }
#else
    const bool metadata_ok =
        !file_error && !capture_path_.empty() &&
        write_metadata(
            offered_bytes,
            fifo_dropped_bytes,
            file_bytes,
            start_input_tick,
            stop_input_tick,
            start_dropped_input_samples,
            stop_dropped_input_samples,
            file_error);
    /* Publish the C8 name last; a final C8 therefore always has a sidecar. */
    const bool publication_ok =
        metadata_ok && !capture_work_path_.empty() &&
        rename_file(capture_work_path_, capture_path_).ok();
    capture_path_ = {};
    capture_work_path_ = {};
    capture_work_path_owned_ = false;
    capture_limit_bytes_ = 0;
    capture_phase_ = CapturePhase::Idle;
    set_capture_controls_locked(false);
    button_capture_.set_text("CAPTURE");
    if (file_error) {
        text_state_.set("SD ERROR");
    } else if (!metadata_ok) {
        text_state_.set("META ERR");
    } else if (!publication_ok) {
        text_state_.set("PUB ERR");
    } else if (!capture_is_acceptable(CaptureAcceptanceEvidence{
                   capture_evidence.valid,
                   capture_report_count_,
                   snapshot_count_,
                   start_input_tick,
                   stop_input_tick,
                   file_bytes,
                   offered_bytes,
                   fifo_dropped_bytes,
                   start_dropped_input_samples,
                   stop_dropped_input_samples,
                   capture_missing_report_count_,
                   aggregate_continuity_flags_,
                   aggregate_capture_continuity_flags_,
               })) {
        text_state_.set("LOSS");
    } else {
        text_state_.set("SAVED");
    }
#endif
}

void PrecisionRxView::recover_snapshot_journal(
    const PrecisionRxCaptureEvidence& evidence,
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    const SnapshotJournalBounds& bounds) {
#else
    uint64_t start_input_tick,
    uint64_t stop_input_tick,
    uint64_t offered_bytes,
    uint64_t fifo_dropped_bytes,
    uint64_t stop_dropped_input_samples) {
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    const auto recovery = validate_snapshot_journal(
        snapshots_,
        evidence,
        bounds);
    snapshot_count_ = recovery.retained_count;
    snapshot_head_ = recovery.head;
    capture_missing_report_count_ = recovery.missing_count;
#else
    std::array<SnapshotRecord, snapshot_history_size> retained{};
    const size_t expected_count =
        ::precision_rx::capture_snapshot_journal_retained(
            evidence.status_reports_generated);
    size_t retained_count = 0;
    capture_missing_report_count_ = 0;
    const bool evidence_stable = (evidence.update_sequence & 1U) == 0U;
    SnapshotRecord previous{};
    bool have_previous = false;

    for (size_t index = 0; index < expected_count; ++index) {
        const uint32_t expected_sequence =
            ::precision_rx::capture_snapshot_journal_sequence(
                evidence.final_report_sequence,
                expected_count,
                index);
        const auto& snapshot =
            snapshots_[::precision_rx::capture_snapshot_journal_slot(
                expected_sequence)];
        const bool in_sequence_interval = ::precision_rx::report_in_capture_interval(
            evidence.valid,
            evidence.final_stream_epoch,
            evidence.final_report_sequence,
            evidence.status_reports_generated,
            snapshot.stream_epoch,
            snapshot.report_sequence);
        const bool in_tick_interval =
            snapshot.first_input_tick >= start_input_tick &&
            snapshot.next_input_tick > snapshot.first_input_tick &&
            snapshot.next_input_tick <= stop_input_tick;
        const bool counters_bounded =
            snapshot.dropped_input_samples <= stop_dropped_input_samples &&
            snapshot.capture_bytes_dropped <= snapshot.capture_bytes_received &&
            snapshot.capture_bytes_received <= offered_bytes &&
            snapshot.capture_bytes_dropped <= fifo_dropped_bytes;
        const bool follows_previous =
            !have_previous ||
            (snapshot.first_input_tick == previous.next_input_tick &&
             snapshot.dropped_input_samples >= previous.dropped_input_samples &&
             snapshot.capture_bytes_received >= previous.capture_bytes_received &&
             snapshot.capture_bytes_dropped >= previous.capture_bytes_dropped);
        const bool is_expected_record =
            evidence_stable &&
            snapshot.stream_epoch == evidence.final_stream_epoch &&
            snapshot.report_sequence == expected_sequence &&
            in_sequence_interval && in_tick_interval && counters_bounded &&
            follows_previous;
        const bool is_final_record = index + 1U == expected_count;
        const bool final_state_matches =
            !is_final_record ||
            (snapshot.next_input_tick == stop_input_tick &&
             snapshot.dropped_input_samples == stop_dropped_input_samples &&
             snapshot.capture_bytes_received == offered_bytes &&
             snapshot.capture_bytes_dropped == fifo_dropped_bytes);

        if (is_expected_record && final_state_matches) {
            retained[retained_count++] = snapshot;
            previous = snapshot;
            have_previous = true;
        } else {
            ++capture_missing_report_count_;
        }
    }

    snapshots_ = retained;
    snapshot_count_ = retained_count;
    snapshot_head_ = retained_count % snapshot_history_size;
#endif
}

void PrecisionRxView::set_capture_controls_locked(bool locked) {
    field_frequency_.set_focusable(!locked);
    field_frequency_step_.set_focusable(!locked);
    field_rf_amp_.set_focusable(!locked);
    field_lna_.set_focusable(!locked);
    field_vga_.set_focusable(!locked);
    options_sample_rate_.set_focusable(!locked);
}

bool PrecisionRxView::write_metadata(
    uint64_t offered_bytes,
    uint64_t fifo_dropped_bytes,
    uint64_t file_bytes,
    uint64_t start_input_tick,
    uint64_t stop_input_tick,
    uint64_t start_dropped_input_samples,
    uint64_t stop_dropped_input_samples,
    bool file_error
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
    ,
    PrecisionRxCaptureTerminalReason terminal_reason) {
#else
    ) {
#endif
    File metadata;
    auto metadata_path = capture_path_;
    metadata_path.replace_extension(u".PRX");
    const auto error = metadata.create_new(metadata_path);
    if (error.is_valid()) {
        return false;
    }

    const uint64_t accepted_bytes =
        offered_bytes >= fifo_dropped_bytes ? offered_bytes - fifo_dropped_bytes : 0;
    const uint64_t accepted_not_written_bytes =
        accepted_bytes >= file_bytes ? accepted_bytes - file_bytes : 0;
    const size_t oldest =
        (snapshot_head_ + snapshot_history_size - snapshot_count_) % snapshot_history_size;
    uint32_t records_crc = 0xffffffffU;
    for (size_t index = 0; index < snapshot_count_; ++index) {
        const auto& snapshot = snapshots_[(oldest + index) % snapshot_history_size];
        records_crc = crc32c_update(records_crc, &snapshot, sizeof(snapshot));
    }

#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
    SidecarHeaderV2 header{};
#else
    SidecarHeaderV1 header{};
#endif
    header.center_frequency_hz = capture_center_frequency_hz_;
    header.capture_start_input_tick = start_input_tick;
    header.capture_stop_input_tick = stop_input_tick;
    header.start_dropped_input_samples = start_dropped_input_samples;
    header.stop_dropped_input_samples = stop_dropped_input_samples;
    header.input_bytes_offered = offered_bytes;
    header.stream_fifo_bytes_dropped = fifo_dropped_bytes;
    header.stream_bytes_accepted = accepted_bytes;
    header.file_bytes_written = file_bytes;
    header.accepted_bytes_not_written = accepted_not_written_bytes;
    header.status_reports_generated = capture_report_count_;
    header.status_reports_missing = capture_missing_report_count_;
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
    header.magic = 0x32585250U; /* "PRX2" in little endian. */
    header.version = 2;
#else
    header.magic = 0x31585250U; /* "PRX1" in little endian. */
    header.version = 1;
#endif
    header.header_bytes = sizeof(header);
    header.record_bytes = sizeof(SnapshotRecord);
    header.sample_format = 1; /* Interleaved signed C8. */
    header.input_sample_rate_hz = capture_sample_rate_hz_;
    header.lna_gain_db = capture_lna_gain_db_;
    header.vga_gain_db = capture_vga_gain_db_;
    header.rf_amp_enabled = capture_rf_amp_enabled_;
    header.file_write_error = file_error;
    header.file_error_code = capture_thread_error_code_;
    header.aggregate_continuity_flags = aggregate_continuity_flags_;
    header.aggregate_capture_continuity_flags = aggregate_capture_continuity_flags_;
    header.aggregate_metric_quality_flags = aggregate_metric_quality_flags_;
    header.retained_record_count = snapshot_count_;
    header.retained_record_capacity = snapshot_history_size;
    header.final_stream_epoch = final_capture_stream_epoch_;
    header.final_report_sequence = final_capture_report_sequence_;
    header.minimum_rms_dbfs_x10 =
        capture_report_count_ ? aggregate_min_rms_dbfs_x10_ : -1200;
    header.minimum_robust_rms_dbfs_x10 =
        capture_report_count_ ? aggregate_min_robust_rms_dbfs_x10_ : -1200;
    header.maximum_robust_rms_dbfs_x10 =
        capture_report_count_ ? aggregate_max_robust_rms_dbfs_x10_ : -1200;
    header.maximum_peak_dbfs_x10 =
        capture_report_count_ ? aggregate_max_peak_dbfs_x10_ : -1200;
    header.minimum_carrier_mod_hz_x10 = aggregate_min_carrier_hz_x10_;
    header.maximum_carrier_mod_hz_x10 = aggregate_max_carrier_hz_x10_;
    header.minimum_coherence_ppm = aggregate_min_coherence_ppm_;
    header.valid_carrier_report_count = aggregate_valid_carrier_reports_;
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
    header.terminal_reason =
        static_cast<uint32_t>(terminal_reason);
    header.capture_target_input_samples = static_cast<uint32_t>(
        ::precision_rx::capture_target_samples(capture_sample_rate_hz_));
#endif
    header.records_crc32c = records_crc ^ 0xffffffffU;
    header.header_crc32c =
        crc32c_update(0xffffffffU, &header, sizeof(header)) ^ 0xffffffffU;

#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
    bool metadata_ok = write_exact(metadata, &header, sizeof(header));
    for (size_t index = 0; index < snapshot_count_; ++index) {
        const auto& snapshot = snapshots_[(oldest + index) % snapshot_history_size];
        metadata_ok = metadata_ok &&
                      write_exact(metadata, &snapshot, sizeof(snapshot));
    }
    return finish_new_file(
        metadata,
        metadata_path,
        metadata_ok);
#else
    if (!write_exact(metadata, &header, sizeof(header))) {
        return false;
    }
    for (size_t index = 0; index < snapshot_count_; ++index) {
        const auto& snapshot = snapshots_[(oldest + index) % snapshot_history_size];
        if (!write_exact(metadata, &snapshot, sizeof(snapshot))) {
            return false;
        }
    }
    return !metadata.sync().is_valid();
#endif
}

}  // namespace ui::external_app::precision_rx
