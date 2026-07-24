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

#ifndef __UI_PRECISION_RX_H__
#define __UI_PRECISION_RX_H__

#include "app_settings.hpp"
#include "capture_thread.hpp"
#include "message.hpp"
#include "precision_rx_capture_writer.hpp"
#include "precision_rx_evidence.hpp"
#include "radio_state.hpp"
#include "ui.hpp"
#include "ui_freq_field.hpp"
#include "ui_navigation.hpp"
#include "ui_receiver.hpp"
#include "ui_widget.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
namespace baseband {
enum class PrecisionRxRateResult : uint8_t;
}
#endif

namespace ui::external_app::precision_rx {

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
struct SnapshotJournalBounds;
#endif

using SnapshotRecord = PrecisionRxSnapshotRecord;

class PrecisionRxView final : public View {
   public:
    explicit PrecisionRxView(NavigationView& nav);
    ~PrecisionRxView();

    PrecisionRxView(const PrecisionRxView&) = delete;
    PrecisionRxView(PrecisionRxView&&) = delete;
    PrecisionRxView& operator=(const PrecisionRxView&) = delete;
    PrecisionRxView& operator=(PrecisionRxView&&) = delete;

    std::string title() const override { return "Precision RX"; }
    void focus() override;

   private:
    enum class CapturePhase : uint8_t {
        Idle,
        Preparing,
        Capturing,
        Stopping,
    };

    /* Full-capture aggregate evidence is retained separately below. */
    static constexpr size_t snapshot_history_size =
        ::precision_rx::capture_snapshot_journal_capacity;
    static constexpr uint32_t capture_rate_limit_hz = 2'000'000;

    NavigationView& nav_;
    RxRadioState radio_state_{
        433'920'000,
        1'750'000,
        2'000'000,
        ReceiverModel::Mode::SpectrumAnalysis};
    uint32_t sample_rate_{2'000'000};
    app_settings::SettingsManager settings_{
        "rx_precision"sv,
        app_settings::Mode::RX,
        {{"sample_rate"sv, &sample_rate_}}};
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    uint32_t committed_sample_rate_{2'000'000};
    size_t committed_sample_rate_index_{1};
    bool rate_faulted_{false};
    bool restoring_sample_rate_option_{false};
#endif

    /* Declared first so the capture thread is destroyed before its M4 journal. */
    std::array<SnapshotRecord, snapshot_history_size> snapshots_{};
    std::unique_ptr<CaptureThread> capture_thread_{};
    std::unique_ptr<PrecisionRxCaptureWriter> capture_writer_{};
    Thread* preparation_thread_{nullptr};
    bool volatile preparation_cancel_requested_{false};
    bool volatile preparation_done_{false};
    /* Zero on success; otherwise decimal SEEEDDDDD. */
    uint32_t preparation_error_code_{0};
    bool capture_work_path_owned_{false};
    CapturePhase capture_phase_{CapturePhase::Idle};
    std::filesystem::path capture_path_{};
    std::filesystem::path capture_work_path_{};
    uint64_t capture_center_frequency_hz_{0};
    uint32_t capture_sample_rate_hz_{0};
    uint8_t capture_lna_gain_db_{0};
    uint8_t capture_vga_gain_db_{0};
    bool capture_rf_amp_enabled_{false};
    uint32_t capture_thread_error_code_{0};
    uint64_t capture_limit_bytes_{0};
    PrecisionRxStatusMessage latest_status_{};
    bool have_status_{false};
    size_t snapshot_head_{0};
    size_t snapshot_count_{0};
    uint64_t capture_report_count_{0};
    uint64_t capture_missing_report_count_{0};
    uint32_t final_capture_stream_epoch_{0};
    uint32_t final_capture_report_sequence_{0};
    uint32_t aggregate_continuity_flags_{0};
    uint32_t aggregate_capture_continuity_flags_{0};
    uint32_t aggregate_metric_quality_flags_{0};
    int32_t aggregate_min_rms_dbfs_x10_{-1200};
    int32_t aggregate_min_robust_rms_dbfs_x10_{-1200};
    int32_t aggregate_max_robust_rms_dbfs_x10_{-1200};
    int32_t aggregate_max_peak_dbfs_x10_{-1200};
    int32_t aggregate_min_carrier_hz_x10_{0};
    int32_t aggregate_max_carrier_hz_x10_{0};
    uint32_t aggregate_min_coherence_ppm_{0};
    uint32_t aggregate_valid_carrier_reports_{0};

    RxFrequencyField field_frequency_{{UI_POS_X(0), UI_POS_Y(0)}, nav_};
    FrequencyStepView field_frequency_step_{{UI_POS_X(10), UI_POS_Y(0)}};
    RFAmpField field_rf_amp_{{UI_POS_X(16), UI_POS_Y(0)}};
    LNAGainField field_lna_{{UI_POS_X(18), UI_POS_Y(0)}};
    VGAGainField field_vga_{{UI_POS_X(21), UI_POS_Y(0)}};

    Labels labels_{
        {{{UI_POS_X(0), UI_POS_Y(2)}, "SR:", Color::light_grey()},
         {{UI_POS_X(0), UI_POS_Y(4)}, "Epoch/Seq", Color::light_grey()},
         {{UI_POS_X(0), UI_POS_Y(5)}, "Input:", Color::light_grey()},
         {{UI_POS_X(0), UI_POS_Y(6)}, "RMS/Pk:", Color::light_grey()},
         {{UI_POS_X(0), UI_POS_Y(7)}, "DC I/Q:", Color::light_grey()},
         {{UI_POS_X(0), UI_POS_Y(8)}, "Carrier:", Color::light_grey()},
         {{UI_POS_X(0), UI_POS_Y(9)}, "Drift:", Color::light_grey()},
         {{UI_POS_X(0), UI_POS_Y(10)}, "Coher:", Color::light_grey()},
         {{UI_POS_X(0), UI_POS_Y(11)}, "S/D/F:", Color::light_grey()},
         {{UI_POS_X(0), UI_POS_Y(12)}, "Gain:", Color::light_grey()},
         {{UI_POS_X(0), UI_POS_Y(13)}, "Uncal/mod:", Color::light_grey()}}};

    OptionsField options_sample_rate_{
        {UI_POS_X(3), UI_POS_Y(2)},
        6,
        {{"1.0M", 1'000'000},
         {"2.0M", 2'000'000},
         {"4.0M", 4'000'000},
         {"8.0M", 8'000'000},
         {"10.0M", 10'000'000},
         {"16.0M", 16'000'000},
         {"20.0M", 20'000'000}}};
    Button button_capture_{{UI_POS_X(10), UI_POS_Y(2), 64, 28}, "CAPTURE"};
    Text text_state_{{UI_POS_X(19), UI_POS_Y(2), 88, 16}, "START"};
    Text text_epoch_{{UI_POS_X(11), UI_POS_Y(4), 144, 16}, "--"};
    Text text_tick_{{UI_POS_X(11), UI_POS_Y(5), 152, 16}, "--"};
    Text text_levels_{{UI_POS_X(11), UI_POS_Y(6), 152, 16}, "--"};
    Text text_dc_{{UI_POS_X(11), UI_POS_Y(7), 152, 16}, "--"};
    Text text_carrier_{{UI_POS_X(11), UI_POS_Y(8), 152, 16}, "--"};
    Text text_drift_{{UI_POS_X(11), UI_POS_Y(9), 152, 16}, "--"};
    Text text_coherence_{{UI_POS_X(11), UI_POS_Y(10), 152, 16}, "--"};
    Text text_loss_{{UI_POS_X(11), UI_POS_Y(11), 152, 16}, "--"};
    Text text_gain_{{UI_POS_X(13), UI_POS_Y(12), 136, 16}, "HOLD"};
    Text text_evidence_{{UI_POS_X(11), UI_POS_Y(13), 152, 16}, "--"};

    MessageHandlerRegistration message_handler_status_{
        Message::ID::PrecisionRxStatus,
        [this](const Message* const message) {
            on_status(*reinterpret_cast<const PrecisionRxStatusMessage*>(message));
        }};
    MessageHandlerRegistration message_handler_frequency_{
        Message::ID::FreqChangeCommand,
        [this](Message* const message) {
            const auto command = static_cast<const FreqChangeCommandMessage*>(message);
            if (capture_phase_ != CapturePhase::Idle) {
                stop_capture();
            }
            field_frequency_.set_value(command->freq);
        }};
    MessageHandlerRegistration message_handler_capture_done_{
        Message::ID::CaptureThreadDone,
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
        [this](const Message* const) {
            if (capture_phase_ == CapturePhase::Preparing && !capture_thread_ &&
                preparation_done_) {
                finish_preparation();
            } else if (capture_thread_ && capture_thread_->done()) {
                stop_capture();
            }
#else
        [this](const Message* const message) {
            const auto& done = *reinterpret_cast<const CaptureThreadDoneMessage*>(message);
            if (capture_phase_ == CapturePhase::Preparing && !capture_thread_ &&
                preparation_done_) {
                finish_preparation();
            } else if (capture_thread_ && done.error != 0) {
                capture_thread_error_code_ = done.error;
                stop_capture();
            }
#endif
        }};

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    bool apply_sample_rate();
    bool reset_measurement_epoch();
    bool finish_sample_rate_change(
        baseband::PrecisionRxRateResult result);
#else
    void apply_sample_rate();
    void reset_measurement_epoch();
#endif
    void on_status(const PrecisionRxStatusMessage& status);
    void update_display();
    void start_capture();
    void finish_preparation();
    void cancel_preparation();
    void stop_capture();
    static msg_t preparation_thread_fn(void* context);
    void recover_snapshot_journal(
        const PrecisionRxCaptureEvidence& evidence,
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        const SnapshotJournalBounds& bounds);
#else
        uint64_t start_input_tick,
        uint64_t stop_input_tick,
        uint64_t offered_bytes,
        uint64_t fifo_dropped_bytes,
        uint64_t stop_dropped_input_samples);
#endif
    void set_capture_controls_locked(bool locked);
    bool write_metadata(
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
        PrecisionRxCaptureTerminalReason terminal_reason);
#else
        );
#endif
};

}  // namespace ui::external_app::precision_rx

#endif /*__UI_PRECISION_RX_H__*/
