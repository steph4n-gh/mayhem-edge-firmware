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

#ifndef __PROC_PRECISION_RX_H__
#define __PROC_PRECISION_RX_H__

#include "baseband_processor.hpp"
#include "baseband_thread.hpp"
#include "precision_rx_capture_boundary.hpp"
#include "precision_rx_metrics.hpp"
#include "precision_rx_evidence.hpp"
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
#include "precision_rx_dma_lease.hpp"
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
#include "precision_rx_rate_transaction.hpp"
#endif
#include "stream_input.hpp"

#include <atomic>
#include <cstdint>
#include <memory>

class PrecisionRxProcessor : public BasebandProcessor {
   public:
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    PrecisionRxProcessor();
#else
    PrecisionRxProcessor() = default;
#endif

    void execute(const buffer_c8_t& buffer) override;
    void on_message(const Message* const message) override;

   private:
    enum class CaptureCommand : uint32_t {
        None = 0,
        Open,
        Close,
    };

    static constexpr uint32_t default_sample_rate = 2'000'000;
    static constexpr uint32_t minimum_sample_rate = 1'000'000;
    static constexpr uint32_t maximum_sample_rate = 20'000'000;

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    /*
     * Stable p12 wire/telemetry values. Sysinfo renders these as
     * BOOT/RUN/PREP/PAUSED/RESUME/FAULT respectively.
     */
    using RateState = precision_rx::rate_transaction::State;
    using RateEvent = precision_rx::rate_transaction::Event;

    static constexpr uint32_t rate_control_timeout_ms = 100;

    RateState rate_state() const;
    void set_rate_state(RateState state);
    bool transition_rate_state(RateEvent event);
    bool publish_running_if_dma_healthy(RateState expected_state);
    bool process_complete_block(const buffer_c8_t& buffer);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    void finish_capture_interval(
        PrecisionRxCaptureTerminalReason terminal_reason);
#endif
    bool wait_while_rate_state(RateState state) const;
    bool wait_for_rate_pause_armed() const;
    bool capture_idle_for_rate_change() const;
    void record_rate_transition_failure();
    bool reject_capture_command_after_dma_fault(
        CaptureCommand command,
        CaptureConfig* config);
    uint32_t request_rate_pause();
    uint32_t resume_rate_change(uint32_t target_rate_hz, uint32_t success_ack);
    uint32_t handle_rate_control(uint32_t request);
    void service_rate_prepare();
#endif

    void configure(uint32_t input_sample_rate_hz);
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    bool service_capture_command();
    bool transition_dma_geometry(bool capture);
    void finish_capture_command();
#else
    void service_capture_command();
#endif
    void request_capture_command(
        CaptureCommand command,
        CaptureConfig* config,
        bool flush = false);
    void record_capture_evidence(const precision_rx::MetricsSnapshot& snapshot);
    void publish(const precision_rx::MetricsSnapshot& snapshot) const;

    precision_rx::MetricsAccumulator metrics_{};
    uint32_t stream_epoch_{0};
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    uint32_t current_sample_rate_hz_{default_sample_rate};
#endif
    bool configured_{false};
    std::atomic<uint32_t> pending_sample_rate_hz_{0};
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    std::atomic<RateState> rate_state_{RateState::Bootstrap};
    std::atomic<uint32_t> committed_sample_rate_hz_{0};
    uint32_t rate_previous_hz_{0};
    uint32_t rate_target_hz_{0};
    uint32_t rate_loss_baseline_{0};
    bool baseband_started_{false};
    precision_rx::rate_transaction::LifetimeLossObservation
        dma_loss_observation_{};
#else
    uint16_t last_dma_missed_transfers_{0};
#endif

    /* Construct and allocate before baseband_thread_ starts DMA. */
    StreamInput capture_stream_{
        precision_rx::capture_write_size,
        precision_rx::capture_local_buffer_count};
    CaptureConfig* active_capture_config_{nullptr};
    precision_rx::CaptureBoundaryState capture_boundary_{};
    std::atomic<CaptureCommand> capture_command_{CaptureCommand::None};
    std::atomic<CaptureConfig*> pending_capture_config_{nullptr};
    std::atomic<bool> capture_flush_requested_{false};
    bool capture_close_started_{false};
    uint64_t capture_close_input_tick_{0};
    uint64_t capture_close_dropped_input_samples_{0};
    uint64_t capture_bytes_received_{0};
    uint64_t capture_bytes_dropped_{0};
    uint32_t pending_capture_continuity_flags_{0};

    /* Threads must remain the final members of the processor. */
    BasebandThread baseband_thread_{
        default_sample_rate,
        this,
        baseband::Direction::Receive
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        ,
        reinterpret_cast<baseband::sample_t*>(capture_stream_.dma_loan_buffer())
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        ,
        false
#endif
    };
};

#endif /*__PROC_PRECISION_RX_H__*/
