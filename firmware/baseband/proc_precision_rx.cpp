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

#include "proc_precision_rx.hpp"

#include "event_m4.hpp"
#include "portapack_shared_memory.hpp"

#include <algorithm>

#if defined(__arm__)
#define PRECISION_RX_CONTROL_SIZE_OPT __attribute__((optimize("Os")))
#else
#define PRECISION_RX_CONTROL_SIZE_OPT
#endif

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
#define PRECISION_RX_RELAXED_LOAD(object) \
    (object).load(std::memory_order_relaxed)
#define PRECISION_RX_RELAXED_STORE(object, value) \
    (object).store((value), std::memory_order_relaxed)
#define PRECISION_RX_RELEASE_STORE(object, value) \
    (object).store((value), std::memory_order_release)
#define PRECISION_RX_ACQUIRE_FENCE() \
    std::atomic_thread_fence(std::memory_order_acquire)
#else
#define PRECISION_RX_RELAXED_LOAD(object) (object).load()
#define PRECISION_RX_RELAXED_STORE(object, value) (object).store(value)
#define PRECISION_RX_RELEASE_STORE(object, value) (object).store(value)
#define PRECISION_RX_ACQUIRE_FENCE()
#endif

#if defined(__arm__)
#define HACKRF_EDGE_STRINGIFY_IMPL(value) #value
#define HACKRF_EDGE_STRINGIFY(value) HACKRF_EDGE_STRINGIFY_IMPL(value)
/* Absolute metadata: proves the mode and implementation share one layout. */
__asm__(
    ".global hackrf_edge_precision_rx_mode_buffer_count_log2\n"
    ".type hackrf_edge_precision_rx_mode_buffer_count_log2, %object\n"
    ".set hackrf_edge_precision_rx_mode_buffer_count_log2, "
    HACKRF_EDGE_STRINGIFY(STREAM_INPUT_BUFFER_COUNT_MAX_LOG2) "\n"
    ".size hackrf_edge_precision_rx_mode_buffer_count_log2, 1\n");
__asm__(
    ".global hackrf_edge_precision_rx_mode_local_buffer_count\n"
    ".type hackrf_edge_precision_rx_mode_local_buffer_count, %object\n"
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
    ".set hackrf_edge_precision_rx_mode_local_buffer_count, 9\n"
#else
    ".set hackrf_edge_precision_rx_mode_local_buffer_count, 8\n"
#endif
    ".size hackrf_edge_precision_rx_mode_local_buffer_count, 1\n"
    ".global hackrf_edge_precision_rx_mode_spill_buffer_count\n"
    ".type hackrf_edge_precision_rx_mode_spill_buffer_count, %object\n"
#if defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC)
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
    ".set hackrf_edge_precision_rx_mode_spill_buffer_count, 2\n"
#else
    ".set hackrf_edge_precision_rx_mode_spill_buffer_count, 3\n"
#endif
#else
    ".set hackrf_edge_precision_rx_mode_spill_buffer_count, 0\n"
#endif
    ".size hackrf_edge_precision_rx_mode_spill_buffer_count, 1\n"
    ".global hackrf_edge_precision_rx_mode_total_buffer_count\n"
    ".type hackrf_edge_precision_rx_mode_total_buffer_count, %object\n"
#if defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC)
    ".set hackrf_edge_precision_rx_mode_total_buffer_count, 11\n"
#else
    ".set hackrf_edge_precision_rx_mode_total_buffer_count, 8\n"
#endif
    ".size hackrf_edge_precision_rx_mode_total_buffer_count, 1\n");
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
__asm__(
    ".global hackrf_edge_precision_rx_dma_capture_rate_limit_hz\n"
    ".type hackrf_edge_precision_rx_dma_capture_rate_limit_hz, %object\n"
    ".set hackrf_edge_precision_rx_dma_capture_rate_limit_hz, 2000000\n"
    ".size hackrf_edge_precision_rx_dma_capture_rate_limit_hz, 4\n"
    ".global hackrf_edge_precision_rx_dma_transition_discards_old_block\n"
    ".type hackrf_edge_precision_rx_dma_transition_discards_old_block, %object\n"
    ".set hackrf_edge_precision_rx_dma_transition_discards_old_block, 1\n"
    ".size hackrf_edge_precision_rx_dma_transition_discards_old_block, 1\n"
    ".global hackrf_edge_precision_rx_dma_transition_resets_epoch\n"
    ".type hackrf_edge_precision_rx_dma_transition_resets_epoch, %object\n"
    ".set hackrf_edge_precision_rx_dma_transition_resets_epoch, 1\n"
    ".size hackrf_edge_precision_rx_dma_transition_resets_epoch, 1\n"
    ".global hackrf_edge_precision_rx_dma_high_rate_bound_request_rejected\n"
    ".type hackrf_edge_precision_rx_dma_high_rate_bound_request_rejected, %object\n"
    ".set hackrf_edge_precision_rx_dma_high_rate_bound_request_rejected, 1\n"
    ".size hackrf_edge_precision_rx_dma_high_rate_bound_request_rejected, 1\n"
    ".global hackrf_edge_precision_rx_dma_abort_force_unbind\n"
    ".type hackrf_edge_precision_rx_dma_abort_force_unbind, %object\n"
    ".set hackrf_edge_precision_rx_dma_abort_force_unbind, 1\n"
    ".size hackrf_edge_precision_rx_dma_abort_force_unbind, 1\n"
    ".global hackrf_edge_precision_rx_dma_abort_requires_consumer_release\n"
    ".type hackrf_edge_precision_rx_dma_abort_requires_consumer_release, %object\n"
    ".set hackrf_edge_precision_rx_dma_abort_requires_consumer_release, 1\n"
    ".size hackrf_edge_precision_rx_dma_abort_requires_consumer_release, 1\n");
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
__asm__(
    ".global hackrf_edge_precision_rx_rate_transaction_protocol_version\n"
    ".type hackrf_edge_precision_rx_rate_transaction_protocol_version, %object\n"
    ".set hackrf_edge_precision_rx_rate_transaction_protocol_version, 3\n"
    ".size hackrf_edge_precision_rx_rate_transaction_protocol_version, 1\n"
    ".global hackrf_edge_precision_rx_rate_prepare_gates_sgpio_before_dma_pause\n"
    ".type hackrf_edge_precision_rx_rate_prepare_gates_sgpio_before_dma_pause, %object\n"
    ".set hackrf_edge_precision_rx_rate_prepare_gates_sgpio_before_dma_pause, 0\n"
    ".size hackrf_edge_precision_rx_rate_prepare_gates_sgpio_before_dma_pause, 1\n"
    ".global hackrf_edge_precision_rx_rate_prepare_halts_dma_before_gating_sgpio\n"
    ".type hackrf_edge_precision_rx_rate_prepare_halts_dma_before_gating_sgpio, %object\n"
    ".set hackrf_edge_precision_rx_rate_prepare_halts_dma_before_gating_sgpio, 1\n"
    ".size hackrf_edge_precision_rx_rate_prepare_halts_dma_before_gating_sgpio, 1\n"
    ".global hackrf_edge_precision_rx_rate_quiesce_failure_bits\n"
    ".type hackrf_edge_precision_rx_rate_quiesce_failure_bits, %object\n"
    ".set hackrf_edge_precision_rx_rate_quiesce_failure_bits, 4\n"
    ".size hackrf_edge_precision_rx_rate_quiesce_failure_bits, 1\n"
    ".global hackrf_edge_precision_rx_rate_transition_failure_count_bits\n"
    ".type hackrf_edge_precision_rx_rate_transition_failure_count_bits, %object\n"
    ".set hackrf_edge_precision_rx_rate_transition_failure_count_bits, 28\n"
    ".size hackrf_edge_precision_rx_rate_transition_failure_count_bits, 1\n"
    ".global hackrf_edge_precision_rx_rate_prepare_ack_requires_pause_armed\n"
    ".type hackrf_edge_precision_rx_rate_prepare_ack_requires_pause_armed, %object\n"
    ".set hackrf_edge_precision_rx_rate_prepare_ack_requires_pause_armed, 1\n"
    ".size hackrf_edge_precision_rx_rate_prepare_ack_requires_pause_armed, 1\n"
    ".global hackrf_edge_precision_rx_rate_commit_publishes_target_before_dma_resume\n"
    ".type hackrf_edge_precision_rx_rate_commit_publishes_target_before_dma_resume, %object\n"
    ".set hackrf_edge_precision_rx_rate_commit_publishes_target_before_dma_resume, 1\n"
    ".size hackrf_edge_precision_rx_rate_commit_publishes_target_before_dma_resume, 1\n"
    ".global hackrf_edge_precision_rx_rate_commit_ack_requires_first_new_rate_completion\n"
    ".type hackrf_edge_precision_rx_rate_commit_ack_requires_first_new_rate_completion, %object\n"
    ".set hackrf_edge_precision_rx_rate_commit_ack_requires_first_new_rate_completion, 1\n"
    ".size hackrf_edge_precision_rx_rate_commit_ack_requires_first_new_rate_completion, 1\n"
    ".global hackrf_edge_precision_rx_rate_fail_closed_on_prepare_failure\n"
    ".type hackrf_edge_precision_rx_rate_fail_closed_on_prepare_failure, %object\n"
    ".set hackrf_edge_precision_rx_rate_fail_closed_on_prepare_failure, 1\n"
    ".size hackrf_edge_precision_rx_rate_fail_closed_on_prepare_failure, 1\n"
    ".global hackrf_edge_precision_rx_rate_fail_closed_on_commit_failure\n"
    ".type hackrf_edge_precision_rx_rate_fail_closed_on_commit_failure, %object\n"
    ".set hackrf_edge_precision_rx_rate_fail_closed_on_commit_failure, 1\n"
    ".size hackrf_edge_precision_rx_rate_fail_closed_on_commit_failure, 1\n");
#endif
#undef HACKRF_EDGE_STRINGIFY
#undef HACKRF_EDGE_STRINGIFY_IMPL
#endif

namespace {

void cross_core_evidence_fence() {
    __asm__ volatile("" ::: "memory");
    __DMB();
    __asm__ volatile("" ::: "memory");
}

PrecisionRxSnapshotRecord make_snapshot_record(
    const precision_rx::MetricsSnapshot& snapshot,
    uint64_t capture_bytes_received,
    uint64_t capture_bytes_dropped) {
    return {
        snapshot.first_input_tick,
        snapshot.next_input_tick,
        snapshot.dropped_input_samples,
        capture_bytes_received,
        capture_bytes_dropped,
        snapshot.stream_epoch,
        snapshot.report_sequence,
        snapshot.continuity_flags,
        snapshot.capture_continuity_flags,
        snapshot.metric_quality_flags,
        snapshot.analysis_stride,
        snapshot.analyzed_sample_count,
        snapshot.sampled_clip_count,
        snapshot.mean_i_q8,
        snapshot.mean_q_q8,
        snapshot.rms_dbfs_x10,
        snapshot.robust_rms_dbfs_x10,
        snapshot.peak_dbfs_x10,
        snapshot.carrier_offset_hz_x10,
        snapshot.carrier_delta_hz_per_s_x10,
        snapshot.coherence_ppm,
    };
}

}  // namespace

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
__attribute__((noinline, noclone, used, externally_visible, optimize("Os")))
PrecisionRxProcessor::PrecisionRxProcessor() {
    /*
     * M0 boot construction is the sole lifetime-counter reset authority.
     * Snapshot its current truth before DMA can start, then never rebase it
     * in configure(), a rate transaction, or a geometry transition.
     */
    shared_memory.m4_dma_rate_hz = 0;
    shared_memory.m4_dma_queue_depth = 0;
    shared_memory.m4_dma_phase = 0;
    dma_loss_observation_.initialize_before_dma(
        shared_memory.m4_dma_missed_lifetime);
    set_rate_state(RateState::Bootstrap);
}
#endif

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
PrecisionRxProcessor::RateState PrecisionRxProcessor::rate_state() const {
    return rate_state_.load(std::memory_order_relaxed);
}

void PrecisionRxProcessor::set_rate_state(const RateState state) {
    shared_memory.m4_dma_rate_state = static_cast<uint8_t>(state);
    cross_core_evidence_fence();
    rate_state_.store(state, std::memory_order_release);
}

__attribute__((noinline, noclone,
               optimize("Os", "no-if-conversion", "no-if-conversion2")))
bool PrecisionRxProcessor::transition_rate_state(const RateEvent event) {
    /*
     * BASEPRI excludes scheduler-capable interrupts while the priority-1 DMA
     * vector is explicitly masked below. Without both levels of exclusion a
     * wakeup could reschedule the worker and leave TC sticky across an entire
     * execute() interval.
     */
    chSysLock();
    if (event != RateEvent::Fatal &&
        !baseband_thread_.begin_precision_rx_rate_state_update()) {
        /*
         * The exclusion helper has already gated/stopped a pending DMA event.
         * Only FAULT may now be published; never let a stale non-fatal reducer
         * result overwrite the priority-1 ISR's cross-core fault state.
         */
        set_rate_state(RateState::Fault);
        chSysUnlock();
        return false;
    }

    const auto transition =
        precision_rx::rate_transaction::reduce(rate_state(), event);
    if (transition.accepted)
        set_rate_state(transition.next);

    if (event != RateEvent::Fatal)
        baseband_thread_.end_precision_rx_rate_state_update();
    chSysUnlock();
    return transition.accepted;
}

__attribute__((noinline, noclone, used, externally_visible,
               optimize("Os", "no-if-conversion", "no-if-conversion2")))
bool PrecisionRxProcessor::publish_running_if_dma_healthy(
    const RateState expected_state) {
    /*
     * transition_rate_state() owns the combined scheduler/priority-1 exclusion
     * and durable-latch validation. The expected-state test may race only into
     * that guarded reducer, never into an unguarded RUN publication.
     */
    const bool expected = rate_state() == expected_state;
    return expected &&
           transition_rate_state(
               expected_state == RateState::PrepareRequested
                   ? RateEvent::PrepareHaltRestored
                   : RateEvent::FirstBlockApplied);
}

/*
 * Linked COMMIT evidence: this out-of-line routine is the sole P12 complete
 * block consumer. Capture receives the full descriptor before metrics, and a
 * true return is published only after both paths have finished.
 */
__attribute__((noinline, noclone, used, externally_visible,
               optimize("Os", "no-if-conversion", "no-if-conversion2")))
bool PrecisionRxProcessor::process_complete_block(
    const buffer_c8_t& buffer) {
    if (!buffer.p || buffer.count == 0U)
        return false;

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    auto terminal_reason = PrecisionRxCaptureTerminalReason::Unspecified;
    if (capture_boundary_.active()) {
        static_assert(
            precision_rx::capture_target_bytes(maximum_sample_rate) <=
                0xffffffffULL,
            "Precision RX capture target must fit the M4 fast-path word");
        const size_t bytes = buffer.count * sizeof(*buffer.p);
        const uint32_t target_bytes =
            current_sample_rate_hz_ *
            precision_rx::capture_duration_seconds *
            precision_rx::complex8_bytes_per_sample;
        const uint32_t received_bytes =
            static_cast<uint32_t>(capture_bytes_received_);
        if (received_bytes > target_bytes ||
            bytes > target_bytes - received_bytes) {
            terminal_reason =
                PrecisionRxCaptureTerminalReason::InvariantFailure;
        } else if (!capture_stream_.try_write_exact(
                       buffer.p,
                       bytes,
                       precision_rx::capture_closing_reserve_buffers)) {
            terminal_reason =
                PrecisionRxCaptureTerminalReason::StoragePressure;
        } else {
            const uint32_t accepted_bytes = received_bytes + bytes;
            capture_bytes_received_ = accepted_bytes;
            if (accepted_bytes == target_bytes) {
                terminal_reason =
                    PrecisionRxCaptureTerminalReason::TargetReached;
            }
        }
        if (terminal_reason !=
                PrecisionRxCaptureTerminalReason::Unspecified &&
            terminal_reason !=
                PrecisionRxCaptureTerminalReason::TargetReached)
            finish_capture_interval(terminal_reason);
    }
#else
    if (capture_boundary_.active()) {
        const size_t bytes = buffer.count * sizeof(*buffer.p);
        const size_t written = capture_stream_.write(buffer.p, bytes);
        capture_bytes_received_ += bytes;
        capture_bytes_dropped_ += bytes - written;
        if (written != bytes) {
            pending_capture_continuity_flags_ |=
                precision_rx::DISCONTINUITY | precision_rx::DROPPED_INPUT;
        }
    }
#endif

    if (metrics_.observe_block(buffer.p, buffer.count)) {
        precision_rx::MetricsSnapshot snapshot;
        if (metrics_.take_snapshot(snapshot)) {
            snapshot.capture_continuity_flags =
                pending_capture_continuity_flags_;
            pending_capture_continuity_flags_ = 0;
            if (capture_boundary_.active())
                record_capture_evidence(snapshot);
            publish(snapshot);
        }
    }
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    if (terminal_reason ==
        PrecisionRxCaptureTerminalReason::TargetReached)
        finish_capture_interval(terminal_reason);
#endif
    return true;
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
void PrecisionRxProcessor::finish_capture_interval(
    const PrecisionRxCaptureTerminalReason terminal_reason) {
    /* Every caller owns an active boundary/configuration pair. */
    if (capture_close_started_)
        return;

    precision_rx::MetricsSnapshot final_snapshot{};
    if (capture_boundary_.active() &&
        metrics_.take_snapshot(final_snapshot, true)) {
        final_snapshot.capture_continuity_flags =
            pending_capture_continuity_flags_;
        pending_capture_continuity_flags_ = 0;
        record_capture_evidence(final_snapshot);
        publish(final_snapshot);
    }

    auto& evidence = active_capture_config_->precision_rx_evidence;
    ++evidence.update_sequence;
    cross_core_evidence_fence();
    evidence.terminal_reason = terminal_reason;
    cross_core_evidence_fence();
    ++evidence.update_sequence;

    capture_boundary_.end_capture();
    active_capture_config_->baseband_stop_input_tick =
        metrics_.input_tick();
    active_capture_config_->baseband_stop_dropped_input_samples =
        metrics_.dropped_input_samples();
    capture_close_started_ = true;

    /*
     * The exact writer reserves two empty descriptors.  A partial data tail
     * plus its zero-length sentinel therefore completes in at most two
     * allocation-free, nonblocking calls.
     */
    (void)capture_stream_.seal();
    (void)capture_stream_.seal();
}
#endif

__attribute__((noinline, noclone, optimize("Os")))
bool PrecisionRxProcessor::wait_while_rate_state(
    const RateState state) const {
    const systime_t started = chTimeNow();
    while (rate_state() == state) {
        if (chTimeElapsedSince(started) >=
            MS2ST(rate_control_timeout_ms)) {
            return false;
        }
        chThdSleepMilliseconds(1);
    }
    PRECISION_RX_ACQUIRE_FENCE();
    return true;
}

__attribute__((noinline, noclone, optimize("Os")))
bool PrecisionRxProcessor::wait_for_rate_pause_armed() const {
    const systime_t started = chTimeNow();
    while (rate_state() == RateState::PausedArmed) {
        if (baseband_thread_.precision_rx_rate_pause_armed()) {
            cross_core_evidence_fence();
            return true;
        }
        if (chTimeElapsedSince(started) >=
            MS2ST(rate_control_timeout_ms)) {
            return false;
        }
        chThdSleepMilliseconds(1);
    }
    return false;
}

bool PrecisionRxProcessor::capture_idle_for_rate_change() const {
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    return PRECISION_RX_RELAXED_LOAD(capture_command_) ==
               CaptureCommand::None &&
           PRECISION_RX_RELAXED_LOAD(pending_capture_config_) == nullptr &&
           active_capture_config_ == nullptr &&
           !capture_boundary_.active() &&
           capture_stream_.unbound();
#else
    return PRECISION_RX_RELAXED_LOAD(capture_command_) ==
               CaptureCommand::None &&
           active_capture_config_ == nullptr &&
           !capture_boundary_.active();
#endif
}

__attribute__((noinline, noclone, optimize("Os")))
void PrecisionRxProcessor::record_rate_transition_failure() {
    chSysLock();
    shared_memory.m4_dma_transition_failures =
        precision_rx::dma_telemetry::increment_transition_failure(
            shared_memory.m4_dma_transition_failures);
    chSysUnlock();
    cross_core_evidence_fence();
}

PRECISION_RX_CONTROL_SIZE_OPT
bool PrecisionRxProcessor::reject_capture_command_after_dma_fault(
    const CaptureCommand command,
    CaptureConfig* const config) {
    if (!baseband_thread_.precision_rx_dma_faulted())
        return false;

    /*
     * The worker has higher priority than the dispatcher and its fatal path
     * contains no blocking operation. Wait only for its explicit quiescence
     * publication; do not leave M0 spinning forever if that publication is
     * lost or corrupted.
     */
    const systime_t started = chTimeNow();
    while (!baseband_thread_.precision_rx_worker_quiesced() &&
           chTimeElapsedSince(started) <
               MS2ST(rate_control_timeout_ms)) {
        chThdSleepMilliseconds(1);
    }
    const bool worker_quiesced =
        baseband_thread_.precision_rx_worker_quiesced();

    CaptureConfig* const pending =
        PRECISION_RX_RELAXED_LOAD(pending_capture_config_);
    CaptureConfig* const requested = config ? config : pending;
    if (requested) {
        requested->application_abort_requested = true;
        if (command == CaptureCommand::Open)
            requested->baseband_open_succeeded = false;
    }
    cross_core_evidence_fence();

    if (command == CaptureCommand::Open) {
        /*
         * An unacknowledged OPEN cannot yet have an M0 BufferExchange owner.
         * Only that exact config may be unbound, and only after the worker's
         * quiescence publication.
         */
        if (worker_quiesced &&
            capture_stream_.abort_unacknowledged_open_after_dma_fault(
                requested) &&
            requested) {
            requested->fifo_buffers_empty = nullptr;
            requested->fifo_buffers_full = nullptr;
        }
    } else if (command == CaptureCommand::Close) {
        /*
         * CLOSE can be requested while M0 still owns FIFO descriptors. Never
         * forge its release byte or reset the ring. Publish abort+sealed and
         * wake BufferExchange; M0 will tear down and publish release itself.
         */
        capture_stream_.signal_bound_capture_abort_after_dma_fault();
    }
    active_capture_config_ = nullptr;
    capture_boundary_.cancel_open();
    capture_close_started_ = false;
    PRECISION_RX_RELAXED_STORE(capture_flush_requested_, false);
    PRECISION_RX_RELAXED_STORE(pending_capture_config_, nullptr);
    transition_rate_state(RateEvent::Fatal);
    PRECISION_RX_RELEASE_STORE(capture_command_, CaptureCommand::None);
    return true;
}

PRECISION_RX_CONTROL_SIZE_OPT
uint32_t PrecisionRxProcessor::request_rate_pause() {
    using namespace precision_rx::rate_control;

    if (!baseband_started_ || rate_state() != RateState::Running) {
        return reject_state;
    }

    if (!transition_rate_state(RateEvent::PrepareRequested))
        return reject_state;
    if (!wait_while_rate_state(RateState::PrepareRequested)) {
        /*
         * The M0 has not touched either clock yet. Resolve the dispatcher /
         * worker race with one direct PREPARE attempt: a healthy failure has
         * restored the unchanged stream and is rejected in RUN; every other
         * result is explicitly stopped before FAULT.
         */
        const bool paused =
            baseband_thread_.prepare_precision_rx_rate_change();
        const bool faulted =
            baseband_thread_.precision_rx_dma_faulted();
        record_rate_transition_failure();
        const auto timeout_action =
            precision_rx::rate_transaction::prepare_timeout_action(
                paused, faulted);
        if (timeout_action ==
            precision_rx::rate_transaction::PrepareTimeoutAction::
                RestoreRunning) {
            if (rate_state() == RateState::Running ||
                publish_running_if_dma_healthy(
                    RateState::PrepareRequested)) {
                return reject_halt_timeout;
            }
        }
        /*
         * A raced successful pause, DMA fault, or unexpected state cannot be
         * rejected while leaving ambiguous hardware live. Gate and stop the
         * old path before publishing FAULT.
         */
        baseband_thread_.fail_close_precision_rx();
        transition_rate_state(RateEvent::Fatal);
        return reject_halt_timeout;
    }

    const RateState state = rate_state();
    if (state == RateState::Running) {
        /* The worker restored RUN only when HALT/ACTIVE drain failed. */
        return reject_halt_timeout;
    }
    if (state != RateState::PausedArmed) {
        record_rate_transition_failure();
        baseband_thread_.fail_close_precision_rx();
        transition_rate_state(RateEvent::Fatal);
        return reject_state;
    }
    if (!wait_for_rate_pause_armed()) {
        record_rate_transition_failure();
        baseband_thread_.fail_close_precision_rx();
        transition_rate_state(RateEvent::Fatal);
        return reject_arm_timeout;
    }
    return 0;
}

PRECISION_RX_CONTROL_SIZE_OPT
uint32_t PrecisionRxProcessor::resume_rate_change(
    const uint32_t target_rate_hz,
    const uint32_t success_ack) {
    using namespace precision_rx::rate_control;

    const bool bootstrap = !baseband_started_;
    if (!bootstrap &&
        !baseband_thread_.precision_rx_rate_pause_armed()) {
        record_rate_transition_failure();
        if (baseband_thread_.precision_rx_rate_paused()) {
            if (wait_for_rate_pause_armed()) {
                return reject_arm_timeout;
            }
        }
        baseband_thread_.fail_close_precision_rx();
        transition_rate_state(RateEvent::Fatal);
        return reject_arm_timeout;
    }

    /*
     * Publish the complete target before enabling LLI0/SGPIO. The worker can
     * therefore only label the first completed new-rate block with the new
     * sampling rate and epoch.
     */
    rate_target_hz_ = target_rate_hz;
    const RateEvent resume_event =
        success_ack == ack_aborted
            ? RateEvent::AbortRequested
            : RateEvent::CommitRequested;
    if (!transition_rate_state(resume_event))
        return reject_state;
    PRECISION_RX_RELEASE_STORE(
        pending_sample_rate_hz_, target_rate_hz);
    baseband_thread_.set_sampling_rate(target_rate_hz);
    cross_core_evidence_fence();

    if (bootstrap) {
        baseband_started_ = true;
        baseband_thread_.start();
    } else if (!baseband_thread_.resume_precision_rx_rate_change()) {
        PRECISION_RX_RELEASE_STORE(pending_sample_rate_hz_, 0U);
        record_rate_transition_failure();
        baseband_thread_.fail_close_precision_rx();
        transition_rate_state(RateEvent::Fatal);
        return reject_resume_timeout;
    }

    if (!wait_while_rate_state(RateState::Resuming)) {
        /*
         * No first completion means COMMIT cannot be acknowledged. Gate and
         * halt the restarted path. A confirmed ordinary waiter remains in
         * PAUSED so M0 can restore the old clock and issue ABORT.
         */
        const bool paused =
            baseband_thread_.precision_rx_rate_paused() ||
            baseband_thread_.prepare_precision_rx_rate_change();
        PRECISION_RX_RELEASE_STORE(pending_sample_rate_hz_, 0U);
        record_rate_transition_failure();
        if (paused) {
            transition_rate_state(RateEvent::ResumeRearmed);
            if (wait_for_rate_pause_armed()) {
                return reject_resume_timeout;
            }
        }
        baseband_thread_.fail_close_precision_rx();
        transition_rate_state(RateEvent::Fatal);
        return reject_resume_timeout;
    }

    if (baseband_thread_.precision_rx_dma_faulted() ||
        rate_state() != RateState::Running) {
        record_rate_transition_failure();
        baseband_thread_.fail_close_precision_rx();
        transition_rate_state(RateEvent::Fatal);
        return reject_resume_timeout;
    }

    if (shared_memory.m4_dma_missed_lifetime !=
        rate_loss_baseline_) {
        /*
         * A real loss invalidates COMMIT even if the first block arrived.
         * Re-establish the ordinary armed pause so the M0 can restore the old
         * physical clock and send ABORT without racing live DMA.
         */
        const uint32_t pause_reject = request_rate_pause();
        if (pause_reject != 0) {
            baseband_thread_.fail_close_precision_rx();
            transition_rate_state(RateEvent::Fatal);
            return pause_reject;
        }
        record_rate_transition_failure();
        return reject_dma_loss;
    }

    return success_ack;
}

PRECISION_RX_CONTROL_SIZE_OPT
uint32_t PrecisionRxProcessor::handle_rate_control(
    const uint32_t request) {
    using namespace precision_rx::rate_control;

    if (baseband_thread_.precision_rx_dma_faulted()) {
        transition_rate_state(RateEvent::Fatal);
        return reject_state;
    }

    if (request == request_commit) {
        if (rate_state() != RateState::PausedArmed ||
            rate_target_hz_ < minimum_sample_rate ||
            rate_target_hz_ > maximum_sample_rate) {
            return reject_state;
        }
        return resume_rate_change(rate_target_hz_, ack_committed);
    }

    if (request == request_abort) {
        if (rate_state() != RateState::PausedArmed ||
            rate_previous_hz_ < minimum_sample_rate ||
            rate_previous_hz_ > maximum_sample_rate) {
            return reject_state;
        }
        /* ABORT is a distinct rollback attempt with its own loss window. */
        rate_loss_baseline_ = shared_memory.m4_dma_missed_lifetime;
        return resume_rate_change(rate_previous_hz_, ack_aborted);
    }

    if (request < minimum_sample_rate ||
        request > maximum_sample_rate) {
        return reject_invalid_rate;
    }
    if (!capture_idle_for_rate_change()) {
        return reject_capture_active;
    }

    const RateState state = rate_state();
    if (state != RateState::Bootstrap &&
        state != RateState::Running) {
        return reject_state;
    }

    if (shared_memory.m4_dma_transaction_id != UINT32_MAX) {
        ++shared_memory.m4_dma_transaction_id;
    }
    rate_target_hz_ = request;
    rate_loss_baseline_ = shared_memory.m4_dma_missed_lifetime;

    if (state == RateState::Bootstrap) {
        /*
         * The thread and DMA have never started, so BOOT is already a
         * statically quiesced PREPARE point. M0 may now establish the first
         * physical clock; COMMIT starts LLI0 at that exact rate.
         */
        rate_previous_hz_ = 0;
        transition_rate_state(RateEvent::BootstrapPrepared);
        return ack_prepared;
    }

    const uint32_t current_rate_hz =
        committed_sample_rate_hz_.load(std::memory_order_relaxed);
    if (current_rate_hz < minimum_sample_rate ||
        current_rate_hz > maximum_sample_rate) {
        record_rate_transition_failure();
        transition_rate_state(RateEvent::Fatal);
        return reject_state;
    }
    rate_previous_hz_ = current_rate_hz;

    if (request == current_rate_hz) {
        /*
         * A same-rate request still needs a real DMA boundary: an active
         * descriptor may straddle a tuning/gain change even when the physical
         * sample clock is unchanged. Quiesce, drain, arm, and restart LLI0,
         * but return ACK_CONFIGURED so M0 skips clock/filter programming.
         */
        const uint32_t pause_reject = request_rate_pause();
        if (pause_reject != 0)
            return pause_reject;
        return resume_rate_change(request, ack_configured);
    }

    const uint32_t prepare_reject = request_rate_pause();
    if (prepare_reject != 0) {
        return prepare_reject;
    }
    return ack_prepared;
}

PRECISION_RX_CONTROL_SIZE_OPT
void PrecisionRxProcessor::service_rate_prepare() {
    if (baseband_thread_.precision_rx_dma_faulted()) {
        transition_rate_state(RateEvent::Fatal);
        return;
    }
    if (rate_state() != RateState::PrepareRequested) {
        return;
    }
    PRECISION_RX_ACQUIRE_FENCE();

    if (!baseband_thread_.prepare_precision_rx_rate_change()) {
        record_rate_transition_failure();
        publish_running_if_dma_healthy(
            RateState::PrepareRequested);
        return;
    }

    if (rate_state() == RateState::PrepareRequested) {
        transition_rate_state(RateEvent::PrepareSucceeded);
    }
}
#endif

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
#endif
void PrecisionRxProcessor::configure(uint32_t input_sample_rate_hz) {
    const uint32_t bounded_rate = std::clamp(
        input_sample_rate_hz,
        minimum_sample_rate,
        maximum_sample_rate);
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    current_sample_rate_hz_ = bounded_rate;
#endif
    ++stream_epoch_;
    baseband_thread_.set_sampling_rate(bounded_rate);
    metrics_.configure(bounded_rate, stream_epoch_);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    committed_sample_rate_hz_.store(
        bounded_rate, std::memory_order_relaxed);
    shared_memory.m4_dma_rate_hz = bounded_rate;
#else
    last_dma_missed_transfers_ = shared_memory.m4_buffer_missed;
#endif
    configured_ = true;
}

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
bool PrecisionRxProcessor::transition_dma_geometry(const bool capture) {
#if !defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    configured_ = false;
#endif
    const bool changed =
        baseband_thread_.set_precision_rx_capture_geometry(capture);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    /*
     * Only a completed HALT/drain/restart establishes a new accounting epoch.
     * A clean HALT timeout resumes the unchanged old ring with its queued
     * completions intact, so relabeling those buffers would corrupt the epoch.
     */
    if (changed) {
        configured_ = false;
        configure(current_sample_rate_hz_);
    }
#else
    /*
     * A timeout resumes the unmodified old ring.  In both cases establish a
     * new accounting epoch: SGPIO gating/HALT can hide an interval that the
     * old DMA missed-transfer counter cannot represent.
     */
    configure(current_sample_rate_hz_);
#endif
    return changed;
}

__attribute__((noinline, noclone, optimize("Os")))
void PrecisionRxProcessor::finish_capture_command() {
    PRECISION_RX_RELAXED_STORE(pending_capture_config_, nullptr);
    PRECISION_RX_RELEASE_STORE(capture_command_, CaptureCommand::None);
}
#endif

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
bool
#else
void
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
PRECISION_RX_CONTROL_SIZE_OPT
#endif
PrecisionRxProcessor::service_capture_command() {
    const CaptureCommand command = PRECISION_RX_RELAXED_LOAD(capture_command_);
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    if (command != CaptureCommand::None)
        PRECISION_RX_ACQUIRE_FENCE();
#endif
    if (command == CaptureCommand::Open) {
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        /*
         * A null pending config while OPEN remains published means rebind
         * failed after entering capture geometry.  Retry the safe monitor
         * transition once per DMA boundary and acknowledge only on success.
         */
        if (PRECISION_RX_RELAXED_LOAD(pending_capture_config_) == nullptr) {
            if (!transition_dma_geometry(false))
                return true;
            finish_capture_command();
            return true;
        }
        if (current_sample_rate_hz_ >
            precision_rx::dma_lease::capture_rate_limit_hz) {
            capture_boundary_.cancel_open();
            finish_capture_command();
            return false;
        }
#endif
        /*
         * OPEN is intentionally split across two DMA boundaries.  The first
         * rebinds already allocated storage but does not acknowledge M0.  On
         * the next execute(), normal missed-transfer accounting has observed
         * any setup overrun; only then do we establish the inclusive capture
         * boundary and publish a successful open.
         */
        const auto boundary = capture_boundary_.advance_open({
            metrics_.input_tick(),
            metrics_.dropped_input_samples(),
        });
        if (boundary.prepares()) {
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
            if (!transition_dma_geometry(true)) {
                capture_boundary_.cancel_open();
                finish_capture_command();
                return true;
            }
#endif
            active_capture_config_ =
                PRECISION_RX_RELAXED_LOAD(pending_capture_config_);
            if (!capture_stream_.rebind(active_capture_config_)) {
                active_capture_config_ = nullptr;
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
                capture_boundary_.cancel_open();
                PRECISION_RX_RELAXED_STORE(pending_capture_config_, nullptr);
                return true;
#else
                capture_boundary_.cancel_open();
                pending_capture_config_.store(nullptr);
                capture_command_.store(CaptureCommand::None);
                return;
#endif
            }
            active_capture_config_->precision_rx_evidence = {};
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
            return true;
#else
            return;
#endif
        }

        if (boundary.acknowledges_open()) {
            if (active_capture_config_) {
                metrics_.begin_capture_interval();
                active_capture_config_->precision_rx_evidence.final_stream_epoch =
                    metrics_.stream_epoch();
                active_capture_config_->baseband_start_input_tick =
                    boundary.capture_start.input_tick;
                active_capture_config_->baseband_stop_input_tick =
                    boundary.capture_start.input_tick;
                active_capture_config_->baseband_start_dropped_input_samples =
                    boundary.capture_start.dropped_input_samples;
                active_capture_config_->baseband_stop_dropped_input_samples =
                    boundary.capture_start.dropped_input_samples;
                capture_bytes_received_ = 0;
                capture_bytes_dropped_ = 0;
                pending_capture_continuity_flags_ = 0;
                capture_close_started_ = false;
                capture_stream_.acknowledge_open();
            } else {
                capture_boundary_.cancel_open();
            }
        }
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        finish_capture_command();
#else
        pending_capture_config_.store(nullptr);
        capture_command_.store(CaptureCommand::None);
#endif
    } else if (command == CaptureCommand::Close) {
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        /* Retry a failed monitor return without repeating close finalization. */
        if (active_capture_config_ == nullptr && capture_stream_.unbound()) {
            if (!transition_dma_geometry(false))
                return true;
            capture_close_started_ = false;
            finish_capture_command();
            return true;
        }
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        const bool abort_requested =
            active_capture_config_ &&
            active_capture_config_->application_abort_requested;
        if (!capture_close_started_) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
            if (active_capture_config_) {
                finish_capture_interval(
                    abort_requested
                        ? PrecisionRxCaptureTerminalReason::ConsumerError
                        : PrecisionRxCaptureTerminalReason::RequestedStop);
            } else {
                capture_boundary_.end_capture();
                capture_close_input_tick_ = metrics_.input_tick();
                capture_close_dropped_input_samples_ =
                    metrics_.dropped_input_samples();
                capture_close_started_ = true;
            }
#else
            precision_rx::MetricsSnapshot final_snapshot{};
            if (capture_boundary_.active() &&
                metrics_.take_snapshot(final_snapshot, true)) {
                final_snapshot.capture_continuity_flags =
                    pending_capture_continuity_flags_;
                pending_capture_continuity_flags_ = 0;
                record_capture_evidence(final_snapshot);
                publish(final_snapshot);
            }
            capture_boundary_.end_capture();
            capture_close_input_tick_ = metrics_.input_tick();
            capture_close_dropped_input_samples_ =
                metrics_.dropped_input_samples();
            capture_close_started_ = true;
#endif
        }

        const bool flush =
            PRECISION_RX_RELAXED_LOAD(capture_flush_requested_) ||
            (active_capture_config_ &&
             active_capture_config_->baseband_producer_sealed);
        if (flush && !abort_requested &&
            active_capture_config_) {
            if (!capture_stream_.seal() || !capture_stream_.drained()) {
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
                return false;
#else
                return;
#endif
            }
        }

#if !defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        if (active_capture_config_) {
            active_capture_config_->baseband_stop_input_tick = capture_close_input_tick_;
            active_capture_config_->baseband_stop_dropped_input_samples =
                capture_close_dropped_input_samples_;
        }
#endif
#else
        if (!capture_close_started_) {
            precision_rx::MetricsSnapshot final_snapshot{};
            if (capture_boundary_.active() &&
                metrics_.take_snapshot(final_snapshot, true)) {
                final_snapshot.capture_continuity_flags =
                    pending_capture_continuity_flags_;
                pending_capture_continuity_flags_ = 0;
                record_capture_evidence(final_snapshot);
                publish(final_snapshot);
            }
            capture_boundary_.end_capture();
            capture_close_input_tick_ = metrics_.input_tick();
            capture_close_dropped_input_samples_ = metrics_.dropped_input_samples();
            capture_close_started_ = true;
        }

        const bool abort_requested =
            active_capture_config_ && active_capture_config_->application_abort_requested;
        const bool flush = PRECISION_RX_RELAXED_LOAD(capture_flush_requested_);
        if (flush && !abort_requested &&
            active_capture_config_) {
            if (!capture_stream_.seal() || !capture_stream_.drained()) {
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
                return false;
#else
                return;
#endif
            }
        }

        if (active_capture_config_) {
            active_capture_config_->baseband_stop_input_tick = capture_close_input_tick_;
            active_capture_config_->baseband_stop_dropped_input_samples =
                capture_close_dropped_input_samples_;
        }
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        bool loan_released = false;
        if (flush && !abort_requested) {
            if (!capture_stream_.unbind_if_drained())
                return false;
            loan_released = true;
        } else if (abort_requested) {
            loan_released = capture_stream_.force_unbind_after_abort();
            if (!loan_released)
                return false;
        }
#endif
        /* Retain the bound FIFO until M0 has joined; rebind only at next OPEN. */
        active_capture_config_ = nullptr;
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        if (loan_released) {
            /*
             * Keep CLOSE published while monitor geometry is not confirmed.
             * capture_close_started_ plus an unbound stream is the retry
             * sentinel, so final evidence/seal work is never repeated.
             */
            if (!transition_dma_geometry(false))
                return true;
            capture_close_started_ = false;
            finish_capture_command();
            return true;
        }
        capture_close_started_ = false;
        finish_capture_command();
#else
        pending_capture_config_.store(nullptr);
        capture_close_started_ = false;
        capture_command_.store(CaptureCommand::None);
#endif
    }
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    return false;
#endif
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
PRECISION_RX_CONTROL_SIZE_OPT
#endif
void PrecisionRxProcessor::request_capture_command(
    CaptureCommand command,
    CaptureConfig* config,
    bool flush) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    /*
     * Capture cannot start before the transactional bootstrap has created the
     * DMA worker. A fatal worker is likewise a synchronous rejection, not an
     * unbounded wait for a DMA boundary that can never arrive.
     */
    if (!baseband_started_) {
        if (config) {
            config->application_abort_requested = true;
            config->baseband_open_succeeded = false;
            cross_core_evidence_fence();
        }
        return;
    }
    if (reject_capture_command_after_dma_fault(command, config))
        return;
#endif
    PRECISION_RX_RELAXED_STORE(pending_capture_config_, config);
    PRECISION_RX_RELAXED_STORE(capture_flush_requested_, flush);
    PRECISION_RX_RELEASE_STORE(capture_command_, command);
    while (PRECISION_RX_RELAXED_LOAD(capture_command_) != CaptureCommand::None) {
        /* BasebandThread owns StreamInput and acknowledges at a DMA boundary. */
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        if (reject_capture_command_after_dma_fault(command, config))
            return;
#endif
    }
    PRECISION_RX_ACQUIRE_FENCE();
}

void PrecisionRxProcessor::execute(const buffer_c8_t& buffer) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    bool rate_configuration_applied = false;
#endif
    const uint32_t pending_sample_rate_hz =
        PRECISION_RX_RELAXED_LOAD(pending_sample_rate_hz_);
    if (pending_sample_rate_hz != 0) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        PRECISION_RX_ACQUIRE_FENCE();
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        if (pending_sample_rate_hz >
                precision_rx::dma_lease::capture_rate_limit_hz &&
            !capture_stream_.unbound()) {
            PRECISION_RX_RELEASE_STORE(pending_sample_rate_hz_, 0U);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
            record_rate_transition_failure();
            baseband_thread_.fail_close_precision_rx();
            transition_rate_state(RateEvent::Fatal);
#endif
            return;
        }
#endif
        configure(pending_sample_rate_hz);
        PRECISION_RX_RELEASE_STORE(pending_sample_rate_hz_, 0U);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        rate_configuration_applied = true;
#endif
    }
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    if (rate_configuration_applied &&
        !precision_rx::rate_transaction::first_block_matches_commit(
            rate_state(),
            true,
            buffer.sampling_rate,
            rate_target_hz_)) {
        /*
         * A queued old-rate descriptor or stale/out-of-order resume must not
         * enter capture or metrics under the new epoch. Stop before either
         * consumer sees the block.
         */
        record_rate_transition_failure();
        baseband_thread_.fail_close_precision_rx();
        transition_rate_state(RateEvent::Fatal);
        return;
    }
#endif
    if (configured_) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        uint32_t newly_missed_transfers = 0U;
        if (!dma_loss_observation_.consume(
                shared_memory.m4_dma_missed_lifetime,
                newly_missed_transfers)) {
            record_rate_transition_failure();
            baseband_thread_.fail_close_precision_rx();
            transition_rate_state(RateEvent::Fatal);
            return;
        }
#else
        const uint16_t current_dma_missed_transfers = shared_memory.m4_buffer_missed;
        const uint16_t newly_missed_transfers = static_cast<uint16_t>(
            current_dma_missed_transfers - last_dma_missed_transfers_);
#endif
#if !defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        last_dma_missed_transfers_ = current_dma_missed_transfers;
#endif
        if (newly_missed_transfers != 0) {
            metrics_.mark_input_drop(
                static_cast<uint64_t>(newly_missed_transfers) * buffer.count);
        }
    }

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    if (service_capture_command()) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        service_rate_prepare();
#endif
        return;
    }
#else
    service_capture_command();
#endif
    if (!configured_) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        service_rate_prepare();
#endif
        return;
    }

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    const bool complete_block_processed =
        process_complete_block(buffer);
    if (!complete_block_processed) {
        record_rate_transition_failure();
        baseband_thread_.fail_close_precision_rx();
        transition_rate_state(RateEvent::Fatal);
        return;
    }
#else
    if (capture_boundary_.active()) {
        const size_t bytes = buffer.count * sizeof(*buffer.p);
        const size_t written = capture_stream_.write(buffer.p, bytes);
        capture_bytes_received_ += bytes;
        capture_bytes_dropped_ += bytes - written;
        if (written != bytes) {
            pending_capture_continuity_flags_ |=
                precision_rx::DISCONTINUITY | precision_rx::DROPPED_INPUT;
        }
    }

    if (metrics_.observe_block(buffer.p, buffer.count)) {
        precision_rx::MetricsSnapshot snapshot;
        if (metrics_.take_snapshot(snapshot)) {
            snapshot.capture_continuity_flags = pending_capture_continuity_flags_;
            pending_capture_continuity_flags_ = 0;
            if (capture_boundary_.active()) {
                record_capture_evidence(snapshot);
            }
            publish(snapshot);
        }
    }
#endif

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    if (rate_configuration_applied && complete_block_processed &&
        rate_state() == RateState::Resuming) {
        /*
         * configure(), lifetime accounting, capture routing, and metrics all
         * consumed one complete block at the published target. Only now can
         * COMMIT observe RUN.
         */
        publish_running_if_dma_healthy(RateState::Resuming);
    }
    service_rate_prepare();
#endif
}

PRECISION_RX_CONTROL_SIZE_OPT void PrecisionRxProcessor::record_capture_evidence(
    const precision_rx::MetricsSnapshot& snapshot) {
    if (!active_capture_config_) {
        return;
    }
    auto& evidence = active_capture_config_->precision_rx_evidence;
    evidence.update_sequence = evidence.update_sequence + 1;
    cross_core_evidence_fence();
    const bool first_report = evidence.status_reports_generated == 0;
    if (first_report) {
        evidence.minimum_rms_dbfs_x10 = snapshot.rms_dbfs_x10;
        evidence.minimum_robust_rms_dbfs_x10 = snapshot.robust_rms_dbfs_x10;
        evidence.maximum_robust_rms_dbfs_x10 = snapshot.robust_rms_dbfs_x10;
        evidence.maximum_peak_dbfs_x10 = snapshot.peak_dbfs_x10;
    } else {
        evidence.minimum_rms_dbfs_x10 =
            std::min(evidence.minimum_rms_dbfs_x10, snapshot.rms_dbfs_x10);
        evidence.minimum_robust_rms_dbfs_x10 = std::min(
            evidence.minimum_robust_rms_dbfs_x10,
            snapshot.robust_rms_dbfs_x10);
        evidence.maximum_robust_rms_dbfs_x10 = std::max(
            evidence.maximum_robust_rms_dbfs_x10,
            snapshot.robust_rms_dbfs_x10);
        evidence.maximum_peak_dbfs_x10 =
            std::max(evidence.maximum_peak_dbfs_x10, snapshot.peak_dbfs_x10);
    }
    evidence.valid = true;
    evidence.final_stream_epoch = snapshot.stream_epoch;
    evidence.final_report_sequence = snapshot.report_sequence;
    ++evidence.status_reports_generated;
    evidence.aggregate_continuity_flags |= snapshot.continuity_flags;
    evidence.aggregate_capture_continuity_flags |=
        snapshot.capture_continuity_flags;
    evidence.aggregate_metric_quality_flags |= snapshot.metric_quality_flags;
    if (active_capture_config_->precision_rx_final_report) {
        auto* const journal =
            active_capture_config_->precision_rx_final_report;
        journal[precision_rx::capture_snapshot_journal_slot(
            snapshot.report_sequence)] = make_snapshot_record(
                snapshot,
                capture_bytes_received_,
                capture_bytes_dropped_);
    }

    if ((snapshot.metric_quality_flags & precision_rx::CARRIER_VALID) != 0) {
        if (evidence.valid_carrier_report_count == 0) {
            evidence.minimum_carrier_mod_hz_x10 = snapshot.carrier_offset_hz_x10;
            evidence.maximum_carrier_mod_hz_x10 = snapshot.carrier_offset_hz_x10;
            evidence.minimum_coherence_ppm = snapshot.coherence_ppm;
        } else {
            evidence.minimum_carrier_mod_hz_x10 = std::min(
                evidence.minimum_carrier_mod_hz_x10,
                snapshot.carrier_offset_hz_x10);
            evidence.maximum_carrier_mod_hz_x10 = std::max(
                evidence.maximum_carrier_mod_hz_x10,
                snapshot.carrier_offset_hz_x10);
            evidence.minimum_coherence_ppm = std::min(
                evidence.minimum_coherence_ppm,
                snapshot.coherence_ppm);
        }
        ++evidence.valid_carrier_report_count;
    }
    cross_core_evidence_fence();
    evidence.update_sequence = evidence.update_sequence + 1;
}

PRECISION_RX_CONTROL_SIZE_OPT void PrecisionRxProcessor::publish(
    const precision_rx::MetricsSnapshot& snapshot) const {
    PrecisionRxStatusMessage message{};
    message.stream_epoch = snapshot.stream_epoch;
    message.report_sequence = snapshot.report_sequence;
    message.continuity_flags = snapshot.continuity_flags;
    message.capture_continuity_flags = snapshot.capture_continuity_flags;
    message.metric_quality_flags = snapshot.metric_quality_flags;
    message.input_sample_rate_hz = snapshot.input_sample_rate_hz;
    message.analysis_stride = snapshot.analysis_stride;
    message.first_input_tick = snapshot.first_input_tick;
    message.next_input_tick = snapshot.next_input_tick;
    message.dropped_input_samples = snapshot.dropped_input_samples;
    message.analyzed_sample_count = snapshot.analyzed_sample_count;
    message.sampled_clip_count = snapshot.sampled_clip_count;
    message.mean_i_q8 = snapshot.mean_i_q8;
    message.mean_q_q8 = snapshot.mean_q_q8;
    message.rms_dbfs_x10 = snapshot.rms_dbfs_x10;
    message.robust_rms_dbfs_x10 = snapshot.robust_rms_dbfs_x10;
    message.peak_dbfs_x10 = snapshot.peak_dbfs_x10;
    message.carrier_offset_hz_x10 = snapshot.carrier_offset_hz_x10;
    message.carrier_delta_hz_per_s_x10 = snapshot.carrier_delta_hz_per_s_x10;
    message.coherence_ppm = snapshot.coherence_ppm;
    message.gain_advice = static_cast<int8_t>(snapshot.gain_advice);
    message.capture_bytes_received = capture_bytes_received_;
    message.capture_bytes_dropped = capture_bytes_dropped_;
    shared_memory.application_queue.push(message);
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
PRECISION_RX_CONTROL_SIZE_OPT
#endif
void PrecisionRxProcessor::on_message(const Message* const message) {
    switch (message->id) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        case Message::ID::Shutdown: {
            const auto& shutdown =
                *reinterpret_cast<const ShutdownMessage*>(message);
            if (shutdown.mode ==
                ShutdownMessage::Mode::PrecisionRxFault) {
                baseband_thread_.fail_close_precision_rx();
                transition_rate_state(RateEvent::Fatal);
            }
            break;
        }
#endif

        case Message::ID::PrecisionRxConfig: {
            const auto& config = *reinterpret_cast<const PrecisionRxConfigMessage*>(message);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
            config.input_sample_rate_hz =
                handle_rate_control(config.input_sample_rate_hz);
            cross_core_evidence_fence();
#else
            PRECISION_RX_RELAXED_STORE(pending_sample_rate_hz_, std::clamp(
                config.input_sample_rate_hz,
                minimum_sample_rate,
                maximum_sample_rate));
            while (PRECISION_RX_RELAXED_LOAD(pending_sample_rate_hz_) != 0) {
                /* Apply and acknowledge at the next DMA buffer boundary. */
            }
            PRECISION_RX_ACQUIRE_FENCE();
#endif
            break;
        }

        case Message::ID::CaptureConfig: {
            const auto& capture = *reinterpret_cast<const CaptureConfigMessage*>(message);
            if (capture.config) {
                request_capture_command(CaptureCommand::Open, capture.config);
            } else {
                request_capture_command(CaptureCommand::Close, nullptr, capture.flush);
            }
            break;
        }

        default:
            break;
    }
}

int main() {
    EventDispatcher event_dispatcher{std::make_unique<PrecisionRxProcessor>()};
    event_dispatcher.run();
    return 0;
}

#undef PRECISION_RX_CONTROL_SIZE_OPT
#undef PRECISION_RX_RELAXED_LOAD
#undef PRECISION_RX_RELAXED_STORE
#undef PRECISION_RX_RELEASE_STORE
#undef PRECISION_RX_ACQUIRE_FENCE
