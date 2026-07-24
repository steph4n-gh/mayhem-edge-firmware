#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

"""Linked-artifact regression checks for the Precision RX Cortex-M4 ELF.

The source-level design relies on one ordering property that ordinary unit
tests cannot prove: the 72 KiB M4-local capture stream must be allocated before
the DMA-owning BasebandThread starts, and live OPEN must only rebind that
retained storage plus exactly 16 KiB of M0-owned shared SRAM.  This tool checks
the linked artifact from each reproducibility lane with the exact GNU Arm
``nm`` and ``objdump`` binaries used by that lane.

The verifier intentionally rejects missing symbols, unexpected inlining,
unrecoverable constant arguments, new allocator call sites, and unknown RAM
regions.  These instruction-pattern checks are diagnostic regression evidence,
not a complete control-flow or register def-use proof.  Release identity is
therefore established separately by the exact full-ELF SHA-256 pins in the
frozen p11 contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


FLASH_BASE = 0x00000000
FLASH_CAPACITY_BYTES = 32_752
RAM_BASE = 0x10000000
RAM_CAPACITY_BYTES = 96 * 1024

EXPECTED_STREAM_WRITE_SIZE = 8 * 1024
EXPECTED_STREAM_BUFFER_COUNT = 9
EXPECTED_STREAM_TOTAL_BUFFER_COUNT = 11
EXPECTED_STREAM_BUFFER_COUNT_LOG2 = 4
EXPECTED_DMA_BUFFER_BYTES = 8 * 1024
EXPECTED_DMA_TRANSFER_BYTES = 2 * 1024
EXPECTED_DMA_TRANSFER_COUNT = 4
EXPECTED_DMA_LLI_BYTES = 64
EXPECTED_DMA_LOAN_BYTES = 8 * 1024
EXPECTED_DMA_MONITOR_RING_BYTES = 16 * 1024
EXPECTED_DMA_MONITOR_TRANSFER_BYTES = 4 * 1024
EXPECTED_DMA_MONITOR_TRANSFER_SAMPLES = 2 * 1024
EXPECTED_DMA_CAPTURE_RING_BYTES = 8 * 1024
EXPECTED_DMA_CAPTURE_TRANSFER_BYTES = 2 * 1024
EXPECTED_DMA_CAPTURE_TRANSFER_SAMPLES = 1024
EXPECTED_DMA_MONITOR_OWNED_LLI_COUNT = 2
EXPECTED_DMA_MONITOR_LOAN_LLI_COUNT = 2
EXPECTED_DMA_LOAN_LOCAL_BUFFER_INDEX = 8
EXPECTED_DMA_CAPTURE_RATE_LIMIT_HZ = 2_000_000
EXPECTED_DMA_SCHEDULER_BACKLOG_DEPTH = 0
EXPECTED_DMA_SERVICE_DEADLINE_NS_AT_20M = 102_400
EXPECTED_DMA_PHYSICAL_RETENTION_NS_AT_20M = 307_200
EXPECTED_P12_DMA_SCHEDULER_BACKLOG_DEPTH = 3
EXPECTED_P12_DMA_COMPLETION_QUEUE_DEPTH = 3
EXPECTED_P12_DMA_COMPLETION_PERIOD_NS_AT_20M = 102_400
EXPECTED_P12_DMA_CLAIM_GUARD_AGE = 2
EXPECTED_P12_DMA_SERVICE_DEADLINE_NS_AT_20M = 204_800
EXPECTED_P12_DMA_OLDEST_CLAIM_DEADLINE_NS_AT_20M = 204_800
EXPECTED_P12_DMA_LIFETIME_LOSS_COUNTER_BITS = 32
EXPECTED_P12_RATE_TRANSACTION_PROTOCOL_VERSION = 2
EXPECTED_P14_CONTROL_ACTIVE_DRAIN_TIMEOUT_US = 10_000
EXPECTED_P14_CONTROL_ACTIVE_DRAIN_TICKS_AT_200M = 2_000_000
EXPECTED_P14_CONTROL_SLOWEST_DESCRIPTOR_TICKS_AT_200M = 409_600
EXPECTED_P14_CONTROL_ACTIVE_DRAIN_LIMIT = (
    EXPECTED_P14_CONTROL_ACTIVE_DRAIN_TICKS_AT_200M - 1
)
EXPECTED_P14_M4_COUNTER_HZ = 200_000_000
EXPECTED_P14_MINIMUM_SAMPLE_RATE_HZ = 1_000_000
EXPECTED_P15_RATE_TRANSACTION_PROTOCOL_VERSION = 3
EXPECTED_P15_QUIESCE_FAILURE_BITS = 4
EXPECTED_P15_TRANSITION_FAILURE_COUNT_BITS = 28
CORTEX_M_SCS_DEMCR_ADDRESS = 0xE000EDFC
CORTEX_M_DWT_CTRL_ADDRESS = 0xE0001000
CORTEX_M_DWT_CYCCNT_ADDRESS = 0xE0001004
PL080_CONTROLLER_BASE_ADDRESS = 0x40002000
PL080_SGPIO_CHANNEL_CONFIG_OFFSET = 0x110
PL080_SGPIO_CHANNEL_CONFIG_ADDRESS = 0x40002110
SGPIO_CONTROLLER_BASE_ADDRESS = 0x40101000
SGPIO_GPIO_OUTREG_OFFSET = 0x214
SGPIO_GPIO_OUTREG_ADDRESS = (
    SGPIO_CONTROLLER_BASE_ADDRESS + SGPIO_GPIO_OUTREG_OFFSET
)
MAX_PROCESSOR_BYTES = 1152
MAX_REBIND_CODE_BYTES = 416
MAX_FIFO_STREAM_BUFFER_IN_CODE_BYTES = 64
MAX_SERVICE_CODE_BYTES = 640
MAX_SERVICE_BULK_BYTES = 256
MAX_PROCESS_COMPLETE_BLOCK_CODE_BYTES = 512
HEAP_METADATA_RESERVE_BYTES = 512
MINIMUM_MODELED_HEADROOM_BYTES = 4 * 1024

REBIND_NAME = "StreamInput::rebind(CaptureConfig*)"
FIFO_STREAM_BUFFER_IN_NAME = "FIFO<StreamBuffer*>::in(StreamBuffer* const&)"
ACKNOWLEDGE_NAME = "StreamInput::acknowledge_open()"
SEAL_NAME = "StreamInput::seal()"
DRAINED_NAME = "StreamInput::drained() const"
SERVICE_NAME = "PrecisionRxProcessor::service_capture_command()"
EXECUTE_PREFIX = "PrecisionRxProcessor::execute("
GEOMETRY_CONSTRUCTOR_PREFIX = "StreamInput::StreamInput("
BASEBAND_CONSTRUCTOR_PREFIX = "BasebandThread::BasebandThread("
BASEBAND_RUN_NAME = "BasebandThread::run()"
EVENT_SHUTDOWN_PREFIX = "EventDispatcher::on_message_shutdown("
BASEBAND_FAIL_CLOSE_NAME = "BasebandThread::fail_close_precision_rx()"
BASEBAND_GEOMETRY_NAME = "BasebandThread::set_precision_rx_capture_geometry(bool)"
DMA_DESCRIPTOR_BUILDER_NAME = "baseband::dma::configure_lease_descriptors(bool)"
DMA_CONFIGURE_LEASE_PREFIX = "baseband::dma::configure_precision_rx_lease("
DMA_SET_GEOMETRY_NAME = "baseband::dma::set_precision_rx_capture_geometry(bool)"
DMA_HALT_DISABLE_PREFIX = "baseband::dma::halt_and_disable_precision_rx("
DMA_QUIESCE_FAILURE_PUBLISH_PREFIX = (
    "baseband::dma::publish_precision_rx_quiesce_failure("
)
DMA_ENABLE_NAME = "baseband::dma::enable_precision_rx()"
DMA_FAIL_PENDING_NAME = (
    "baseband::dma::fail_if_precision_rx_dma_error_pending_locked()"
)
DMA_FAIL_LOCKED_PREFIX = "baseband::dma::fail_precision_rx_dma_locked("
DMA_WAIT_NAME = "baseband::dma::wait_for_buffer()"
DMA_LOAN_NAME = "StreamInput::dma_loan_buffer()"
DMA_RELEASE_NAME = "StreamInput::release_dma_loan()"
DMA_UNBIND_DRAINED_NAME = "StreamInput::unbind_if_drained()"
DMA_FORCE_UNBIND_NAME = "StreamInput::force_unbind_after_abort()"
TRANSITION_NAME = "PrecisionRxProcessor::transition_dma_geometry(bool)"
FINISH_COMMAND_NAME = "PrecisionRxProcessor::finish_capture_command()"
PROCESSOR_CONFIGURE_PREFIX = "PrecisionRxProcessor::configure("
PROCESSOR_CONSTRUCTOR_PREFIX = "PrecisionRxProcessor::PrecisionRxProcessor("
PROCESSOR_MESSAGE_PREFIX = "PrecisionRxProcessor::on_message("
PROCESSOR_RATE_PAUSE_PREFIX = "PrecisionRxProcessor::request_rate_pause("
PROCESSOR_RATE_RESUME_PREFIX = "PrecisionRxProcessor::resume_rate_change("
PROCESSOR_RATE_SERVICE_PREFIX = "PrecisionRxProcessor::service_rate_prepare("
PROCESSOR_PUBLISH_RUNNING_PREFIX = (
    "PrecisionRxProcessor::publish_running_if_dma_healthy("
)
PROCESSOR_COMPLETE_BLOCK_PREFIX = (
    "PrecisionRxProcessor::process_complete_block("
)
PROCESSOR_WAIT_RATE_STATE_PREFIX = (
    "PrecisionRxProcessor::wait_while_rate_state("
)
PROCESSOR_RATE_STATE_PREFIX = "PrecisionRxProcessor::rate_state() const"
METRICS_OBSERVE_BLOCK_PREFIX = (
    "precision_rx::MetricsAccumulator::observe_block("
)
PROCESSOR_PUBLISH_PREFIX = "PrecisionRxProcessor::publish("
DMA_FAST_TERMINAL_COUNT_NAME = (
    "hackrf_edge_precision_rx_dma_fast_terminal_count"
)
DMA_FAST_FAULT_NAME = "hackrf_edge_precision_rx_dma_fast_fault"
DMA_DEFERRED_INTERRUPT_NAME = (
    "hackrf_edge_precision_rx_dma_deferred_interrupt"
)
DMA_FAST_LATCH_PREFIX = "baseband::dma::latch_precision_rx_dma_fault_fast("
DMA_COMPLETE_FAULT_NAME = (
    "baseband::dma::complete_precision_rx_dma_fault_locked()"
)
DMA_VECTOR_NAME = "Vector48"
DMA_DEFERRED_VECTOR_NAME = "VectorBC"
LATE_INIT_NAME = "__late_init"
SGPIO_CONFIGURE_NAME = "baseband::SGPIO::configure(baseband::Direction)"
SGPIO_STREAMING_DISABLE_PREFIX = "baseband::SGPIO::streaming_disable()"
DMA_GATE_OPEN_NAME = (
    "baseband::dma::open_precision_rx_sgpio_gate_locked()"
)
BASEBAND_RATE_PREPARE_NAME = (
    "BasebandThread::prepare_precision_rx_rate_change()"
)
BASEBAND_RATE_RESUME_NAME = (
    "BasebandThread::resume_precision_rx_rate_change()"
)
BASEBAND_RATE_ARMED_NAME = (
    "BasebandThread::precision_rx_rate_pause_armed() const"
)
DMA_RATE_PAUSE_NAME = "baseband::dma::pause_precision_rx_rate_change()"
DMA_RATE_RESUME_NAME = "baseband::dma::resume_precision_rx_rate_change()"
DMA_RATE_ARMED_NAME = "baseband::dma::precision_rx_rate_pause_armed()"
DMA_FAULTED_NAME = "baseband::dma::precision_rx_dma_faulted()"
DMA_ERROR_PENDING_NAME = "baseband::dma::dma_error_pending"
DMA_FATAL_LATCH_NAME = "baseband::dma::dma_fatal_latched"
DMA_CLAIM_COMPLETION_NAME = (
    "baseband::dma::claim_precision_rx_completion("
    "baseband::dma::PrecisionRxDmaCompletion&)"
)
DMA_RATE_STATE_BEGIN_NAME = (
    "baseband::dma::begin_precision_rx_rate_state_update()"
)
DMA_RATE_STATE_END_NAME = (
    "baseband::dma::end_precision_rx_rate_state_update()"
)
DMA_QUIESCE_SHUTDOWN_NAME = (
    "baseband::dma::quiesce_precision_rx_for_shutdown()"
)
DMA_WAKE_SHUTDOWN_NAME = (
    "baseband::dma::wake_precision_rx_worker_for_shutdown()"
)
DMA_STOP_SHUTDOWN_NAME = "baseband::dma::stop_precision_rx_for_shutdown()"
PROCESSOR_TRANSITION_RATE_STATE_PREFIX = (
    "PrecisionRxProcessor::transition_rate_state("
)
RATE_REQUEST_COMMIT = 0x80000001
RATE_ACK_COMMITTED = 0xC0000003
RATE_STATE_RUNNING = 1
RATE_STATE_PAUSED_ARMED = 3
RATE_STATE_RESUMING = 4
SHARED_MEMORY_BASE = 0x10088000
M4_DMA_MISSED_LIFETIME_OFFSET = 0x1A38
M4_DMA_MISSED_LIFETIME_ADDRESS = (
    SHARED_MEMORY_BASE + M4_DMA_MISSED_LIFETIME_OFFSET
)
M4_DMA_TRANSITION_FAILURES_OFFSET = 0x1A58
M4_DMA_TRANSITION_FAILURES_ADDRESS = (
    SHARED_MEMORY_BASE + M4_DMA_TRANSITION_FAILURES_OFFSET
)
BEGIN_CAPTURE_NAME = "precision_rx::MetricsAccumulator::begin_capture_interval()"
IMPL_GEOMETRY_SYMBOL = "hackrf_edge_stream_input_impl_buffer_count_log2"
MODE_GEOMETRY_SYMBOL = "hackrf_edge_precision_rx_mode_buffer_count_log2"
MODE_LOCAL_BUFFER_COUNT_SYMBOL = (
    "hackrf_edge_precision_rx_mode_local_buffer_count"
)
MODE_SPILL_BUFFER_COUNT_SYMBOL = (
    "hackrf_edge_precision_rx_mode_spill_buffer_count"
)
MODE_TOTAL_BUFFER_COUNT_SYMBOL = (
    "hackrf_edge_precision_rx_mode_total_buffer_count"
)
DMA_BUFFER_BYTES_SYMBOL = "hackrf_edge_precision_rx_dma_buffer_bytes"
DMA_TRANSFER_BYTES_SYMBOL = "hackrf_edge_precision_rx_dma_transfer_bytes"
DMA_TRANSFER_COUNT_SYMBOL = "hackrf_edge_precision_rx_dma_transfer_count"
DMA_LLI_LOOP_SYMBOL = "baseband::dma::lli_loop"
DMA_LOAN_BYTES_SYMBOL = "hackrf_edge_precision_rx_dma_loan_bytes"
DMA_MONITOR_RING_BYTES_SYMBOL = "hackrf_edge_precision_rx_dma_monitor_ring_bytes"
DMA_MONITOR_TRANSFER_BYTES_SYMBOL = (
    "hackrf_edge_precision_rx_dma_monitor_transfer_bytes"
)
DMA_MONITOR_TRANSFER_SAMPLES_SYMBOL = (
    "hackrf_edge_precision_rx_dma_monitor_transfer_samples"
)
DMA_CAPTURE_RING_BYTES_SYMBOL = "hackrf_edge_precision_rx_dma_capture_ring_bytes"
DMA_CAPTURE_TRANSFER_BYTES_SYMBOL = (
    "hackrf_edge_precision_rx_dma_capture_transfer_bytes"
)
DMA_CAPTURE_TRANSFER_SAMPLES_SYMBOL = (
    "hackrf_edge_precision_rx_dma_capture_transfer_samples"
)
DMA_MONITOR_OWNED_LLI_COUNT_SYMBOL = (
    "hackrf_edge_precision_rx_dma_monitor_owned_lli_count"
)
DMA_MONITOR_LOAN_LLI_COUNT_SYMBOL = (
    "hackrf_edge_precision_rx_dma_monitor_loan_lli_count"
)
DMA_LOAN_LOCAL_BUFFER_INDEX_SYMBOL = (
    "hackrf_edge_precision_rx_dma_loan_local_buffer_index"
)
DMA_TERMINAL_COUNT_INTERRUPT_COUNT_SYMBOL = (
    "hackrf_edge_precision_rx_dma_terminal_count_interrupt_count"
)
DMA_CAPTURE_RATE_LIMIT_HZ_SYMBOL = (
    "hackrf_edge_precision_rx_dma_capture_rate_limit_hz"
)
DMA_TRANSITION_DISCARDS_SYMBOL = (
    "hackrf_edge_precision_rx_dma_transition_discards_old_block"
)
DMA_TRANSITION_RESETS_EPOCH_SYMBOL = (
    "hackrf_edge_precision_rx_dma_transition_resets_epoch"
)
DMA_HIGH_RATE_BOUND_REJECTED_SYMBOL = (
    "hackrf_edge_precision_rx_dma_high_rate_bound_request_rejected"
)
DMA_ABORT_FORCE_UNBIND_SYMBOL = (
    "hackrf_edge_precision_rx_dma_abort_force_unbind"
)
DMA_ABORT_REQUIRES_RELEASE_SYMBOL = (
    "hackrf_edge_precision_rx_dma_abort_requires_consumer_release"
)
DMA_SCHEDULER_BACKLOG_DEPTH_SYMBOL = (
    "hackrf_edge_precision_rx_dma_scheduler_backlog_depth"
)
DMA_SERVICE_DEADLINE_SYMBOL = (
    "hackrf_edge_precision_rx_dma_service_deadline_ns_at_20m"
)
DMA_PHYSICAL_RETENTION_SYMBOL = (
    "hackrf_edge_precision_rx_dma_physical_retention_ns_at_20m"
)
DMA_COMPLETION_QUEUE_DEPTH_SYMBOL = (
    "hackrf_edge_precision_rx_dma_completion_queue_depth"
)
DMA_COMPLETION_PERIOD_SYMBOL = (
    "hackrf_edge_precision_rx_dma_completion_period_ns_at_20m"
)
DMA_OLDEST_CLAIM_DEADLINE_SYMBOL = (
    "hackrf_edge_precision_rx_dma_oldest_claim_deadline_ns_at_20m"
)
DMA_CLAIM_GUARD_AGE_SYMBOL = (
    "hackrf_edge_precision_rx_dma_claim_guard_age"
)
DMA_QUEUE_DROPS_OLDEST_SYMBOL = (
    "hackrf_edge_precision_rx_dma_queue_drops_oldest"
)
DMA_QUEUE_SPSC_SYMBOL = "hackrf_edge_precision_rx_dma_queue_spsc"
DMA_QUEUE_FULL_FAIL_CLOSED_SYMBOL = (
    "hackrf_edge_precision_rx_dma_queue_full_fail_closed"
)
DMA_FAST_IRQ_PRIORITY_SYMBOL = (
    "hackrf_edge_precision_rx_dma_fast_irq_priority"
)
DMA_DEFERRED_IRQ_SYMBOL = "hackrf_edge_precision_rx_dma_deferred_irq"
DMA_DEFERRED_IRQ_PRIORITY_SYMBOL = (
    "hackrf_edge_precision_rx_dma_deferred_irq_priority"
)
DMA_FAST_TC_W1C_FIRST_SYMBOL = (
    "hackrf_edge_precision_rx_dma_fast_tc_w1c_first"
)
DMA_FAST_ERROR_GATE_FIRST_SYMBOL = (
    "hackrf_edge_precision_rx_dma_fast_error_gate_first"
)
DMA_UNEXPECTED_CHANNEL_FAIL_CLOSED_SYMBOL = (
    "hackrf_edge_precision_rx_dma_unexpected_channel_fail_closed"
)
DMA_WORKER_CLAIM_IRQ_EXCLUSION_SYMBOL = (
    "hackrf_edge_precision_rx_dma_worker_claim_irq_exclusion"
)
DMA_SOFTWARE_DESCRIPTOR_PHASE_SYMBOL = (
    "hackrf_edge_precision_rx_dma_software_descriptor_phase"
)
DMA_GATE_OPEN_IRQ_EXCLUSION_SYMBOL = (
    "hackrf_edge_precision_rx_dma_gate_open_irq_exclusion"
)
DMA_GATE_OPEN_REQUIRES_CHANNEL_ENABLED_SYMBOL = (
    "hackrf_edge_precision_rx_dma_gate_open_requires_channel_enabled"
)
DMA_RATE_STATE_IRQ_EXCLUSION_SYMBOL = (
    "hackrf_edge_precision_rx_dma_rate_state_irq_exclusion"
)
DMA_RATE_STATE_SCHEDULER_EXCLUSION_SYMBOL = (
    "hackrf_edge_precision_rx_dma_rate_state_scheduler_exclusion"
)
DMA_CLAIM_PRESERVES_OWN_TC_SYMBOL = (
    "hackrf_edge_precision_rx_dma_claim_preserves_own_tc"
)
DMA_RATE_STATE_PRESERVES_OWN_TC_SYMBOL = (
    "hackrf_edge_precision_rx_dma_rate_state_preserves_own_tc"
)
DMA_EXCLUSION_PRESERVES_NVIC_PENDING_SYMBOL = (
    "hackrf_edge_precision_rx_dma_exclusion_preserves_nvic_pending"
)
DMA_SHUTDOWN_ACTIVE_DRAIN_SYMBOL = (
    "hackrf_edge_precision_rx_dma_shutdown_active_drain"
)
DMA_SHUTDOWN_ACTIVE_SPIN_LIMIT_SYMBOL = (
    "hackrf_edge_precision_rx_dma_shutdown_active_spin_limit"
)
DMA_SHUTDOWN_TIMEOUT_HALTS_SYMBOL = (
    "hackrf_edge_precision_rx_dma_shutdown_timeout_halts"
)
DMA_CONTROL_ACTIVE_DRAIN_TIMEOUT_US_SYMBOL = (
    "hackrf_edge_precision_rx_dma_control_active_drain_timeout_us"
)
DMA_CONTROL_ACTIVE_DRAIN_TICKS_AT_200M_SYMBOL = (
    "hackrf_edge_precision_rx_dma_control_active_drain_ticks_at_200m"
)
DMA_CONTROL_ACTIVE_DRAIN_USES_DWT_SYMBOL = (
    "hackrf_edge_precision_rx_dma_control_active_drain_uses_dwt"
)
DMA_CONTROL_ACTIVE_DRAIN_COUNTER_GUARD_SYMBOL = (
    "hackrf_edge_precision_rx_dma_control_active_drain_counter_guard"
)
DMA_CONTROL_SLOWEST_DESCRIPTOR_TICKS_AT_200M_SYMBOL = (
    "hackrf_edge_precision_rx_dma_control_slowest_descriptor_ticks_at_200m"
)
DMA_LIFETIME_LOSS_COUNTER_BITS_SYMBOL = (
    "hackrf_edge_precision_rx_dma_lifetime_loss_counter_bits"
)
DMA_LIFETIME_LOSS_SATURATING_SYMBOL = (
    "hackrf_edge_precision_rx_dma_lifetime_loss_saturating"
)
RATE_TRANSACTION_PROTOCOL_VERSION_SYMBOL = (
    "hackrf_edge_precision_rx_rate_transaction_protocol_version"
)
RATE_PREPARE_GATES_SGPIO_SYMBOL = (
    "hackrf_edge_precision_rx_rate_prepare_gates_sgpio_before_dma_pause"
)
RATE_PREPARE_HALTS_DMA_BEFORE_GATING_SGPIO_SYMBOL = (
    "hackrf_edge_precision_rx_rate_prepare_halts_dma_before_gating_sgpio"
)
RATE_QUIESCE_FAILURE_BITS_SYMBOL = (
    "hackrf_edge_precision_rx_rate_quiesce_failure_bits"
)
RATE_TRANSITION_FAILURE_COUNT_BITS_SYMBOL = (
    "hackrf_edge_precision_rx_rate_transition_failure_count_bits"
)
RATE_PREPARE_ACK_REQUIRES_ARMED_SYMBOL = (
    "hackrf_edge_precision_rx_rate_prepare_ack_requires_pause_armed"
)
RATE_COMMIT_PUBLISHES_TARGET_SYMBOL = (
    "hackrf_edge_precision_rx_rate_commit_publishes_target_before_dma_resume"
)
RATE_COMMIT_ACK_REQUIRES_COMPLETION_SYMBOL = (
    "hackrf_edge_precision_rx_rate_commit_ack_requires_first_new_rate_completion"
)
RATE_FAIL_CLOSED_PREPARE_SYMBOL = (
    "hackrf_edge_precision_rx_rate_fail_closed_on_prepare_failure"
)
RATE_FAIL_CLOSED_COMMIT_SYMBOL = (
    "hackrf_edge_precision_rx_rate_fail_closed_on_commit_failure"
)
ENERGY_TO_DBFS_NAME = (
    "precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)"
)
LOG10_KERNEL_NAME = "__ieee754_log10f"
LOG10_WRAPPER_NAMES = frozenset({"log10", "log10f", "__log10f"})
NON_POSITIVE_DBFS_X10 = -1200

P12_ABSOLUTE_METADATA = {
    DMA_COMPLETION_QUEUE_DEPTH_SYMBOL: EXPECTED_P12_DMA_COMPLETION_QUEUE_DEPTH,
    DMA_COMPLETION_PERIOD_SYMBOL: EXPECTED_P12_DMA_COMPLETION_PERIOD_NS_AT_20M,
    DMA_OLDEST_CLAIM_DEADLINE_SYMBOL: (
        EXPECTED_P12_DMA_OLDEST_CLAIM_DEADLINE_NS_AT_20M
    ),
    DMA_CLAIM_GUARD_AGE_SYMBOL: EXPECTED_P12_DMA_CLAIM_GUARD_AGE,
    DMA_QUEUE_DROPS_OLDEST_SYMBOL: 0,
    DMA_QUEUE_SPSC_SYMBOL: 1,
    DMA_QUEUE_FULL_FAIL_CLOSED_SYMBOL: 1,
    DMA_FAST_IRQ_PRIORITY_SYMBOL: 1,
    DMA_DEFERRED_IRQ_SYMBOL: 31,
    DMA_DEFERRED_IRQ_PRIORITY_SYMBOL: 3,
    DMA_FAST_TC_W1C_FIRST_SYMBOL: 1,
    DMA_FAST_ERROR_GATE_FIRST_SYMBOL: 1,
    DMA_UNEXPECTED_CHANNEL_FAIL_CLOSED_SYMBOL: 1,
    DMA_WORKER_CLAIM_IRQ_EXCLUSION_SYMBOL: 1,
    DMA_SOFTWARE_DESCRIPTOR_PHASE_SYMBOL: 1,
    DMA_GATE_OPEN_IRQ_EXCLUSION_SYMBOL: 1,
    DMA_GATE_OPEN_REQUIRES_CHANNEL_ENABLED_SYMBOL: 1,
    DMA_RATE_STATE_IRQ_EXCLUSION_SYMBOL: 1,
    DMA_RATE_STATE_SCHEDULER_EXCLUSION_SYMBOL: 1,
    DMA_CLAIM_PRESERVES_OWN_TC_SYMBOL: 1,
    DMA_RATE_STATE_PRESERVES_OWN_TC_SYMBOL: 1,
    DMA_EXCLUSION_PRESERVES_NVIC_PENDING_SYMBOL: 1,
    DMA_SHUTDOWN_ACTIVE_DRAIN_SYMBOL: 1,
    DMA_SHUTDOWN_ACTIVE_SPIN_LIMIT_SYMBOL: 65536,
    DMA_SHUTDOWN_TIMEOUT_HALTS_SYMBOL: 1,
    DMA_CONTROL_ACTIVE_DRAIN_TIMEOUT_US_SYMBOL: (
        EXPECTED_P14_CONTROL_ACTIVE_DRAIN_TIMEOUT_US
    ),
    DMA_CONTROL_ACTIVE_DRAIN_TICKS_AT_200M_SYMBOL: (
        EXPECTED_P14_CONTROL_ACTIVE_DRAIN_TICKS_AT_200M
    ),
    DMA_CONTROL_ACTIVE_DRAIN_USES_DWT_SYMBOL: 1,
    DMA_CONTROL_ACTIVE_DRAIN_COUNTER_GUARD_SYMBOL: 1,
    DMA_CONTROL_SLOWEST_DESCRIPTOR_TICKS_AT_200M_SYMBOL: (
        EXPECTED_P14_CONTROL_SLOWEST_DESCRIPTOR_TICKS_AT_200M
    ),
    DMA_LIFETIME_LOSS_COUNTER_BITS_SYMBOL: (
        EXPECTED_P12_DMA_LIFETIME_LOSS_COUNTER_BITS
    ),
    DMA_LIFETIME_LOSS_SATURATING_SYMBOL: 1,
    RATE_TRANSACTION_PROTOCOL_VERSION_SYMBOL: (
        EXPECTED_P15_RATE_TRANSACTION_PROTOCOL_VERSION
    ),
    RATE_PREPARE_GATES_SGPIO_SYMBOL: 0,
    RATE_PREPARE_HALTS_DMA_BEFORE_GATING_SGPIO_SYMBOL: 1,
    RATE_QUIESCE_FAILURE_BITS_SYMBOL: EXPECTED_P15_QUIESCE_FAILURE_BITS,
    RATE_TRANSITION_FAILURE_COUNT_BITS_SYMBOL: (
        EXPECTED_P15_TRANSITION_FAILURE_COUNT_BITS
    ),
    RATE_PREPARE_ACK_REQUIRES_ARMED_SYMBOL: 1,
    RATE_COMMIT_PUBLISHES_TARGET_SYMBOL: 1,
    RATE_COMMIT_ACK_REQUIRES_COMPLETION_SYMBOL: 1,
    RATE_FAIL_CLOSED_PREPARE_SYMBOL: 1,
    RATE_FAIL_CLOSED_COMMIT_SYMBOL: 1,
}

P14_TEST_ABSOLUTE_METADATA = {
    name: value
    for name, value in P12_ABSOLUTE_METADATA.items()
    if name
    not in {
        RATE_PREPARE_HALTS_DMA_BEFORE_GATING_SGPIO_SYMBOL,
        RATE_QUIESCE_FAILURE_BITS_SYMBOL,
        RATE_TRANSITION_FAILURE_COUNT_BITS_SYMBOL,
    }
}
P14_TEST_ABSOLUTE_METADATA[RATE_TRANSACTION_PROTOCOL_VERSION_SYMBOL] = (
    EXPECTED_P12_RATE_TRANSACTION_PROTOCOL_VERSION
)
P14_TEST_ABSOLUTE_METADATA[RATE_PREPARE_GATES_SGPIO_SYMBOL] = 1


class VerificationError(RuntimeError):
    """A linked artifact does not prove the required contract."""


@dataclass(frozen=True)
class Symbol:
    address: int
    size: int
    kind: str
    name: str


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str
    target: str | None


@dataclass(frozen=True)
class Function:
    address: int
    name: str
    instructions: tuple[Instruction, ...]


@dataclass(frozen=True)
class Section:
    name: str
    size: int
    vma: int
    lma: int
    flags: frozenset[str]


@dataclass(frozen=True)
class GateConfig:
    flash_base: int = FLASH_BASE
    flash_capacity_bytes: int = FLASH_CAPACITY_BYTES
    ram_base: int = RAM_BASE
    ram_capacity_bytes: int = RAM_CAPACITY_BYTES
    expected_stream_write_size: int = EXPECTED_STREAM_WRITE_SIZE
    expected_stream_buffer_count: int = EXPECTED_STREAM_BUFFER_COUNT
    expected_dma_buffer_bytes: int = EXPECTED_DMA_BUFFER_BYTES
    expected_dma_transfer_bytes: int = EXPECTED_DMA_TRANSFER_BYTES
    expected_dma_transfer_count: int = EXPECTED_DMA_TRANSFER_COUNT
    expected_dma_lli_bytes: int = EXPECTED_DMA_LLI_BYTES
    expected_dma_loan_bytes: int = EXPECTED_DMA_LOAN_BYTES
    expected_dma_monitor_ring_bytes: int = EXPECTED_DMA_MONITOR_RING_BYTES
    expected_dma_monitor_transfer_bytes: int = EXPECTED_DMA_MONITOR_TRANSFER_BYTES
    expected_dma_monitor_transfer_samples: int = EXPECTED_DMA_MONITOR_TRANSFER_SAMPLES
    expected_dma_capture_ring_bytes: int = EXPECTED_DMA_CAPTURE_RING_BYTES
    expected_dma_capture_transfer_bytes: int = EXPECTED_DMA_CAPTURE_TRANSFER_BYTES
    expected_dma_capture_transfer_samples: int = EXPECTED_DMA_CAPTURE_TRANSFER_SAMPLES
    max_processor_bytes: int = MAX_PROCESSOR_BYTES
    max_rebind_code_bytes: int = MAX_REBIND_CODE_BYTES
    max_service_code_bytes: int = MAX_SERVICE_CODE_BYTES
    max_service_bulk_bytes: int = MAX_SERVICE_BULK_BYTES
    heap_metadata_reserve_bytes: int = HEAP_METADATA_RESERVE_BYTES
    minimum_modeled_headroom_bytes: int = MINIMUM_MODELED_HEADROOM_BYTES


NM_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([A-Za-z])\s+(.+?)\s*$"
)
FUNCTION_HEADER = re.compile(r"^\s*([0-9a-fA-F]+) <(.+)>:\s*$")
INSTRUCTION_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+"
    r"(?:(?:[0-9a-fA-F]{4,8})\s+)+"
    r"([A-Za-z][A-Za-z0-9.]*)\s*(.*?)\s*$"
)
# GNU objdump demangled targets can themselves contain nested ``<>`` template
# syntax.  Match through the final closing delimiter on the operand line.
TARGET = re.compile(r"<(.+)>")
SECTION_LINE = re.compile(
    r"^\s*\d+\s+(\S+)\s+([0-9a-fA-F]+)\s+"
    r"([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+"
    r"[0-9a-fA-F]+\s+\S+\s*$"
)
WORD_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+[0-9a-fA-F]+\s+\.word\s+"
    r"(0x[0-9a-fA-F]+|[0-9]+)\s*$"
)
IMMEDIATE_MOVE = re.compile(
    r"^(r(?:1[0-5]|[0-9])|sp|lr),\s*#(0x[0-9a-fA-F]+|[0-9]+)\b"
)
BRANCH_TARGET_ADDRESS = re.compile(
    r"(?:^|,\s*)([0-9a-fA-F]+)\s+<[^>]+>"
)
IMMEDIATE_VALUE = re.compile(r"#(0x[0-9a-fA-F]+|[0-9]+)\b")
REGISTER_NAME = r"(?:r(?:1[0-5]|[0-9])|ip|sp|lr|pc)"
REGISTER_OPERAND = re.compile(rf"\b({REGISTER_NAME})\b")
MEMORY_OPERAND = re.compile(
    rf"\[\s*({REGISTER_NAME})(?:\s*,\s*#(0x[0-9a-fA-F]+|[0-9]+))?\s*\]"
)
INDEXED_MEMORY_OPERAND = re.compile(
    rf"\[\s*({REGISTER_NAME})\s*,\s*({REGISTER_NAME})"
    r"(?:\s*,\s*lsl\s*#(0x[0-9a-fA-F]+|[0-9]+))?\s*\]"
)
PC_LITERAL_TARGET = re.compile(r";\s*\(\s*([0-9a-fA-F]+)\s+<")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def parse_nm(text: str) -> list[Symbol]:
    symbols: list[Symbol] = []
    for line in text.splitlines():
        match = NM_LINE.match(line)
        if match:
            symbols.append(
                Symbol(
                    address=int(match.group(1), 16),
                    size=int(match.group(2), 16),
                    kind=match.group(3),
                    name=match.group(4),
                )
            )
    _require(bool(symbols), "nm output contains no sized defined symbols")
    return symbols


def parse_disassembly(text: str) -> list[Function]:
    functions: list[Function] = []
    current_name: str | None = None
    current_address = 0
    current_instructions: list[Instruction] = []

    def finish() -> None:
        nonlocal current_name, current_address, current_instructions
        if current_name is None:
            return
        functions.append(
            Function(
                current_address,
                current_name,
                tuple(current_instructions),
            )
        )

    for line in text.splitlines():
        header = FUNCTION_HEADER.match(line)
        if header:
            finish()
            current_address = int(header.group(1), 16)
            current_name = header.group(2)
            current_instructions = []
            continue
        if current_name is None:
            continue
        instruction = INSTRUCTION_LINE.match(line)
        if instruction:
            operands = instruction.group(3).strip()
            target_match = TARGET.search(operands)
            current_instructions.append(
                Instruction(
                    address=int(instruction.group(1), 16),
                    mnemonic=instruction.group(2),
                    operands=operands,
                    target=target_match.group(1) if target_match else None,
                )
            )
    finish()
    _require(bool(functions), "objdump output contains no disassembled functions")
    return functions


def parse_sections(text: str) -> list[Section]:
    sections: list[Section] = []
    pending: tuple[str, int, int, int] | None = None
    for line in text.splitlines():
        match = SECTION_LINE.match(line)
        if match:
            if pending is not None:
                name, size, vma, lma = pending
                sections.append(Section(name, size, vma, lma, frozenset()))
            pending = (
                match.group(1),
                int(match.group(2), 16),
                int(match.group(3), 16),
                int(match.group(4), 16),
            )
            continue
        if pending is not None and line.strip():
            flags = frozenset(part.strip() for part in line.split(",") if part.strip())
            name, size, vma, lma = pending
            sections.append(Section(name, size, vma, lma, flags))
            pending = None
    if pending is not None:
        name, size, vma, lma = pending
        sections.append(Section(name, size, vma, lma, frozenset()))
    _require(bool(sections), "objdump section output contains no sections")
    return sections


def parse_literal_words(text: str) -> dict[int, int]:
    return {
        int(match.group(1), 16): int(match.group(2), 0)
        for line in text.splitlines()
        if (match := WORD_LINE.match(line))
    }


def _unique_function(
    functions: Sequence[Function],
    description: str,
    predicate: Callable[[str], bool],
) -> Function:
    matches = [function for function in functions if predicate(function.name)]
    _require(len(matches) == 1, f"expected exactly one {description}; found {len(matches)}")
    return matches[0]


def _unique_symbol_size(
    symbols: Sequence[Symbol],
    description: str,
    predicate: Callable[[str], bool],
) -> int:
    matches = {(symbol.address, symbol.size) for symbol in symbols if predicate(symbol.name)}
    _require(len(matches) == 1, f"expected exactly one sized {description}; found {len(matches)}")
    _, size = next(iter(matches))
    _require(size > 0, f"{description} has zero code size")
    return size


def _unique_symbol_value(
    symbols: Sequence[Symbol],
    name: str,
) -> int:
    matches = [symbol for symbol in symbols if symbol.name == name]
    _require(len(matches) == 1, f"expected exactly one {name}; found {len(matches)}")
    symbol = matches[0]
    _require(symbol.kind.upper() == "A", f"{name} must be an absolute symbol")
    return symbol.address


def _p12_metadata(
    symbols: Sequence[Symbol],
    expected_metadata: dict[str, int] = P12_ABSOLUTE_METADATA,
) -> dict[str, int] | None:
    """Return the complete p12 metadata set, or ``None`` for a legacy ELF.

    Presence of any p12-only symbol selects the p12 profile.  This deliberately
    makes a partially stripped or partially compiled transaction contract fail
    closed instead of silently falling back to the p11 checks.
    """

    symbol_names = {symbol.name for symbol in symbols}
    if not symbol_names.intersection(expected_metadata):
        return None

    metadata = {
        name: _unique_symbol_value(symbols, name)
        for name in expected_metadata
    }
    for name, expected in expected_metadata.items():
        actual = metadata[name]
        _require(
            actual == expected,
            f"linked p12 metadata {name} is {actual}; expected {expected}",
        )
    return metadata


def _calls(function: Function) -> list[Instruction]:
    return [
        instruction
        for instruction in function.instructions
        if instruction.mnemonic in {"bl", "blx"}
    ]


def _calls_matching(
    function: Function,
    predicate: Callable[[str], bool],
) -> list[Instruction]:
    return [
        instruction
        for instruction in _calls(function)
        if instruction.target is not None and predicate(instruction.target)
    ]


def _reachable_call_paths(
    functions: Sequence[Function],
    root: Function,
    predicate: Callable[[str], bool],
    *,
    maximum_depth: int = 8,
) -> list[tuple[tuple[str, ...], Instruction]]:
    """Find direct or helper-mediated calls retained by optimized LTO output."""

    functions_by_name = {function.name: function for function in functions}
    matches: list[tuple[tuple[str, ...], Instruction]] = []

    def visit(
        function: Function,
        path: tuple[str, ...],
        visited: frozenset[str],
    ) -> None:
        if len(path) > maximum_depth:
            return
        for transfer in function.instructions:
            if (
                transfer.target is None
                or transfer.mnemonic
                not in {"bl", "blx", "b", "b.n", "b.w"}
            ):
                continue
            if predicate(transfer.target):
                matches.append((path, transfer))
            callee = functions_by_name.get(transfer.target)
            if callee is not None and callee.name not in visited:
                visit(
                    callee,
                    path + (callee.name,),
                    visited | {callee.name},
                )

    visit(root, (root.name,), frozenset({root.name}))
    return matches


def _require_one_call(
    function: Function,
    description: str,
    predicate: Callable[[str], bool],
) -> Instruction:
    matches = _calls_matching(function, predicate)
    _require(
        len(matches) == 1,
        f"{function.name} must call {description} exactly once; found {len(matches)}",
    )
    return matches[0]


def _instruction_immediates(instruction: Instruction) -> set[int]:
    return {
        int(match.group(1), 0)
        for match in IMMEDIATE_VALUE.finditer(instruction.operands)
    }


def _has_immediate(instruction: Instruction, value: int) -> bool:
    return value in _instruction_immediates(instruction)


def _memory_offset(instruction: Instruction, value: int) -> bool:
    memory_operand = instruction.operands.split(";", 1)[0]
    for match in IMMEDIATE_VALUE.finditer(memory_operand):
        if int(match.group(1), 0) == value:
            return True
    return False


def _canonical_register(register: str) -> str:
    return {
        "ip": "r12",
        "sp": "r13",
        "lr": "r14",
        "pc": "r15",
    }.get(register, register)


def _operand_registers(instruction: Instruction) -> tuple[str, ...]:
    operands = instruction.operands.split(";", 1)[0]
    return tuple(
        _canonical_register(match.group(1))
        for match in REGISTER_OPERAND.finditer(operands)
    )


def _first_operand_register(instruction: Instruction) -> str | None:
    registers = _operand_registers(instruction)
    return registers[0] if registers else None


def _memory_location(instruction: Instruction) -> tuple[str, int] | None:
    operands = instruction.operands.split(";", 1)[0]
    match = MEMORY_OPERAND.search(operands)
    if match is None:
        return None
    return (
        _canonical_register(match.group(1)),
        int(match.group(2), 0) if match.group(2) is not None else 0,
    )


def _pc_literal_target(instruction: Instruction) -> int | None:
    location = _memory_location(instruction)
    if location is None or location[0] != "r15":
        return None
    match = PC_LITERAL_TARGET.search(instruction.operands)
    return int(match.group(1), 16) if match else None


def _load_records(
    function: Function,
) -> list[tuple[Instruction, str, str, int]]:
    records: list[tuple[Instruction, str, str, int]] = []
    for instruction in function.instructions:
        if not instruction.mnemonic.startswith("ldr"):
            continue
        location = _memory_location(instruction)
        registers = _operand_registers(instruction)
        if location is None or not registers:
            continue
        base, offset = location
        records.append((instruction, registers[0], base, offset))
        if instruction.mnemonic.startswith("ldrd") and len(registers) >= 2:
            records.append((instruction, registers[1], base, offset + 4))
    return records


def _branch_condition_register(instruction: Instruction) -> str | None:
    if instruction.mnemonic not in {"cbz", "cbnz"}:
        return None
    return _first_operand_register(instruction)


def _require_zero_failure_branch_after_call(
    function: Function,
    call: Instruction,
    description: str,
) -> Instruction:
    tail = [
        instruction
        for instruction in function.instructions
        if instruction.address > call.address
        and not instruction.mnemonic.startswith("nop")
    ]
    _require(bool(tail), f"{description} result is not tested")
    first = tail[0]
    if first.mnemonic == "cbz" and _branch_condition_register(first) == "r0":
        return first
    if (
        first.mnemonic.startswith("cmp")
        and _operand_registers(first)[:1] == ("r0",)
        and _has_immediate(first, 0)
        and len(tail) >= 2
        and tail[1].mnemonic.startswith("beq")
    ):
        return tail[1]
    raise VerificationError(
        f"{description} must immediately branch on the returned r0 value"
    )


def _zero_branch_after_load(
    function: Function,
    load: Instruction,
    description: str,
) -> Instruction:
    register = _first_operand_register(load)
    tail = [
        instruction
        for instruction in function.instructions
        if instruction.address > load.address
        and not instruction.mnemonic.startswith("nop")
    ]
    _require(bool(tail), f"{description} is not tested")
    first = tail[0]
    if first.mnemonic == "cbz" and _branch_condition_register(first) == register:
        return first
    if (
        first.mnemonic.startswith("cmp")
        and _operand_registers(first)[:1] == (register,)
        and _has_immediate(first, 0)
        and len(tail) >= 2
        and tail[1].mnemonic.startswith("beq")
    ):
        return tail[1]
    raise VerificationError(f"{description} must immediately test its loaded value")


def _find_unsigned_rate_limit_guard(
    function: Function,
    *,
    object_offset: int,
    expected_limit: int,
    literal_words: dict[int, int],
    function_size: int,
    minimum_address: int | None = None,
    maximum_address: int | None = None,
    maximum_load_distance: int = 32,
) -> tuple[Instruction, Instruction, Instruction, Instruction]:
    candidates = [
        instruction
        for instruction in function.instructions
        if _load_at_offset(instruction, object_offset)
        and (minimum_address is None or instruction.address > minimum_address)
        and (maximum_address is None or instruction.address < maximum_address)
    ]
    for object_load in candidates:
        object_register = _first_operand_register(object_load)
        limit_loads = [
            instruction
            for instruction in function.instructions
            if object_load.address < instruction.address
            <= object_load.address + maximum_load_distance
            and instruction.mnemonic.startswith("ldr")
            and (target := _pc_literal_target(instruction)) is not None
            and function.address <= target < function.address + function_size
            and literal_words.get(target) == expected_limit
        ]
        for limit_load in limit_loads:
            limit_register = _first_operand_register(limit_load)
            comparisons = [
                instruction
                for instruction in function.instructions
                if limit_load.address < instruction.address <= limit_load.address + 8
                and instruction.mnemonic.startswith("cmp")
                and _operand_registers(instruction)[:2]
                == (object_register, limit_register)
            ]
            for comparison in comparisons:
                following = [
                    instruction
                    for instruction in function.instructions
                    if instruction.address > comparison.address
                    and not instruction.mnemonic.startswith("nop")
                ]
                if following and following[0].mnemonic.startswith("bls"):
                    return object_load, limit_load, comparison, following[0]
    raise VerificationError(
        f"{function.name} lacks a linked unsigned {expected_limit} Hz guard "
        f"for object offset {object_offset}"
    )


def _is_branch(instruction: Instruction) -> bool:
    mnemonic = instruction.mnemonic.lower().split(".", 1)[0]
    return mnemonic in {
        "b",
        "bal",
        "beq",
        "bne",
        "bcs",
        "bcc",
        "bhs",
        "blo",
        "bmi",
        "bpl",
        "bvs",
        "bvc",
        "bhi",
        "bls",
        "bge",
        "blt",
        "bgt",
        "ble",
        "bl",
        "blx",
        "bx",
        "cbz",
        "cbnz",
    }


def _is_conditional_branch(instruction: Instruction) -> bool:
    mnemonic = instruction.mnemonic.lower().split(".", 1)[0]
    return mnemonic in {
        "beq",
        "bne",
        "bcs",
        "bcc",
        "bhs",
        "blo",
        "bmi",
        "bpl",
        "bvs",
        "bvc",
        "bhi",
        "bls",
        "bge",
        "blt",
        "bgt",
        "ble",
        "cbz",
        "cbnz",
    }


def _branch_target_address(instruction: Instruction) -> int | None:
    match = BRANCH_TARGET_ADDRESS.search(instruction.operands)
    return int(match.group(1), 16) if match else None


def _indices_matching(
    function: Function,
    predicate: Callable[[Instruction], bool],
) -> list[int]:
    return [
        index
        for index, instruction in enumerate(function.instructions)
        if predicate(instruction)
    ]


def _require_ordered_instructions(
    function: Function,
    requirements: Sequence[tuple[str, Callable[[Instruction], bool]]],
) -> list[Instruction]:
    matched: list[Instruction] = []
    next_index = 0
    for description, predicate in requirements:
        for index in range(next_index, len(function.instructions)):
            instruction = function.instructions[index]
            if predicate(instruction):
                matched.append(instruction)
                next_index = index + 1
                break
        else:
            raise VerificationError(
                f"{function.name} lacks ordered instruction: {description}"
            )
    return matched


def _dmb(instruction: Instruction) -> bool:
    return instruction.mnemonic == "dmb"


def _is_return_instruction(instruction: Instruction) -> bool:
    registers = _operand_registers(instruction)
    return (
        instruction.mnemonic in {"bx", "bx.n"}
        and registers == ("r14",)
    ) or (
        instruction.mnemonic.startswith("ldr")
        and registers
        and registers[0] == "r15"
        and _memory_location(instruction) == ("r13", 0)
    ) or (
        (
            instruction.mnemonic.startswith("pop")
            or instruction.mnemonic.startswith("ldm")
        )
        and "r15" in registers
    )


def _control_flow_successors(
    function: Function,
    *,
    reject_thumb_it: bool = True,
) -> dict[int, frozenset[int]]:
    """Build a conservative intraprocedural Thumb control-flow graph.

    Calls return to the following instruction.  Direct branches must resolve
    to a parsed instruction inside the function; an escaping unconditional
    branch is treated as a tail exit.  Unknown indirect/table branches are
    rejected so a release proof cannot silently omit a bypass edge.
    """

    instructions = tuple(sorted(function.instructions, key=lambda ins: ins.address))
    if reject_thumb_it:
        for instruction in instructions:
            mnemonic = instruction.mnemonic.lower().split(".", 1)[0]
            _require(
                re.fullmatch(r"it[te]{0,3}", mnemonic) is None,
                f"{function.name} contains unsupported Thumb IT predication at "
                f"0x{instruction.address:x}",
            )
    addresses = {instruction.address for instruction in instructions}
    successors: dict[int, frozenset[int]] = {}
    for index, instruction in enumerate(instructions):
        following = (
            instructions[index + 1].address
            if index + 1 < len(instructions)
            and 0 < instructions[index + 1].address - instruction.address <= 4
            else None
        )
        mnemonic = instruction.mnemonic
        if _is_return_instruction(instruction):
            successors[instruction.address] = frozenset()
            continue
        if mnemonic.startswith(("tbb", "tbh")) or (
            mnemonic.startswith("bx") and mnemonic not in {"blx"}
        ):
            raise VerificationError(
                f"{function.name} contains an unmodelled indirect control "
                f"transfer at 0x{instruction.address:x}"
            )
        if mnemonic in {"bl", "blx"}:
            successors[instruction.address] = (
                frozenset({following}) if following is not None else frozenset()
            )
            continue
        if _is_branch(instruction):
            target = _branch_target_address(instruction)
            _require(
                target is not None,
                f"{function.name} contains an unresolved branch at "
                f"0x{instruction.address:x}",
            )
            local_target = target if target in addresses else None
            if _is_conditional_branch(instruction):
                _require(
                    following is not None,
                    f"{function.name} conditional branch at "
                    f"0x{instruction.address:x} has no reviewed fallthrough",
                )
                edges = {following}
                if local_target is not None:
                    edges.add(local_target)
                successors[instruction.address] = frozenset(edges)
            else:
                successors[instruction.address] = (
                    frozenset({local_target})
                    if local_target is not None
                    else frozenset()
                )
            continue
        successors[instruction.address] = (
            frozenset({following}) if following is not None else frozenset()
        )
    return successors


def _dominators_from(
    function: Function,
    start_address: int,
    *,
    reject_thumb_it: bool = True,
) -> tuple[dict[int, frozenset[int]], frozenset[int]]:
    """Return dominators and reachable nodes for one reviewed function."""

    successors = _control_flow_successors(
        function,
        reject_thumb_it=reject_thumb_it,
    )
    _require(
        start_address in successors,
        f"{function.name} CFG start 0x{start_address:x} is not an instruction",
    )
    reachable: set[int] = set()
    pending = [start_address]
    while pending:
        address = pending.pop()
        if address in reachable:
            continue
        reachable.add(address)
        pending.extend(successors[address] - reachable)

    predecessors: dict[int, set[int]] = {address: set() for address in reachable}
    for source in reachable:
        for target in successors[source]:
            if target in reachable:
                predecessors[target].add(source)

    dominators: dict[int, set[int]] = {
        address: ({start_address} if address == start_address else set(reachable))
        for address in reachable
    }
    changed = True
    while changed:
        changed = False
        for address in reachable:
            if address == start_address:
                continue
            incoming = predecessors[address]
            new = {address}
            if incoming:
                common = set(reachable)
                for predecessor in incoming:
                    common.intersection_update(dominators[predecessor])
                new.update(common)
            if new != dominators[address]:
                dominators[address] = new
                changed = True
    return (
        {
            address: frozenset(values)
            for address, values in dominators.items()
        },
        frozenset(reachable),
    )


def _require_cfg_dominance(
    function: Function,
    *,
    start: Instruction,
    target: Instruction,
    required: Sequence[tuple[str, Instruction]],
    reject_thumb_it: bool = True,
) -> None:
    dominators, reachable = _dominators_from(
        function,
        start.address,
        reject_thumb_it=reject_thumb_it,
    )
    _require(
        target.address in reachable,
        f"{function.name} CFG target 0x{target.address:x} is unreachable "
        "from the reviewed transaction path",
    )
    for description, instruction in required:
        _require(
            instruction.address in dominators[target.address],
            f"{description} must dominate 0x{target.address:x} in "
            f"{function.name}",
        )


def _verify_rebind_fifo_helper(
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
) -> dict[str, int | bool | str]:
    """Prove the sole p12 rebind helper is a small, bounded FIFO insertion.

    This is intentionally narrower than approving arbitrary helper calls.  The
    reviewed helper may neither call out nor loop: its only backward transfer
    may target a return instruction.  Its publication barrier must remain
    between the pointer-slot store and the FIFO index store.
    """

    helper = _unique_function(
        functions,
        FIFO_STREAM_BUFFER_IN_NAME,
        lambda name: name == FIFO_STREAM_BUFFER_IN_NAME,
    )
    helper_size = _unique_symbol_size(
        symbols,
        FIFO_STREAM_BUFFER_IN_NAME,
        lambda name: name == FIFO_STREAM_BUFFER_IN_NAME,
    )
    _require(
        helper_size <= MAX_FIFO_STREAM_BUFFER_IN_CODE_BYTES,
        f"{FIFO_STREAM_BUFFER_IN_NAME} grew to {helper_size} bytes; maximum is "
        f"{MAX_FIFO_STREAM_BUFFER_IN_CODE_BYTES}",
    )
    _require(
        not _calls(helper),
        f"{FIFO_STREAM_BUFFER_IN_NAME} must remain call-free and nonallocating",
    )

    instructions_by_address = {
        instruction.address: instruction
        for instruction in helper.instructions
    }
    helper_end = helper.address + helper_size
    for branch in (ins for ins in helper.instructions if _is_branch(ins)):
        if _is_return_instruction(branch):
            continue
        target = _branch_target_address(branch)
        _require(
            target is not None
            and helper.address <= target < helper_end,
            f"{FIFO_STREAM_BUFFER_IN_NAME} contains an indirect or escaping "
            "branch",
        )
        if target <= branch.address:
            _require(
                target in instructions_by_address
                and _is_return_instruction(instructions_by_address[target]),
                f"{FIFO_STREAM_BUFFER_IN_NAME} contains an unbounded backward "
                "branch",
            )

    barriers = [ins for ins in helper.instructions if _dmb(ins)]
    _require(
        len(barriers) == 1,
        f"{FIFO_STREAM_BUFFER_IN_NAME} must contain exactly one publication DMB",
    )
    barrier = barriers[0]
    _require(
        any(
            ins.address < barrier.address and ins.mnemonic.startswith("str")
            for ins in helper.instructions
        )
        and any(
            ins.address > barrier.address and ins.mnemonic.startswith("str")
            for ins in helper.instructions
        ),
        f"{FIFO_STREAM_BUFFER_IN_NAME} must publish the pointer slot before "
        "advancing the FIFO index",
    )
    return {
        "name": helper.name,
        "code_bytes": helper_size,
        "maximum_code_bytes": MAX_FIFO_STREAM_BUFFER_IN_CODE_BYTES,
        "call_free": True,
        "bounded": True,
        "publication_order_linked": True,
    }


def _literal_loads(
    function: Function,
    literal_words: dict[int, int],
    value: int,
) -> list[Instruction]:
    return [
        instruction
        for instruction in function.instructions
        if instruction.mnemonic.startswith("ldr")
        and (target := _pc_literal_target(instruction)) is not None
        and literal_words.get(target) == value
    ]


def _next_non_nop(
    function: Function,
    address: int,
    *,
    limit: int | None = None,
) -> Instruction | None:
    return next(
        (
            instruction
            for instruction in function.instructions
            if instruction.address > address
            and (limit is None or instruction.address < limit)
            and not instruction.mnemonic.startswith("nop")
        ),
        None,
    )


def _instruction_at(function: Function, address: int | None) -> Instruction | None:
    if address is None:
        return None
    return next(
        (
            instruction
            for instruction in function.instructions
            if instruction.address == address
        ),
        None,
    )


def _written_registers(instruction: Instruction) -> frozenset[str]:
    """Return a conservative set of general-register destinations.

    Most Thumb instructions write only their first operand.  The paired and
    multiple-load families are the important exception for the p12 ACK
    preservation proof: an ``ldrd r2, r7, [...]`` must be treated as
    overwriting both r2 *and* r7.  Treat all listed registers as destinations
    for load-multiple/pop, and both leading operands for paired-result
    instructions.  False rejection is preferable to silently accepting an
    unmodelled multi-destination write in a release verifier.
    """

    mnemonic = instruction.mnemonic.lower()
    registers = _operand_registers(instruction)
    if not registers:
        return frozenset()
    if (
        mnemonic.startswith(
            (
                "b",
                "cmp",
                "cmn",
                "tst",
                "teq",
                "str",
                "stm",
                "push",
                "msr",
            )
        )
        or mnemonic in {"dmb", "dsb", "isb", "sev", "wfe", "wfi"}
    ):
        return frozenset()
    if mnemonic.startswith(("pop", "ldm")):
        return frozenset(registers)
    if mnemonic.startswith(
        (
            "ldrd",
            "ldrexd",
            "umull",
            "umlal",
            "smull",
            "smlal",
        )
    ):
        return frozenset(registers[:2])
    return frozenset(registers[:1])


def _writes_register(instruction: Instruction, register: str) -> bool:
    return register in _written_registers(instruction)


def _clobbers_register(instruction: Instruction, register: str) -> bool:
    if instruction.mnemonic in {"bl", "blx"}:
        return register in {"r0", "r1", "r2", "r3", "r12", "r14"}
    return _writes_register(instruction, register)


def _require_register_preserved(
    function: Function,
    register: str,
    *,
    after: Instruction,
    before: Instruction,
    description: str,
) -> None:
    clobbers = [
        instruction
        for instruction in function.instructions
        if after.address < instruction.address < before.address
        and _clobbers_register(instruction, register)
    ]
    _require(
        not clobbers,
        f"{description} register {register} is overwritten between "
        f"0x{after.address:x} and 0x{before.address:x}",
    )


def _last_register_writer(
    function: Function,
    register: str,
    *,
    before: Instruction,
) -> Instruction | None:
    return next(
        (
            instruction
            for instruction in reversed(function.instructions)
            if instruction.address < before.address
            and _clobbers_register(instruction, register)
        ),
        None,
    )


def _constant_register_value(
    function: Function,
    register: str,
    *,
    before: Instruction,
    literal_words: dict[int, int],
) -> tuple[int, Instruction] | None:
    writer = _last_register_writer(function, register, before=before)
    if writer is None:
        return None
    literal_target = _pc_literal_target(writer)
    if literal_target is not None and literal_target in literal_words:
        return literal_words[literal_target], writer
    if writer.mnemonic.startswith(("mov", "mvn")):
        immediates = _instruction_immediates(writer)
        if len(immediates) == 1:
            value = next(iter(immediates))
            if writer.mnemonic.startswith("mvn"):
                value = (~value) & 0xFFFFFFFF
            return value, writer
    return None


def _bitwise_or_uses_constant(
    function: Function,
    instruction: Instruction,
    value: int,
    *,
    literal_words: dict[int, int],
) -> bool:
    if not instruction.mnemonic.startswith("orr"):
        return False
    if _has_immediate(instruction, value):
        return True
    registers = _operand_registers(instruction)
    return any(
        (constant := _constant_register_value(
            function,
            register,
            before=instruction,
            literal_words=literal_words,
        ))
        is not None
        and constant[0] == value
        for register in registers[1:]
    )


def _comparison_uses_constant(
    function: Function,
    instruction: Instruction,
    value: int,
    *,
    literal_words: dict[int, int],
) -> bool:
    if not instruction.mnemonic.startswith("cmp"):
        return False
    if _has_immediate(instruction, value):
        return True
    return any(
        (constant := _constant_register_value(
            function,
            register,
            before=instruction,
            literal_words=literal_words,
        ))
        is not None
        and constant[0] == value
        for register in _operand_registers(instruction)
    )


def _linked_word_load_address(
    function: Function,
    instruction: Instruction,
    *,
    literal_words: dict[int, int],
) -> tuple[int, tuple[Instruction, ...]] | None:
    """Recover a constant address for a reviewed word load."""

    if not instruction.mnemonic.startswith("ldr"):
        return None
    operands = instruction.operands.split(";", 1)[0]
    indexed = INDEXED_MEMORY_OPERAND.search(operands)
    if indexed is not None:
        base_register = _canonical_register(indexed.group(1))
        index_register = _canonical_register(indexed.group(2))
        shift = int(indexed.group(3), 0) if indexed.group(3) else 0
        base = _constant_register_value(
            function,
            base_register,
            before=instruction,
            literal_words=literal_words,
        )
        index = _constant_register_value(
            function,
            index_register,
            before=instruction,
            literal_words=literal_words,
        )
        if base is None or index is None:
            return None
        return (
            (base[0] + (index[0] << shift)) & 0xFFFFFFFF,
            (base[1], index[1]),
        )

    location = _memory_location(instruction)
    if location is None or location[0] == "r15":
        return None
    base = _constant_register_value(
        function,
        location[0],
        before=instruction,
        literal_words=literal_words,
    )
    if base is None:
        return None
    return ((base[0] + location[1]) & 0xFFFFFFFF, (base[1],))


def _compare_then_branch(
    function: Function,
    *,
    minimum_address: int,
    maximum_address: int,
    register: str,
    immediate: int | None = None,
    branch_prefix: str | None = None,
) -> tuple[Instruction, Instruction]:
    comparisons = [
        instruction
        for instruction in function.instructions
        if minimum_address < instruction.address < maximum_address
        and instruction.mnemonic.startswith("cmp")
        and register in _operand_registers(instruction)
        and (immediate is None or _has_immediate(instruction, immediate))
    ]
    for comparison in comparisons:
        following = [
            instruction
            for instruction in function.instructions
            if comparison.address < instruction.address < maximum_address
            and not instruction.mnemonic.startswith("nop")
        ][:3]
        for index, branch in enumerate(following):
            if not _is_conditional_branch(branch):
                continue
            harmless_intermediate = all(
                instruction.mnemonic.startswith(("mov", "uxt", "sxt"))
                and not instruction.mnemonic.endswith("s")
                for instruction in following[:index]
            )
            if (
                harmless_intermediate
                and (
                    branch_prefix is None
                    or branch.mnemonic.startswith(branch_prefix)
                )
            ):
                return comparison, branch
            break
    raise VerificationError(
        f"{function.name} lacks a reviewed compare/branch for {register}"
    )


def _external_control_transfers(
    function: Function,
) -> list[Instruction]:
    """Return calls and direct tail calls that leave ``function``."""

    transfers: list[Instruction] = []
    for instruction in function.instructions:
        if instruction.mnemonic in {"bl", "blx"}:
            transfers.append(instruction)
            continue
        if instruction.mnemonic not in {"b", "b.n", "b.w"}:
            continue
        if instruction.target is None:
            continue
        if instruction.target.startswith(f"{function.name}+"):
            continue
        transfers.append(instruction)
    return transfers


def _require_transfer_targets(
    function: Function,
    allowed: frozenset[str],
) -> list[Instruction]:
    transfers = _external_control_transfers(function)
    unreviewed = [
        instruction
        for instruction in transfers
        if instruction.target not in allowed
    ]
    _require(
        not unreviewed,
        f"{function.name} contains an unreviewed external transfer: "
        + ", ".join(
            instruction.target or "<indirect>"
            for instruction in unreviewed
        ),
    )
    indirect = [
        instruction
        for instruction in function.instructions
        if (
            instruction.mnemonic in {"blx", "bx"}
            and instruction.target is None
            and not _is_return_instruction(instruction)
        )
        or instruction.mnemonic.startswith(("tbb", "tbh"))
    ]
    _require(
        not indirect,
        f"{function.name} contains an indirect or table control transfer",
    )
    return transfers


def _require_bounded_no_backward_branch(function: Function) -> None:
    """Reject linked fast paths with a reachable control-flow cycle.

    A compiler may legitimately emit a backward edge to a shared suffix in an
    otherwise acyclic function.  Treating every backward edge as a loop made
    the proof depend on code layout rather than control flow.  Thumb IT blocks
    are safe to traverse here because this check only asks whether an edge
    cycle exists; the predicated instructions still fall through.
    """

    successors = _control_flow_successors(function, reject_thumb_it=False)
    if not function.instructions:
        return
    entry = min(instruction.address for instruction in function.instructions)
    visiting: set[int] = set()
    visited: set[int] = set()

    def visit(address: int) -> None:
        _require(
            address not in visiting,
            f"{function.name} contains an unbounded control-flow cycle at "
            f"0x{address:x}",
        )
        if address in visited:
            return
        visiting.add(address)
        for target in successors[address]:
            visit(target)
        visiting.remove(address)
        visited.add(address)

    visit(entry)


def _verify_p12_dma_irq_split(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove the linked priority-1/priority-3 DMA interrupt split."""

    fast_vector = _unique_function(
        functions,
        "priority-1 DMA vector",
        lambda name: name == DMA_VECTOR_NAME,
    )
    deferred_vector = _unique_function(
        functions,
        "priority-3 deferred DMA vector",
        lambda name: name == DMA_DEFERRED_VECTOR_NAME,
    )
    fast_terminal = _unique_function(
        functions,
        DMA_FAST_TERMINAL_COUNT_NAME,
        lambda name: name == DMA_FAST_TERMINAL_COUNT_NAME,
    )
    fast_fault = _unique_function(
        functions,
        DMA_FAST_FAULT_NAME,
        lambda name: name == DMA_FAST_FAULT_NAME,
    )
    fast_latch = _unique_function(
        functions,
        "fast DMA fault latch",
        lambda name: name.startswith(DMA_FAST_LATCH_PREFIX),
    )
    deferred_interrupt = _unique_function(
        functions,
        DMA_DEFERRED_INTERRUPT_NAME,
        lambda name: name == DMA_DEFERRED_INTERRUPT_NAME,
    )
    late_init = _unique_function(
        functions,
        LATE_INIT_NAME,
        lambda name: name == LATE_INIT_NAME,
    )

    maximum_sizes = {
        DMA_VECTOR_NAME: 128,
        DMA_DEFERRED_VECTOR_NAME: 64,
        DMA_FAST_TERMINAL_COUNT_NAME: 256,
        DMA_FAST_FAULT_NAME: 16,
        "fast DMA fault latch": 160,
        DMA_DEFERRED_INTERRUPT_NAME: 64,
        LATE_INIT_NAME: 128,
    }
    linked_sizes = {
        DMA_VECTOR_NAME: _unique_symbol_size(
            symbols, DMA_VECTOR_NAME, lambda name: name == DMA_VECTOR_NAME
        ),
        DMA_DEFERRED_VECTOR_NAME: _unique_symbol_size(
            symbols,
            DMA_DEFERRED_VECTOR_NAME,
            lambda name: name == DMA_DEFERRED_VECTOR_NAME,
        ),
        DMA_FAST_TERMINAL_COUNT_NAME: _unique_symbol_size(
            symbols,
            DMA_FAST_TERMINAL_COUNT_NAME,
            lambda name: name == DMA_FAST_TERMINAL_COUNT_NAME,
        ),
        DMA_FAST_FAULT_NAME: _unique_symbol_size(
            symbols,
            DMA_FAST_FAULT_NAME,
            lambda name: name == DMA_FAST_FAULT_NAME,
        ),
        "fast DMA fault latch": _unique_symbol_size(
            symbols,
            "fast DMA fault latch",
            lambda name: name.startswith(DMA_FAST_LATCH_PREFIX),
        ),
        DMA_DEFERRED_INTERRUPT_NAME: _unique_symbol_size(
            symbols,
            DMA_DEFERRED_INTERRUPT_NAME,
            lambda name: name == DMA_DEFERRED_INTERRUPT_NAME,
        ),
        LATE_INIT_NAME: _unique_symbol_size(
            symbols, LATE_INIT_NAME, lambda name: name == LATE_INIT_NAME
        ),
    }
    for name, size in linked_sizes.items():
        _require(
            size <= maximum_sizes[name],
            f"{name} grew to {size} bytes; maximum is "
            f"{maximum_sizes[name]}",
        )

    init_vector_transfers = [
        instruction
        for instruction in _external_control_transfers(late_init)
        if instruction.target == "nvicEnableVector"
    ]
    _require(
        len(init_vector_transfers) == 2,
        "__late_init must enable exactly the DMA and deferred SGPIO vectors",
    )
    enabled_vectors = {
        (
            _immediate_argument_before_call(late_init, call, "r0"),
            _immediate_argument_before_call(late_init, call, "r1"),
        )
        for call in init_vector_transfers
    }
    _require(
        enabled_vectors == {(31, 96), (2, 32)},
        "linked NVIC initialization must enable SGPIO IRQ31 at priority 3 "
        "and DMA IRQ2 at priority 1",
    )
    sgpio_clear_offsets = {
        _memory_location(instruction)[1]
        for instruction in late_init.instructions
        if instruction.address < init_vector_transfers[0].address
        and instruction.mnemonic.startswith("str")
        and _memory_location(instruction) is not None
        and _memory_location(instruction)[1]
        in {0xF00, 0xF10, 0xF20, 0xF30, 0xF40, 0xF50, 0xF60, 0xF70}
    }
    _require(
        sgpio_clear_offsets
        == {0xF00, 0xF10, 0xF20, 0xF30, 0xF40, 0xF50, 0xF60, 0xF70}
        and any(
            instruction.address < init_vector_transfers[0].address
            and _dmb(instruction)
            for instruction in late_init.instructions
        ),
        "linked init must disable and clear every SGPIO hardware interrupt "
        "source before enabling its software-deferred vector",
    )

    fast_vector_transfers = _require_transfer_targets(
        fast_vector,
        frozenset({DMA_FAST_FAULT_NAME, DMA_FAST_TERMINAL_COUNT_NAME}),
    )
    _require_transfer_targets(
        fast_fault,
        frozenset({fast_latch.name}),
    )
    _require_transfer_targets(
        fast_terminal,
        frozenset({fast_latch.name}),
    )
    _require_transfer_targets(fast_latch, frozenset())
    _require_bounded_no_backward_branch(fast_latch)
    _require_bounded_no_backward_branch(fast_terminal)

    tc_status_loads = [
        instruction
        for instruction in fast_vector.instructions
        if instruction.mnemonic.startswith("ldr")
        and _memory_offset(instruction, 4)
    ]
    err_status_loads = [
        instruction
        for instruction in fast_vector.instructions
        if instruction.mnemonic.startswith("ldr")
        and _memory_offset(instruction, 12)
    ]
    enabled_channel_loads = [
        instruction
        for instruction in fast_vector.instructions
        if instruction.mnemonic.startswith("ldr")
        and _memory_offset(instruction, 28)
    ]
    tc_clears = [
        instruction
        for instruction in fast_vector.instructions
        if instruction.mnemonic.startswith("str")
        and _memory_offset(instruction, 8)
    ]
    err_clears = [
        instruction
        for instruction in fast_vector.instructions
        if instruction.mnemonic.startswith("str")
        and _memory_offset(instruction, 16)
    ]
    terminal_calls = [
        instruction
        for instruction in fast_vector_transfers
        if instruction.target == DMA_FAST_TERMINAL_COUNT_NAME
    ]
    fault_calls = [
        instruction
        for instruction in fast_vector_transfers
        if instruction.target == DMA_FAST_FAULT_NAME
    ]
    _require(
        len(tc_status_loads) == 1
        and len(err_status_loads) == 1
        and len(enabled_channel_loads) == 1
        and len(tc_clears) == 1
        and len(err_clears) == 1,
        "priority-1 vector must sample TC/ERR/enabled channels and clear "
        "TC/ERR exactly once",
    )
    _require(
        len(terminal_calls) == 1
        and len(fault_calls) == 2
        and tc_clears[0].address < terminal_calls[0].address
        and all(call.address < err_clears[0].address for call in fault_calls),
        "priority-1 vector must W1C TC before normal bookkeeping and invoke "
        "the fast fail-close before ERR W1C",
    )

    gate_stores = [
        instruction
        for instruction in fast_latch.instructions
        if instruction.mnemonic.startswith("str")
        and _memory_offset(instruction, 532)
    ]
    channel_config_stores = [
        instruction
        for instruction in fast_latch.instructions
        if instruction.mnemonic.startswith("str")
        and _memory_offset(instruction, 272)
    ]
    _require(
        len(gate_stores) == 1
        and len(channel_config_stores) == 1
        and gate_stores[0].address < channel_config_stores[0].address,
        "fast fault latch must close the SGPIO request gate before disabling "
        "DMA channel 0",
    )
    fault_state_values = [
        instruction
        for instruction in fast_latch.instructions
        if instruction.mnemonic.startswith("mov")
        and _has_immediate(instruction, 5)
    ]
    fatal_stores = [
        instruction
        for instruction in fast_latch.instructions
        if instruction.mnemonic.startswith("str")
        and instruction.address > channel_config_stores[0].address
    ]
    _require(
        len(fault_state_values) == 1
        and bool(fatal_stores)
        and any(
            instruction.address > fatal_stores[-1].address
            and _dmb(instruction)
            for instruction in fast_latch.instructions
        ),
        "fast fault latch must publish FAULT/fatal state before its final DMB",
    )

    pend_stores = [
        instruction
        for instruction in fast_vector.instructions
        if instruction.mnemonic.startswith("str")
        and _memory_offset(instruction, 256)
    ]
    _require(
        len(pend_stores) == 1
        and any(
            instruction.address < pend_stores[0].address
            and _dmb(instruction)
            for instruction in fast_vector.instructions
        ),
        "priority-1 vector must DMB before software-pending IRQ31",
    )

    deferred_transfers = _external_control_transfers(deferred_vector)
    deferred_hook_calls = [
        instruction
        for instruction in deferred_transfers
        if instruction.target == DMA_DEFERRED_INTERRUPT_NAME
    ]
    lock_calls = [
        instruction
        for instruction in deferred_transfers
        if instruction.target == "dbg_check_lock_from_isr"
    ]
    unlock_calls = [
        instruction
        for instruction in deferred_transfers
        if instruction.target == "dbg_check_unlock_from_isr"
    ]
    _require(
        len(deferred_hook_calls) == 1
        and len(lock_calls) == 1
        and len(unlock_calls) == 1
        and lock_calls[0].address < deferred_hook_calls[0].address
        < unlock_calls[0].address,
        "VectorBC must be the sole kernel-safe deferred bridge under the "
        "reviewed ISR lock",
    )
    deferred_targets = {
        instruction.target
        for instruction in _external_control_transfers(deferred_interrupt)
    }
    _require(
        DMA_COMPLETE_FAULT_NAME in deferred_targets
        and any(
            target is not None
            and target.startswith("ThreadWait::wake_from_interrupt(")
            for target in deferred_targets
        )
        and DMA_FAST_FAULT_NAME not in deferred_targets
        and DMA_FAST_TERMINAL_COUNT_NAME not in deferred_targets,
        "deferred DMA hook must own accounting/wake and must not re-enter "
        "the fast producer",
    )

    return {
        "dma_irq": 2,
        "dma_vector": DMA_VECTOR_NAME,
        "dma_priority": 1,
        "deferred_irq": 31,
        "deferred_vector": DMA_DEFERRED_VECTOR_NAME,
        "deferred_priority": 3,
        "sgpio_hardware_sources_disabled": True,
        "software_pended_continuation_only": True,
        "tc_w1c_precedes_normal_bookkeeping": True,
        "error_gate_precedes_err_w1c": True,
        "enabled_channel_invariant_sampled": True,
        "fast_transitive_call_allowlist_linked": True,
        "fast_path_call_free_latch": True,
        "fast_path_bounded": True,
        "dmb_precedes_deferred_pend": True,
        "deferred_only_kernel_wake": True,
        "linked_code_bytes": linked_sizes,
    }


def _verify_p12_completion_claim(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
    claim: Function,
    wait: Function,
) -> dict[str, object]:
    """Prove the IRQ-excluded SPSC dequeue used by the worker."""

    claim_size = _unique_symbol_size(
        symbols,
        DMA_CLAIM_COMPLETION_NAME,
        lambda name: name == DMA_CLAIM_COMPLETION_NAME,
    )
    _require(
        claim_size <= 256,
        f"{DMA_CLAIM_COMPLETION_NAME} grew to {claim_size} bytes; maximum is 256",
    )
    fast_latch = _unique_function(
        functions,
        "fast DMA fault latch",
        lambda name: name.startswith(DMA_FAST_LATCH_PREFIX),
    )
    claim_transfers = _require_transfer_targets(
        claim,
        frozenset({fast_latch.name}),
    )
    latch_calls = [
        instruction
        for instruction in claim_transfers
        if instruction.target == fast_latch.name
    ]
    _require(
        len(latch_calls) == 2,
        "completion claim must have exactly the queue/reuse and exceptional "
        "DMA-status fail-close calls",
    )
    _require_bounded_no_backward_branch(claim)
    _require(
        not any(_store_at_offset(instruction, 384) for instruction in claim.instructions),
        "completion claim must preserve the DMA NVIC pending indication for "
        "the normal fast ISR",
    )

    claim_order = _require_ordered_instructions(
        claim,
        (
            (
                "exclude the priority-1 DMA vector before claiming",
                lambda ins: _store_at_offset(ins, 128),
            ),
            ("publish claim IRQ exclusion", _dmb),
            (
                "read the completion consumer index",
                lambda ins: _load_at_offset(ins, 28),
            ),
            (
                "read the completion producer index",
                lambda ins: _load_at_offset(ins, 24),
            ),
            ("test completion queue emptiness", lambda ins: ins.mnemonic.startswith("cmp")),
            ("acquire the queued completion", _dmb),
            (
                "copy the queued completion",
                lambda ins: ins.mnemonic.startswith("ldm"),
            ),
            (
                "publish the copied completion",
                lambda ins: ins.mnemonic.startswith("stm"),
            ),
            ("complete the queue-entry acquire", _dmb),
            (
                "advance the completion consumer index",
                lambda ins: _store_at_offset(ins, 28),
            ),
            (
                "load the claimed descriptor index",
                lambda ins: _load_at_offset(ins, 0),
            ),
            (
                "bound the claimed descriptor index",
                lambda ins: ins.mnemonic.startswith("cmp")
                and _has_immediate(ins, 3),
            ),
            (
                "load the claimed completion sequence",
                lambda ins: _load_at_offset(ins, 4),
            ),
            (
                "derive completion age",
                lambda ins: ins.mnemonic.startswith("sub"),
            ),
            (
                "enforce the two-completion claim guard",
                lambda ins: _comparison_uses_constant(
                    claim,
                    ins,
                    1,
                    literal_words=literal_words,
                ),
            ),
            (
                "sample terminal-count status without retiring it",
                lambda ins: _load_at_offset(ins, 4),
            ),
            (
                "sample DMA error status",
                lambda ins: _load_at_offset(ins, 12),
            ),
            (
                "sample enabled DMA channels",
                lambda ins: _load_at_offset(ins, 28),
            ),
            (
                "fail-close an exceptional DMA invariant violation",
                lambda ins: ins.address == latch_calls[-1].address,
            ),
            (
                "clear exceptional terminal-count status after latching",
                lambda ins: _store_at_offset(ins, 8),
            ),
            (
                "clear exceptional DMA error status after latching",
                lambda ins: _store_at_offset(ins, 16),
            ),
            (
                "software-pend deferred fault completion",
                lambda ins: _store_at_offset(ins, 256),
            ),
            ("publish before DMA vector re-enable", _dmb),
            (
                "re-enable the priority-1 DMA vector",
                lambda ins: _store_at_offset(ins, 0),
            ),
        ),
    )
    status_start = claim_order[-7]
    status_latch = latch_calls[-1]
    status_predicate = [
        instruction
        for instruction in claim.instructions
        if status_start.address < instruction.address < status_latch.address
    ]
    _require(
        any(
            instruction.mnemonic.startswith("bic")
            and _has_immediate(instruction, 1)
            for instruction in status_predicate
        ),
        "completion claim must exclude the expected channel from the "
        "exceptional-status test",
    )
    _require(
        len(
            [
                instruction
                for instruction in status_predicate
                if instruction.mnemonic.startswith(("and", "tst"))
                and _has_immediate(instruction, 1)
            ]
        )
        >= 2,
        "completion claim must isolate own-channel ERR and gate own-channel "
        "TC behind the failed-claim state",
    )
    _require(
        any(
            _comparison_uses_constant(
                claim,
                instruction,
                2,
                literal_words=literal_words,
            )
            for instruction in status_predicate
        ),
        "completion claim must test whether an earlier queue/reuse check "
        "already failed before own-channel TC can join the fault predicate",
    )
    _require(
        len(
            [
                instruction
                for instruction in status_predicate
                if _is_conditional_branch(instruction)
            ]
        )
        >= 2,
        "completion claim must keep the exceptional-status and failed-claim "
        "TC predicates conditional",
    )

    wait_claims = _calls_matching(
        wait,
        lambda name: name == DMA_CLAIM_COMPLETION_NAME,
    )
    wait_sleeps = _calls_matching(
        wait,
        lambda name: name.startswith("ThreadWait::sleep_locked("),
    )
    _require(
        len(wait_claims) == 2
        and len(wait_sleeps) == 1
        and wait_claims[0].address < wait_sleeps[0].address
        < wait_claims[1].address,
        "wait_for_buffer must claim once before sleeping and once after its "
        "locked wakeup",
    )
    claim_callers = {
        function.name
        for function in functions
        if _calls_matching(
            function,
            lambda name: name == DMA_CLAIM_COMPLETION_NAME,
        )
    }
    _require(
        claim_callers == {wait.name},
        "completion claim helper has callers outside wait_for_buffer",
    )

    return {
        "function": claim.name,
        "linked_code_bytes": claim_size,
        "priority1_irq_excluded": True,
        "nvic_pending_preserved": True,
        "queue_entry_acquire_published": True,
        "claim_guard_age": 2,
        "sole_own_channel_tc_preserved": True,
        "exceptional_status_fail_closed": True,
        "worker_claims_before_and_after_locked_sleep": True,
        "proof_instruction_count": len(claim_order),
    }


def _verify_p12_rate_wait_helper(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
) -> Function:
    """Prove the bounded helper that waits for M4 to leave RESUMING."""

    wait_helper = _unique_function(
        functions,
        "bounded rate-state wait helper",
        lambda name: name.startswith(PROCESSOR_WAIT_RATE_STATE_PREFIX),
    )
    rate_state = _unique_function(
        functions,
        "rate-state accessor",
        lambda name: name.startswith(PROCESSOR_RATE_STATE_PREFIX),
    )
    helper_size = _unique_symbol_size(
        symbols,
        "bounded rate-state wait helper",
        lambda name: name.startswith(PROCESSOR_WAIT_RATE_STATE_PREFIX),
    )
    _require(
        helper_size <= 80,
        "bounded rate-state wait helper grew to "
        f"{helper_size} bytes; maximum is 80",
    )
    transfers = _require_transfer_targets(
        wait_helper,
        frozenset({rate_state.name, "chThdSleep"}),
    )
    rate_calls = [
        instruction
        for instruction in transfers
        if instruction.target == rate_state.name
    ]
    sleep_calls = [
        instruction
        for instruction in transfers
        if instruction.target == "chThdSleep"
    ]
    _require(
        len(rate_calls) == 1 and len(sleep_calls) == 1,
        "rate-state wait helper must have one state sample and one bounded "
        "thread-sleep site",
    )
    expected_copies = [
        instruction
        for instruction in wait_helper.instructions
        if instruction.address < rate_calls[0].address
        and instruction.mnemonic.startswith("mov")
        and len(_operand_registers(instruction)) >= 2
        and _operand_registers(instruction)[1] == "r1"
        and _operand_registers(instruction)[0]
        in {"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"}
    ]
    _require(
        len(expected_copies) == 1,
        "rate-state wait helper must preserve its expected-state argument",
    )
    expected_register = _operand_registers(expected_copies[0])[0]
    wait_order = _require_ordered_instructions(
        wait_helper,
        (
            (
                "sample the wait deadline baseline",
                lambda ins: _load_at_offset(ins, 12),
            ),
            (
                "sample the current rate state",
                lambda ins: ins.address == rate_calls[0].address,
            ),
            (
                "compare the current state with the expected state",
                lambda ins: ins.mnemonic.startswith("cmp")
                and {"r0", expected_register}.issubset(
                    set(_operand_registers(ins))
                ),
            ),
            (
                "exit when the state changes",
                lambda ins: ins.mnemonic.startswith("bne"),
            ),
            (
                "sample the current wait tick",
                lambda ins: _load_at_offset(ins, 12),
            ),
            (
                "derive elapsed wait ticks",
                lambda ins: ins.mnemonic.startswith("sub"),
            ),
            (
                "bound the wait to 100 ticks",
                lambda ins: ins.mnemonic.startswith("cmp")
                and _has_immediate(ins, 99),
            ),
            (
                "reject the expired wait",
                lambda ins: ins.mnemonic.startswith("bhi"),
            ),
            (
                "sleep for one tick",
                lambda ins: ins.address == sleep_calls[0].address,
            ),
            (
                "repeat the bounded state sample",
                lambda ins: ins.mnemonic in {"b", "b.n", "b.w"},
            ),
        ),
    )
    loop_target = _branch_target_address(wait_order[-1])
    _require(
        loop_target is not None
        and wait_order[0].address < loop_target <= rate_calls[0].address,
        "rate-state wait loop must return to its state sample",
    )
    success_values = [
        instruction
        for instruction in wait_helper.instructions
        if instruction.mnemonic.startswith("mov")
        and _first_operand_register(instruction) == "r0"
        and _has_immediate(instruction, 1)
    ]
    timeout_values = [
        instruction
        for instruction in wait_helper.instructions
        if instruction.mnemonic.startswith("mov")
        and _first_operand_register(instruction) == "r0"
        and _has_immediate(instruction, 0)
    ]
    _require(
        success_values
        and timeout_values
        and any(
            success_values[-1].address < instruction.address
            and _dmb(instruction)
            for instruction in wait_helper.instructions
        ),
        "rate-state wait helper must acquire-publish success and return zero "
        "on timeout",
    )
    return wait_helper


def _verify_p12_rate_state_irq_exclusion(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove the priority-1 DMA exclusion shared by rate publication/gate RMW."""

    begin = _unique_function(
        functions,
        DMA_RATE_STATE_BEGIN_NAME,
        lambda name: name == DMA_RATE_STATE_BEGIN_NAME,
    )
    end = _unique_function(
        functions,
        DMA_RATE_STATE_END_NAME,
        lambda name: name == DMA_RATE_STATE_END_NAME,
    )
    transition = _unique_function(
        functions,
        "rate-state transition reducer",
        lambda name: name.startswith(PROCESSOR_TRANSITION_RATE_STATE_PREFIX),
    )
    gate = _unique_function(
        functions,
        DMA_GATE_OPEN_NAME,
        lambda name: name == DMA_GATE_OPEN_NAME,
    )
    fast_latch = _unique_function(
        functions,
        "fast DMA fault latch",
        lambda name: name.startswith(DMA_FAST_LATCH_PREFIX),
    )
    begin_size = _unique_symbol_size(
        symbols,
        DMA_RATE_STATE_BEGIN_NAME,
        lambda name: name == DMA_RATE_STATE_BEGIN_NAME,
    )
    end_size = _unique_symbol_size(
        symbols,
        DMA_RATE_STATE_END_NAME,
        lambda name: name == DMA_RATE_STATE_END_NAME,
    )
    _require(
        begin_size <= 128 and end_size <= 32,
        "rate-state DMA exclusion helpers exceed their reviewed code bounds",
    )
    begin_transfers = _require_transfer_targets(
        begin,
        frozenset({fast_latch.name}),
    )
    _require_transfer_targets(end, frozenset())
    _require(
        len(begin_transfers) == 1
        and begin_transfers[0].target == fast_latch.name,
        "rate-state exclusion begin must have exactly one fail-close call",
    )
    _require_bounded_no_backward_branch(begin)
    _require_bounded_no_backward_branch(end)
    _require(
        not any(_store_at_offset(instruction, 384) for instruction in begin.instructions),
        "rate-state exclusion must preserve the DMA NVIC pending indication "
        "for the normal fast ISR",
    )

    begin_callers = {
        function.name
        for function in functions
        if _calls_matching(
            function,
            lambda name: name == DMA_RATE_STATE_BEGIN_NAME,
        )
    }
    end_callers = {
        function.name
        for function in functions
        if _calls_matching(
            function,
            lambda name: name == DMA_RATE_STATE_END_NAME,
        )
    }
    _require(
        begin_callers == {transition.name, gate.name}
        and end_callers == {transition.name, gate.name},
        "rate-state DMA exclusion helpers have callers outside the transition "
        "reducer and SGPIO gate-open helper",
    )

    begin_order = _require_ordered_instructions(
        begin,
        (
            (
                "mask the priority-1 DMA vector",
                lambda instruction: _store_at_offset(instruction, 128),
            ),
            ("publish DMA vector exclusion", _dmb),
            (
                "sample terminal-count status without retiring it",
                lambda instruction: _load_at_offset(instruction, 4),
            ),
            (
                "sample DMA error status",
                lambda instruction: _load_at_offset(instruction, 12),
            ),
            (
                "sample enabled DMA channels",
                lambda instruction: _load_at_offset(instruction, 28),
            ),
            (
                "branch to the healthy return when exceptional samples are clean",
                lambda instruction: instruction.mnemonic.startswith("beq"),
            ),
            (
                "latch an unhealthy exclusion sample",
                lambda instruction: instruction.address
                == begin_transfers[0].address,
            ),
            (
                "clear terminal-count status after latching",
                lambda instruction: _store_at_offset(instruction, 8),
            ),
            (
                "clear DMA error status after latching",
                lambda instruction: _store_at_offset(instruction, 16),
            ),
            (
                "software-pend deferred fault completion",
                lambda instruction: _store_at_offset(instruction, 256),
            ),
            ("publish the deferred fault before re-enable", _dmb),
            (
                "re-enable the priority-1 DMA vector on failure",
                lambda instruction: _store_at_offset(instruction, 0),
            ),
        ),
    )
    health_predicate = [
        instruction
        for instruction in begin.instructions
        if begin_order[4].address < instruction.address < begin_order[5].address
    ]
    _require(
        any(
            instruction.mnemonic.startswith("bic")
            and _has_immediate(instruction, 1)
            for instruction in health_predicate
        )
        and any(
            instruction.mnemonic.startswith(("and", "tst"))
            and _has_immediate(instruction, 1)
            for instruction in health_predicate
        ),
        "rate-state exclusion must remove sole own-channel TC from the "
        "unexpected-status term and add own-channel ERR separately",
    )
    fatal_symbols = [
        symbol for symbol in symbols if symbol.name == DMA_FATAL_LATCH_NAME
    ]
    _require(
        len(fatal_symbols) == 1
        and fatal_symbols[0].kind.lower() == "b"
        and fatal_symbols[0].size in {1, 4},
        "rate-state exclusion requires one linked durable DMA fatal latch",
    )
    fatal_base_loads = _literal_loads(
        begin,
        literal_words,
        fatal_symbols[0].address,
    )
    _require(
        len(fatal_base_loads) == 1,
        "rate-state exclusion health test is not linked to dma_fatal_latched",
    )
    fatal_base_register = _first_operand_register(fatal_base_loads[0])
    fatal_value_loads = [
        instruction
        for instruction in begin.instructions
        if fatal_base_register is not None
        and instruction.address > fatal_base_loads[0].address
        and instruction.address < begin_order[5].address
        and instruction.mnemonic.startswith("ldr")
        and _memory_location(instruction) == (fatal_base_register, 0)
    ]
    _require(
        len(fatal_value_loads) == 1,
        "rate-state exclusion must include the durable fatal latch in its "
        "final health decision",
    )
    irq_mask_values = [
        instruction
        for instruction in begin.instructions
        if instruction.mnemonic.startswith("mov")
        and _has_immediate(instruction, 4)
    ]
    _require(
        len(irq_mask_values) >= 2,
        "rate-state exclusion must use DMA IRQ mask bit 2 for mask/re-enable",
    )

    begin_successors = _control_flow_successors(begin)

    def begin_reachable(start: int | None) -> frozenset[int]:
        reached: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reached or address not in begin_successors:
                continue
            reached.add(address)
            pending.extend(begin_successors[address] - reached)
        return frozenset(reached)

    health_branch = begin_order[5]
    healthy_entry = _branch_target_address(health_branch)
    unhealthy_entry_instruction = _next_non_nop(begin, health_branch.address)
    _require(
        healthy_entry is not None and unhealthy_entry_instruction is not None,
        "rate-state exclusion health branch has an unresolved path",
    )
    healthy_reachable = begin_reachable(healthy_entry)
    unhealthy_reachable = begin_reachable(unhealthy_entry_instruction.address)
    failure_reenable = begin_order[-1]
    exceptional_only = (
        begin_transfers[0],
        begin_order[7],
        begin_order[8],
        begin_order[9],
        failure_reenable,
    )
    _require(
        all(instruction.address in unhealthy_reachable for instruction in exceptional_only)
        and all(
            instruction.address not in healthy_reachable
            for instruction in exceptional_only
        ),
        "healthy rate-state exclusion must retain IRQ exclusion; unhealthy "
        "status alone may latch, W1C, pend deferred work, and re-enable",
    )
    success_values = [
        instruction
        for instruction in begin.instructions
        if instruction.address in healthy_reachable
        and instruction.mnemonic.startswith("mov")
        and _first_operand_register(instruction) == "r0"
        and _has_immediate(instruction, 1)
    ]
    failure_values = [
        instruction
        for instruction in begin.instructions
        if instruction.address in unhealthy_reachable
        and instruction.mnemonic.startswith("mov")
        and _first_operand_register(instruction) == "r0"
        and _has_immediate(instruction, 0)
    ]
    _require(
        len(success_values) == 1 and len(failure_values) == 1,
        "rate-state exclusion must return true only for the clean sampled path",
    )

    end_order = _require_ordered_instructions(
        end,
        (
            ("publish protected writes before re-enable", _dmb),
            (
                "re-enable the priority-1 DMA vector",
                lambda instruction: _store_at_offset(instruction, 0),
            ),
        ),
    )
    _require(
        len(
            [
                instruction
                for instruction in end.instructions
                if _store_at_offset(instruction, 0)
            ]
        )
        == 1
        and any(
            instruction.mnemonic.startswith("mov")
            and _has_immediate(instruction, 4)
            for instruction in end.instructions
        )
        and end_order[0].address < end_order[1].address,
        "rate-state exclusion end must DMB then re-enable DMA IRQ2 exactly once",
    )

    return {
        "begin_function": begin.name,
        "end_function": end.name,
        "begin_code_bytes": begin_size,
        "end_code_bytes": end_size,
        "exclusive_callers": sorted(begin_callers),
        "priority1_mask_preserves_nvic_pending": True,
        "final_tc_err_enabled_fatal_sample": True,
        "sole_own_channel_tc_preserved": True,
        "unhealthy_sample_fails_closed_before_w1c": True,
        "unhealthy_sample_pends_deferred_before_reenable": True,
        "healthy_sample_retains_exclusion": True,
        "end_dmb_precedes_reenable": True,
    }


def _verify_p12_gate_open_helper(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
) -> dict[str, object]:
    """Prove that SGPIO can open only after DMA exclusion and E-bit validation."""

    gate = _unique_function(
        functions,
        DMA_GATE_OPEN_NAME,
        lambda name: name == DMA_GATE_OPEN_NAME,
    )
    begin = _unique_function(
        functions,
        DMA_RATE_STATE_BEGIN_NAME,
        lambda name: name == DMA_RATE_STATE_BEGIN_NAME,
    )
    end = _unique_function(
        functions,
        DMA_RATE_STATE_END_NAME,
        lambda name: name == DMA_RATE_STATE_END_NAME,
    )
    fast_latch = _unique_function(
        functions,
        "fast DMA fault latch",
        lambda name: name.startswith(DMA_FAST_LATCH_PREFIX),
    )
    gate_size = _unique_symbol_size(
        symbols,
        DMA_GATE_OPEN_NAME,
        lambda name: name == DMA_GATE_OPEN_NAME,
    )
    _require(
        gate_size <= 96,
        f"{DMA_GATE_OPEN_NAME} grew to {gate_size} bytes; maximum is 96",
    )
    transfers = _require_transfer_targets(
        gate,
        frozenset({begin.name, end.name, fast_latch.name}),
    )
    transfer_counts = {
        target: sum(transfer.target == target for transfer in transfers)
        for target in {begin.name, end.name, fast_latch.name}
    }
    _require(
        transfer_counts
        == {
            begin.name: 1,
            end.name: 1,
            fast_latch.name: 1,
        },
        "SGPIO gate-open helper must retain one DMA exclusion begin/end and "
        "one fail-close call",
    )
    _require_bounded_no_backward_branch(gate)
    begin_call = next(
        transfer for transfer in transfers if transfer.target == begin.name
    )
    end_call = next(
        transfer for transfer in transfers if transfer.target == end.name
    )
    latch_call = next(
        transfer for transfer in transfers if transfer.target == fast_latch.name
    )
    begin_branch = _next_non_nop(gate, begin_call.address)
    _require(
        begin_branch is not None
        and begin_branch.mnemonic == "cbz"
        and _branch_condition_register(begin_branch) == "r0",
        "SGPIO gate-open helper must immediately reject a failed DMA "
        "exclusion begin",
    )

    channel_loads = [
        instruction
        for instruction in gate.instructions
        if begin_branch.address < instruction.address < latch_call.address
        and _load_at_offset(instruction, 272)
    ]
    _require(
        len(channel_loads) == 1,
        "SGPIO gate-open helper must sample DMA channel CONFIG exactly once",
    )
    channel_register = _first_operand_register(channel_loads[0])
    channel_masks = [
        instruction
        for instruction in gate.instructions
        if channel_loads[0].address < instruction.address < latch_call.address
        and instruction.mnemonic.startswith("and")
        and _first_operand_register(instruction) == channel_register
        and _has_immediate(instruction, 1)
    ]
    _require(
        len(channel_masks) == 1,
        "SGPIO gate-open helper must isolate the DMA channel enable bit",
    )
    enabled_branch = _next_non_nop(gate, channel_masks[0].address)
    _require(
        enabled_branch is not None
        and enabled_branch.mnemonic.startswith("bne"),
        "SGPIO gate-open helper must enter its open path only when CONFIG.E "
        "is set",
    )

    gate_loads = [
        instruction
        for instruction in gate.instructions
        if _load_at_offset(instruction, 532)
    ]
    gate_stores = [
        instruction
        for instruction in gate.instructions
        if instruction.mnemonic.startswith("str")
        and _store_at_offset(instruction, 532)
    ]
    gate_clears = [
        instruction
        for instruction in gate.instructions
        if instruction.mnemonic.startswith("bic")
        and _has_immediate(instruction, 1 << 10)
    ]
    pend_stores = [
        instruction
        for instruction in gate.instructions
        if instruction.mnemonic.startswith("str")
        and _store_at_offset(instruction, 256)
    ]
    _require(
        len(gate_loads) == 1
        and len(gate_clears) == 1
        and len(gate_stores) == 1
        and gate_loads[0].address < gate_clears[0].address
        < gate_stores[0].address
        and _first_operand_register(gate_loads[0])
        == _first_operand_register(gate_clears[0])
        == _first_operand_register(gate_stores[0]),
        "SGPIO gate-open helper must perform exactly one reviewed bit-10 "
        "read/clear/write",
    )
    _require(
        len(pend_stores) == 1
        and latch_call.address < pend_stores[0].address < end_call.address,
        "disabled DMA channel must fail-close and pend deferred completion "
        "before ending IRQ exclusion",
    )

    successors = _control_flow_successors(gate)

    def reachable(start: int | None) -> frozenset[int]:
        reached: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reached or address not in successors:
                continue
            reached.add(address)
            pending.extend(successors[address] - reached)
        return frozenset(reached)

    begin_failure_entry = _branch_target_address(begin_branch)
    begin_success_instruction = _next_non_nop(gate, begin_branch.address)
    disabled_instruction = _next_non_nop(gate, enabled_branch.address)
    healthy_entry = _branch_target_address(enabled_branch)
    _require(
        begin_failure_entry is not None
        and begin_success_instruction is not None
        and disabled_instruction is not None
        and healthy_entry is not None,
        "SGPIO gate-open helper has an unresolved reviewed branch",
    )
    begin_failure_reachable = reachable(begin_failure_entry)
    begin_success_reachable = reachable(begin_success_instruction.address)
    disabled_reachable = reachable(disabled_instruction.address)
    healthy_reachable = reachable(healthy_entry)
    _require(
        channel_loads[0].address in begin_success_reachable
        and channel_loads[0].address not in begin_failure_reachable
        and end_call.address not in begin_failure_reachable
        and gate_stores[0].address not in begin_failure_reachable
        and latch_call.address not in begin_failure_reachable,
        "failed DMA exclusion begin must return without sampling/opening SGPIO "
        "or ending an exclusion it does not own",
    )
    _require(
        latch_call.address in disabled_reachable
        and pend_stores[0].address in disabled_reachable
        and end_call.address in disabled_reachable
        and gate_stores[0].address not in disabled_reachable,
        "CONFIG.E-clear path must latch, pend, and end without opening SGPIO",
    )
    _require(
        gate_stores[0].address in healthy_reachable
        and end_call.address in healthy_reachable
        and latch_call.address not in healthy_reachable
        and pend_stores[0].address not in healthy_reachable,
        "CONFIG.E-set path must open SGPIO then end without taking the fault "
        "path",
    )

    returns = [
        instruction
        for instruction in gate.instructions
        if _is_return_instruction(instruction)
    ]
    sinks = {address for address, outgoing in successors.items() if not outgoing}
    _require(
        len(returns) == 1 and sinks == {returns[0].address},
        "every SGPIO gate-open helper path must reach one reviewed return",
    )
    saved_results = [
        instruction
        for instruction in gate.instructions
        if instruction.mnemonic.startswith("str")
        and _memory_location(instruction) == ("r13", 4)
        and _first_operand_register(instruction) == "r0"
    ]
    restored_results = [
        instruction
        for instruction in gate.instructions
        if instruction.mnemonic.startswith("ldr")
        and _memory_location(instruction) == ("r13", 4)
        and _first_operand_register(instruction) == "r0"
    ]
    _require(
        len(saved_results) == 2
        and len(restored_results) == 1
        and end_call.address < restored_results[0].address
        and any(
            instruction.address in disabled_reachable
            for instruction in saved_results
        )
        and any(
            instruction.address in healthy_reachable
            for instruction in saved_results
        ),
        "SGPIO gate-open helper must preserve the false/true CONFIG.E result "
        "across the common exclusion end",
    )

    return {
        "function": gate.name,
        "linked_code_bytes": gate_size,
        "begin_failure_returns_closed": True,
        "channel_config_e_sampled_once": True,
        "disabled_channel_latches_and_pends": True,
        "disabled_channel_cannot_open_gate": True,
        "enabled_channel_opens_gate_under_exclusion": True,
        "all_success_paths_end_exclusion": True,
        "result_preserved_across_exclusion_end": True,
    }


def _verify_p12_shutdown_quiesce(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove bounded ACTIVE drain and fail-stop worker teardown."""

    quiesce = _unique_function(
        functions,
        DMA_QUIESCE_SHUTDOWN_NAME,
        lambda name: name == DMA_QUIESCE_SHUTDOWN_NAME,
    )
    baseband_run = _unique_function(
        functions,
        BASEBAND_RUN_NAME,
        lambda name: name == BASEBAND_RUN_NAME,
    )
    streaming_disable = _unique_function(
        functions,
        "SGPIO streaming-disable helper",
        lambda name: name.startswith(SGPIO_STREAMING_DISABLE_PREFIX),
    )
    quiesce_size = _unique_symbol_size(
        symbols,
        DMA_QUIESCE_SHUTDOWN_NAME,
        lambda name: name == DMA_QUIESCE_SHUTDOWN_NAME,
    )
    _require(
        quiesce_size <= 96,
        f"{DMA_QUIESCE_SHUTDOWN_NAME} grew to {quiesce_size} bytes; maximum is 96",
    )
    _require_transfer_targets(quiesce, frozenset())
    _require(
        not _calls(quiesce),
        "shutdown quiesce helper must remain call-free",
    )
    quiesce_callers = {
        function.name
        for function in functions
        if _calls_matching(
            function,
            lambda name: name == DMA_QUIESCE_SHUTDOWN_NAME,
        )
    }
    _require(
        quiesce_callers == {baseband_run.name},
        "shutdown quiesce helper must be owned only by BasebandThread::run",
    )

    nvic_base_loads = _literal_loads(
        quiesce,
        literal_words,
        0xE000E100,
    )
    shutdown_mask_loads = _literal_loads(
        quiesce,
        literal_words,
        0x80000004,
    )
    channel_base_loads = _literal_loads(
        quiesce,
        literal_words,
        0x40002110,
    )
    _require(
        len(nvic_base_loads) == 2
        and len(shutdown_mask_loads) == 2
        and len(channel_base_loads) == 1,
        "shutdown quiesce must link exact NVIC, DMA+deferred IRQ mask, and "
        "PL080 channel-CONFIG addresses",
    )

    irq_disable_stores = [
        instruction
        for instruction in quiesce.instructions
        if _store_at_offset(instruction, 128)
    ]
    pending_clear_stores = [
        instruction
        for instruction in quiesce.instructions
        if _store_at_offset(instruction, 384)
    ]
    halt_sets = [
        instruction
        for instruction in quiesce.instructions
        if instruction.mnemonic.startswith("orr")
        and _has_immediate(instruction, 1 << 18)
    ]
    enable_clears = [
        instruction
        for instruction in quiesce.instructions
        if instruction.mnemonic.startswith("bic")
        and _has_immediate(instruction, 1)
    ]
    _require(
        len(irq_disable_stores) == 1
        and len(pending_clear_stores) == 1
        and len(halt_sets) == 1
        and len(enable_clears) == 1,
        "shutdown quiesce must mask both vectors, set HALT, clear E, and "
        "retire pending vectors exactly once",
    )
    halt_store = _next_non_nop(quiesce, halt_sets[0].address)
    enable_store = _next_non_nop(quiesce, enable_clears[0].address)
    _require(
        halt_store is not None
        and halt_store.mnemonic.startswith("str")
        and _store_at_offset(halt_store, 0)
        and enable_store is not None
        and enable_store.mnemonic.startswith("str")
        and _store_at_offset(enable_store, 0),
        "shutdown quiesce must commit both HALT-set and E-clear channel images",
    )
    quiesce_order = _require_ordered_instructions(
        quiesce,
        (
            (
                "mask DMA and deferred vectors",
                lambda instruction: instruction.address
                == irq_disable_stores[0].address,
            ),
            ("publish vector exclusion", _dmb),
            (
                "set PL080 HALT",
                lambda instruction: instruction.address == halt_sets[0].address,
            ),
            (
                "commit PL080 HALT",
                lambda instruction: instruction.address == halt_store.address,
            ),
            ("publish PL080 HALT", _dmb),
            (
                "initialize the bounded ACTIVE spin count",
                lambda instruction: instruction.mnemonic.startswith("mov")
                and _first_operand_register(instruction) == "r0"
                and _has_immediate(instruction, 65536),
            ),
            (
                "sample PL080 ACTIVE",
                lambda instruction: instruction.mnemonic.startswith("ldr")
                and _memory_location(instruction) == ("r3", 0),
            ),
            (
                "test PL080 ACTIVE bit 17",
                lambda instruction: instruction.mnemonic.startswith("lsl")
                and _has_immediate(instruction, 14),
            ),
            (
                "leave the loop when ACTIVE clears",
                lambda instruction: instruction.mnemonic.startswith("bpl"),
            ),
            (
                "decrement the bounded ACTIVE spin count",
                lambda instruction: instruction.mnemonic.startswith("sub")
                and _first_operand_register(instruction) == "r0"
                and _has_immediate(instruction, 1),
            ),
            (
                "repeat only while spin count remains",
                lambda instruction: instruction.mnemonic.startswith("bne"),
            ),
            (
                "clear PL080 channel E",
                lambda instruction: instruction.address
                == enable_clears[0].address,
            ),
            (
                "commit PL080 channel E clear",
                lambda instruction: instruction.address == enable_store.address,
            ),
            ("publish PL080 channel disable", _dmb),
            (
                "retire DMA and deferred pending vectors",
                lambda instruction: instruction.address
                == pending_clear_stores[0].address,
            ),
            ("publish terminal pending-vector retirement", _dmb),
        ),
    )
    active_load = quiesce_order[6]
    active_branch = quiesce_order[8]
    loop_branch = quiesce_order[10]
    _require(
        _branch_target_address(loop_branch) == active_load.address,
        "shutdown ACTIVE loop must return only to its linked CONFIG sample",
    )
    timeout_return = _next_non_nop(quiesce, loop_branch.address)
    success_entry = _branch_target_address(active_branch)
    _require(
        timeout_return is not None
        and _is_return_instruction(timeout_return)
        and success_entry is not None,
        "shutdown quiesce timeout/success split is unresolved",
    )
    successors = _control_flow_successors(quiesce)

    def reachable(start: int | None) -> frozenset[int]:
        reached: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reached or address not in successors:
                continue
            reached.add(address)
            pending.extend(successors[address] - reached)
        return frozenset(reached)

    timeout_reachable = reachable(timeout_return.address)
    success_reachable = reachable(success_entry)
    _require(
        enable_store.address not in timeout_reachable
        and pending_clear_stores[0].address not in timeout_reachable
        and enable_store.address in success_reachable
        and pending_clear_stores[0].address in success_reachable,
        "shutdown timeout must preserve ownership and bypass E/pending clear; "
        "only drained ACTIVE may complete teardown",
    )
    success_values = [
        instruction
        for instruction in quiesce.instructions
        if instruction.address in success_reachable
        and instruction.mnemonic.startswith("mov")
        and _first_operand_register(instruction) == "r0"
        and _has_immediate(instruction, 1)
    ]
    _require(
        len(success_values) == 1,
        "shutdown quiesce must return true only after terminal E/pending clear",
    )

    run_quiesce_calls = _calls_matching(
        baseband_run,
        lambda name: name == DMA_QUIESCE_SHUTDOWN_NAME,
    )
    halt_calls = _calls_matching(
        baseband_run,
        lambda name: name == "port_halt",
    )
    disable_calls = _calls_matching(
        baseband_run,
        lambda name: name == streaming_disable.name,
    )
    _require(
        len(run_quiesce_calls) == 1
        and len(halt_calls) == 1
        and disable_calls,
        "BasebandThread shutdown must retain one quiesce, one fail-stop halt, "
        "and an SGPIO gate close",
    )
    run_quiesce = run_quiesce_calls[0]
    last_disable = next(
        (
            call
            for call in reversed(disable_calls)
            if call.address < run_quiesce.address
        ),
        None,
    )
    run_comparison = _next_non_nop(baseband_run, run_quiesce.address)
    run_success_branch = (
        _next_non_nop(baseband_run, run_comparison.address)
        if run_comparison is not None
        else None
    )
    run_failure_call = (
        _next_non_nop(baseband_run, run_success_branch.address)
        if run_success_branch is not None
        else None
    )
    _require(
        last_disable is not None
        and _next_non_nop(baseband_run, last_disable.address) == run_quiesce
        and run_comparison is not None
        and run_comparison.mnemonic.startswith("cmp")
        and _operand_registers(run_comparison)[:1] == ("r0",)
        and _has_immediate(run_comparison, 0)
        and run_success_branch is not None
        and run_success_branch.mnemonic.startswith("bne")
        and run_failure_call == halt_calls[0],
        "BasebandThread must close SGPIO, quiesce, branch on its exact result, "
        "and fail-stop immediately on timeout",
    )
    run_successors = _control_flow_successors(
        baseband_run,
        reject_thumb_it=False,
    )

    def run_reachable(start: int | None) -> frozenset[int]:
        reached: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reached or address not in run_successors:
                continue
            reached.add(address)
            pending.extend(run_successors[address] - reached)
        return frozenset(reached)

    successful_shutdown = run_reachable(
        _branch_target_address(run_success_branch)
    )
    quiesced_publications = [
        instruction
        for instruction in _calls(baseband_run)
        if instruction.address in successful_shutdown
        and instruction.target is not None
        and instruction.target.startswith(
            "BasebandThread::publish_precision_rx_worker_quiesced("
        )
    ]
    _require(
        halt_calls[0].address not in successful_shutdown
        and len(quiesced_publications) == 1
        and _immediate_argument_before_call(
            baseband_run,
            quiesced_publications[0],
            "r0",
        )
        == 1,
        "successful shutdown must publish worker-quiesced and bypass port_halt",
    )

    return {
        "function": quiesce.name,
        "linked_code_bytes": quiesce_size,
        "shutdown_irq_mask": "0x80000004",
        "active_spin_limit": 65536,
        "vectors_masked_before_halt": True,
        "active_drained_before_e_clear": True,
        "timeout_preserves_dma_ownership": True,
        "terminal_pending_bits_retired": True,
        "worker_closes_sgpio_before_quiesce": True,
        "worker_timeout_calls_port_halt": True,
        "worker_success_publishes_quiesced": True,
    }


def _verify_p15_shutdown_wake_predicate(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove the normal destructor's durable wake predicate end to end."""

    wake = _unique_function(
        functions,
        DMA_WAKE_SHUTDOWN_NAME,
        lambda name: name == DMA_WAKE_SHUTDOWN_NAME,
    )
    wait_for_buffer = _unique_function(
        functions,
        "Precision RX DMA waiter",
        lambda name: name == DMA_WAIT_NAME,
    )
    pending_symbols = [
        symbol
        for symbol in symbols
        if symbol.name == DMA_ERROR_PENDING_NAME
    ]
    fatal_symbols = [
        symbol
        for symbol in symbols
        if symbol.name == DMA_FATAL_LATCH_NAME
    ]
    _require(
        len(pending_symbols) == len(fatal_symbols) == 1
        and pending_symbols[0].size == 1
        and fatal_symbols[0].size == 4
        and pending_symbols[0].address != fatal_symbols[0].address,
        "normal wake predicate must bind distinct one-byte dma_error_pending "
        "and four-byte dma_fatal_latched symbols",
    )
    pending_symbol = pending_symbols[0]
    fatal_symbol = fatal_symbols[0]

    wake_call = _require_one_call(
        wake,
        "ThreadWait durable shutdown wake",
        lambda name: name == "ThreadWait::wake_from_interrupt(int)",
    )
    wake_pending_loads = _literal_loads(
        wake,
        literal_words,
        pending_symbol.address,
    )
    wake_predicate_stores = [
        instruction
        for instruction in wake.instructions
        if instruction.address < wake_call.address
        and instruction.mnemonic.startswith("strb")
    ]
    _require(
        len(wake_pending_loads) == len(wake_predicate_stores) == 1,
        "normal shutdown wake must link and store dma_error_pending exactly "
        "once",
    )
    wake_pending_register = _first_operand_register(
        wake_pending_loads[0]
    )
    _require(
        _memory_location(wake_predicate_stores[0])
        == (wake_pending_register, 0),
        "normal shutdown wake must store its durable predicate to the exact "
        "linked dma_error_pending byte",
    )
    wake_dmbs = [
        instruction
        for instruction in wake.instructions
        if instruction.address < wake_call.address and _dmb(instruction)
    ]
    wake_non_stack_stores = [
        instruction
        for instruction in wake.instructions
        if instruction.mnemonic.startswith("str")
        and (
            (location := _memory_location(instruction)) is None
            or location[0] != "r13"
        )
    ]
    wake_lock = _require_one_call(
        wake,
        "scheduler lock check",
        lambda name: name == "dbg_check_lock",
    )
    wake_unlock = _require_one_call(
        wake,
        "scheduler unlock check",
        lambda name: name == "dbg_check_unlock",
    )
    _require(
        wake_non_stack_stores == wake_predicate_stores
        and len(wake_dmbs) == 1
        and wake_lock.address < wake_predicate_stores[0].address
        < wake_dmbs[0].address < wake_call.address
        < wake_unlock.address
        and {
            call.target for call in _calls(wake)
        }
        == {
            "dbg_check_lock",
            "ThreadWait::wake_from_interrupt(int)",
            "dbg_check_unlock",
        }
        and not _literal_loads(
            wake,
            literal_words,
            SGPIO_CONTROLLER_BASE_ADDRESS,
        )
        and not _literal_loads(
            wake,
            literal_words,
            PL080_SGPIO_CHANNEL_CONFIG_ADDRESS,
        ),
        "normal teardown wake must lock, set only its predicate, publish, "
        "wake, and unlock without SGPIO/PL080 mutation",
    )

    wait_pending_loads = _literal_loads(
        wait_for_buffer,
        literal_words,
        pending_symbol.address,
    )
    wait_fatal_loads = _literal_loads(
        wait_for_buffer,
        literal_words,
        fatal_symbol.address,
    )
    _require(
        len(wait_pending_loads) == len(wait_fatal_loads) == 1
        and wait_fatal_loads[0].address
        < wait_pending_loads[0].address,
        "wait_for_buffer must test the distinct fatal latch before the "
        "normal dma_error_pending wake predicate",
    )
    pending_base_register = _first_operand_register(
        wait_pending_loads[0]
    )
    pending_alias_moves = [
        instruction
        for instruction in wait_for_buffer.instructions
        if instruction.address > wait_pending_loads[0].address
        and instruction.mnemonic.startswith("mov")
        and _operand_registers(instruction)[1:]
        == (pending_base_register,)
    ]
    _require(
        len(pending_alias_moves) == 1,
        "wait_for_buffer must retain one linked alias of dma_error_pending "
        "across its locked sleep",
    )
    pending_alias_register = _first_operand_register(
        pending_alias_moves[0]
    )
    pending_locations = {
        (pending_base_register, 0),
        (pending_alias_register, 0),
    }
    pending_reads = [
        instruction
        for instruction in wait_for_buffer.instructions
        if instruction.mnemonic.startswith("ldrb")
        and _memory_location(instruction) in pending_locations
    ]
    pending_clears = [
        instruction
        for instruction in wait_for_buffer.instructions
        if instruction.mnemonic.startswith("strb")
        and _memory_location(instruction) in pending_locations
    ]
    sleep_calls = _calls_matching(
        wait_for_buffer,
        lambda name: name.startswith("ThreadWait::sleep_locked("),
    )
    _require(
        len(pending_reads) == 2
        and len(pending_clears) == 2
        and len(sleep_calls) == 1
        and pending_reads[0].address < pending_clears[0].address
        < sleep_calls[0].address < pending_reads[1].address
        < pending_clears[1].address,
        "wait_for_buffer must consume and clear dma_error_pending both "
        "before waiter installation and after the negative wake",
    )

    wake_callers = [
        function
        for function in functions
        if _calls_matching(
            function,
            lambda name: name == DMA_WAKE_SHUTDOWN_NAME,
        )
    ]
    _require(
        bool(wake_callers)
        and all(
            function.name.startswith(
                "BasebandThread::~BasebandThread()"
            )
            or function.name.startswith(
                "PrecisionRxProcessor::~PrecisionRxProcessor()"
            )
            for function in wake_callers
        ),
        "durable normal shutdown wake may appear only in the BasebandThread "
        "destructor or its LTO-inlined PrecisionRxProcessor destructors",
    )
    for destructor in wake_callers:
        destructor_terminate = _require_one_call(
            destructor,
            "normal worker terminate publication",
            lambda name: name == "chThdTerminate",
        )
        destructor_wake = _require_one_call(
            destructor,
            "normal worker shutdown wake",
            lambda name: name == DMA_WAKE_SHUTDOWN_NAME,
        )
        destructor_wait = _require_one_call(
            destructor,
            "normal worker join",
            lambda name: name == "chThdWait",
        )
        _require(
            destructor_terminate.address < destructor_wake.address
            < destructor_wait.address
            and not _calls_matching(
                destructor,
                lambda name: name == DMA_STOP_SHUTDOWN_NAME
                or name.startswith(SGPIO_STREAMING_DISABLE_PREFIX),
            ),
            "normal destructor must publish terminate, durably wake, then "
            "join without invoking fatal gate/stop machinery",
        )

    return {
        "dma_error_pending_address": (
            f"0x{pending_symbol.address:08x}"
        ),
        "dma_error_pending_bytes": pending_symbol.size,
        "dma_fatal_latched_address": (
            f"0x{fatal_symbol.address:08x}"
        ),
        "dma_fatal_latched_bytes": fatal_symbol.size,
        "predicate_distinct_from_fatal_latch": True,
        "wake_store_dmb_before_thread_wake": True,
        "waiter_consumes_before_sleep": True,
        "waiter_consumes_after_wake": True,
        "destructor_terminate_wake_wait_order": True,
        "wake_callers": sorted(
            function.name for function in wake_callers
        ),
        "linked_instruction_calibrated": True,
    }


def _verify_p15_shutdown_quiesce(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove normal teardown keeps the source live through HALT/ACTIVE drain."""

    quiesce = _unique_function(
        functions,
        DMA_QUIESCE_SHUTDOWN_NAME,
        lambda name: name == DMA_QUIESCE_SHUTDOWN_NAME,
    )
    wake = _unique_function(
        functions,
        DMA_WAKE_SHUTDOWN_NAME,
        lambda name: name == DMA_WAKE_SHUTDOWN_NAME,
    )
    wake_predicate_proof = _verify_p15_shutdown_wake_predicate(
        symbols=symbols,
        functions=functions,
        literal_words=literal_words,
    )
    baseband_run = _unique_function(
        functions,
        BASEBAND_RUN_NAME,
        lambda name: name == BASEBAND_RUN_NAME,
    )
    quiesce_size = _unique_symbol_size(
        symbols,
        DMA_QUIESCE_SHUTDOWN_NAME,
        lambda name: name == DMA_QUIESCE_SHUTDOWN_NAME,
    )
    _require(
        quiesce_size <= 160,
        f"{DMA_QUIESCE_SHUTDOWN_NAME} grew to {quiesce_size} bytes; "
        "maximum is 160",
    )
    _require_transfer_targets(quiesce, frozenset())
    _require(
        not _calls(quiesce),
        "P15 shutdown quiesce helper must remain call-free",
    )
    quiesce_callers = [
        function
        for function in functions
        if _calls_matching(
            function,
            lambda name: name == DMA_QUIESCE_SHUTDOWN_NAME,
        )
    ]
    _require(
        len(quiesce_callers) == 1
        and quiesce_callers[0].name == baseband_run.name,
        "P15 shutdown quiesce must be owned only by BasebandThread::run",
    )

    nvic_base_loads = _literal_loads(
        quiesce,
        literal_words,
        0xE000E100,
    )
    shutdown_mask_loads = _literal_loads(
        quiesce,
        literal_words,
        0x80000004,
    )
    channel_base_loads = _literal_loads(
        quiesce,
        literal_words,
        PL080_SGPIO_CHANNEL_CONFIG_ADDRESS,
    )
    sgpio_base_loads = _literal_loads(
        quiesce,
        literal_words,
        SGPIO_CONTROLLER_BASE_ADDRESS,
    )
    _require(
        len(nvic_base_loads) == 2
        and len(shutdown_mask_loads) == 2
        and len(channel_base_loads) == 1
        and len(sgpio_base_loads) == 2,
        "P15 shutdown must link exact NVIC, IRQ mask, PL080 CONFIG, and "
        "two HOST_DISABLE transaction bases",
    )

    irq_disable_stores = [
        instruction
        for instruction in quiesce.instructions
        if _store_at_offset(instruction, 128)
    ]
    pending_clear_stores = [
        instruction
        for instruction in quiesce.instructions
        if _store_at_offset(instruction, 384)
    ]
    halt_sets = [
        instruction
        for instruction in quiesce.instructions
        if instruction.mnemonic.startswith("orr")
        and _has_immediate(instruction, 1 << 18)
    ]
    enable_clears = [
        instruction
        for instruction in quiesce.instructions
        if instruction.mnemonic.startswith("bic")
        and _has_immediate(instruction, 1)
    ]
    gate_sets = [
        instruction
        for instruction in quiesce.instructions
        if instruction.mnemonic.startswith("orr")
        and _has_immediate(instruction, 1 << 10)
    ]
    _require(
        len(irq_disable_stores) == 1
        and len(pending_clear_stores) == 1
        and len(halt_sets) == 1
        and len(enable_clears) == 1
        and len(gate_sets) == 2,
        "P15 shutdown must mask vectors, set H once, gate both terminal "
        "paths, clear E only after drain, and retire pending vectors once",
    )

    halt_set = halt_sets[0]
    halt_store = _next_non_nop(quiesce, halt_set.address)
    halt_dmb = (
        _next_non_nop(quiesce, halt_store.address)
        if halt_store is not None
        else None
    )
    enable_clear = enable_clears[0]
    enable_store = _next_non_nop(quiesce, enable_clear.address)
    enable_dmb = (
        _next_non_nop(quiesce, enable_store.address)
        if enable_store is not None
        else None
    )
    _require(
        halt_store is not None
        and halt_store.mnemonic.startswith("str")
        and _store_at_offset(halt_store, 0)
        and halt_dmb is not None
        and _dmb(halt_dmb)
        and enable_store is not None
        and enable_store.mnemonic.startswith("str")
        and _store_at_offset(enable_store, 0)
        and enable_dmb is not None
        and _dmb(enable_dmb),
        "P15 shutdown must commit and publish exact H-set and E-clear "
        "CONFIG images",
    )

    active_loads: list[Instruction] = []
    active_tests: list[Instruction] = []
    for instruction in quiesce.instructions:
        if (
            not instruction.mnemonic.startswith("ldr")
            or _memory_location(instruction) != ("r3", 0)
        ):
            continue
        test = _next_non_nop(quiesce, instruction.address)
        if (
            test is not None
            and (
                (
                    test.mnemonic.startswith("and")
                    and _has_immediate(test, 1 << 17)
                )
                or (
                    test.mnemonic.startswith("lsl")
                    and _has_immediate(test, 14)
                )
            )
        ):
            active_loads.append(instruction)
            active_tests.append(test)
    _require(
        len(active_loads) == 2 and len(active_tests) == 2,
        "P15 shutdown must sample ACTIVE in the bounded live-source loop "
        "and again after the posted gate readback",
    )
    loop_active_load, post_gate_active_load = active_loads
    loop_active_test, post_gate_active_test = active_tests
    loop_active_branch = _next_non_nop(
        quiesce,
        loop_active_test.address,
    )
    post_gate_active_branch = _next_non_nop(
        quiesce,
        post_gate_active_test.address,
    )
    spin_init = next(
        (
            instruction
            for instruction in quiesce.instructions
            if halt_dmb.address < instruction.address
            < loop_active_load.address
            and instruction.mnemonic.startswith("mov")
            and _first_operand_register(instruction) == "r0"
            and _has_immediate(instruction, 65536)
        ),
        None,
    )
    spin_decrement = _next_non_nop(
        quiesce,
        loop_active_branch.address
        if loop_active_branch is not None
        else loop_active_test.address,
    )
    spin_branch = (
        _next_non_nop(quiesce, spin_decrement.address)
        if spin_decrement is not None
        else None
    )
    _require(
        spin_init is not None
        and loop_active_branch is not None
        and loop_active_branch.mnemonic.startswith(("beq", "bpl"))
        and spin_decrement is not None
        and spin_decrement.mnemonic.startswith("sub")
        and _has_immediate(spin_decrement, 1)
        and spin_branch is not None
        and spin_branch.mnemonic.startswith("bne")
        and _branch_target_address(spin_branch)
        == loop_active_load.address,
        "P15 shutdown must retain the exact bounded 65,536-sample ACTIVE "
        "loop",
    )

    gate_transactions: list[
        tuple[Instruction, Instruction, Instruction, Instruction]
    ] = []
    for gate_set in sorted(gate_sets, key=lambda item: item.address):
        gate_store = _next_non_nop(quiesce, gate_set.address)
        gate_dmb = (
            _next_non_nop(quiesce, gate_store.address)
            if gate_store is not None
            else None
        )
        gate_readback = (
            _next_non_nop(quiesce, gate_dmb.address)
            if gate_dmb is not None
            else None
        )
        _require(
            gate_store is not None
            and gate_store.mnemonic.startswith("str")
            and _memory_location(gate_store)[1:]
            == (SGPIO_GPIO_OUTREG_OFFSET,)
            and gate_dmb is not None
            and _dmb(gate_dmb)
            and gate_readback is not None
            and gate_readback.mnemonic.startswith("ldr")
            and _memory_location(gate_readback)[1:]
            == (SGPIO_GPIO_OUTREG_OFFSET,),
            "each P15 shutdown HOST_DISABLE path must use an exact RMW, DMB, "
            "and posted-write readback",
        )
        gate_transactions.append(
            (gate_set, gate_store, gate_dmb, gate_readback)
        )
    timeout_gate, success_gate = gate_transactions
    timeout_sgpio_base, success_sgpio_base = sorted(
        sgpio_base_loads,
        key=lambda instruction: instruction.address,
    )
    timeout_gate_value = _next_non_nop(
        quiesce,
        timeout_sgpio_base.address,
    )
    success_gate_value = _next_non_nop(
        quiesce,
        success_sgpio_base.address,
    )
    timeout_prefix = [
        instruction
        for instruction in quiesce.instructions
        if spin_branch.address < instruction.address
        < timeout_gate[0].address
    ]
    post_gate_success_entry = _instruction_at(
        quiesce,
        _branch_target_address(post_gate_active_branch),
    )
    _require(
        timeout_sgpio_base.address
        == _next_non_nop(quiesce, spin_branch.address).address
        and timeout_gate_value is not None
        and timeout_sgpio_base.address < timeout_gate_value.address
        < timeout_gate[0].address
        and not any(
            _is_branch(instruction)
            or _is_return_instruction(instruction)
            for instruction in timeout_prefix
        )
        and _branch_target_address(loop_active_branch)
        == success_sgpio_base.address
        and success_gate_value is not None
        and success_sgpio_base.address < success_gate_value.address
        < success_gate[0].address
        and _next_non_nop(quiesce, success_gate[3].address)
        == post_gate_active_load
        and post_gate_active_branch is not None
        and post_gate_active_branch.mnemonic.startswith("bpl")
        and post_gate_success_entry is not None
        and _next_non_nop(
            quiesce,
            post_gate_success_entry.address,
        )
        == enable_clear,
        "P15 shutdown must route timeout to gate-and-false and ACTIVE-clear "
        "to gate/readback/recheck before E-clear",
    )

    successors = _control_flow_successors(quiesce)

    def reachable(start: int | None) -> frozenset[int]:
        reached: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reached or address not in successors:
                continue
            reached.add(address)
            pending.extend(successors[address] - reached)
        return frozenset(reached)

    timeout_reachable = reachable(timeout_gate[0].address)
    success_reachable = reachable(success_gate[0].address)
    reassert_entry = _next_non_nop(
        quiesce,
        post_gate_active_branch.address,
    )
    reassert_reachable = reachable(
        reassert_entry.address if reassert_entry is not None else None
    )
    _require(
        timeout_gate[1].address in timeout_reachable
        and enable_store.address not in timeout_reachable
        and pending_clear_stores[0].address not in timeout_reachable
        and enable_store.address in success_reachable
        and pending_clear_stores[0].address in success_reachable
        and reassert_entry is not None
        and enable_store.address not in reassert_reachable
        and pending_clear_stores[0].address not in reassert_reachable,
        "shutdown timeout and post-gate ACTIVE reassertion must gate and "
        "return false while preserving E/ownership; only stable A==0 may "
        "retire E/pending",
    )
    _require_cfg_dominance(
        quiesce,
        start=quiesce.instructions[0],
        target=timeout_gate[1],
        required=(
            ("vector mask store", irq_disable_stores[0]),
            ("PL080 H set", halt_set),
            ("PL080 H store", halt_store),
            ("PL080 H publication", halt_dmb),
            ("bounded spin initialization", spin_init),
            ("live-source ACTIVE sample", loop_active_load),
            ("ACTIVE loop test", loop_active_test),
            ("spin-count decrement", spin_decrement),
            ("spin-count exhausted branch", spin_branch),
            ("timeout HOST_DISABLE set", timeout_gate[0]),
        ),
    )
    _require_cfg_dominance(
        quiesce,
        start=quiesce.instructions[0],
        target=success_gate[1],
        required=(
            ("vector mask store", irq_disable_stores[0]),
            ("PL080 H set", halt_set),
            ("PL080 H store", halt_store),
            ("PL080 H publication", halt_dmb),
            ("live-source ACTIVE sample", loop_active_load),
            ("ACTIVE-clear branch", loop_active_branch),
            ("success HOST_DISABLE set", success_gate[0]),
        ),
    )
    _require_cfg_dominance(
        quiesce,
        start=success_gate[0],
        target=enable_store,
        required=(
            ("success HOST_DISABLE set", success_gate[0]),
            ("success HOST_DISABLE store", success_gate[1]),
            ("success HOST_DISABLE DMB", success_gate[2]),
            ("success HOST_DISABLE readback", success_gate[3]),
            ("post-gate ACTIVE load", post_gate_active_load),
            ("post-gate ACTIVE test", post_gate_active_test),
            ("stable post-gate ACTIVE branch", post_gate_active_branch),
            ("PL080 E clear", enable_clear),
        ),
    )

    run_quiesce = _require_one_call(
        baseband_run,
        "P15 terminal DMA quiesce",
        lambda name: name == DMA_QUIESCE_SHUTDOWN_NAME,
    )
    run_halt = _require_one_call(
        baseband_run,
        "P15 terminal fail-stop",
        lambda name: name == "port_halt",
    )
    run_comparison = _next_non_nop(baseband_run, run_quiesce.address)
    run_success_branch = (
        _next_non_nop(baseband_run, run_comparison.address)
        if run_comparison is not None
        else None
    )
    run_failure = (
        _next_non_nop(baseband_run, run_success_branch.address)
        if run_success_branch is not None
        else None
    )
    _require(
        run_comparison is not None
        and run_comparison.mnemonic.startswith("cmp")
        and _first_operand_register(run_comparison) == "r0"
        and _has_immediate(run_comparison, 0)
        and run_success_branch is not None
        and run_success_branch.mnemonic.startswith("bne")
        and run_failure == run_halt,
        "BasebandThread::run must branch on the exact quiesce result and "
        "fail-stop immediately on false",
    )
    faulted_call = _require_one_call(
        baseband_run,
        "worker fatal-DMA test",
        lambda name: name == DMA_FAULTED_NAME,
    )
    faulted_compare = _next_non_nop(
        baseband_run,
        faulted_call.address,
    )
    faulted_branch = (
        _next_non_nop(baseband_run, faulted_compare.address)
        if faulted_compare is not None
        else None
    )
    inline_gate_sets = [
        instruction
        for instruction in baseband_run.instructions
        if faulted_call.address < instruction.address
        < run_quiesce.address
        and instruction.mnemonic.startswith("orr")
        and _has_immediate(instruction, 1 << 10)
    ]
    called_gate_closes = [
        call
        for call in _calls(baseband_run)
        if faulted_call.address < call.address < run_quiesce.address
        and call.target is not None
        and call.target.startswith(SGPIO_STREAMING_DISABLE_PREFIX)
    ]
    _require(
        len(inline_gate_sets) + len(called_gate_closes) == 1,
        "worker must retain exactly one fatal-only SGPIO gate close",
    )
    if inline_gate_sets:
        fatal_gate_start = inline_gate_sets[0]
        fatal_gate_end = _next_non_nop(
            baseband_run,
            fatal_gate_start.address,
        )
        _require(
            fatal_gate_end is not None
            and fatal_gate_end.mnemonic.startswith("str"),
            "inlined worker fatal gate must publish HOST_DISABLE",
        )
    else:
        fatal_gate_start = called_gate_closes[0]
        fatal_gate_end = fatal_gate_start
    _require(
        faulted_compare is not None
        and faulted_compare.mnemonic.startswith("cmp")
        and _first_operand_register(faulted_compare) == "r0"
        and _has_immediate(faulted_compare, 0)
        and faulted_branch is not None
        and faulted_branch.mnemonic.startswith("beq")
        and _branch_target_address(faulted_branch)
        < faulted_call.address
        and not any(
            _is_branch(instruction)
            or _is_return_instruction(instruction)
            for instruction in baseband_run.instructions
            if faulted_branch.address < instruction.address
            < fatal_gate_start.address
        ),
        "only the exact fatal-DMA fallthrough may enter the worker SGPIO "
        "fail-close",
    )
    normal_shutdown_branches = [
        instruction
        for instruction in baseband_run.instructions
        if instruction.address < faulted_call.address
        and _is_conditional_branch(instruction)
        and (
            target := _branch_target_address(instruction)
        ) is not None
        and fatal_gate_end.address < target < run_quiesce.address
    ]
    _require(
        len(normal_shutdown_branches) == 1,
        "normal worker termination must branch past the fatal SGPIO gate "
        "and enter common terminal quiesce",
    )

    wake_call = _require_one_call(
        wake,
        "ThreadWait durable shutdown wake",
        lambda name: name == "ThreadWait::wake_from_interrupt(int)",
    )
    wake_predicate_stores = [
        instruction
        for instruction in wake.instructions
        if instruction.address < wake_call.address
        and instruction.mnemonic.startswith("strb")
        and _first_operand_register(instruction) in {"r2", "r3"}
    ]
    pending_symbols = [
        symbol
        for symbol in symbols
        if symbol.name == DMA_ERROR_PENDING_NAME
    ]
    fatal_symbols = [
        symbol
        for symbol in symbols
        if symbol.name == DMA_FATAL_LATCH_NAME
    ]
    _require(
        len(pending_symbols) == len(fatal_symbols) == 1
        and pending_symbols[0].size == 1
        and fatal_symbols[0].size == 4
        and pending_symbols[0].address != fatal_symbols[0].address,
        "normal wake predicate must bind distinct one-byte dma_error_pending "
        "and four-byte dma_fatal_latched symbols",
    )
    pending_symbol = pending_symbols[0]
    fatal_symbol = fatal_symbols[0]
    wake_pending_loads = _literal_loads(
        wake,
        literal_words,
        pending_symbol.address,
    )
    _require(
        len(wake_pending_loads) == 1
        and len(wake_predicate_stores) == 1,
        "normal shutdown wake must link dma_error_pending exactly once",
    )
    wake_pending_register = _first_operand_register(
        wake_pending_loads[0]
    )
    _require(
        _memory_location(wake_predicate_stores[0])
        == (wake_pending_register, 0),
        "normal shutdown wake must store its durable predicate to the exact "
        "linked dma_error_pending byte",
    )
    wake_dmbs = [
        instruction
        for instruction in wake.instructions
        if instruction.address < wake_call.address and _dmb(instruction)
    ]
    wake_non_stack_stores = [
        instruction
        for instruction in wake.instructions
        if instruction.mnemonic.startswith("str")
        and (
            (location := _memory_location(instruction)) is None
            or location[0] != "r13"
        )
    ]
    wake_call_targets = {
        call.target for call in _calls(wake)
    }
    wake_lock_call = next(
        (
            call
            for call in _calls(wake)
            if call.target == "dbg_check_lock"
        ),
        None,
    )
    wake_unlock_call = next(
        (
            call
            for call in _calls(wake)
            if call.target == "dbg_check_unlock"
        ),
        None,
    )
    _require(
        len(wake_predicate_stores) == 1
        and wake_non_stack_stores == wake_predicate_stores
        and wake_dmbs
        and wake_predicate_stores[-1].address < wake_dmbs[-1].address
        < wake_call.address
        and wake_call_targets
        == {
            "dbg_check_lock",
            "ThreadWait::wake_from_interrupt(int)",
            "dbg_check_unlock",
        }
        and wake_lock_call is not None
        and wake_unlock_call is not None
        and wake_lock_call.address
        < wake_predicate_stores[-1].address
        < wake_dmbs[-1].address
        < wake_call.address
        < wake_unlock_call.address
        and not _literal_loads(
            wake,
            literal_words,
            SGPIO_CONTROLLER_BASE_ADDRESS,
        )
        and not _literal_loads(
            wake,
            literal_words,
            PL080_SGPIO_CHANNEL_CONFIG_ADDRESS,
        ),
        "normal teardown wake must lock, durably set only its predicate, "
        "wake, and unlock without queue/owner/descriptor/SGPIO/PL080 mutation",
    )
    wait_for_buffer = _unique_function(
        functions,
        "Precision RX DMA waiter",
        lambda name: name == DMA_WAIT_NAME,
    )
    wait_pending_loads = _literal_loads(
        wait_for_buffer,
        literal_words,
        pending_symbol.address,
    )
    wait_fatal_loads = _literal_loads(
        wait_for_buffer,
        literal_words,
        fatal_symbol.address,
    )
    _require(
        len(wait_pending_loads) == len(wait_fatal_loads) == 1
        and wait_fatal_loads[0].address
        < wait_pending_loads[0].address,
        "wait_for_buffer must test the distinct fatal latch before the "
        "normal dma_error_pending wake predicate",
    )
    pending_base_register = _first_operand_register(
        wait_pending_loads[0]
    )
    pending_alias_moves = [
        instruction
        for instruction in wait_for_buffer.instructions
        if instruction.address > wait_pending_loads[0].address
        and instruction.mnemonic.startswith("mov")
        and _operand_registers(instruction)[1:]
        == (pending_base_register,)
    ]
    _require(
        len(pending_alias_moves) == 1,
        "wait_for_buffer must retain one linked alias of dma_error_pending "
        "across its locked sleep",
    )
    pending_alias_register = _first_operand_register(
        pending_alias_moves[0]
    )
    pending_reads = [
        instruction
        for instruction in wait_for_buffer.instructions
        if instruction.mnemonic.startswith("ldrb")
        and _memory_location(instruction)
        in {
            (pending_base_register, 0),
            (pending_alias_register, 0),
        }
    ]
    pending_clears = [
        instruction
        for instruction in wait_for_buffer.instructions
        if instruction.mnemonic.startswith("strb")
        and _memory_location(instruction)
        in {
            (pending_base_register, 0),
            (pending_alias_register, 0),
        }
    ]
    sleep_calls = _calls_matching(
        wait_for_buffer,
        lambda name: name.startswith("ThreadWait::sleep_locked("),
    )
    _require(
        len(pending_reads) == 2
        and len(pending_clears) == 2
        and len(sleep_calls) == 1
        and pending_reads[0].address < pending_clears[0].address
        < sleep_calls[0].address < pending_reads[1].address
        < pending_clears[1].address,
        "wait_for_buffer must consume and clear dma_error_pending both "
        "before waiter installation and after the negative wake",
    )
    wake_callers = [
        function
        for function in functions
        if _calls_matching(
            function,
            lambda name: name == DMA_WAKE_SHUTDOWN_NAME,
        )
    ]
    _require(
        bool(wake_callers)
        and all(
            function.name.startswith(
                "BasebandThread::~BasebandThread()"
            )
            or function.name.startswith(
                "PrecisionRxProcessor::~PrecisionRxProcessor()"
            )
            for function in wake_callers
        ),
        "durable normal shutdown wake may appear only in the BasebandThread "
        "destructor or its LTO-inlined PrecisionRxProcessor destructors",
    )
    for destructor in wake_callers:
        destructor_wake = _require_one_call(
            destructor,
            "normal worker shutdown wake",
            lambda name: name == DMA_WAKE_SHUTDOWN_NAME,
        )
        destructor_wait = _require_one_call(
            destructor,
            "normal worker join",
            lambda name: name == "chThdWait",
        )
        destructor_terminate = _require_one_call(
            destructor,
            "normal worker terminate publication",
            lambda name: name == "chThdTerminate",
        )
        _require(
            destructor_terminate.address < destructor_wake.address
            < destructor_wait.address
            and not _calls_matching(
                destructor,
                lambda name: name == DMA_STOP_SHUTDOWN_NAME
                or name.startswith(SGPIO_STREAMING_DISABLE_PREFIX),
            ),
            "normal destructor must publish terminate, durably wake, then "
            "join without invoking fatal gate/stop machinery",
        )

    return {
        "function": quiesce.name,
        "linked_code_bytes": quiesce_size,
        "shutdown_irq_mask": "0x80000004",
        "active_spin_limit": 65536,
        "normal_destructor_durable_wake_only": True,
        "dma_error_pending_address": (
            f"0x{pending_symbol.address:08x}"
        ),
        "dma_error_pending_bytes": pending_symbol.size,
        "dma_fatal_latched_address": (
            f"0x{fatal_symbol.address:08x}"
        ),
        "dma_fatal_latched_bytes": fatal_symbol.size,
        "shutdown_predicate_distinct_from_fatal_latch": True,
        "waiter_consumes_predicate_before_sleep": True,
        "waiter_consumes_predicate_after_wake": True,
        "destructor_order_terminate_wake_wait": True,
        "wake_predicate": wake_predicate_proof,
        "vectors_masked_before_halt": True,
        "halt_precedes_live_source_active_drain": True,
        "active_drain_precedes_sgpio_gate": True,
        "gate_readback_before_active_recheck": True,
        "stable_active_clear_precedes_e_clear": True,
        "timeout_gates_before_fail_stop": True,
        "timeout_preserves_dma_ownership": True,
        "active_reassertion_preserves_dma_ownership": True,
        "worker_timeout_calls_port_halt": True,
        "linked_instruction_calibrated": True,
    }


def _verify_p15_shutdown_mode_dispatch(
    *,
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove the linked Shutdown ID/mode path reaches fail-close and Fatal."""

    main = _unique_function(
        functions,
        "main",
        lambda name: name == "main",
    )
    dispatcher = _unique_function(
        functions,
        "P15 shutdown dispatcher",
        lambda name: name.startswith(EVENT_SHUTDOWN_PREFIX),
    )
    processor = _unique_function(
        functions,
        "PrecisionRxProcessor::on_message",
        lambda name: name.startswith(PROCESSOR_MESSAGE_PREFIX),
    )
    fail_close = _unique_function(
        functions,
        BASEBAND_FAIL_CLOSE_NAME,
        lambda name: name == BASEBAND_FAIL_CLOSE_NAME,
    )

    dispatcher_call = _require_one_call(
        main,
        "P15 shutdown dispatcher",
        lambda name: name.startswith(EVENT_SHUTDOWN_PREFIX),
    )
    dispatcher_callers = [
        function.name
        for function in functions
        if _calls_matching(
            function,
            lambda name: name.startswith(EVENT_SHUTDOWN_PREFIX),
        )
    ]
    _require(
        dispatcher_callers == [main.name],
        "P15 shutdown dispatcher must have main as its sole direct caller",
    )
    main_id_splits: list[
        tuple[Instruction, Instruction, Instruction]
    ] = []
    for comparison in main.instructions:
        if (
            not comparison.mnemonic.startswith("cmp")
            or not _has_immediate(comparison, 5)
        ):
            continue
        id_register = _first_operand_register(comparison)
        if id_register is None:
            continue
        id_load = _last_register_writer(
            main,
            id_register,
            before=comparison,
        )
        branch = _next_non_nop(main, comparison.address)
        if (
            id_load is not None
            and id_load.mnemonic.startswith("ldr")
            and _memory_location(id_load) == ("r1", 0)
            and branch is not None
            and branch.mnemonic.startswith("beq")
            and (
                branch_target := _branch_target_address(branch)
            ) is not None
            and branch_target <= dispatcher_call.address
        ):
            main_id_splits.append((id_load, comparison, branch))
    _require(
        len(main_id_splits) == 1,
        "main must route exactly linked Shutdown ID=5 to the shutdown "
        "dispatcher",
    )
    main_id_load, main_id_compare, main_id_branch = main_id_splits[0]
    main_message_pointer_load = _last_register_writer(
        main,
        "r1",
        before=main_id_load,
    )
    main_fault_entry = _instruction_at(
        main,
        _branch_target_address(main_id_branch),
    )
    _require(
        main_message_pointer_load is not None
        and main_message_pointer_load.mnemonic.startswith("ldr")
        and _memory_location(main_message_pointer_load)[1:] == (0,)
        and main_fault_entry is not None
        and main_fault_entry.address <= dispatcher_call.address
        and not any(
            _is_branch(instruction)
            or _is_return_instruction(instruction)
            or _clobbers_register(instruction, "r1")
            for instruction in main.instructions
            if main_fault_entry.address <= instruction.address
            < dispatcher_call.address
        ),
        "main Shutdown ID=5 branch must enter the direct dispatcher call",
    )
    _require_register_preserved(
        main,
        "r1",
        after=main_message_pointer_load,
        before=main_id_branch,
        description="main Shutdown message pointer",
    )

    dispatcher_forward_calls = [
        call
        for call in _calls(dispatcher)
        if call.target is None
    ]
    _require(
        len(dispatcher_forward_calls) == 1
        and dispatcher_forward_calls[0].mnemonic == "blx"
        and len(_operand_registers(dispatcher_forward_calls[0])) == 1,
        "P15 shutdown dispatcher must retain one indirect processor forward",
    )
    dispatcher_forward = dispatcher_forward_calls[0]
    dispatcher_mode_loads = [
        instruction
        for instruction in dispatcher.instructions
        if instruction.mnemonic.startswith("ldr")
        and _memory_location(instruction) == ("r1", 4)
    ]
    _require(
        len(dispatcher_mode_loads) == 1,
        "P15 shutdown dispatcher must load mode from message offset 4",
    )
    dispatcher_mode_load = dispatcher_mode_loads[0]
    dispatcher_mode_register = _first_operand_register(
        dispatcher_mode_load
    )
    dispatcher_mode_compare = _next_non_nop(
        dispatcher,
        dispatcher_mode_load.address,
    )
    _require(
        dispatcher_mode_register is not None
        and dispatcher_mode_compare is not None
        and dispatcher_mode_compare.mnemonic.startswith("cmp")
        and _first_operand_register(dispatcher_mode_compare)
        == dispatcher_mode_register
        and _instruction_immediates(dispatcher_mode_compare) == {1},
        "P15 shutdown dispatcher must compare the linked mode to "
        "PrecisionRxFault=1",
    )
    dispatcher_mode_branches = [
        instruction
        for instruction in dispatcher.instructions
        if dispatcher_mode_compare.address < instruction.address
        < dispatcher_forward.address
        and _is_conditional_branch(instruction)
    ]
    _require(
        len(dispatcher_mode_branches) == 1
        and dispatcher_mode_branches[0].mnemonic.startswith("bne"),
        "only dispatcher mode=PrecisionRxFault may enter processor forwarding",
    )
    dispatcher_mode_branch = dispatcher_mode_branches[0]
    intervening_dispatcher_prologue = [
        instruction
        for instruction in dispatcher.instructions
        if dispatcher_mode_compare.address < instruction.address
        < dispatcher_mode_branch.address
    ]
    _require(
        all(
            instruction.mnemonic.startswith(("push", "mov"))
            for instruction in intervening_dispatcher_prologue
        ),
        "dispatcher mode comparison flags must reach its branch without "
        "modification",
    )
    dispatcher_stop_entry = _instruction_at(
        dispatcher,
        _branch_target_address(dispatcher_mode_branch),
    )
    dispatcher_stop_store = (
        _next_non_nop(dispatcher, dispatcher_stop_entry.address)
        if dispatcher_stop_entry is not None
        else None
    )
    _require(
        dispatcher_stop_entry is not None
        and dispatcher_stop_entry.mnemonic.startswith("mov")
        and _instruction_immediates(dispatcher_stop_entry) == {0}
        and dispatcher_stop_store is not None
        and dispatcher_stop_store.mnemonic.startswith("strb")
        and _memory_location(dispatcher_stop_store)[1:] == (4,)
        and _first_operand_register(dispatcher_stop_store)
        == _first_operand_register(dispatcher_stop_entry),
        "both shutdown modes must clear the dispatcher run flag after the "
        "optional processor forward",
    )
    dispatcher_successors = _control_flow_successors(dispatcher)

    def dispatcher_reachable(start: int | None) -> frozenset[int]:
        reached: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reached or address not in dispatcher_successors:
                continue
            reached.add(address)
            pending.extend(dispatcher_successors[address] - reached)
        return frozenset(reached)

    dispatcher_fault_entry = _next_non_nop(
        dispatcher,
        dispatcher_mode_branch.address,
    )
    dispatcher_normal_reachable = dispatcher_reachable(
        dispatcher_stop_entry.address
    )
    dispatcher_fault_reachable = dispatcher_reachable(
        (
            dispatcher_fault_entry.address
            if dispatcher_fault_entry is not None
            else None
        )
    )
    _require(
        dispatcher_fault_entry is not None
        and dispatcher_forward.address in dispatcher_fault_reachable
        and dispatcher_forward.address not in dispatcher_normal_reachable
        and dispatcher_stop_store.address in dispatcher_fault_reachable
        and dispatcher_stop_store.address in dispatcher_normal_reachable,
        "dispatcher fault mode must forward then stop while normal mode "
        "bypasses forwarding and stops",
    )
    _require_register_preserved(
        dispatcher,
        "r1",
        after=dispatcher_mode_load,
        before=dispatcher_forward,
        description="dispatcher Shutdown message pointer",
    )

    processor_fail_close = _require_one_call(
        processor,
        "BasebandThread fail-close",
        lambda name: name == BASEBAND_FAIL_CLOSE_NAME,
    )
    processor_id_compares = [
        instruction
        for instruction in processor.instructions
        if instruction.mnemonic.startswith("cmp")
        and _instruction_immediates(instruction) == {5}
    ]
    _require(
        len(processor_id_compares) == 1,
        "processor must retain one exact Shutdown ID=5 comparison",
    )
    processor_id_compare = processor_id_compares[0]
    processor_id_register = _first_operand_register(
        processor_id_compare
    )
    processor_id_load = (
        _last_register_writer(
            processor,
            processor_id_register,
            before=processor_id_compare,
        )
        if processor_id_register is not None
        else None
    )
    processor_id_branch = _next_non_nop(
        processor,
        processor_id_compare.address,
    )
    _require(
        processor_id_load is not None
        and processor_id_load.mnemonic.startswith("ldr")
        and _memory_location(processor_id_load) == ("r1", 0)
        and processor_id_branch is not None
        and processor_id_branch.mnemonic.startswith("bne"),
        "processor must reject messages other than linked Shutdown ID=5",
    )
    processor_mode_load = _next_non_nop(
        processor,
        processor_id_branch.address,
    )
    processor_mode_compare = (
        _next_non_nop(processor, processor_mode_load.address)
        if processor_mode_load is not None
        else None
    )
    processor_mode_branch = (
        _next_non_nop(processor, processor_mode_compare.address)
        if processor_mode_compare is not None
        else None
    )
    _require(
        processor_mode_load is not None
        and processor_mode_load.mnemonic.startswith("ldr")
        and _memory_location(processor_mode_load) == ("r1", 4)
        and processor_mode_compare is not None
        and processor_mode_compare.mnemonic.startswith("cmp")
        and _first_operand_register(processor_mode_compare)
        == _first_operand_register(processor_mode_load)
        and _instruction_immediates(processor_mode_compare) == {1}
        and processor_mode_branch is not None
        and processor_mode_branch.mnemonic.startswith("bne")
        and _branch_target_address(processor_id_branch)
        == _branch_target_address(processor_mode_branch),
        "processor must accept only Shutdown mode=PrecisionRxFault=1 and "
        "send all other ID/mode values to one bypass",
    )
    processor_fault_entry = _next_non_nop(
        processor,
        processor_mode_branch.address,
    )
    processor_fatal_transfers = [
        instruction
        for instruction in processor.instructions
        if instruction.address > processor_fail_close.address
        and instruction.target is not None
        and instruction.target.startswith(
            PROCESSOR_TRANSITION_RATE_STATE_PREFIX
        )
        and instruction.mnemonic in {
            "bl",
            "blx",
            "b",
            "b.n",
            "b.w",
        }
    ]
    _require(
        bool(processor_fatal_transfers),
        "processor Shutdown fault path must retain a post-fail-close rate "
        "state transition",
    )
    processor_fatal_transfer = min(
        processor_fatal_transfers,
        key=lambda instruction: instruction.address,
    )
    fatal_event_moves = [
        instruction
        for instruction in processor.instructions
        if processor_fail_close.address < instruction.address
        < processor_fatal_transfer.address
        and instruction.mnemonic.startswith("mov")
        and _first_operand_register(instruction) == "r1"
        and _instruction_immediates(instruction) == {8}
    ]
    _require(
        len(fatal_event_moves) == 1,
        "processor Shutdown fault path must transition with exact Fatal "
        "event=8",
    )
    _require_register_preserved(
        processor,
        "r1",
        after=fatal_event_moves[0],
        before=processor_fatal_transfer,
        description="processor Fatal event",
    )
    processor_successors = _control_flow_successors(
        processor,
        reject_thumb_it=False,
    )

    def processor_reachable(start: int | None) -> frozenset[int]:
        reached: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reached or address not in processor_successors:
                continue
            reached.add(address)
            pending.extend(processor_successors[address] - reached)
        return frozenset(reached)

    processor_fault_reachable = processor_reachable(
        (
            processor_fault_entry.address
            if processor_fault_entry is not None
            else None
        )
    )
    processor_bypass_reachable = processor_reachable(
        _branch_target_address(processor_mode_branch)
    )
    _require(
        processor_fault_entry is not None
        and processor_fail_close.address in processor_fault_reachable
        and processor_fatal_transfer.address in processor_fault_reachable
        and processor_fail_close.address not in processor_bypass_reachable
        and processor_fatal_transfer.address
        not in processor_bypass_reachable,
        "only processor Shutdown fault mode may reach fail-close and Fatal",
    )

    sgpio_base_loads = _literal_loads(
        fail_close,
        literal_words,
        SGPIO_CONTROLLER_BASE_ADDRESS,
    )
    _require(
        len(sgpio_base_loads) == 1,
        "BasebandThread fail-close must link the exact SGPIO controller base",
    )
    sgpio_base_load = sgpio_base_loads[0]
    sgpio_base_register = _first_operand_register(sgpio_base_load)
    fail_close_gate_loads = [
        instruction
        for instruction in fail_close.instructions
        if instruction.mnemonic.startswith("ldr")
        and _memory_location(instruction)
        == (sgpio_base_register, SGPIO_GPIO_OUTREG_OFFSET)
    ]
    fail_close_gate_sets = [
        instruction
        for instruction in fail_close.instructions
        if instruction.mnemonic.startswith("orr")
        and _instruction_immediates(instruction) == {1 << 10}
    ]
    fail_close_gate_stores = [
        instruction
        for instruction in fail_close.instructions
        if instruction.mnemonic.startswith("str")
        and _memory_location(instruction)
        == (sgpio_base_register, SGPIO_GPIO_OUTREG_OFFSET)
    ]
    _require(
        len(fail_close_gate_loads)
        == len(fail_close_gate_sets)
        == len(fail_close_gate_stores)
        == 1,
        "BasebandThread fail-close must retain one exact HOST_DISABLE "
        "read/ORR/store transaction",
    )
    fail_close_gate_load = fail_close_gate_loads[0]
    fail_close_gate_set = fail_close_gate_sets[0]
    fail_close_gate_store = fail_close_gate_stores[0]
    first_fail_close_call = min(
        _calls(fail_close),
        key=lambda instruction: instruction.address,
    )
    _require(
        sgpio_base_load.address < fail_close_gate_load.address
        < fail_close_gate_set.address < fail_close_gate_store.address
        < first_fail_close_call.address
        and _first_operand_register(fail_close_gate_load)
        == _first_operand_register(fail_close_gate_set)
        == _first_operand_register(fail_close_gate_store)
        and not any(
            instruction.mnemonic.startswith("bic")
            and _has_immediate(instruction, 1 << 10)
            for instruction in fail_close.instructions
        ),
        "BasebandThread fail-close must close HOST_DISABLE before any stop "
        "logic and must never reopen it",
    )

    return {
        "main_function": main.name,
        "dispatcher_function": dispatcher.name,
        "processor_function": processor.name,
        "fail_close_function": fail_close.name,
        "shutdown_message_id": 5,
        "precision_rx_fault_mode": 1,
        "fatal_transition_event": 8,
        "main_message_pointer_preserved": True,
        "fault_mode_forwarded_to_processor": True,
        "normal_mode_bypasses_processor_forward": True,
        "processor_fault_mode_calls_fail_close": True,
        "processor_normal_mode_bypasses_fail_close": True,
        "fail_close_sgpio_host_disable_first": True,
        "processor_fault_mode_transitions_fatal": True,
        "linked_instruction_calibrated": True,
    }


def _verify_p12_transition_rate_state(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove the linked, IRQ-excluded rate-state reducer and publisher.

    ``publish_running_if_dma_healthy`` is intentionally a small optimistic
    front end.  The durable fault check and state publication live here under
    the combined ChibiOS lock and priority-1 DMA exclusion.  The compiler
    lowers the constexpr reducer to one eight-entry Thumb TBB table, so this
    proof expands that exact table instead of treating it as an opaque branch.
    """

    transition = _unique_function(
        functions,
        "rate-state transition reducer",
        lambda name: name.startswith(PROCESSOR_TRANSITION_RATE_STATE_PREFIX),
    )
    begin = _unique_function(
        functions,
        DMA_RATE_STATE_BEGIN_NAME,
        lambda name: name == DMA_RATE_STATE_BEGIN_NAME,
    )
    end = _unique_function(
        functions,
        DMA_RATE_STATE_END_NAME,
        lambda name: name == DMA_RATE_STATE_END_NAME,
    )
    rate_state = _unique_function(
        functions,
        "rate-state accessor",
        lambda name: name.startswith(PROCESSOR_RATE_STATE_PREFIX),
    )
    linked_sizes = {
        "transition": _unique_symbol_size(
            symbols,
            "rate-state transition reducer",
            lambda name: name.startswith(PROCESSOR_TRANSITION_RATE_STATE_PREFIX),
        ),
        "begin_irq_exclusion": _unique_symbol_size(
            symbols,
            DMA_RATE_STATE_BEGIN_NAME,
            lambda name: name == DMA_RATE_STATE_BEGIN_NAME,
        ),
        "end_irq_exclusion": _unique_symbol_size(
            symbols,
            DMA_RATE_STATE_END_NAME,
            lambda name: name == DMA_RATE_STATE_END_NAME,
        ),
        "state_accessor": _unique_symbol_size(
            symbols,
            "rate-state accessor",
            lambda name: name.startswith(PROCESSOR_RATE_STATE_PREFIX),
        ),
    }
    maximum_sizes = {
        "transition": 224,
        "begin_irq_exclusion": 128,
        "end_irq_exclusion": 32,
        "state_accessor": 16,
    }
    for name, size in linked_sizes.items():
        _require(
            size <= maximum_sizes[name],
            f"{name} grew to {size} bytes; maximum is {maximum_sizes[name]}",
        )
    irq_exclusion_report = _verify_p12_rate_state_irq_exclusion(
        symbols=symbols,
        functions=functions,
        literal_words=literal_words,
    )

    accessor_transfers = _external_control_transfers(rate_state)
    accessor_loads = [
        instruction
        for instruction in rate_state.instructions
        if _load_at_offset(instruction, 624)
    ]
    accessor_returns = [
        instruction
        for instruction in rate_state.instructions
        if _is_return_instruction(instruction)
    ]
    _require(
        not accessor_transfers
        and len(accessor_loads) == 1
        and _first_operand_register(accessor_loads[0]) == "r0"
        and len(accessor_returns) == 1
        and not any(
            instruction.mnemonic.startswith("str")
            for instruction in rate_state.instructions
        )
        and not any(
            _writes_register(instruction, "r1")
            for instruction in rate_state.instructions
        ),
        "rate-state accessor must be a call-free, read-only offset-624 load "
        "that preserves publisher argument r1",
    )

    allowed_targets = frozenset(
        {
            "dbg_check_lock",
            "dbg_check_unlock",
            begin.name,
            end.name,
            rate_state.name,
        }
    )
    transfers = _external_control_transfers(transition)
    _require(
        all(transfer.target in allowed_targets for transfer in transfers),
        f"{transition.name} contains an unreviewed external transfer",
    )
    transfer_counts = {
        target: sum(transfer.target == target for transfer in transfers)
        for target in allowed_targets
    }
    _require(
        transfer_counts
        == {
            "dbg_check_lock": 1,
            "dbg_check_unlock": 1,
            begin.name: 1,
            end.name: 1,
            rate_state.name: 1,
        },
        "rate-state transition must retain exactly one lock, unlock, DMA "
        "begin/end exclusion, and current-state sample",
    )
    _require(
        not any(
            instruction.mnemonic == "blx" and instruction.target is None
            for instruction in transition.instructions
        ),
        "rate-state transition contains an indirect call",
    )
    _require(
        not any(
            re.fullmatch(
                r"it[te]{0,3}",
                instruction.mnemonic.lower().split(".", 1)[0],
            )
            for instruction in transition.instructions
        ),
        "rate-state transition contains unsupported Thumb IT predication",
    )

    table_branches = [
        instruction
        for instruction in transition.instructions
        if instruction.mnemonic.startswith("tbb")
    ]
    _require(
        len(table_branches) == 1
        and not any(
            instruction.mnemonic.startswith("tbh")
            for instruction in transition.instructions
        ),
        "rate-state transition must retain exactly one reviewed eight-entry TBB",
    )
    table_branch = table_branches[0]
    table_registers = _operand_registers(table_branch)
    _require(
        table_registers == ("r15", "r3"),
        "rate-state transition TBB must use the reviewed PC/r3 index",
    )
    table_base = (table_branch.address + 4) & ~3
    table_word_values = (
        literal_words.get(table_base),
        literal_words.get(table_base + 4),
    )
    _require(
        table_word_values == (0x14110E07, 0x29221B14),
        "rate-state transition TBB does not match the reviewed eight-event "
        "reducer dispatch",
    )
    table_targets = frozenset(
        table_base + 2 * ((word >> shift) & 0xFF)
        for word in table_word_values
        if word is not None
        for shift in (0, 8, 16, 24)
    )

    instructions = tuple(
        sorted(transition.instructions, key=lambda instruction: instruction.address)
    )
    instructions_by_address = {
        instruction.address: instruction for instruction in instructions
    }
    addresses = frozenset(instructions_by_address)
    _require(
        table_targets.issubset(addresses),
        "rate-state transition TBB contains a target outside the reducer",
    )

    successors: dict[int, frozenset[int]] = {}
    for index, instruction in enumerate(instructions):
        following = (
            instructions[index + 1].address
            if index + 1 < len(instructions)
            and 0 < instructions[index + 1].address - instruction.address <= 4
            else None
        )
        if _is_return_instruction(instruction):
            successors[instruction.address] = frozenset()
        elif instruction.address == table_branch.address:
            successors[instruction.address] = table_targets
        elif instruction.mnemonic.startswith(("tbb", "tbh")) or (
            instruction.mnemonic.startswith("bx")
            and not _is_return_instruction(instruction)
        ):
            raise VerificationError(
                "rate-state transition contains an unreviewed indirect transfer"
            )
        elif instruction.mnemonic in {"bl", "blx"}:
            successors[instruction.address] = (
                frozenset({following}) if following is not None else frozenset()
            )
        elif _is_branch(instruction):
            target = _branch_target_address(instruction)
            _require(
                target is not None,
                "rate-state transition contains an unresolved direct branch",
            )
            local_target = target if target in addresses else None
            if _is_conditional_branch(instruction):
                _require(
                    following is not None and local_target is not None,
                    "rate-state transition conditional branch leaves the "
                    "reviewed reducer",
                )
                successors[instruction.address] = frozenset(
                    {following, local_target}
                )
            else:
                _require(
                    local_target is not None,
                    "rate-state transition contains an external tail branch",
                )
                successors[instruction.address] = frozenset({local_target})
        else:
            _require(
                following is not None,
                "rate-state transition has an unterminated instruction path",
            )
            successors[instruction.address] = frozenset({following})

    entry = instructions[0]

    def reachable_from(start: int | None) -> frozenset[int]:
        reached: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reached or address not in successors:
                continue
            reached.add(address)
            pending.extend(successors[address] - reached)
        return frozenset(reached)

    reachable = reachable_from(entry.address)
    _require(
        reachable == addresses,
        "rate-state transition contains unreachable or unreviewed reducer code",
    )
    visiting: set[int] = set()
    visited: set[int] = set()

    def reject_cycle(address: int) -> None:
        _require(
            address not in visiting,
            "rate-state transition contains an unbounded control-flow cycle",
        )
        if address in visited:
            return
        visiting.add(address)
        for successor in successors[address]:
            reject_cycle(successor)
        visiting.remove(address)
        visited.add(address)

    reject_cycle(entry.address)
    returns = [
        instruction
        for instruction in instructions
        if _is_return_instruction(instruction)
    ]
    sinks = {
        address for address, outgoing in successors.items() if not outgoing
    }
    _require(
        len(returns) == 1 and sinks == {returns[0].address},
        "every rate-state transition path must terminate at one reviewed return",
    )

    predecessors: dict[int, set[int]] = {address: set() for address in reachable}
    for source in reachable:
        for target in successors[source]:
            predecessors[target].add(source)
    dominators: dict[int, set[int]] = {
        address: ({entry.address} if address == entry.address else set(reachable))
        for address in reachable
    }
    changed = True
    while changed:
        changed = False
        for address in reachable:
            if address == entry.address:
                continue
            incoming = predecessors[address]
            new = {address}
            if incoming:
                common = set(reachable)
                for predecessor in incoming:
                    common.intersection_update(dominators[predecessor])
                new.update(common)
            if new != dominators[address]:
                dominators[address] = new
                changed = True

    lock = next(
        transfer for transfer in transfers if transfer.target == "dbg_check_lock"
    )
    unlock = next(
        transfer for transfer in transfers if transfer.target == "dbg_check_unlock"
    )
    begin_call = next(
        transfer for transfer in transfers if transfer.target == begin.name
    )
    end_call = next(
        transfer for transfer in transfers if transfer.target == end.name
    )
    rate_call = next(
        transfer for transfer in transfers if transfer.target == rate_state.name
    )
    _require(
        lock.address in dominators[unlock.address]
        and lock.address in dominators[returns[0].address]
        and unlock.address in dominators[returns[0].address],
        "every rate-state transition return must pass the reviewed lock/unlock",
    )

    event_copies = [
        instruction
        for instruction in instructions
        if instruction.address < lock.address
        and instruction.mnemonic.startswith("mov")
        and len(_operand_registers(instruction)) >= 2
        and _operand_registers(instruction)[1] == "r1"
        and _operand_registers(instruction)[0]
        in {"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"}
    ]
    _require(
        len(event_copies) == 1,
        "rate-state transition must preserve event r1 in one callee-saved register",
    )
    event_register = _operand_registers(event_copies[0])[0]
    fatal_comparisons = [
        instruction
        for instruction in instructions
        if instruction.mnemonic.startswith("cmp")
        and _operand_registers(instruction)[:1] == (event_register,)
        and _has_immediate(instruction, 8)
    ]
    _require(
        len(fatal_comparisons) == 2,
        "rate-state transition must test Fatal event 8 before and after reduction",
    )
    first_fatal_branch = _next_non_nop(
        transition, fatal_comparisons[0].address
    )
    second_fatal_branch = _next_non_nop(
        transition, fatal_comparisons[1].address
    )
    _require(
        first_fatal_branch is not None
        and first_fatal_branch.mnemonic.startswith("beq")
        and second_fatal_branch is not None
        and second_fatal_branch.mnemonic.startswith("beq"),
        "Fatal event must be the sole branch that skips DMA begin/end exclusion",
    )
    reducer_entry = _branch_target_address(first_fatal_branch)
    _require(
        reducer_entry == rate_call.address - 2
        or reducer_entry == rate_call.address - 4
        or reducer_entry in addresses,
        "Fatal event branch has no reviewed reducer entry",
    )
    reducer_instruction = _instruction_at(transition, reducer_entry)
    _require(
        reducer_instruction is not None
        and reducer_instruction.address <= rate_call.address,
        "Fatal event branch does not enter the current-state reducer",
    )

    after_begin = [
        instruction
        for instruction in instructions
        if instruction.address > begin_call.address
        and not instruction.mnemonic.startswith("nop")
    ]
    _require(
        len(after_begin) >= 2
        and after_begin[0].mnemonic.startswith("mov")
        and _operand_registers(after_begin[0])[:2][1:] == ("r0",)
        and after_begin[1].mnemonic == "cbnz"
        and _branch_condition_register(after_begin[1]) == "r0"
        and _branch_target_address(after_begin[1]) == reducer_entry,
        "DMA exclusion begin result must be preserved and branch immediately "
        "into the reducer only on success",
    )
    accepted_register = _first_operand_register(after_begin[0])
    _require(
        accepted_register is not None,
        "rate-state transition does not preserve the begin/reducer result",
    )
    begin_failure_entry = _next_non_nop(
        transition, after_begin[1].address
    )
    _require(
        begin_failure_entry is not None,
        "DMA exclusion failure has no fail-closed state path",
    )

    state_stores = [
        instruction
        for instruction in instructions
        if instruction.mnemonic.startswith("strb")
        and _store_at_offset(instruction, 624)
    ]
    _require(
        len(state_stores) == 2,
        "rate-state transition must retain exactly two release-published "
        "offset-624 state stores",
    )
    failure_store, accepted_store = state_stores
    _require(
        begin_failure_entry.address <= failure_store.address < reducer_entry
        and table_branch.address < accepted_store.address,
        "rate-state transition state stores are outside their reviewed "
        "failure/accepted paths",
    )
    for description, store in (
        ("begin-failure FAULT", failure_store),
        ("accepted reducer state", accepted_store),
    ):
        source_register = _first_operand_register(store)
        shared_stores = [
            instruction
            for instruction in instructions
            if instruction.address < store.address
            and instruction.mnemonic.startswith("strb")
            and not _store_at_offset(instruction, 624)
            and _first_operand_register(instruction) == source_register
        ]
        _require(
            shared_stores,
            f"{description} must publish the same state to shared telemetry",
        )
        shared_store = shared_stores[-1]
        barriers = [
            instruction
            for instruction in instructions
            if shared_store.address < instruction.address < store.address
            and _dmb(instruction)
        ]
        _require(
            len(barriers) >= 2
            and lock.address in dominators[store.address],
            f"{description} must cross-core publish then release-store under lock",
        )

    failure_source = _first_operand_register(failure_store)
    failure_writer = (
        _last_register_writer(
            transition,
            failure_source,
            before=failure_store,
        )
        if failure_source is not None
        else None
    )
    _require(
        failure_writer is not None
        and failure_writer.mnemonic.startswith("mov")
        and _has_immediate(failure_writer, 5),
        "DMA exclusion failure must materialize and publish FAULT state 5",
    )
    failure_reachable = reachable_from(begin_failure_entry.address)
    _require(
        failure_store.address in failure_reachable
        and unlock.address in failure_reachable
        and rate_call.address not in failure_reachable
        and table_branch.address not in failure_reachable
        and accepted_store.address not in failure_reachable
        and end_call.address not in failure_reachable,
        "DMA exclusion failure must publish FAULT and unlock without reducing, "
        "publishing a non-fatal state, or re-enabling through end",
    )

    reducer_order = _require_ordered_instructions(
        transition,
        (
            (
                "sample the current rate state",
                lambda instruction: instruction.address == rate_call.address,
            ),
            (
                "normalize the eight-event table index",
                lambda instruction: instruction.mnemonic.startswith("sub")
                and event_register in _operand_registers(instruction)
                and _has_immediate(instruction, 1),
            ),
            (
                "bound the eight-event table index",
                lambda instruction: instruction.mnemonic.startswith("cmp")
                and _has_immediate(instruction, 7),
            ),
            (
                "dispatch the reviewed eight-event reducer",
                lambda instruction: instruction.address == table_branch.address,
            ),
        ),
    )
    _require(
        reducer_entry <= reducer_order[0].address
        and begin_call.address < reducer_entry,
        "rate-state reducer must run after the non-fatal DMA exclusion begin",
    )
    next_state_literals = {
        next(iter(_instruction_immediates(instruction)))
        for instruction in instructions
        if table_branch.address < instruction.address < accepted_store.address
        and instruction.mnemonic.startswith("mov")
        and _first_operand_register(instruction) == "r2"
        and len(_instruction_immediates(instruction)) == 1
    }
    _require(
        next_state_literals == {1, 2, 3, 4, 5},
        "rate-state reducer must retain the complete RUN/PREP/PAUSED/RESUME/"
        "FAULT next-state set",
    )

    acceptance_branches = [
        instruction
        for instruction in instructions
        if table_branch.address < instruction.address < accepted_store.address
        and instruction.mnemonic == "cbz"
    ]
    _require(
        len(acceptance_branches) == 1,
        "rate-state reducer must have one accepted-result publication guard",
    )
    acceptance_branch = acceptance_branches[0]
    acceptance_source = _branch_condition_register(acceptance_branch)
    acceptance_copies = [
        instruction
        for instruction in instructions
        if instruction.address < acceptance_branch.address
        and instruction.mnemonic.startswith("mov")
        and _operand_registers(instruction)[:2]
        == (accepted_register, acceptance_source)
    ]
    _require(
        len(acceptance_copies) == 1
        and _branch_target_address(acceptance_branch)
        == fatal_comparisons[1].address,
        "rate-state reducer must preserve its accepted result and skip state "
        "publication when false",
    )
    accepted_fallthrough = _next_non_nop(
        transition, acceptance_branch.address
    )
    _require(
        accepted_fallthrough is not None
        and accepted_store.address
        in reachable_from(accepted_fallthrough.address)
        and accepted_store.address
        not in reachable_from(_branch_target_address(acceptance_branch)),
        "only an accepted reducer result may reach the state publication",
    )

    unlock_target = _branch_target_address(second_fatal_branch)
    end_following = _next_non_nop(transition, second_fatal_branch.address)
    _require(
        unlock_target == unlock.address
        and end_following is not None
        and end_following.address == end_call.address
        and _next_non_nop(transition, end_call.address) == unlock,
        "non-fatal transitions must end DMA exclusion before unlock while "
        "Fatal skips that re-enable",
    )
    result_copies = [
        instruction
        for instruction in instructions
        if unlock.address < instruction.address < returns[0].address
        and instruction.mnemonic.startswith("mov")
        and _operand_registers(instruction)[:2]
        == ("r0", accepted_register)
    ]
    _require(
        len(result_copies) == 1,
        "rate-state transition must return the preserved accepted result",
    )

    return {
        "function": transition.name,
        "linked_code_bytes": linked_sizes,
        "scheduler_lock_exact": True,
        "priority1_dma_exclusion_exact": True,
        "fatal_skips_dma_reenable": True,
        "begin_failure_publishes_fault": True,
        "eight_event_tbb_words": [
            f"0x{value:08x}" for value in table_word_values if value is not None
        ],
        "accepted_state_release_published": True,
        "all_returns_unlock": True,
        "state_accessor_preserves_expected_argument": True,
        "irq_exclusion": irq_exclusion_report,
    }


def _verify_p12_commit_ack_dominance(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
    processor_message: Function,
    processor_rate_resume: Function,
    processor_publish_running: Function,
    execute: Function,
    execute_configure_call: Instruction,
    baseband_run: Function,
    run_wait_call: Instruction,
) -> dict[str, object]:
    """Bind COMMITTED to the first completely processed new-rate DMA block.

    The proof is deliberately calibrated to the optimized p12 artifact.  It
    follows the COMMIT literal into ``resume_rate_change``, proves that the
    acknowledgement value is preserved across the resume/poll loop, and then
    ties the only RUN publication to ``execute`` after a waiter-provided DMA
    buffer has been processed with the pending rate.
    """

    request_loads = _literal_loads(
        processor_message,
        literal_words,
        RATE_REQUEST_COMMIT,
    )
    process_complete_block = _unique_function(
        functions,
        "Precision RX complete-block processor",
        lambda name: name.startswith(PROCESSOR_COMPLETE_BLOCK_PREFIX),
    )
    process_complete_block_size = _unique_symbol_size(
        symbols,
        "Precision RX complete-block processor",
        lambda name: name.startswith(PROCESSOR_COMPLETE_BLOCK_PREFIX),
    )
    _require(
        process_complete_block_size <= MAX_PROCESS_COMPLETE_BLOCK_CODE_BYTES,
        "Precision RX complete-block processor grew to "
        f"{process_complete_block_size} bytes; maximum is "
        f"{MAX_PROCESS_COMPLETE_BLOCK_CODE_BYTES}",
    )
    complete_observe_calls = _calls_matching(
        process_complete_block,
        lambda name: name.startswith(METRICS_OBSERVE_BLOCK_PREFIX),
    )
    complete_publish_calls = _calls_matching(
        process_complete_block,
        lambda name: name.startswith(PROCESSOR_PUBLISH_PREFIX),
    )
    _require(
        len(complete_observe_calls) == 1 and len(complete_publish_calls) == 1,
        "complete-block processor must retain one metrics observation and one "
        "snapshot publication call",
    )
    committed_loads = _literal_loads(
        processor_message,
        literal_words,
        RATE_ACK_COMMITTED,
    )
    _require(
        len(request_loads) == 1,
        "p12 on_message must contain exactly one linked COMMIT request literal",
    )
    _require(
        len(committed_loads) == 1,
        "p12 on_message must contain exactly one linked COMMITTED ACK literal",
    )
    request_load = request_loads[0]
    committed_load = committed_loads[0]
    request_register = _first_operand_register(request_load)
    committed_register = _first_operand_register(committed_load)
    _require(
        request_register is not None and committed_register == "r2",
        "linked COMMIT dispatch must pass COMMITTED as resume argument r2",
    )

    message_resume_call = _require_one_call(
        processor_message,
        processor_rate_resume.name,
        lambda name: name == processor_rate_resume.name,
    )
    request_compare, request_branch = _compare_then_branch(
        processor_message,
        minimum_address=request_load.address,
        maximum_address=committed_load.address,
        register=request_register,
    )
    request_branch_mnemonic = request_branch.mnemonic.lower().split(".", 1)[0]
    _require(
        request_branch_mnemonic in {"beq", "bne"},
        "linked COMMIT request compare must select exactly one equality arm",
    )
    if request_branch_mnemonic == "beq":
        commit_target = _branch_target_address(request_branch)
    else:
        commit_fallthrough = _next_non_nop(
            processor_message,
            request_branch.address,
        )
        commit_target = (
            commit_fallthrough.address
            if commit_fallthrough is not None
            else None
        )
    commit_state_loads = [
        instruction
        for instruction in processor_message.instructions
        if commit_target is not None
        and commit_target <= instruction.address < committed_load.address
        and _load_at_offset(instruction, 624)
    ]
    commit_state_calls = [
        instruction
        for instruction in _calls(processor_message)
        if commit_target is not None
        and commit_target <= instruction.address < committed_load.address
        and instruction.target is not None
        and instruction.target.startswith("PrecisionRxProcessor::rate_state() const")
    ]
    _require(
        len(commit_state_loads) + len(commit_state_calls) == 1,
        "linked COMMIT branch must reach exactly one rate-state validation",
    )
    commit_state_validation = (
        commit_state_loads[0]
        if commit_state_loads
        else commit_state_calls[0]
    )
    commit_state_register = (
        _first_operand_register(commit_state_validation)
        if commit_state_loads
        else "r0"
    )
    _require(
        commit_state_register is not None,
        "COMMIT state validation has no result register",
    )
    _, commit_state_reject = _compare_then_branch(
        processor_message,
        minimum_address=commit_state_validation.address,
        maximum_address=committed_load.address,
        register=commit_state_register,
        immediate=RATE_STATE_PAUSED_ARMED,
        branch_prefix="bne",
    )
    commit_reject_target = _branch_target_address(commit_state_reject)
    commit_target_loads = [
        instruction
        for instruction in processor_message.instructions
        if commit_state_reject.address < instruction.address
        < committed_load.address
        and _load_at_offset(instruction, 636)
    ]
    _require(
        len(commit_target_loads) == 1
        and _first_operand_register(commit_target_loads[0]) == "r1",
        "COMMIT must pass the PREPARE-validated target rate as resume argument r1",
    )
    _require(
        request_compare.address < commit_state_validation.address
        < commit_target_loads[0].address < committed_load.address
        < message_resume_call.address
        and commit_reject_target is not None
        and commit_reject_target > commit_target_loads[0].address,
        "COMMIT state/target/ACK dispatch ordering is not fail-closed",
    )
    message_successors = _control_flow_successors(
        processor_message,
        reject_thumb_it=False,
    )
    reject_reachable: set[int] = set()
    reject_pending = [commit_reject_target]
    while reject_pending:
        address = reject_pending.pop()
        if address in reject_reachable or address not in message_successors:
            continue
        reject_reachable.add(address)
        reject_pending.extend(message_successors[address] - reject_reachable)
    _require(
        message_resume_call.address not in reject_reachable
        and any(
            instruction.address in reject_reachable
            and (
                _is_return_instruction(instruction)
                or _store_at_offset(instruction, 4)
            )
            for instruction in processor_message.instructions
        ),
        "COMMIT state rejection must reach a response/return without the "
        "resume call",
    )

    response_branch = _next_non_nop(
        processor_message,
        message_resume_call.address,
    )
    response_store = _instruction_at(
        processor_message,
        _branch_target_address(response_branch)
        if response_branch is not None
        else None,
    )
    _require(
        response_branch is not None
        and response_branch.mnemonic in {"b", "b.n", "b.w"}
        and response_store is not None
        and _store_at_offset(response_store, 4)
        and _first_operand_register(response_store) == "r0",
        "on_message must store the exact resume result directly into the "
        "rate-control response",
    )

    lower_resume_call = _require_one_call(
        processor_rate_resume,
        BASEBAND_RATE_RESUME_NAME,
        lambda name: name == BASEBAND_RATE_RESUME_NAME,
    )
    target_publications = [
        instruction
        for instruction in processor_rate_resume.instructions
        if instruction.address < lower_resume_call.address
        and _store_at_offset(instruction, 636)
    ]
    pending_publications = [
        instruction
        for instruction in processor_rate_resume.instructions
        if instruction.address < lower_resume_call.address
        and _store_at_offset(instruction, 620)
    ]
    _require(
        len(target_publications) == 1 and len(pending_publications) == 1,
        "resume_rate_change must uniquely publish target and pending rate "
        "before DMA resume",
    )
    target_publication = target_publications[0]
    pending_publication = pending_publications[0]
    ack_copies = [
        instruction
        for instruction in processor_rate_resume.instructions
        if instruction.address < target_publication.address
        and instruction.mnemonic.startswith("mov")
        and len(_operand_registers(instruction)) >= 2
        and _operand_registers(instruction)[1] == "r2"
        and _operand_registers(instruction)[0]
        in {"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"}
    ]
    _require(
        len(ack_copies) == 1,
        "resume_rate_change must preserve success ACK r2 in exactly one "
        "callee-saved register",
    )
    ack_copy = ack_copies[0]
    ack_register = _operand_registers(ack_copy)[0]
    publication_barriers = [
        instruction
        for instruction in processor_rate_resume.instructions
        if target_publication.address < instruction.address
        < pending_publication.address
        and _dmb(instruction)
    ]
    _require(
        ack_copy.address < target_publication.address
        < pending_publication.address < lower_resume_call.address
        and bool(publication_barriers),
        "resume_rate_change must preserve ACK and release-publish the target "
        "before DMA resume",
    )

    rate_wait_helper = _verify_p12_rate_wait_helper(
        symbols=symbols,
        functions=functions,
    )
    poll_wait_calls = [
        instruction
        for instruction in _calls(processor_rate_resume)
        if instruction.target == rate_wait_helper.name
    ]
    _require(
        len(poll_wait_calls) == 1
        and lower_resume_call.address < poll_wait_calls[0].address
        and _immediate_argument_before_call(
            processor_rate_resume,
            poll_wait_calls[0],
            "r1",
        )
        == RATE_STATE_RESUMING,
        "resume_rate_change must call the bounded post-resume state wait with "
        "RESUMING",
    )
    poll_state_load = poll_wait_calls[0]
    poll_result_branches = [
        instruction
        for instruction in processor_rate_resume.instructions
        if poll_state_load.address < instruction.address
        <= poll_state_load.address + 16
        and _is_conditional_branch(instruction)
        and _branch_condition_register(instruction) == "r0"
    ]
    _require(
        len(poll_result_branches) == 1,
        "resume_rate_change must branch on the bounded RESUMING wait result",
    )
    poll_branch = poll_result_branches[0]

    fault_call = _require_one_call(
        processor_rate_resume,
        DMA_FAULTED_NAME,
        lambda name: name == DMA_FAULTED_NAME,
    )
    direct_fault_branches = [
        instruction
        for instruction in processor_rate_resume.instructions
        if fault_call.address < instruction.address
        < fault_call.address + 20
        and instruction.mnemonic == "cbnz"
        and _branch_condition_register(instruction) == "r0"
    ]
    if direct_fault_branches:
        _require(
            len(direct_fault_branches) == 1,
            "fatal-DMA query must have one direct nonzero rejection branch",
        )
        fault_compare = direct_fault_branches[0]
        fault_branch = direct_fault_branches[0]
    else:
        fault_compare, fault_branch = _compare_then_branch(
            processor_rate_resume,
            minimum_address=fault_call.address,
            maximum_address=fault_call.address + 20,
            register="r0",
            immediate=0,
            branch_prefix="bne",
        )
    _require_register_preserved(
        processor_rate_resume,
        "r0",
        after=fault_call,
        before=fault_compare,
        description="fatal-DMA query result",
    )
    running_state_loads = [
        instruction
        for instruction in processor_rate_resume.instructions
        if fault_branch.address < instruction.address
        and _load_at_offset(instruction, 624)
    ]
    running_state_calls = [
        instruction
        for instruction in _calls(processor_rate_resume)
        if fault_branch.address < instruction.address
        and instruction.target is not None
        and instruction.target.startswith(PROCESSOR_RATE_STATE_PREFIX)
    ]
    _require(
        len(running_state_loads) + len(running_state_calls) == 1,
        "resume_rate_change must verify RUNNING after the first-block poll",
    )
    running_state_load = (
        running_state_loads[0]
        if running_state_loads
        else running_state_calls[0]
    )
    running_state_register = (
        _first_operand_register(running_state_load)
        if running_state_loads
        else "r0"
    )
    _require(running_state_register is not None, "RUNNING state load has no register")
    running_state_compare, running_state_branch = _compare_then_branch(
        processor_rate_resume,
        minimum_address=running_state_load.address,
        maximum_address=running_state_load.address + 20,
        register=running_state_register,
        immediate=RATE_STATE_RUNNING,
        branch_prefix="bne",
    )
    _require_register_preserved(
        processor_rate_resume,
        running_state_register,
        after=running_state_load,
        before=running_state_compare,
        description="RUNNING-state load",
    )
    baseline_loads = [
        instruction
        for instruction in processor_rate_resume.instructions
        if running_state_branch.address < instruction.address
        and _load_at_offset(instruction, 640)
    ]
    _require(
        bool(baseline_loads),
        "resume_rate_change must compare lifetime loss with its PREPARE baseline",
    )
    baseline_load = baseline_loads[0]
    baseline_register = _first_operand_register(baseline_load)
    _require(baseline_register is not None, "loss baseline load has no register")
    loss_compare, loss_branch = _compare_then_branch(
        processor_rate_resume,
        minimum_address=baseline_load.address,
        maximum_address=baseline_load.address + 32,
        register=baseline_register,
    )
    loss_branch_mnemonic = loss_branch.mnemonic.lower().split(".", 1)[0]
    _require(
        loss_branch_mnemonic in {"beq", "bne"},
        "lifetime-loss comparison must select exactly one equality arm",
    )
    loss_compare_registers = _operand_registers(loss_compare)[:2]
    _require(
        len(loss_compare_registers) == 2
        and baseline_register in loss_compare_registers
        and loss_compare_registers[0] != loss_compare_registers[1],
        "lifetime-loss validation must compare the baseline with a distinct "
        "current-counter register",
    )
    current_loss_register = next(
        register
        for register in loss_compare_registers
        if register != baseline_register
    )
    current_loss_loads = []
    current_loss_address_evidence: tuple[Instruction, ...] = ()
    for instruction in processor_rate_resume.instructions:
        if not (
            running_state_branch.address < instruction.address
            < loss_compare.address
            and instruction.mnemonic.startswith("ldr")
            and _first_operand_register(instruction) == current_loss_register
        ):
            continue
        recovered = _linked_word_load_address(
            processor_rate_resume,
            instruction,
            literal_words=literal_words,
        )
        if (
            recovered is not None
            and recovered[0] == M4_DMA_MISSED_LIFETIME_ADDRESS
        ):
            current_loss_loads.append(instruction)
            current_loss_address_evidence = recovered[1]
    _require(
        len(current_loss_loads) == 1,
        "resume_rate_change must bind its current lifetime-loss operand to "
        f"shared_memory.m4_dma_missed_lifetime at "
        f"0x{M4_DMA_MISSED_LIFETIME_ADDRESS:08x}",
    )
    current_loss_load = current_loss_loads[0]
    _require_register_preserved(
        processor_rate_resume,
        baseline_register,
        after=baseline_load,
        before=loss_compare,
        description="lifetime-loss baseline",
    )
    _require_register_preserved(
        processor_rate_resume,
        current_loss_register,
        after=current_loss_load,
        before=loss_compare,
        description="current lifetime-loss sample",
    )

    success_moves = [
        instruction
        for instruction in processor_rate_resume.instructions
        if instruction.address > loss_branch.address
        and instruction.mnemonic.startswith("mov")
        and _operand_registers(instruction)[:2] == ("r0", ack_register)
    ]
    _require(
        len(success_moves) == 1,
        "resume_rate_change must return the preserved COMMITTED ACK exactly once",
    )
    success_move = success_moves[0]
    success_tail = [
        instruction
        for instruction in processor_rate_resume.instructions
        if success_move.address < instruction.address
        and not instruction.mnemonic.startswith("nop")
    ][:3]
    success_return = next(
        (
            instruction
            for instruction in success_tail
            if _is_return_instruction(instruction)
        ),
        None,
    )
    _require(
        success_return is not None
        and not any(
            _writes_register(instruction, "r0")
            for instruction in success_tail
            if instruction.address < success_return.address
        ),
        "COMMITTED ACK must return without modification immediately after all "
        "success guards",
    )
    resume_successors = _control_flow_successors(
        processor_rate_resume,
        reject_thumb_it=False,
    )

    def reachable_from(start: int | None) -> frozenset[int]:
        reachable: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reachable or address not in resume_successors:
                continue
            reachable.add(address)
            pending.extend(resume_successors[address] - reachable)
        return frozenset(reachable)

    loss_fallthrough = _next_non_nop(
        processor_rate_resume,
        loss_branch.address,
    )
    loss_equal_start = (
        _branch_target_address(loss_branch)
        if loss_branch_mnemonic == "beq"
        else (
            loss_fallthrough.address
            if loss_fallthrough is not None
            else None
        )
    )
    loss_mismatch_start = (
        _branch_target_address(loss_branch)
        if loss_branch_mnemonic == "bne"
        else (
            loss_fallthrough.address
            if loss_fallthrough is not None
            else None
        )
    )
    failure_starts = (
        _branch_target_address(fault_branch),
        _branch_target_address(running_state_branch),
        loss_mismatch_start,
    )

    instructions_by_address = {
        instruction.address: instruction
        for instruction in processor_rate_resume.instructions
    }

    def write_states_at_target(
        start: int | None,
        target: int,
    ) -> frozenset[bool]:
        pending: list[tuple[int, bool]] = (
            [(start, False)] if start is not None else []
        )
        visited: set[tuple[int, bool]] = set()
        reached: set[bool] = set()
        while pending:
            address, wrote = pending.pop()
            state = (address, wrote)
            if state in visited or address not in resume_successors:
                continue
            visited.add(state)
            if address == target:
                reached.add(wrote)
                continue
            instruction = instructions_by_address[address]
            next_wrote = wrote or _writes_register(
                instruction,
                ack_register,
            )
            pending.extend(
                (successor, next_wrote)
                for successor in resume_successors[address]
            )
        return frozenset(reached)

    success_path_ack_overwrites = [
        instruction
        for instruction in processor_rate_resume.instructions
        if ack_copy.address < instruction.address < loss_compare.address
        and _writes_register(instruction, ack_register)
        and loss_compare.address in reachable_from(instruction.address)
    ]
    _require(
        fault_compare.address < running_state_load.address
        < baseline_load.address < success_move.address
        and not success_path_ack_overwrites
        and success_move.address in reachable_from(loss_equal_start)
        and write_states_at_target(
            loss_equal_start,
            success_move.address,
        )
        == frozenset({False})
        and all(
            start is not None
            and loss_compare.address not in reachable_from(start)
            and False not in write_states_at_target(
                start,
                success_move.address,
            )
            for start in failure_starts
        ),
        "preserved COMMITTED ACK register is overwritten; DMA fault, "
        "non-RUNNING state, or lifetime loss must bypass COMMITTED",
    )
    resume_it_indices = [
        index
        for index, instruction in enumerate(processor_rate_resume.instructions)
        if re.fullmatch(
            r"it[te]{0,3}",
            instruction.mnemonic.lower().split(".", 1)[0],
        )
    ]
    for index in resume_it_indices:
        block = processor_rate_resume.instructions[index : index + 5]
        predicated_moves = block[1:3]
        _require(
            len(block) == 5
            and block[0].mnemonic.lower().split(".", 1)[0] == "ite"
            and len(predicated_moves) == 2
            and all(
                instruction.mnemonic.startswith("mov")
                and _first_operand_register(instruction) == "r1"
                for instruction in predicated_moves
            )
            and {
                value
                for instruction in predicated_moves
                for value in _instruction_immediates(instruction)
            }
            == {4, 5}
            and block[-1].target is not None
            and block[-1].target.startswith(
                "PrecisionRxProcessor::transition_rate_state("
            ),
            "resume_rate_change contains an unreviewed Thumb IT block",
        )
    bootstrap_start_calls = _calls_matching(
        processor_rate_resume,
        lambda name: name == "BasebandThread::start()",
    )
    _require(
        len(bootstrap_start_calls) <= 1,
        "resume_rate_change has multiple bootstrap DMA start sites",
    )
    activation_addresses = {
        lower_resume_call.address,
        *(call.address for call in bootstrap_start_calls),
    }
    reachable_without_activation: set[int] = set()
    activation_pending = [processor_rate_resume.instructions[0].address]
    while activation_pending:
        address = activation_pending.pop()
        if (
            address in reachable_without_activation
            or address in activation_addresses
        ):
            continue
        reachable_without_activation.add(address)
        activation_pending.extend(
            resume_successors.get(address, frozenset())
            - reachable_without_activation
        )
    _require(
        loss_branch.address not in reachable_without_activation,
        "every COMMITTED path must cross bootstrap start or DMA resume",
    )
    _require_cfg_dominance(
        processor_rate_resume,
        start=processor_rate_resume.instructions[0],
        target=loss_branch,
        required=(
            ("COMMITTED ACK preservation", ack_copy),
            ("target-rate publication", target_publication),
            ("pending-rate publication", pending_publication),
            ("release barrier before DMA resume", publication_barriers[-1]),
            ("RESUMING poll", poll_state_load),
            ("fatal-DMA query", fault_call),
            ("fatal-DMA rejection branch", fault_branch),
            ("RUNNING-state validation", running_state_load),
            ("non-RUNNING rejection branch", running_state_branch),
            ("lifetime-loss validation", baseline_load),
            (
                "linked current lifetime-loss counter load",
                current_loss_load,
            ),
            ("lifetime-loss rejection branch", loss_branch),
            *tuple(
                (
                    "current lifetime-loss address materialization",
                    instruction,
                )
                for instruction in current_loss_address_evidence
            ),
        ),
        reject_thumb_it=False,
    )

    post_configure = Function(
        execute.address,
        execute.name,
        tuple(
            instruction
            for instruction in execute.instructions
            if instruction.address > execute_configure_call.address
        ),
    )
    configure_tail = _require_ordered_instructions(
        post_configure,
        (
            ("configure publication DMB", _dmb),
            (
                "clear value for consumed pending rate",
                lambda ins: ins.mnemonic.startswith("mov")
                and _has_immediate(ins, 0),
            ),
            (
                "clear consumed pending rate",
                lambda ins: _store_at_offset(ins, 620),
            ),
            (
                "mark this as the first new-rate block",
                lambda ins: ins.mnemonic.startswith("mov")
                and _has_immediate(ins, 1),
            ),
            (
                "branch into first-block processing",
                lambda ins: ins.mnemonic in {"b", "b.n", "b.w"},
            ),
        ),
    )
    clear_value, pending_clear, first_marker, marker_branch = configure_tail[1:]
    clear_register = _first_operand_register(clear_value)
    marker_register = _first_operand_register(first_marker)
    block_complete_call = _require_one_call(
        execute,
        process_complete_block.name,
        lambda name: name == process_complete_block.name,
    )
    block_failure_branch = _require_zero_failure_branch_after_call(
        execute,
        block_complete_call,
        "complete-block processing",
    )
    marker_branch_target = _instruction_at(
        execute,
        _branch_target_address(marker_branch),
    )
    _require(
        clear_register is not None
        and _first_operand_register(pending_clear) == clear_register
        and marker_register is not None
        and marker_branch_target is not None,
        "execute must publish the pending-rate clear and enter common "
        "first-block processing",
    )
    stack_marker = (
        _memory_location(marker_branch_target) == ("r13", 16)
        and _first_operand_register(marker_branch_target) == marker_register
    )
    if stack_marker:
        marker_entry_branch = None
        _require(
            marker_register == clear_register,
            "stack first-block marker must use the reviewed clear register",
        )
        marker_anchor = marker_branch_target
        marker_loads = [
            instruction
            for instruction in execute.instructions
            if instruction.address > marker_anchor.address
            and instruction.mnemonic.startswith("ldr")
            and _memory_location(instruction) == ("r13", 16)
        ]
        _require(
            len(marker_loads) == 1,
            "execute must consume the first-new-rate marker exactly once",
        )
        marker_load = marker_loads[0]
        marker_load_register = _first_operand_register(marker_load)
        _require(
            marker_load_register is not None,
            "first-block marker load has no register",
        )
        _, marker_nonzero_branch = _compare_then_branch(
            execute,
            minimum_address=marker_load.address,
            maximum_address=marker_load.address + 16,
            register=marker_load_register,
            immediate=0,
            branch_prefix="bne",
        )
        marker_storage = "stack"
    else:
        _require(
            marker_register
            in {"r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"}
            and marker_branch_target.address < first_marker.address,
            "register first-block marker must be callee-saved and branch "
            "back to common processing",
        )
        marker_branches = [
            instruction
            for instruction in execute.instructions
            if instruction.address > block_failure_branch.address
            and instruction.mnemonic == "cbnz"
            and _branch_condition_register(instruction) == marker_register
        ]
        _require(
            len(marker_branches) == 1,
            "execute must consume its register first-block marker exactly once",
        )
        marker_anchor = first_marker
        marker_load = marker_branches[0]
        marker_nonzero_branch = marker_branches[0]
        marker_entry_loads = [
            instruction
            for instruction in execute.instructions
            if instruction.address < execute_configure_call.address
            and _load_at_offset(instruction, 620)
            and _first_operand_register(instruction) == marker_register
        ]
        _require(
            len(marker_entry_loads) == 1,
            "register marker must originate from the pending-rate load",
        )
        marker_entry_branches = [
            instruction
            for instruction in execute.instructions
            if marker_entry_loads[0].address < instruction.address
            < block_complete_call.address
            and instruction.mnemonic == "cbnz"
            and _branch_condition_register(instruction) == marker_register
        ]
        _require(
            len(marker_entry_branches) == 1,
            "pending-rate nonzero branch must select the configure path",
        )
        marker_entry_branch = marker_entry_branches[0]
        marker_storage = "callee-saved-register"
    publish_state_load = _instruction_at(
        execute,
        _branch_target_address(marker_nonzero_branch),
    )
    _require(
        publish_state_load is not None and _load_at_offset(publish_state_load, 624),
        "nonzero first-block marker must enter at RESUMING-state validation",
    )
    publish_state_register = _first_operand_register(publish_state_load)
    _require(publish_state_register is not None, "publish state load has no register")
    _, publish_state_reject = _compare_then_branch(
        execute,
        minimum_address=publish_state_load.address,
        maximum_address=publish_state_load.address + 20,
        register=publish_state_register,
        immediate=RATE_STATE_RESUMING,
        branch_prefix="bne",
    )
    publish_call = _require_one_call(
        execute,
        processor_publish_running.name,
        lambda name: name == processor_publish_running.name,
    )
    publish_reject_target = _branch_target_address(publish_state_reject)
    block_failure_target = _branch_target_address(block_failure_branch)
    execute_successors = _control_flow_successors(execute)

    def execute_reachable(start: int | None) -> frozenset[int]:
        reachable: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reachable or address not in execute_successors:
                continue
            reachable.add(address)
            pending.extend(execute_successors[address] - reachable)
        return frozenset(reachable)

    publish_success_entry = _next_non_nop(
        execute,
        publish_state_reject.address,
    )
    _require(
        any(
            publish_state_load.address < instruction.address
            < publish_call.address
            and _operand_registers(instruction)[:2]
            == ("r1", publish_state_register)
            for instruction in execute.instructions
        )
        and publish_state_reject.address < publish_call.address
        and publish_reject_target is not None
        and block_failure_target is not None
        and publish_success_entry is not None
        and publish_call.address
        in execute_reachable(publish_success_entry.address)
        and publish_call.address
        not in execute_reachable(publish_reject_target)
        and publish_call.address
        not in execute_reachable(block_failure_target),
        "execute must pass RESUMING to the RUN publisher and bypass it for "
        "every other state",
    )
    if stack_marker:
        marker_slot_stores = [
            instruction
            for instruction in execute.instructions
            if marker_anchor.address <= instruction.address < marker_load.address
            and instruction.mnemonic.startswith("str")
            and _memory_location(instruction) == ("r13", 16)
        ]
        _require(
            marker_slot_stores == [marker_anchor],
            "first-new-rate marker stack slot must not be overwritten before "
            "publication validation",
        )
    else:
        marker_path_start = _next_non_nop(execute, marker_anchor.address)
        instructions_by_address = {
            instruction.address: instruction
            for instruction in execute.instructions
        }

        def marker_write_states(
            start: int | None,
            target: int,
        ) -> frozenset[bool]:
            pending: list[tuple[int, bool]] = (
                [(start, False)] if start is not None else []
            )
            visited: set[tuple[int, bool]] = set()
            reached: set[bool] = set()
            while pending:
                address, clobbered = pending.pop()
                state = (address, clobbered)
                if state in visited or address not in execute_successors:
                    continue
                visited.add(state)
                if address == target:
                    reached.add(clobbered)
                    continue
                instruction = instructions_by_address[address]
                next_clobbered = clobbered or _writes_register(
                    instruction,
                    marker_register,
                )
                pending.extend(
                    (successor, next_clobbered)
                    for successor in execute_successors[address]
                )
            return frozenset(reached)

        marker_target_states = marker_write_states(
            marker_path_start.address
            if marker_path_start is not None
            else None,
            marker_load.address,
        )
        nonconfigure_start = _next_non_nop(
            execute,
            marker_entry_branch.address,
        )
        nonconfigure_states = marker_write_states(
            nonconfigure_start.address
            if nonconfigure_start is not None
            else None,
            marker_load.address,
        )
        _require(
            marker_target_states == frozenset({False})
            and nonconfigure_states == frozenset({False}),
            "callee-saved first-new-rate marker is overwritten before "
            "publication validation",
        )
        configure_entry = _instruction_at(
            execute,
            _branch_target_address(marker_entry_branch),
        )
        _require(
            configure_entry is not None,
            "pending-rate branch has no configure-path entry",
        )
        _require_cfg_dominance(
            execute,
            start=configure_entry,
            target=marker_anchor,
            required=(
                ("pending-rate configure", execute_configure_call),
                ("consumed pending-rate clear", pending_clear),
            ),
        )
    marker_dominance = (
        (("first-new-rate marker publication", marker_anchor),)
        if stack_marker
        else ()
    )
    _require_cfg_dominance(
        execute,
        start=execute.instructions[0],
        target=publish_call,
        required=(
            *marker_dominance,
            (
                "complete first-new-rate block processing",
                block_complete_call,
            ),
            (
                "failed complete-block rejection branch",
                block_failure_branch,
            ),
            ("first-block completion marker consumption", marker_load),
            ("RESUMING-state validation", publish_state_load),
            ("non-RESUMING rejection branch", publish_state_reject),
        ),
    )

    linked_control_common = {
        "commit_request_literal": f"0x{RATE_REQUEST_COMMIT:08x}",
        "committed_ack_literal": f"0x{RATE_ACK_COMMITTED:08x}",
        "commit_dispatch_validates_paused_armed": True,
        "commit_dispatch_uses_prepared_target": True,
        "resume_preserves_committed_ack": True,
        "resume_polls_past_resuming": True,
        "resume_rejects_dma_fault": True,
        "resume_requires_running_state": True,
        "resume_requires_unchanged_lifetime_loss": True,
        "wait_precedes_processor_execute": True,
        "first_buffer_configures_pending_rate": True,
        "first_buffer_marker_survives_processing": True,
        "first_buffer_marker_storage": (
            "stack-slot-16"
            if stack_marker
            else f"callee-saved-{marker_register}"
        ),
        "complete_block_function": process_complete_block.name,
        "complete_block_code_bytes": process_complete_block_size,
        "complete_block_result_gates_run_publication": True,
        "complete_block_metrics_observation_bound": True,
        "complete_block_snapshot_publication_bound": True,
        "first_buffer_processing_cfg_dominates_run_publication": True,
        "running_publication_requires_resuming": True,
        "commit_ack_dominated_by_first_new_rate_completion": True,
    }
    indirect_execute_calls = [
        instruction
        for instruction in baseband_run.instructions
        if instruction.mnemonic == "blx" and instruction.target is None
    ]
    _require(
        len(indirect_execute_calls) == 1
        and run_wait_call.address < indirect_execute_calls[0].address,
        "BasebandThread must obtain a completed DMA buffer before invoking "
        "processor execute",
    )

    publisher_external_transfers = _external_control_transfers(
        processor_publish_running
    )
    publisher_transition_transfers = [
        instruction
        for instruction in publisher_external_transfers
        if instruction.target is not None
        and instruction.target.startswith(PROCESSOR_TRANSITION_RATE_STATE_PREFIX)
    ]
    if publisher_transition_transfers:
        _require(
            len(publisher_transition_transfers) == 1,
            "RUN publisher must delegate to exactly one rate-state transition",
        )
        transition_report = _verify_p12_transition_rate_state(
            symbols=symbols,
            functions=functions,
            literal_words=literal_words,
        )
        rate_state = _unique_function(
            functions,
            "rate-state accessor",
            lambda name: name.startswith(PROCESSOR_RATE_STATE_PREFIX),
        )
        transition_target = publisher_transition_transfers[0].target
        _require(
            transition_target is not None,
            "RUN publisher transition tail has no linked target",
        )
        publisher_size = _unique_symbol_size(
            symbols,
            "RUN publisher",
            lambda name: name.startswith(PROCESSOR_PUBLISH_RUNNING_PREFIX),
        )
        _require(
            publisher_size <= 64,
            f"delegating RUN publisher grew to {publisher_size} bytes; "
            "maximum is 64",
        )
        _require_transfer_targets(
            processor_publish_running,
            frozenset({rate_state.name, transition_target}),
        )
        publisher_rate_calls = [
            instruction
            for instruction in publisher_external_transfers
            if instruction.target == rate_state.name
        ]
        _require(
            len(publisher_rate_calls) == 1
            and len(publisher_external_transfers) == 2,
            "delegating RUN publisher must contain only one state sample and "
            "one transition tail",
        )
        _require(
            not any(
                instruction.mnemonic.startswith("str")
                and _store_at_offset(instruction, 624)
                for instruction in processor_publish_running.instructions
            ),
            "delegating RUN publisher must not store rate state outside the "
            "guarded transition",
        )
        state_call = publisher_rate_calls[0]
        state_comparison = _next_non_nop(
            processor_publish_running, state_call.address
        )
        mismatch_branch = (
            _next_non_nop(
                processor_publish_running, state_comparison.address
            )
            if state_comparison is not None
            else None
        )
        _require(
            state_comparison is not None
            and state_comparison.mnemonic.startswith("cmp")
            and _operand_registers(state_comparison)[:2] == ("r0", "r1")
            and mismatch_branch is not None
            and mismatch_branch.mnemonic.startswith("bne"),
            "delegating RUN publisher must compare the sampled state with "
            "expected r1 and reject mismatch immediately",
        )
        _require(
            not any(
                _writes_register(instruction, "r1")
                for instruction in processor_publish_running.instructions
                if instruction.address < state_comparison.address
            ),
            "delegating RUN publisher overwrites expected state r1 before "
            "comparison",
        )
        mismatch_target = _branch_target_address(mismatch_branch)
        mismatch_entry = _instruction_at(
            processor_publish_running, mismatch_target
        )
        success_entry = _next_non_nop(
            processor_publish_running, mismatch_branch.address
        )
        transition_tail = publisher_transition_transfers[0]
        _require(
            mismatch_entry is not None and success_entry is not None,
            "delegating RUN publisher has an unresolved equality branch",
        )
        publisher_successors = _control_flow_successors(
            processor_publish_running
        )

        def publisher_reachable(start: int | None) -> frozenset[int]:
            reached: set[int] = set()
            pending = [start] if start is not None else []
            while pending:
                address = pending.pop()
                if address in reached or address not in publisher_successors:
                    continue
                reached.add(address)
                pending.extend(publisher_successors[address] - reached)
            return frozenset(reached)

        equality_reachable = publisher_reachable(success_entry.address)
        mismatch_reachable = publisher_reachable(mismatch_entry.address)
        _require(
            transition_tail.address in equality_reachable
            and transition_tail.address not in mismatch_reachable,
            "state mismatch must not reach the guarded RUN transition",
        )
        event_values = [
            instruction
            for instruction in processor_publish_running.instructions
            if instruction.mnemonic.startswith("mov")
            and _first_operand_register(instruction) == "r1"
            and len(_instruction_immediates(instruction)) == 1
        ]
        _require(
            len(event_values) == 2
            and {
                next(iter(_instruction_immediates(instruction)))
                for instruction in event_values
            }
            == {3, 7},
            "RUN publisher must select only PrepareHaltRestored event 3 or "
            "FirstBlockApplied event 7",
        )
        prepare_comparisons = [
            instruction
            for instruction in processor_publish_running.instructions
            if mismatch_branch.address < instruction.address
            < transition_tail.address
            and instruction.mnemonic.startswith("cmp")
            and _operand_registers(instruction)[:1] == ("r0",)
            and _has_immediate(instruction, 2)
        ]
        _require(
            len(prepare_comparisons) == 1
            and (
                prepare_branch := _next_non_nop(
                    processor_publish_running,
                    prepare_comparisons[0].address,
                )
            )
            is not None
            and prepare_branch.mnemonic.startswith("beq"),
            "RUN publisher must select event 3 only for PrepareRequested "
            "state 2",
        )
        equality_sinks = {
            address
            for address in equality_reachable
            if not publisher_successors[address]
        }
        mismatch_sinks = {
            address
            for address in mismatch_reachable
            if not publisher_successors[address]
        }
        mismatch_zero_values = [
            instruction
            for instruction in processor_publish_running.instructions
            if instruction.address in mismatch_reachable
            and instruction.mnemonic.startswith("mov")
            and _first_operand_register(instruction) == "r0"
            and _has_immediate(instruction, 0)
        ]
        _require(
            equality_sinks == {transition_tail.address}
            and transition_tail.address not in mismatch_sinks
            and len(mismatch_zero_values) == 1,
            "RUN publisher equality paths must tail-call the transition while "
            "the mismatch path returns false",
        )
        return {
            **linked_control_common,
            "running_publication_delegates_guarded_transition": True,
            "running_publication_rejects_fatal_dma": True,
            "running_publication_fatal_latch_symbol_bound": True,
            "rate_state_transition": transition_report,
        }

    publisher_lock_calls = _calls_matching(
        processor_publish_running,
        lambda name: name == "dbg_check_lock",
    )
    publisher_unlock_calls = _calls_matching(
        processor_publish_running,
        lambda name: name == "dbg_check_unlock",
    )
    _require(
        len(publisher_lock_calls) == 1 and len(publisher_unlock_calls) == 1,
        "RUN publisher must retain one reviewed ChibiOS lock/unlock region",
    )
    publisher_lock = publisher_lock_calls[0]
    publisher_unlock = publisher_unlock_calls[0]
    expected_copies = [
        instruction
        for instruction in processor_publish_running.instructions
        if instruction.address < publisher_lock.address
        and instruction.mnemonic.startswith("mov")
        and len(_operand_registers(instruction)) >= 2
        and _operand_registers(instruction)[1] == "r1"
    ]
    _require(
        len(expected_copies) == 1,
        "RUN publisher must preserve its expected state argument",
    )
    expected_register = _operand_registers(expected_copies[0])[0]
    publisher_state_loads = [
        instruction
        for instruction in processor_publish_running.instructions
        if publisher_lock.address < instruction.address < publisher_unlock.address
        and _load_at_offset(instruction, 624)
    ]
    _require(
        len(publisher_state_loads) == 1,
        "RUN publisher must load the current rate state once under lock",
    )
    publisher_state_load = publisher_state_loads[0]
    publisher_state_register = _first_operand_register(publisher_state_load)
    _require(publisher_state_register is not None, "publisher state load has no register")
    fatal_loads = [
        instruction
        for instruction in processor_publish_running.instructions
        if publisher_lock.address < instruction.address
        < publisher_state_load.address
        and instruction.mnemonic.startswith("ldrb")
        and _memory_offset(instruction, 0)
    ]
    _require(
        len(fatal_loads) == 1,
        "RUN publisher must sample the fatal DMA latch under lock",
    )
    fatal_register = _first_operand_register(fatal_loads[0])
    _require(fatal_register is not None, "fatal latch load has no register")
    fatal_latch_symbols = [
        symbol
        for symbol in symbols
        if symbol.name == DMA_FATAL_LATCH_NAME
    ]
    _require(
        len(fatal_latch_symbols) == 1
        and fatal_latch_symbols[0].kind.lower() == "b"
        and fatal_latch_symbols[0].size == 1,
        "RUN publisher requires one linked one-byte fatal DMA latch symbol",
    )
    fatal_location = _memory_location(fatal_loads[0])
    _require(
        fatal_location is not None and fatal_location[1] == 0,
        "fatal DMA latch must be loaded at offset zero from its linked base",
    )
    fatal_base_register = fatal_location[0]
    fatal_base_writers = [
        instruction
        for instruction in processor_publish_running.instructions
        if publisher_lock.address < instruction.address < fatal_loads[0].address
        and _writes_register(instruction, fatal_base_register)
    ]
    _require(
        bool(fatal_base_writers),
        "RUN publisher does not materialize the fatal DMA latch address",
    )
    fatal_base_writer = fatal_base_writers[-1]
    fatal_literal_target = _pc_literal_target(fatal_base_writer)
    _require(
        fatal_base_writer.mnemonic.startswith("ldr")
        and fatal_literal_target is not None
        and literal_words.get(fatal_literal_target)
        == fatal_latch_symbols[0].address,
        "RUN publisher fatal test is not linked to dma_fatal_latched",
    )
    fatal_branches = [
        instruction
        for instruction in processor_publish_running.instructions
        if publisher_state_load.address < instruction.address
        < publisher_unlock.address
        and _is_conditional_branch(instruction)
        and _branch_condition_register(instruction) == fatal_register
    ]
    _require(
        len(fatal_branches) == 1
        and fatal_branches[0].mnemonic == "cbnz",
        "RUN publisher must reject a latched DMA fault before state transition",
    )
    _require_register_preserved(
        processor_publish_running,
        fatal_register,
        after=fatal_loads[0],
        before=fatal_branches[0],
        description="linked fatal DMA latch sample",
    )
    state_comparisons = [
        instruction
        for instruction in processor_publish_running.instructions
        if fatal_branches[0].address < instruction.address
        < publisher_unlock.address
        and instruction.mnemonic.startswith("cmp")
        and set(_operand_registers(instruction)[:2])
        == {expected_register, publisher_state_register}
    ]
    _require(
        len(state_comparisons) == 1,
        "RUN publisher must compare current and expected state under lock",
    )
    _require_register_preserved(
        processor_publish_running,
        publisher_state_register,
        after=publisher_state_load,
        before=state_comparisons[0],
        description="RUN publisher current state",
    )
    _require_register_preserved(
        processor_publish_running,
        expected_register,
        after=expected_copies[0],
        before=state_comparisons[0],
        description="RUN publisher expected state",
    )
    success_branch = _next_non_nop(
        processor_publish_running,
        state_comparisons[0].address,
        limit=publisher_unlock.address,
    )
    success_target = _branch_target_address(success_branch) if success_branch else None
    _require(
        success_branch is not None
        and success_branch.mnemonic.startswith("beq")
        and success_target is not None,
        "RUN publisher must enter its RUNNING path only on state equality",
    )
    success_path = [
        instruction
        for instruction in processor_publish_running.instructions
        if success_target <= instruction.address
    ]
    running_values = [
        instruction
        for instruction in success_path
        if instruction.mnemonic.startswith("mov")
        and _has_immediate(instruction, RATE_STATE_RUNNING)
    ]
    _require(
        len(running_values) == 1,
        "RUN publisher success path must materialize RUNNING exactly once",
    )
    running_value = running_values[0]
    running_register = _first_operand_register(running_value)
    common_branches = [
        instruction
        for instruction in success_path
        if instruction.address > running_value.address
        and instruction.mnemonic in {"b", "b.n", "b.w"}
    ]
    _require(
        bool(common_branches),
        "RUN publisher success path must branch into its locked publication",
    )
    common_target = _branch_target_address(common_branches[0])
    running_stores = [
        instruction
        for instruction in processor_publish_running.instructions
        if common_target is not None
        and common_target <= instruction.address
        and _store_at_offset(instruction, 624)
        and _first_operand_register(instruction) == running_register
    ]
    _require(
        len(running_stores) == 1
        and any(
            common_target <= instruction.address < running_stores[0].address
            and _dmb(instruction)
            for instruction in processor_publish_running.instructions
        ),
        "RUN publisher must release-publish RUNNING under the reviewed lock",
    )
    _require_register_preserved(
        processor_publish_running,
        running_register,
        after=running_value,
        before=running_stores[0],
        description="RUNNING publication value",
    )
    _require_cfg_dominance(
        processor_publish_running,
        start=processor_publish_running.instructions[0],
        target=running_value,
        required=(
            ("reviewed system lock", publisher_lock),
            ("linked fatal DMA latch load", fatal_loads[0]),
            ("fatal DMA rejection branch", fatal_branches[0]),
            ("expected-state comparison", state_comparisons[0]),
            ("state-equality branch", success_branch),
        ),
    )
    store_to_unlock = _next_non_nop(
        processor_publish_running,
        running_stores[0].address,
    )
    _require(
        store_to_unlock is not None
        and store_to_unlock.mnemonic in {"b", "b.n", "b.w"}
        and _branch_target_address(store_to_unlock) == publisher_unlock.address,
        "RUNNING publication must flow directly to the lock release",
    )

    return {
        **linked_control_common,
        "running_publication_delegates_guarded_transition": False,
        "running_publication_rejects_fatal_dma": True,
        "running_publication_fatal_latch_symbol_bound": True,
        "rate_state_transition": None,
    }


def _load_at_offset(instruction: Instruction, offset: int) -> bool:
    return instruction.mnemonic.startswith("ldr") and _memory_offset(
        instruction, offset
    )


def _store_at_offset(instruction: Instruction, offset: int) -> bool:
    return instruction.mnemonic.startswith("str") and _memory_offset(
        instruction, offset
    )


def _verify_p14_control_active_drain(
    *,
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove the rate-control HALT drain uses the reviewed DWT deadline.

    The linked sequence must reject a disabled trace/cycle counter before
    publishing HALT, sample CYCCNT only after HALT+DMB, and use unsigned
    ``now - start`` arithmetic.  The compiler encodes the exact
    ``elapsed >= 2,000,000`` boundary as ``elapsed <= 1,999,999`` looping
    back to the ACTIVE sample.  A final, distinct ACTIVE sample separates
    the timeout H-only rollback from the success E/IRQ-clear path.  Every
    channel-CONFIG RMW is bound from a fresh load at absolute 0x40002110
    through its same-register bit operation to the same-source store.
    """

    halt = _unique_function(
        functions,
        "p14 Precision RX DWT HALT/disable helper",
        lambda name: name.startswith(DMA_HALT_DISABLE_PREFIX),
    )
    _require(
        bool(halt.instructions),
        "p14 Precision RX DWT HALT/disable helper contains no instructions",
    )
    pending_error_calls = sorted(
        _calls_matching(
            halt,
            lambda name: name == DMA_FAIL_PENDING_NAME,
        ),
        key=lambda instruction: instruction.address,
    )
    _require(
        len(pending_error_calls) == 4,
        "control ACTIVE drain must retain exactly four pending-error checks",
    )
    (
        initial_error_call,
        timeout_error_call,
        success_error_call,
        final_error_call,
    ) = pending_error_calls

    def word_load(instruction: Instruction) -> bool:
        return instruction.mnemonic.lower() in {"ldr", "ldr.w"}

    def word_store(instruction: Instruction) -> bool:
        return instruction.mnemonic.lower() in {"str", "str.w"}

    def exact_memory_location(
        instruction: Instruction,
    ) -> tuple[str, int] | None:
        operands = instruction.operands.split(";", 1)[0].strip()
        match = re.fullmatch(
            rf"({REGISTER_NAME})\s*,\s*"
            rf"\[\s*({REGISTER_NAME})"
            r"(?:\s*,\s*#(0x[0-9a-fA-F]+|[0-9]+))?\s*\]",
            operands,
        )
        if match is None:
            return None
        return (
            _canonical_register(match.group(2)),
            int(match.group(3), 0) if match.group(3) is not None else 0,
        )

    def word_literal_loads(value: int) -> list[Instruction]:
        return [
            instruction
            for instruction in _literal_loads(halt, literal_words, value)
            if word_load(instruction)
            and (
                location := exact_memory_location(instruction)
            ) is not None
            and location[0] == "r15"
        ]

    demcr_base_loads = word_literal_loads(0xE000EDF0)
    dwt_base_loads = word_literal_loads(CORTEX_M_DWT_CTRL_ADDRESS)
    channel_config_loads = word_literal_loads(
        PL080_SGPIO_CHANNEL_CONFIG_ADDRESS
    )
    timeout_limit_loads = word_literal_loads(
        EXPECTED_P14_CONTROL_ACTIVE_DRAIN_LIMIT
    )
    _require(
        len(demcr_base_loads) == 1
        and len(dwt_base_loads) == 1
        and len(channel_config_loads) == 1
        and len(timeout_limit_loads) == 1,
        "control ACTIVE drain must link exact DEMCR, DWT, PL080 CONFIG, "
        "and 1,999,999-cycle boundary literals",
    )
    demcr_base_load = demcr_base_loads[0]
    dwt_base_load = dwt_base_loads[0]
    channel_config_load = channel_config_loads[0]
    timeout_limit_load = timeout_limit_loads[0]
    demcr_base_register = _first_operand_register(demcr_base_load)
    dwt_base_register = _first_operand_register(dwt_base_load)
    channel_config_register = _first_operand_register(channel_config_load)

    demcr_accesses = [
        instruction
        for instruction in halt.instructions
        if demcr_base_load.address < instruction.address < dwt_base_load.address
        and word_load(instruction)
        and (location := exact_memory_location(instruction)) is not None
        and location[0] == demcr_base_register
        and 0xE000EDF0 + location[1] == CORTEX_M_SCS_DEMCR_ADDRESS
    ]
    dwt_ctrl_accesses = [
        instruction
        for instruction in halt.instructions
        if dwt_base_load.address < instruction.address
        and word_load(instruction)
        and exact_memory_location(instruction) == (dwt_base_register, 0)
    ]
    _require(
        len(demcr_accesses) == 1 and len(dwt_ctrl_accesses) == 1,
        "control ACTIVE drain must load SCS_DEMCR.TRCENA and "
        "DWT_CTRL.CYCCNTENA exactly once before HALT",
    )
    demcr_access = demcr_accesses[0]
    dwt_ctrl_access = dwt_ctrl_accesses[0]

    def require_guard(
        access: Instruction,
        *,
        shift: int,
        description: str,
    ) -> tuple[Instruction, Instruction, Instruction]:
        access_register = _first_operand_register(access)
        bit_test = _next_non_nop(halt, access.address)
        branch = (
            _next_non_nop(halt, bit_test.address)
            if bit_test is not None
            else None
        )
        _require(
            bit_test is not None
            and bit_test.mnemonic.lower().split(".", 1)[0] == "lsls"
            and _has_immediate(bit_test, shift)
            and access_register in _operand_registers(bit_test)[1:]
            and branch is not None
            and branch.mnemonic.lower().split(".", 1)[0] == "bpl",
            f"{description} must reject a clear enable bit before HALT",
        )
        failure = _instruction_at(halt, _branch_target_address(branch))
        failure_return = (
            _next_non_nop(halt, failure.address)
            if failure is not None
            else None
        )
        _require(
            failure is not None
            and failure.mnemonic.lower() == "movs"
            and _first_operand_register(failure) == "r0"
            and _instruction_immediates(failure) == {0}
            and failure_return is not None
            and _is_return_instruction(failure_return),
            f"{description} clear-bit branch must reach the shared false return",
        )
        return bit_test, branch, failure

    demcr_test, demcr_branch, demcr_failure = require_guard(
        demcr_access,
        shift=7,
        description="SCS_DEMCR.TRCENA guard",
    )
    dwt_test, dwt_branch, dwt_failure = require_guard(
        dwt_ctrl_access,
        shift=31,
        description="DWT_CTRL.CYCCNTENA guard",
    )
    _require(
        _branch_target_address(demcr_branch)
        == _branch_target_address(dwt_branch),
        "both DWT counter guards must share the pre-HALT false return",
    )
    shared_false = demcr_failure
    initial_result_branch = _next_non_nop(
        halt, initial_error_call.address
    )
    _require(
        initial_result_branch is not None
        and initial_result_branch.mnemonic.lower() == "cbz"
        and _branch_condition_register(initial_result_branch) == "r0"
        and _branch_target_address(initial_result_branch)
        == demcr_base_load.address
        and _next_non_nop(halt, initial_result_branch.address)
        == shared_false,
        "initial pending-error check must take the healthy zero result to "
        "the counter guards and reject nonzero at the shared false return",
    )

    def require_nonzero_error_rejection(
        *,
        call: Instruction,
        healthy_entry: Instruction | None,
        description: str,
    ) -> tuple[Instruction, Instruction]:
        comparison = _next_non_nop(halt, call.address)
        branch = (
            _next_non_nop(halt, comparison.address)
            if comparison is not None
            else None
        )
        _require(
            comparison is not None
            and comparison.mnemonic.lower() == "cmp"
            and _operand_registers(comparison)[:1] == ("r0",)
            and _instruction_immediates(comparison) == {0}
            and branch is not None
            and branch.mnemonic.lower().split(".", 1)[0] == "bne"
            and _branch_target_address(branch) == shared_false.address
            and healthy_entry is not None
            and _next_non_nop(halt, branch.address) == healthy_entry,
            f"{description} pending-error check must reject nonzero at the "
            "shared false return and continue only on zero",
        )
        assert comparison is not None
        assert branch is not None
        return comparison, branch

    def require_config_rmw(
        *,
        description: str,
        base_literal: int,
        base_register: str | None,
        offset: int,
        value_load: Instruction | None,
        operation: Instruction | None,
        operation_name: str,
        operation_mask: int,
        store: Instruction | None,
    ) -> str:
        value_register = (
            _first_operand_register(value_load)
            if value_load is not None
            else None
        )
        load_location = (
            exact_memory_location(value_load)
            if value_load is not None
            else None
        )
        store_location = (
            exact_memory_location(store) if store is not None else None
        )
        _require(
            value_load is not None
            and word_load(value_load)
            and value_register is not None
            and base_register is not None
            and value_register != base_register
            and load_location == (base_register, offset)
            and base_literal + offset
            == PL080_SGPIO_CHANNEL_CONFIG_ADDRESS
            and operation is not None
            and operation.mnemonic.lower().split(".", 1)[0]
            == operation_name
            and _instruction_immediates(operation) == {operation_mask}
            and _operand_registers(operation)[:2]
            == (value_register, value_register)
            and store is not None
            and word_store(store)
            and store_location == (base_register, offset)
            and _operand_registers(store)[:2]
            == (value_register, base_register),
            f"{description} must bind a fresh absolute 0x40002110 CONFIG "
            f"load through same-register {operation_name.upper()} to the "
            "same-source absolute CONFIG store",
        )
        assert value_register is not None
        return value_register

    halt_sets = [
        instruction
        for instruction in halt.instructions
        if instruction.mnemonic.startswith("orr")
        and _has_immediate(instruction, 1 << 18)
    ]
    _require(
        len(halt_sets) == 1,
        "control ACTIVE drain must set PL080 HALT exactly once",
    )
    halt_set = halt_sets[0]
    halt_config_value_load = _next_non_nop(
        halt, channel_config_load.address
    )
    halt_store = _next_non_nop(halt, halt_set.address)
    halt_dmb = (
        _next_non_nop(halt, halt_store.address)
        if halt_store is not None
        else None
    )
    _require(
        halt_config_value_load is not None
        and _next_non_nop(halt, halt_config_value_load.address) == halt_set
        and halt_dmb is not None
        and _dmb(halt_dmb),
        "PL080 HALT must be stored to channel CONFIG then published by DMB",
    )
    require_config_rmw(
        description="HALT-set CONFIG RMW",
        base_literal=PL080_SGPIO_CHANNEL_CONFIG_ADDRESS,
        base_register=channel_config_register,
        offset=0,
        value_load=halt_config_value_load,
        operation=halt_set,
        operation_name="orr",
        operation_mask=1 << 18,
        store=halt_store,
    )
    _require_register_preserved(
        halt,
        channel_config_register,
        after=channel_config_load,
        before=halt_config_value_load,
        description="direct CH0 CONFIG base",
    )
    _require_cfg_dominance(
        halt,
        start=halt.instructions[0],
        target=halt_set,
        required=(
            ("SCS_DEMCR load", demcr_access),
            ("SCS_DEMCR.TRCENA test", demcr_test),
            ("SCS_DEMCR.TRCENA rejection", demcr_branch),
            ("DWT_CTRL load", dwt_ctrl_access),
            ("DWT_CTRL.CYCCNTENA test", dwt_test),
            ("DWT_CTRL.CYCCNTENA rejection", dwt_branch),
        ),
    )

    cyccnt_loads = [
        instruction
        for instruction in halt.instructions
        if instruction.address > halt_dmb.address
        and word_load(instruction)
        and exact_memory_location(instruction) == (dwt_base_register, 4)
    ]
    _require(
        len(cyccnt_loads) == 2,
        "control ACTIVE drain must load DWT_CYCCNT (0xE0001004) exactly "
        "twice: start and loop sample",
    )
    start_load, now_load = cyccnt_loads
    start_register = _first_operand_register(start_load)
    now_register = _first_operand_register(now_load)
    _require(
        start_register is not None
        and now_register is not None
        and start_register != dwt_base_register
        and now_register != dwt_base_register,
        "DWT_CYCCNT start/now destinations must not alias the loop-carried "
        "DWT base register",
    )
    _require_register_preserved(
        halt,
        dwt_base_register,
        after=dwt_base_load,
        before=now_load,
        description="DWT register base",
    )

    active_test_pairs: list[tuple[Instruction, Instruction]] = []
    for instruction in halt.instructions:
        if (
            instruction.address <= start_load.address
            or not word_load(instruction)
            or exact_memory_location(instruction)
            != (channel_config_register, 0)
        ):
            continue
        test = _next_non_nop(halt, instruction.address)
        loaded_register = _first_operand_register(instruction)
        if (
            test is not None
            and test.mnemonic.lower().split(".", 1)[0] == "lsls"
            and _has_immediate(test, 14)
            and loaded_register in _operand_registers(test)[1:]
        ):
            active_test_pairs.append((instruction, test))
    _require(
        len(active_test_pairs) == 2,
        "control ACTIVE drain must retain distinct loop and final PL080 "
        "ACTIVE samples",
    )
    (loop_active_load, loop_active_test), (
        final_active_load,
        final_active_test,
    ) = active_test_pairs
    loop_active_branch = _next_non_nop(halt, loop_active_test.address)
    final_active_branch = _next_non_nop(halt, final_active_test.address)
    _require(
        loop_active_branch is not None
        and loop_active_branch.mnemonic.lower().split(".", 1)[0] == "bpl"
        and _branch_target_address(loop_active_branch)
        == final_active_load.address
        and _next_non_nop(halt, loop_active_branch.address) == now_load
        and final_active_branch is not None
        and final_active_branch.mnemonic.lower().split(".", 1)[0] == "bpl"
        and _branch_target_address(final_active_branch)
        == success_error_call.address,
        "the loop ACTIVE-clear branch must enter the final recheck and its "
        "ACTIVE-set fallthrough must sample CYCCNT; final ACTIVE clear must "
        "enter the first success pending-error check",
    )

    elapsed_subtract = _next_non_nop(halt, now_load.address)
    elapsed_compare = (
        _next_non_nop(halt, elapsed_subtract.address)
        if elapsed_subtract is not None
        else None
    )
    loop_branch = (
        _next_non_nop(halt, elapsed_compare.address)
        if elapsed_compare is not None
        else None
    )
    elapsed_register = (
        _first_operand_register(elapsed_subtract)
        if elapsed_subtract is not None
        else None
    )
    timeout_limit_register = _first_operand_register(timeout_limit_load)
    _require(
        halt_dmb.address < timeout_limit_load.address < start_load.address
        < loop_active_load.address < now_load.address
        < final_active_load.address,
        "CYCCNT start/loop sampling must follow HALT+DMB and precede the "
        "distinct final ACTIVE recheck",
    )
    _require(
        elapsed_subtract is not None
        and elapsed_subtract.mnemonic.lower().split(".", 1)[0] == "subs"
        and _operand_registers(elapsed_subtract)[:3]
        == (now_register, now_register, start_register)
        and elapsed_compare is not None
        and elapsed_compare.mnemonic.lower().split(".", 1)[0] == "cmp"
        and _operand_registers(elapsed_compare)[:2]
        == (elapsed_register, timeout_limit_register)
        and loop_branch is not None
        and loop_branch.mnemonic.lower().split(".", 1)[0] == "bls"
        and _branch_target_address(loop_branch) == loop_active_load.address,
        "control ACTIVE drain must use wrap-safe unsigned (now - start) "
        "< 2,000,000 timing, not a signed or direct-deadline comparison",
    )
    _require(
        _next_non_nop(halt, loop_branch.address) == final_active_load,
        "the exact deadline exit must flow directly into the final PL080 "
        "ACTIVE recheck",
    )
    _require_register_preserved(
        halt,
        timeout_limit_register,
        after=timeout_limit_load,
        before=elapsed_compare,
        description="control ACTIVE drain timeout limit",
    )
    _require_register_preserved(
        halt,
        start_register,
        after=start_load,
        before=elapsed_subtract,
        description="control ACTIVE drain CYCCNT start",
    )

    halt_clears = [
        instruction
        for instruction in halt.instructions
        if instruction.address > final_active_branch.address
        and instruction.mnemonic.startswith("bic")
        and _has_immediate(instruction, 1 << 18)
    ]
    enable_clears = [
        instruction
        for instruction in halt.instructions
        if instruction.address > final_active_branch.address
        and instruction.mnemonic.startswith("bic")
        and _has_immediate(instruction, 1)
    ]
    _require(
        len(halt_clears) == 1 and len(enable_clears) == 1,
        "control ACTIVE timeout must clear H only; success must clear E "
        "exactly once",
    )
    halt_clear = halt_clears[0]
    timeout_config_value_load = next(
        (
            instruction
            for instruction in reversed(halt.instructions)
            if instruction.address < halt_clear.address
            and not instruction.mnemonic.startswith("nop")
        ),
        None,
    )
    halt_clear_store = _next_non_nop(halt, halt_clear.address)
    halt_clear_dmb = (
        _next_non_nop(halt, halt_clear_store.address)
        if halt_clear_store is not None
        else None
    )
    timeout_return_branch = (
        _next_non_nop(halt, halt_clear_dmb.address)
        if halt_clear_dmb is not None
        else None
    )
    _require(
        halt_clear_dmb is not None
        and _dmb(halt_clear_dmb)
        and timeout_return_branch is not None
        and timeout_return_branch.mnemonic in {"b", "b.n", "b.w"},
        "control ACTIVE timeout must commit H-only rollback, DMB, then "
        "return",
    )
    require_config_rmw(
        description="timeout H-clear CONFIG RMW",
        base_literal=PL080_SGPIO_CHANNEL_CONFIG_ADDRESS,
        base_register=channel_config_register,
        offset=0,
        value_load=timeout_config_value_load,
        operation=halt_clear,
        operation_name="bic",
        operation_mask=1 << 18,
        store=halt_clear_store,
    )
    require_nonzero_error_rejection(
        call=timeout_error_call,
        healthy_entry=timeout_config_value_load,
        description="timeout rollback",
    )
    _require_register_preserved(
        halt,
        channel_config_register,
        after=channel_config_load,
        before=timeout_config_value_load,
        description="direct CH0 CONFIG base through ACTIVE drain",
    )
    timeout_return = _instruction_at(
        halt, _branch_target_address(timeout_return_branch)
    )
    _require(
        timeout_return is not None and _is_return_instruction(timeout_return),
        "control ACTIVE timeout H-only rollback must branch to a shared return",
    )

    enable_clear = enable_clears[0]
    success_controller_base_loads = word_literal_loads(
        PL080_CONTROLLER_BASE_ADDRESS
    )
    _require(
        len(success_controller_base_loads) == 1,
        "control ACTIVE success must link one exact PL080 controller base",
    )
    success_controller_base_load = success_controller_base_loads[0]
    success_controller_base_register = _first_operand_register(
        success_controller_base_load
    )
    success_error_compare, success_error_branch = (
        require_nonzero_error_rejection(
            call=success_error_call,
            healthy_entry=success_controller_base_load,
            description="pre-disable success",
        )
    )
    success_config_value_load = next(
        (
            instruction
            for instruction in reversed(halt.instructions)
            if instruction.address < enable_clear.address
            and not instruction.mnemonic.startswith("nop")
        ),
        None,
    )
    success_status_load = _next_non_nop(
        halt, success_controller_base_load.address
    )
    success_status_register = (
        _first_operand_register(success_status_load)
        if success_status_load is not None
        else None
    )
    success_status_mask = (
        _next_non_nop(halt, success_status_load.address)
        if success_status_load is not None
        else None
    )
    pending_terminal_count_store = (
        _next_non_nop(halt, success_status_mask.address)
        if success_status_mask is not None
        else None
    )
    _require(
        success_status_load is not None
        and word_load(success_status_load)
        and exact_memory_location(success_status_load)
        == (success_controller_base_register, 4)
        and success_status_register is not None
        and success_status_register != success_controller_base_register
        and success_status_mask is not None
        and success_status_mask.mnemonic.lower().split(".", 1)[0] == "and"
        and _instruction_immediates(success_status_mask) == {1}
        and _operand_registers(success_status_mask)[:2]
        == (success_status_register, success_status_register)
        and pending_terminal_count_store is not None
        and pending_terminal_count_store.mnemonic.lower() == "strb"
        and exact_memory_location(pending_terminal_count_store) is not None
        and _first_operand_register(pending_terminal_count_store)
        == success_status_register
        and _next_non_nop(halt, pending_terminal_count_store.address)
        == success_config_value_load,
        "success path must bind a word-width CH0 terminal-count sample and "
        "mask 1 before the fresh CONFIG E-clear RMW",
    )
    enable_store = _next_non_nop(halt, enable_clear.address)
    require_config_rmw(
        description="success E-clear CONFIG RMW",
        base_literal=PL080_CONTROLLER_BASE_ADDRESS,
        base_register=success_controller_base_register,
        offset=PL080_SGPIO_CHANNEL_CONFIG_OFFSET,
        value_load=success_config_value_load,
        operation=enable_clear,
        operation_name="bic",
        operation_mask=1,
        store=enable_store,
    )
    _require_register_preserved(
        halt,
        success_controller_base_register,
        after=success_controller_base_load,
        before=success_config_value_load,
        description="PL080 controller base for success CONFIG access",
    )
    terminal_count_clear_stores = [
        instruction
        for instruction in halt.instructions
        if instruction.address > enable_store.address
        and word_store(instruction)
        and (location := exact_memory_location(instruction)) is not None
        and location[1] == 8
    ]
    error_clear_stores = [
        instruction
        for instruction in halt.instructions
        if instruction.address > enable_store.address
        and word_store(instruction)
        and (location := exact_memory_location(instruction)) is not None
        and location[1] == 16
    ]
    _require(
        len(terminal_count_clear_stores) == 1
        and len(error_clear_stores) == 1,
        "control ACTIVE success must retain terminal-count and error IRQ "
        "clears",
    )
    terminal_count_clear_store = terminal_count_clear_stores[0]
    error_clear_store = error_clear_stores[0]
    channel_mask_value = next(
        (
            instruction
            for instruction in reversed(halt.instructions)
            if instruction.address < terminal_count_clear_store.address
            and not instruction.mnemonic.startswith("nop")
        ),
        None,
    )
    channel_mask_register = (
        _first_operand_register(channel_mask_value)
        if channel_mask_value is not None
        else None
    )
    final_error_compare, final_error_branch = require_nonzero_error_rejection(
        call=final_error_call,
        healthy_entry=channel_mask_value,
        description="post-disable success",
    )
    _require(
        channel_mask_value is not None
        and channel_mask_value.mnemonic.lower() == "movs"
        and _instruction_immediates(channel_mask_value) == {1}
        and channel_mask_register is not None
        and channel_mask_register != success_controller_base_register
        and _next_non_nop(halt, channel_mask_value.address)
        == terminal_count_clear_store
        and _next_non_nop(halt, terminal_count_clear_store.address)
        == error_clear_store
        and exact_memory_location(terminal_count_clear_store)
        == (success_controller_base_register, 8)
        and exact_memory_location(error_clear_store)
        == (success_controller_base_register, 16)
        and _operand_registers(terminal_count_clear_store)[:2]
        == (channel_mask_register, success_controller_base_register)
        and _operand_registers(error_clear_store)[:2]
        == (channel_mask_register, success_controller_base_register),
        "success IRQ retirement must bind exact CH0 mask 1 through the "
        "same value register to PL080 base offsets 8 and 16",
    )
    _require_register_preserved(
        halt,
        success_controller_base_register,
        after=success_controller_base_load,
        before=error_clear_store,
        description="PL080 controller base through success IRQ retirement",
    )
    _require_cfg_dominance(
        halt,
        start=final_active_branch,
        target=error_clear_store,
        required=(
            ("first success pending-error call", success_error_call),
            ("first success pending-error compare", success_error_compare),
            ("first success pending-error rejection", success_error_branch),
            ("PL080 controller-base literal load", success_controller_base_load),
            ("terminal-count status load", success_status_load),
            ("terminal-count CH0 mask", success_status_mask),
            (
                "terminal-count pending-state publication",
                pending_terminal_count_store,
            ),
            ("fresh success CONFIG load", success_config_value_load),
            ("success CONFIG enable clear", enable_clear),
            ("success CONFIG store", enable_store),
            ("final success pending-error call", final_error_call),
            ("final success pending-error compare", final_error_compare),
            ("final success pending-error rejection", final_error_branch),
            ("CH0 IRQ-clear mask", channel_mask_value),
            ("terminal-count IRQ clear", terminal_count_clear_store),
        ),
    )
    irq_clear_stores = [
        terminal_count_clear_store,
        error_clear_store,
    ]
    timeout_entry = _next_non_nop(halt, final_active_branch.address)
    success_entry = _instruction_at(
        halt, _branch_target_address(final_active_branch)
    )
    _require(
        timeout_entry is not None and success_entry is not None,
        "control ACTIVE final recheck timeout/success split is unresolved",
    )
    successors = _control_flow_successors(halt)

    def reachable(start: int) -> frozenset[int]:
        reached: set[int] = set()
        pending = [start]
        while pending:
            address = pending.pop()
            if address in reached or address not in successors:
                continue
            reached.add(address)
            pending.extend(successors[address] - reached)
        return frozenset(reached)

    timeout_reachable = reachable(timeout_entry.address)
    success_reachable = reachable(success_entry.address)
    demcr_failure_reachable = reachable(demcr_failure.address)
    dwt_failure_reachable = reachable(dwt_failure.address)
    _require(
        halt_set.address not in demcr_failure_reachable
        and halt_set.address not in dwt_failure_reachable,
        "disabled DWT counter guards must reject before publishing HALT",
    )
    _require(
        halt_clear_store.address in timeout_reachable
        and enable_store.address not in timeout_reachable
        and all(
            instruction.address not in timeout_reachable
            for instruction in irq_clear_stores
        )
        and enable_store.address in success_reachable
        and all(
            instruction.address in success_reachable
            for instruction in irq_clear_stores
        ),
        "control ACTIVE timeout must complete H-only rollback before and "
        "without reaching E/IRQ clear",
    )

    descriptor_ticks = (
        EXPECTED_DMA_MONITOR_TRANSFER_SAMPLES
        * EXPECTED_P14_M4_COUNTER_HZ
        // EXPECTED_P14_MINIMUM_SAMPLE_RATE_HZ
    )
    _require(
        descriptor_ticks
        == EXPECTED_P14_CONTROL_SLOWEST_DESCRIPTOR_TICKS_AT_200M
        and descriptor_ticks
        < EXPECTED_P14_CONTROL_ACTIVE_DRAIN_TICKS_AT_200M
        < (1 << 31),
        "reviewed 409,600-cycle slowest descriptor must fit the 2,000,000-"
        "cycle wrap-safe control drain budget",
    )

    return {
        "function": halt.name,
        "demcr_address": CORTEX_M_SCS_DEMCR_ADDRESS,
        "dwt_ctrl_address": CORTEX_M_DWT_CTRL_ADDRESS,
        "dwt_cyccnt_address": CORTEX_M_DWT_CYCCNT_ADDRESS,
        "pl080_channel_config_address": (
            PL080_SGPIO_CHANNEL_CONFIG_ADDRESS
        ),
        "counter_frequency_hz": EXPECTED_P14_M4_COUNTER_HZ,
        "timeout_us": EXPECTED_P14_CONTROL_ACTIVE_DRAIN_TIMEOUT_US,
        "timeout_ticks": EXPECTED_P14_CONTROL_ACTIVE_DRAIN_TICKS_AT_200M,
        "loop_max_elapsed_ticks": EXPECTED_P14_CONTROL_ACTIVE_DRAIN_LIMIT,
        "minimum_sample_rate_hz": EXPECTED_P14_MINIMUM_SAMPLE_RATE_HZ,
        "slowest_descriptor_samples": EXPECTED_DMA_MONITOR_TRANSFER_SAMPLES,
        "slowest_descriptor_ticks_at_200m": descriptor_ticks,
        "both_counter_guards_before_halt": True,
        "cyccnt_sample_after_halt_dmb": True,
        "unsigned_wrap_safe_elapsed": True,
        "exact_deadline_boundary": True,
        "final_active_recheck": True,
        "timeout_h_only_rollback": True,
        "timeout_bypasses_e_and_irq_clear": True,
        "halt_set_config_rmw_def_use_bound": True,
        "timeout_h_clear_config_rmw_def_use_bound": True,
        "success_e_clear_config_rmw_def_use_bound": True,
        "success_irq_clear_base_and_mask_bound": True,
        "all_pending_error_results_fail_closed": True,
        "config_and_dwt_base_registers_preserved": True,
        "exact_word_mmio_and_literal_access_shapes": True,
        "success_chain_cfg_dominated": True,
        "linked_instruction_calibrated": True,
    }


def _verify_p15_channel_disabled_quiesce_failures(
    *,
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove both E==0 control callers durably publish qfail=7 and fault."""

    publisher = _unique_function(
        functions,
        "P15 quiesce-failure publisher",
        lambda name: name.startswith(
            DMA_QUIESCE_FAILURE_PUBLISH_PREFIX
        ),
    )
    latch = _unique_function(
        functions,
        "P15 fast DMA fault latch",
        lambda name: name.startswith(DMA_FAST_LATCH_PREFIX),
    )
    path_reports: list[dict[str, object]] = []
    for description, function_name in (
        ("rate pause", DMA_RATE_PAUSE_NAME),
        ("capture geometry", DMA_SET_GEOMETRY_NAME),
    ):
        function = _unique_function(
            functions,
            f"P15 {description} ChannelDisabled caller",
            lambda name, expected=function_name: name == expected,
        )
        controller_base_loads = _literal_loads(
            function,
            literal_words,
            PL080_CONTROLLER_BASE_ADDRESS,
        )
        _require(
            bool(controller_base_loads),
            f"P15 {description} must link the exact PL080 controller base",
        )
        enable_splits: list[
            tuple[
                Instruction,
                Instruction,
                Instruction,
                Instruction,
            ]
        ] = []
        for controller_base_load in controller_base_loads:
            controller_base_register = _first_operand_register(
                controller_base_load
            )
            for config_load in function.instructions:
                if (
                    config_load.address <= controller_base_load.address
                    or not config_load.mnemonic.startswith("ldr")
                    or _memory_location(config_load)
                    != (
                        controller_base_register,
                        PL080_SGPIO_CHANNEL_CONFIG_OFFSET,
                    )
                ):
                    continue
                enable_test = _next_non_nop(
                    function,
                    config_load.address,
                )
                enable_branch = (
                    _next_non_nop(function, enable_test.address)
                    if enable_test is not None
                    else None
                )
                if (
                    enable_test is not None
                    and enable_test.mnemonic.startswith("ands")
                    and _instruction_immediates(enable_test) == {1}
                    and _first_operand_register(enable_test)
                    == _first_operand_register(config_load)
                    and enable_branch is not None
                    and enable_branch.mnemonic.startswith("bne")
                ):
                    enable_splits.append(
                        (
                            controller_base_load,
                            config_load,
                            enable_test,
                            enable_branch,
                        )
                    )
        _require(
            len(enable_splits) == 1,
            f"P15 {description} must retain one exact channel-E split",
        )
        (
            controller_base_load,
            config_load,
            enable_test,
            enable_branch,
        ) = enable_splits[0]
        enable_register = _first_operand_register(enable_test)
        reason_move = _next_non_nop(
            function,
            enable_branch.address,
        )
        reason_publish = (
            _next_non_nop(function, reason_move.address)
            if reason_move is not None
            else None
        )
        _require(
            reason_move is not None
            and reason_move.mnemonic.startswith("mov")
            and _first_operand_register(reason_move) == "r0"
            and _instruction_immediates(reason_move) == {7}
            and reason_publish is not None
            and reason_publish.mnemonic in {"bl", "blx"}
            and reason_publish.target == publisher.name,
            f"P15 {description} disabled-channel fallthrough must publish "
            "exact qfail=ChannelDisabled(7)",
        )
        latch_calls = [
            call
            for call in _calls(function)
            if call.address > reason_publish.address
            and call.target == latch.name
        ]
        _require(
            len(latch_calls) == 1,
            f"P15 {description} ChannelDisabled path must call the fast "
            "fatal DMA latch once",
        )
        latch_call = latch_calls[0]
        latch_r0 = _last_register_writer(
            function,
            "r0",
            before=latch_call,
        )
        latch_r1 = _last_register_writer(
            function,
            "r1",
            before=latch_call,
        )
        _require(
            enable_register is not None
            and latch_r0 is not None
            and latch_r1 is not None
            and latch_r0.mnemonic.startswith("mov")
            and latch_r1.mnemonic.startswith("mov")
            and _operand_registers(latch_r0)[1:]
            == (enable_register,)
            and _operand_registers(latch_r1)[1:]
            == (enable_register,),
            f"P15 {description} ChannelDisabled path must pass the sampled "
            "E==0 status to the fatal latch",
        )
        nvic_base_loads = _literal_loads(
            function,
            literal_words,
            0xE000E100,
        )
        _require(
            len(nvic_base_loads) == 1,
            f"P15 {description} ChannelDisabled path must link NVIC ISER/"
            "ISPR base",
        )
        nvic_base_register = _first_operand_register(
            nvic_base_loads[0]
        )
        deferred_pends = [
            instruction
            for instruction in function.instructions
            if instruction.address > latch_call.address
            and instruction.mnemonic.startswith("str")
            and _memory_location(instruction)
            == (nvic_base_register, 256)
        ]
        _require(
            len(deferred_pends) == 1,
            f"P15 {description} ChannelDisabled path must pend the deferred "
            "IRQ exactly once",
        )
        deferred_pend = deferred_pends[0]
        deferred_value_register = _first_operand_register(
            deferred_pend
        )
        deferred_value = (
            _last_register_writer(
                function,
                deferred_value_register,
                before=deferred_pend,
            )
            if deferred_value_register is not None
            else None
        )
        deferred_dmb = _next_non_nop(
            function,
            deferred_pend.address,
        )
        disabled_exit_branch = (
            _next_non_nop(function, deferred_dmb.address)
            if deferred_dmb is not None
            else None
        )
        disabled_false_move = (
            _instruction_at(
                function,
                _branch_target_address(disabled_exit_branch),
            )
            if disabled_exit_branch is not None
            else None
        )
        _require(
            deferred_value is not None
            and deferred_value.mnemonic.startswith("mov")
            and _instruction_immediates(deferred_value)
            == {0x80000000}
            and deferred_dmb is not None
            and _dmb(deferred_dmb)
            and disabled_exit_branch is not None
            and disabled_exit_branch.mnemonic in {"b", "b.n", "b.w"}
            and disabled_false_move is not None
            and disabled_false_move.mnemonic.startswith("mov")
            and _operand_registers(disabled_false_move)[:2]
            == ("r0", enable_register),
            f"P15 {description} ChannelDisabled path must publish the "
            "deferred fault before returning its sampled false result",
        )
        successors = _control_flow_successors(
            function,
            reject_thumb_it=False,
        )

        def reachable(start: int | None) -> frozenset[int]:
            reached: set[int] = set()
            pending = [start] if start is not None else []
            while pending:
                address = pending.pop()
                if address in reached or address not in successors:
                    continue
                reached.add(address)
                pending.extend(successors[address] - reached)
            return frozenset(reached)

        disabled_reachable = reachable(reason_move.address)
        enabled_reachable = reachable(
            _branch_target_address(enable_branch)
        )
        returns = [
            instruction
            for instruction in function.instructions
            if _is_return_instruction(instruction)
        ]
        _require(
            len(returns) == 1
            and reason_publish.address in disabled_reachable
            and latch_call.address in disabled_reachable
            and deferred_pend.address in disabled_reachable
            and deferred_dmb.address in disabled_reachable
            and disabled_false_move.address in disabled_reachable
            and returns[0].address in disabled_reachable
            and reason_move.address not in enabled_reachable
            and reason_publish.address not in enabled_reachable,
            f"P15 {description} E==0 CFG must exclusively reach durable "
            "qfail=7, fatal latch, deferred pend, and false return",
        )
        path_reports.append(
            {
                "function": function.name,
                "channel_config_offset": (
                    PL080_SGPIO_CHANNEL_CONFIG_OFFSET
                ),
                "quiesce_failure_reason": 7,
                "fatal_latch": latch.name,
                "deferred_irq_mask": "0x80000000",
                "durable_before_false_return": True,
                "enabled_channel_bypasses_reason_7": True,
            }
        )

    return {
        "reason": 7,
        "reason_name": "ChannelDisabled",
        "publisher": publisher.name,
        "paths": path_reports,
        "rate_pause_bound": True,
        "capture_geometry_bound": True,
        "fatal_latch_and_deferred_pend_bound": True,
        "linked_instruction_calibrated": True,
    }


def _verify_p15_control_active_drain(
    *,
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove P15's live-source HALT/drain/gate/disable transaction.

    The ordinary deadline path must restore H and return without touching the
    SGPIO gate, channel E, interrupt status, descriptors, or software queues.
    Only the ACTIVE-clear path may close HOST_DISABLE. A second ACTIVE sample
    after the posted gate readback must dominate E-clear; reassertion is a
    distinct fatal-latch path, never a recoverable timeout.
    """

    halt = _unique_function(
        functions,
        "p15 Precision RX HALT/drain/gate/disable helper",
        lambda name: name.startswith(DMA_HALT_DISABLE_PREFIX),
    )
    publisher = _unique_function(
        functions,
        "p15 quiesce-failure publisher",
        lambda name: name.startswith(DMA_QUIESCE_FAILURE_PUBLISH_PREFIX),
    )
    channel_disabled_proof = (
        _verify_p15_channel_disabled_quiesce_failures(
            functions=functions,
            literal_words=literal_words,
        )
    )
    _require(
        not _calls(publisher),
        "quiesce-failure publisher must remain call-free",
    )

    def exact_memory_location(
        instruction: Instruction,
    ) -> tuple[str, int] | None:
        operands = instruction.operands.split(";", 1)[0].strip()
        match = re.fullmatch(
            rf"({REGISTER_NAME})\s*,\s*"
            rf"\[\s*({REGISTER_NAME})"
            r"(?:\s*,\s*#(0x[0-9a-fA-F]+|[0-9]+))?\s*\]",
            operands,
        )
        if match is None:
            return None
        return (
            _canonical_register(match.group(2)),
            int(match.group(3), 0) if match.group(3) is not None else 0,
        )

    def word_load(instruction: Instruction) -> bool:
        return instruction.mnemonic.lower() in {"ldr", "ldr.w"}

    def word_store(instruction: Instruction) -> bool:
        return instruction.mnemonic.lower() in {"str", "str.w"}

    def word_literal_loads(
        function: Function,
        value: int,
    ) -> list[Instruction]:
        return [
            instruction
            for instruction in _literal_loads(function, literal_words, value)
            if word_load(instruction)
            and exact_memory_location(instruction) is not None
        ]

    publisher_base_loads = word_literal_loads(
        publisher,
        SHARED_MEMORY_BASE,
    )
    publisher_offsets = [
        instruction
        for instruction in publisher.instructions
        if instruction.mnemonic.lower() == "movw"
        and _instruction_immediates(instruction)
        == {M4_DMA_TRANSITION_FAILURES_OFFSET}
    ]
    _require(
        len(publisher_base_loads) == 1 and len(publisher_offsets) == 1,
        "quiesce-failure publisher must bind the fixed SharedMemory base and "
        "m4_dma_transition_failures offset",
    )
    publisher_base_register = _first_operand_register(
        publisher_base_loads[0]
    )
    publisher_offset_register = _first_operand_register(
        publisher_offsets[0]
    )
    publisher_order = _require_ordered_instructions(
        publisher,
        (
            (
                "load packed transition-failure word",
                lambda instruction: word_load(instruction)
                and _operand_registers(instruction)[1:]
                == (publisher_base_register, publisher_offset_register),
            ),
            (
                "preserve the low 28-bit transition-failure count",
                lambda instruction: instruction.mnemonic.startswith("bic")
                and _instruction_immediates(instruction)
                == {0xF0000000},
            ),
            (
                "pack the four-bit quiesce reason at bit 28",
                lambda instruction: instruction.mnemonic.startswith("orr")
                and _first_operand_register(instruction) == "r0"
                and 28 in _instruction_immediates(instruction),
            ),
            (
                "store the packed transition-failure word",
                lambda instruction: word_store(instruction)
                and _first_operand_register(instruction) == "r0"
                and _operand_registers(instruction)[1:]
                == (publisher_base_register, publisher_offset_register),
            ),
            ("durably publish the quiesce reason", _dmb),
            ("return after durable publication", _is_return_instruction),
        ),
    )
    _require(
        publisher_order[3].address < publisher_order[4].address,
        "quiesce reason must be stored before its publication barrier",
    )

    pending_error_calls = sorted(
        _calls_matching(
            halt,
            lambda name: name == DMA_FAIL_PENDING_NAME,
        ),
        key=lambda instruction: instruction.address,
    )
    _require(
        len(pending_error_calls) == 4,
        "p15 control drain must retain four staged pending-error checks",
    )
    (
        initial_error_call,
        timeout_error_call,
        after_drain_error_call,
        after_disable_error_call,
    ) = pending_error_calls
    qfail_calls = _calls_matching(
        halt,
        lambda name: name.startswith(
            DMA_QUIESCE_FAILURE_PUBLISH_PREFIX
        ),
    )
    _require(
        len(qfail_calls) == 4,
        "p15 control drain must retain four linked quiesce-reason "
        "publication sites",
    )

    successors = _control_flow_successors(halt)
    instructions_by_address = {
        instruction.address: instruction for instruction in halt.instructions
    }

    def reachable(start: int | None) -> frozenset[int]:
        reached: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reached or address not in successors:
                continue
            reached.add(address)
            pending.extend(successors[address] - reached)
        return frozenset(reached)

    def following_address(instruction: Instruction) -> int | None:
        later = sorted(
            candidate.address
            for candidate in halt.instructions
            if candidate.address > instruction.address
            and candidate.address - instruction.address <= 4
        )
        return later[0] if later else None

    def split_pending_result(
        call: Instruction,
        description: str,
    ) -> tuple[int, int, Instruction]:
        following = [
            instruction
            for instruction in halt.instructions
            if call.address < instruction.address <= call.address + 10
            and _is_conditional_branch(instruction)
        ]
        _require(
            bool(following),
            f"{description} must branch on the exact pending-error result",
        )
        branch = following[0]
        _require(
            branch.mnemonic.lower().split(".", 1)[0] == "cbz"
            and _branch_condition_register(branch) == "r0",
            f"{description} must continue only when pending-error returns zero",
        )
        healthy = _branch_target_address(branch)
        failed = following_address(branch)
        _require(
            healthy is not None and failed is not None,
            f"{description} pending-error split is unresolved",
        )
        return healthy, failed, branch

    reason_moves: dict[int, Instruction] = {}
    for reason in (0, 1, 2, 3, 4, 5, 6, 8):
        matches = [
            instruction
            for instruction in halt.instructions
            if instruction.mnemonic.lower() in {"mov", "movs", "mov.w"}
            and _first_operand_register(instruction) == "r0"
            and _instruction_immediates(instruction) == {reason}
        ]
        _require(
            len(matches) == 1,
            f"p15 control drain must materialize qfail reason {reason} "
            "exactly once",
        )
        reason_moves[reason] = matches[0]

    qfail_call_addresses = {call.address for call in qfail_calls}
    for reason, move in reason_moves.items():
        starts = successors.get(move.address, frozenset())
        pending: list[tuple[int, bool]] = [
            (address, False) for address in starts
        ]
        visited: set[tuple[int, bool]] = set()
        reached_publisher = False
        escaped = False
        while pending:
            address, clobbered = pending.pop()
            state = (address, clobbered)
            if state in visited:
                continue
            visited.add(state)
            instruction = instructions_by_address[address]
            if address in qfail_call_addresses:
                reached_publisher = reached_publisher or not clobbered
                continue
            next_clobbered = clobbered or _writes_register(
                instruction,
                "r0",
            )
            next_addresses = successors[address]
            if not next_addresses:
                escaped = True
                continue
            pending.extend(
                (next_address, next_clobbered)
                for next_address in next_addresses
            )
        _require(
            reached_publisher and not escaped,
            f"qfail reason {reason} must reach durable publication without "
            "an r0 clobber or return bypass",
        )

    initial_healthy, initial_failed, initial_branch = split_pending_result(
        initial_error_call,
        "pre-HALT",
    )
    timeout_healthy, timeout_failed, timeout_branch = split_pending_result(
        timeout_error_call,
        "ACTIVE-timeout",
    )
    drain_healthy, drain_failed, drain_branch = split_pending_result(
        after_drain_error_call,
        "post-drain",
    )
    disable_healthy, disable_failed, disable_branch = split_pending_result(
        after_disable_error_call,
        "post-disable",
    )
    _require(
        reason_moves[3].address in reachable(initial_failed)
        and reason_moves[3].address not in reachable(initial_healthy)
        and reason_moves[4].address in reachable(timeout_failed)
        and reason_moves[4].address not in reachable(timeout_healthy)
        and reason_moves[5].address in reachable(drain_failed)
        and reason_moves[5].address not in reachable(drain_healthy)
        and reason_moves[6].address in reachable(disable_failed)
        and reason_moves[6].address not in reachable(disable_healthy),
        "pending-error stages must publish exact qfail reasons 3/4/5/6",
    )

    demcr_loads = word_literal_loads(halt, 0xE000EDF0)
    dwt_loads = word_literal_loads(halt, CORTEX_M_DWT_CTRL_ADDRESS)
    config_loads = word_literal_loads(
        halt,
        PL080_SGPIO_CHANNEL_CONFIG_ADDRESS,
    )
    timeout_limit_loads = word_literal_loads(
        halt,
        EXPECTED_P14_CONTROL_ACTIVE_DRAIN_LIMIT,
    )
    _require(
        len(demcr_loads) == len(dwt_loads) == len(config_loads)
        == len(timeout_limit_loads) == 1,
        "p15 control drain must link exact DEMCR, DWT, PL080 CONFIG, and "
        "1,999,999-cycle limit literals",
    )
    demcr_base = _first_operand_register(demcr_loads[0])
    dwt_base = _first_operand_register(dwt_loads[0])
    config_base = _first_operand_register(config_loads[0])
    demcr_accesses = [
        instruction
        for instruction in halt.instructions
        if word_load(instruction)
        and exact_memory_location(instruction) == (demcr_base, 12)
    ]
    dwt_ctrl_accesses = [
        instruction
        for instruction in halt.instructions
        if word_load(instruction)
        and exact_memory_location(instruction) == (dwt_base, 0)
    ]
    _require(
        len(demcr_accesses) == 1 and len(dwt_ctrl_accesses) == 1,
        "p15 control drain must sample both counter-enable guards exactly "
        "once",
    )
    demcr_test = next(
        (
            instruction
            for instruction in halt.instructions
            if demcr_accesses[0].address < instruction.address
            <= demcr_accesses[0].address + 8
            and instruction.mnemonic.startswith("lsl")
            and _has_immediate(instruction, 7)
        ),
        None,
    )
    demcr_branch = (
        _next_non_nop(halt, demcr_test.address)
        if demcr_test is not None
        else None
    )
    dwt_test = next(
        (
            instruction
            for instruction in halt.instructions
            if dwt_ctrl_accesses[0].address < instruction.address
            <= dwt_ctrl_accesses[0].address + 8
            and instruction.mnemonic.startswith("lsl")
            and _has_immediate(instruction, 31)
        ),
        None,
    )
    dwt_branch = (
        _next_non_nop(halt, dwt_test.address)
        if dwt_test is not None
        else None
    )
    _require(
        demcr_test is not None
        and demcr_test.mnemonic.startswith("lsl")
        and _has_immediate(demcr_test, 7)
        and demcr_branch is not None
        and demcr_branch.mnemonic.startswith("bpl")
        and dwt_test is not None
        and dwt_test.mnemonic.startswith("lsl")
        and _has_immediate(dwt_test, 31)
        and dwt_branch is not None
        and dwt_branch.mnemonic.startswith("bpl")
        and reason_moves[1].address
        in reachable(_branch_target_address(demcr_branch))
        and reason_moves[1].address
        in reachable(_branch_target_address(dwt_branch)),
        "disabled DEMCR/DWT counters must publish qfail=CounterUnavailable "
        "before HALT",
    )

    halt_sets = [
        instruction
        for instruction in halt.instructions
        if instruction.mnemonic.startswith("orr")
        and _has_immediate(instruction, 1 << 18)
    ]
    halt_clears = [
        instruction
        for instruction in halt.instructions
        if instruction.mnemonic.startswith("bic")
        and _has_immediate(instruction, 1 << 18)
    ]
    enable_clears = [
        instruction
        for instruction in halt.instructions
        if instruction.mnemonic.startswith("bic")
        and _has_immediate(instruction, 1)
    ]
    _require(
        len(halt_sets) == len(halt_clears) == len(enable_clears) == 1,
        "p15 control drain must set H once, clear H only on timeout, and "
        "clear E once on success",
    )
    halt_set = halt_sets[0]
    halt_store = _next_non_nop(halt, halt_set.address)
    halt_dmb = (
        _next_non_nop(halt, halt_store.address)
        if halt_store is not None
        else None
    )
    _require(
        halt_store is not None
        and word_store(halt_store)
        and exact_memory_location(halt_store) == (config_base, 0)
        and halt_dmb is not None
        and _dmb(halt_dmb),
        "p15 PL080 HALT must be committed to CONFIG and published by DMB",
    )

    cyccnt_loads = [
        instruction
        for instruction in halt.instructions
        if instruction.address > halt_dmb.address
        and word_load(instruction)
        and exact_memory_location(instruction) == (dwt_base, 4)
    ]
    _require(
        len(cyccnt_loads) == 2,
        "p15 control drain must sample DWT_CYCCNT exactly at start and in "
        "the loop",
    )
    start_load, now_load = cyccnt_loads
    elapsed_subtract = _next_non_nop(halt, now_load.address)
    elapsed_compare = (
        _next_non_nop(halt, elapsed_subtract.address)
        if elapsed_subtract is not None
        else None
    )
    loop_back = (
        _next_non_nop(halt, elapsed_compare.address)
        if elapsed_compare is not None
        else None
    )
    _require(
        elapsed_subtract is not None
        and elapsed_subtract.mnemonic.startswith("sub")
        and elapsed_compare is not None
        and elapsed_compare.mnemonic.startswith("cmp")
        and loop_back is not None
        and loop_back.mnemonic.startswith("bls"),
        "p15 ACTIVE deadline must retain unsigned now-start/limit/loop "
        "instructions",
    )

    pre_gate_active_pairs: list[tuple[Instruction, Instruction]] = []
    for instruction in halt.instructions:
        if (
            not word_load(instruction)
            or exact_memory_location(instruction) != (config_base, 0)
        ):
            continue
        test = _next_non_nop(halt, instruction.address)
        if (
            test is not None
            and test.mnemonic.startswith("lsl")
            and _has_immediate(test, 14)
        ):
            pre_gate_active_pairs.append((instruction, test))
    _require(
        len(pre_gate_active_pairs) == 2,
        "p15 control drain must retain loop and deadline-final ACTIVE "
        "samples before gating",
    )
    (loop_active_load, loop_active_test), (
        deadline_active_load,
        deadline_active_test,
    ) = pre_gate_active_pairs
    loop_active_branch = _next_non_nop(
        halt,
        loop_active_test.address,
    )
    deadline_active_branch = _next_non_nop(
        halt,
        deadline_active_test.address,
    )
    _require(
        loop_active_branch is not None
        and loop_active_branch.mnemonic.startswith("bpl")
        and _branch_target_address(loop_active_branch)
        == deadline_active_load.address
        and _branch_target_address(loop_back) == loop_active_load.address
        and deadline_active_branch is not None
        and deadline_active_branch.mnemonic.startswith("bpl")
        and _branch_target_address(deadline_active_branch)
        == after_drain_error_call.address,
        "p15 loop must resample ACTIVE and branch to the post-drain check "
        "only on the distinct deadline-final A==0 sample",
    )

    timeout_entry = following_address(deadline_active_branch)
    success_entry = _branch_target_address(deadline_active_branch)
    _require(
        timeout_entry == timeout_error_call.address
        and success_entry == after_drain_error_call.address,
        "p15 deadline-final ACTIVE split is unresolved",
    )

    sgpio_base_loads = word_literal_loads(
        halt,
        SGPIO_CONTROLLER_BASE_ADDRESS,
    )
    _require(
        len(sgpio_base_loads) == 1,
        "p15 control drain must link one exact SGPIO controller base",
    )
    sgpio_base_load = sgpio_base_loads[0]
    sgpio_base_register = _first_operand_register(sgpio_base_load)
    gate_value_load = _next_non_nop(halt, sgpio_base_load.address)
    gate_set = (
        _next_non_nop(halt, gate_value_load.address)
        if gate_value_load is not None
        else None
    )
    gate_store = (
        _next_non_nop(halt, gate_set.address)
        if gate_set is not None
        else None
    )
    gate_dmb = (
        _next_non_nop(halt, gate_store.address)
        if gate_store is not None
        else None
    )
    gate_readback = (
        _next_non_nop(halt, gate_dmb.address)
        if gate_dmb is not None
        else None
    )
    _require(
        gate_value_load is not None
        and word_load(gate_value_load)
        and exact_memory_location(gate_value_load)
        == (sgpio_base_register, SGPIO_GPIO_OUTREG_OFFSET)
        and gate_set is not None
        and gate_set.mnemonic.startswith("orr")
        and _instruction_immediates(gate_set) == {1 << 10}
        and gate_store is not None
        and word_store(gate_store)
        and exact_memory_location(gate_store)
        == (sgpio_base_register, SGPIO_GPIO_OUTREG_OFFSET)
        and gate_dmb is not None
        and _dmb(gate_dmb)
        and gate_readback is not None
        and word_load(gate_readback)
        and exact_memory_location(gate_readback)
        == (sgpio_base_register, SGPIO_GPIO_OUTREG_OFFSET),
        "p15 HOST_DISABLE must use an exact SGPIO OUTREG RMW, DMB, and "
        "posted-write readback",
    )
    _require(
        not any(
            instruction.mnemonic.startswith("bic")
            and _has_immediate(instruction, 1 << 10)
            for instruction in halt.instructions
        ),
        "p15 quiesce helper must never reopen HOST_DISABLE",
    )

    post_gate_active_load = _next_non_nop(halt, gate_readback.address)
    post_gate_active_test = (
        _next_non_nop(halt, post_gate_active_load.address)
        if post_gate_active_load is not None
        else None
    )
    post_gate_active_branch = (
        _next_non_nop(halt, post_gate_active_test.address)
        if post_gate_active_test is not None
        else None
    )
    _require(
        post_gate_active_load is not None
        and word_load(post_gate_active_load)
        and exact_memory_location(post_gate_active_load)
        == (config_base, 0)
        and post_gate_active_test is not None
        and post_gate_active_test.mnemonic.startswith("and")
        and _instruction_immediates(post_gate_active_test)
        == {1 << 17}
        and post_gate_active_branch is not None
        and post_gate_active_branch.mnemonic.startswith("beq"),
        "p15 must recheck PL080 ACTIVE after the gate readback and before "
        "E-clear",
    )

    controller_base_loads = word_literal_loads(
        halt,
        PL080_CONTROLLER_BASE_ADDRESS,
    )
    _require(
        len(controller_base_loads) == 1,
        "p15 success path must link one exact PL080 controller base",
    )
    controller_base_load = controller_base_loads[0]
    controller_base_register = _first_operand_register(controller_base_load)
    _require(
        _branch_target_address(post_gate_active_branch)
        == controller_base_load.address,
        "post-gate A==0 must enter the PL080 status/E-clear success path",
    )

    active_reassert_entry = following_address(post_gate_active_branch)
    active_reassert_reachable = reachable(active_reassert_entry)
    latch_calls = _calls_matching(
        halt,
        lambda name: name.startswith(DMA_FAST_LATCH_PREFIX),
    )
    _require(
        reason_moves[8].address in active_reassert_reachable
        and len(latch_calls) == 1
        and latch_calls[0].address in active_reassert_reachable,
        "post-gate ACTIVE reassertion must publish qfail=8 and enter the "
        "fatal DMA latch",
    )

    enable_clear = enable_clears[0]
    enable_store = _next_non_nop(halt, enable_clear.address)
    _require(
        enable_store is not None
        and word_store(enable_store)
        and exact_memory_location(enable_store)
        == (controller_base_register, PL080_SGPIO_CHANNEL_CONFIG_OFFSET),
        "p15 success E-clear must store to exact CH0 CONFIG",
    )
    terminal_count_clears = [
        instruction
        for instruction in halt.instructions
        if word_store(instruction)
        and exact_memory_location(instruction)
        == (controller_base_register, 8)
    ]
    error_clears = [
        instruction
        for instruction in halt.instructions
        if word_store(instruction)
        and exact_memory_location(instruction)
        == (controller_base_register, 16)
    ]
    _require(
        len(terminal_count_clears) == len(error_clears) == 1,
        "p15 success must retain exact CH0 TC/ERR W1C retirement",
    )

    halt_clear = halt_clears[0]
    halt_clear_store = _next_non_nop(halt, halt_clear.address)
    _require(
        halt_clear_store is not None
        and word_store(halt_clear_store)
        and exact_memory_location(halt_clear_store) == (config_base, 0),
        "p15 ordinary timeout must commit an exact H-only CONFIG rollback",
    )
    timeout_reachable = reachable(timeout_entry)
    healthy_timeout_reachable = reachable(timeout_healthy)
    success_reachable = reachable(success_entry)
    forbidden_timeout_addresses = {
        gate_store.address,
        enable_store.address,
        terminal_count_clears[0].address,
        error_clears[0].address,
    }
    forbidden_timeout_calls = {
        call.address
        for call in _calls(halt)
        if call.target is not None
        and (
            "configure_lease_descriptors" in call.target
            or "discard_completion_queue" in call.target
            or "reset_completion_queue" in call.target
        )
    }
    _require(
        halt_clear_store.address in healthy_timeout_reachable
        and reason_moves[2].address in healthy_timeout_reachable
        and not (
            forbidden_timeout_addresses | forbidden_timeout_calls
        ).intersection(healthy_timeout_reachable)
        and gate_store.address not in timeout_reachable
        and gate_store.address in success_reachable
        and enable_store.address in success_reachable,
        "ordinary ACTIVE timeout must clear H and publish qfail=2 without "
        "gate/E/W1C/descriptor/queue mutation; success must reach gate and E",
    )
    _require_cfg_dominance(
        halt,
        start=initial_error_call,
        target=gate_store,
        required=(
            ("pre-HALT pending-error check", initial_error_call),
            ("pre-HALT healthy branch", initial_branch),
            ("PL080 H set", halt_set),
            ("PL080 H store", halt_store),
            ("PL080 H publication barrier", halt_dmb),
            ("DWT drain start sample", start_load),
            ("live-source ACTIVE loop sample", loop_active_load),
            ("live-source ACTIVE loop test", loop_active_test),
            ("deadline-final ACTIVE sample", deadline_active_load),
            ("deadline-final ACTIVE test", deadline_active_test),
            ("deadline-final ACTIVE-clear branch", deadline_active_branch),
            ("post-drain pending-error check", after_drain_error_call),
            ("post-drain healthy branch", drain_branch),
            ("HOST_DISABLE base load", sgpio_base_load),
            ("HOST_DISABLE value load", gate_value_load),
            ("HOST_DISABLE set", gate_set),
        ),
    )
    _require_cfg_dominance(
        halt,
        start=after_drain_error_call,
        target=enable_store,
        required=(
            ("post-drain error check", after_drain_error_call),
            ("post-drain healthy branch", drain_branch),
            ("HOST_DISABLE base load", sgpio_base_load),
            ("HOST_DISABLE value load", gate_value_load),
            ("HOST_DISABLE set", gate_set),
            ("HOST_DISABLE store", gate_store),
            ("HOST_DISABLE publication barrier", gate_dmb),
            ("HOST_DISABLE readback", gate_readback),
            ("post-gate ACTIVE load", post_gate_active_load),
            ("post-gate ACTIVE test", post_gate_active_test),
            ("post-gate ACTIVE-clear branch", post_gate_active_branch),
            ("PL080 controller-base load", controller_base_load),
        ),
    )

    return {
        "function": halt.name,
        "quiesce_failure_publisher": publisher.name,
        "demcr_address": CORTEX_M_SCS_DEMCR_ADDRESS,
        "dwt_ctrl_address": CORTEX_M_DWT_CTRL_ADDRESS,
        "dwt_cyccnt_address": CORTEX_M_DWT_CYCCNT_ADDRESS,
        "pl080_channel_config_address": (
            PL080_SGPIO_CHANNEL_CONFIG_ADDRESS
        ),
        "sgpio_gpio_outreg_address": SGPIO_GPIO_OUTREG_ADDRESS,
        "counter_frequency_hz": EXPECTED_P14_M4_COUNTER_HZ,
        "timeout_us": EXPECTED_P14_CONTROL_ACTIVE_DRAIN_TIMEOUT_US,
        "timeout_ticks": EXPECTED_P14_CONTROL_ACTIVE_DRAIN_TICKS_AT_200M,
        "loop_max_elapsed_ticks": EXPECTED_P14_CONTROL_ACTIVE_DRAIN_LIMIT,
        "halt_precedes_active_drain": True,
        "active_drain_precedes_sgpio_gate": True,
        "gate_readback_before_final_active_recheck": True,
        "final_active_recheck_precedes_e_clear": True,
        "ordinary_timeout_h_only_rollback": True,
        "ordinary_timeout_gate_untouched": True,
        "ordinary_timeout_software_state_untouched": True,
        "active_reassertion_fatal_latched": True,
        "all_quiesce_failure_reasons_durable": True,
        "channel_disabled_quiesce_failure": channel_disabled_proof,
        "success_irq_clear_bound": True,
        "linked_instruction_calibrated": True,
    }


def _verify_p13_energy_log10_safety(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove the diagnostic dBFS helper uses the guarded newlib kernel directly.

    Calling ``__ieee754_log10f`` avoids the public newlib wrapper retained by
    ``std::log10``.  The size optimization is release-safe only when the
    optimized ELF still proves that the exact non-positive guard bypasses the
    kernel and returns the reviewed floor value.
    """

    energy = _unique_function(
        functions,
        "Precision RX energy-to-dBFS helper",
        lambda name: name == ENERGY_TO_DBFS_NAME,
    )
    energy_symbols = [
        symbol for symbol in symbols if symbol.name == ENERGY_TO_DBFS_NAME
    ]
    _require(
        len(energy_symbols) == 1 and energy_symbols[0].size > 0,
        "expected exactly one sized Precision RX energy-to-dBFS helper",
    )
    _require(
        energy_symbols[0].address == energy.address,
        "Precision RX energy-to-dBFS symbol and disassembly addresses differ",
    )

    wrapper_definitions = sorted(
        {
            symbol.name
            for symbol in symbols
            if symbol.name in LOG10_WRAPPER_NAMES
        }
    )
    _require(
        not wrapper_definitions,
        "linked log10 wrapper path must be absent; found: "
        + ", ".join(wrapper_definitions),
    )
    wrapper_calls = _calls_matching(
        energy,
        lambda name: name in LOG10_WRAPPER_NAMES,
    )
    _require(
        not wrapper_calls,
        "Precision RX energy-to-dBFS helper must not call a log10 wrapper",
    )

    kernel_symbols = [
        symbol for symbol in symbols if symbol.name == LOG10_KERNEL_NAME
    ]
    _require(
        len(kernel_symbols) == 1 and kernel_symbols[0].size > 0,
        f"expected exactly one sized {LOG10_KERNEL_NAME} kernel; "
        f"found {len(kernel_symbols)}",
    )
    kernel_calls = _calls_matching(
        energy,
        lambda name: name == LOG10_KERNEL_NAME,
    )
    _require(
        len(kernel_calls) == 1,
        "Precision RX energy-to-dBFS helper must call "
        f"{LOG10_KERNEL_NAME} exactly once; found {len(kernel_calls)}",
    )
    kernel_call = kernel_calls[0]

    zero_compares = [
        instruction
        for instruction in energy.instructions
        if instruction.address < kernel_call.address
        and instruction.mnemonic.lower().startswith("vcmpe")
        and re.search(r"\bs0\b", instruction.operands.lower()) is not None
        and re.search(
            r"#(?:0(?:\.0+)?|0x0)(?:\b|$)",
            instruction.operands.lower(),
        )
        is not None
    ]
    _require(
        len(zero_compares) == 1,
        "Precision RX energy-to-dBFS helper must contain exactly one "
        "vcmpe.f32 s0, #0.0 non-positive guard; "
        f"found {len(zero_compares)}",
    )
    zero_compare = zero_compares[0]
    flags_transfer = _next_non_nop(energy, zero_compare.address)
    guard_branch = (
        _next_non_nop(energy, flags_transfer.address)
        if flags_transfer is not None
        else None
    )
    _require(
        flags_transfer is not None
        and flags_transfer.mnemonic.lower().split(".", 1)[0] == "vmrs"
        and re.search(
            r"\bapsr(?:_nzcv)?\s*,\s*fpscr\b",
            flags_transfer.operands.lower(),
        )
        is not None,
        "non-positive energy guard must transfer VFP flags to APSR with VMRS",
    )
    _require(
        guard_branch is not None
        and guard_branch.mnemonic.lower().split(".", 1)[0] == "bls",
        "non-positive energy guard must use BLS immediately after VMRS",
    )
    _require(
        guard_branch.address < kernel_call.address,
        "non-positive energy guard must precede the direct log10 kernel call",
    )

    _require_bounded_no_backward_branch(energy)
    # The reviewed positive-result clamp uses a compiler-generated Thumb IT
    # block after the kernel call.  Predication has no control-flow edge and
    # cannot bypass the earlier guard, so model it as fallthrough here.
    successors = _control_flow_successors(energy, reject_thumb_it=False)
    entry = _instruction_at(energy, energy.address)
    _require(
        entry is not None,
        "Precision RX energy-to-dBFS helper lacks an instruction at its entry",
    )
    dominators, reachable = _dominators_from(
        energy,
        entry.address,
        reject_thumb_it=False,
    )
    _require(
        kernel_call.address in reachable,
        "direct log10 kernel call is unreachable from energy-to-dBFS entry",
    )
    _require(
        {
            zero_compare.address,
            flags_transfer.address,
            guard_branch.address,
        }.issubset(dominators[kernel_call.address]),
        "non-positive energy guard must dominate the direct log10 kernel call",
    )

    branch_target = _branch_target_address(guard_branch)
    positive_path = _next_non_nop(energy, guard_branch.address)
    _require(
        branch_target is not None
        and positive_path is not None
        and successors[guard_branch.address]
        == frozenset({branch_target, positive_path.address}),
        "non-positive energy guard must have reviewed positive and fallback "
        "successors",
    )

    def reachable_from(start: int) -> frozenset[int]:
        visited: set[int] = set()
        pending = [start]
        while pending:
            address = pending.pop()
            if address in visited or address not in successors:
                continue
            visited.add(address)
            pending.extend(successors[address] - visited)
        return frozenset(visited)

    positive_reachable = reachable_from(positive_path.address)
    fallback_reachable = reachable_from(branch_target)
    _require(
        kernel_call.address in positive_reachable
        and kernel_call.address not in fallback_reachable,
        "non-positive branch must bypass the direct log10 kernel call",
    )
    fallback_instructions = [
        instruction
        for instruction in energy.instructions
        if instruction.address in fallback_reachable
    ]
    _require(
        any(
            _is_return_instruction(instruction)
            for instruction in fallback_instructions
        )
        and not any(
            instruction.mnemonic in {"bl", "blx"}
            for instruction in fallback_instructions
        ),
        "non-positive energy fallback must return without an external call",
    )
    fallback_floor_loads = [
        instruction
        for instruction in _literal_loads(
            energy,
            literal_words,
            NON_POSITIVE_DBFS_X10 & 0xFFFFFFFF,
        )
        if instruction.address in fallback_reachable
        and _first_operand_register(instruction) == "r0"
    ]
    _require(
        len(fallback_floor_loads) == 1,
        "non-positive energy fallback must return the linked -1200 dBFS-x10 "
        "floor",
    )

    return {
        "function": energy.name,
        "linked_code_bytes": energy_symbols[0].size,
        "non_positive_compare_address": f"0x{zero_compare.address:x}",
        "guard_branch_address": f"0x{guard_branch.address:x}",
        "kernel_call_address": f"0x{kernel_call.address:x}",
        "kernel_target": LOG10_KERNEL_NAME,
        "non_positive_guard_dominates_kernel": True,
        "wrapper_path_absent": True,
        "non_positive_fallback_dbfs_x10": NON_POSITIVE_DBFS_X10,
        "bounded": True,
        "linked_instruction_calibrated": True,
    }


def _is_geometry_constructor(name: str) -> bool:
    return (
        name.startswith(GEOMETRY_CONSTRUCTOR_PREFIX)
        and "CaptureConfig" not in name
        and name.count(",") == 1
    )


def _is_baseband_constructor(name: str) -> bool:
    return name.startswith(BASEBAND_CONSTRUCTOR_PREFIX)


def _is_operator_new(name: str) -> bool:
    return name.startswith("operator new(") and not name.startswith("operator new[]")


def _is_operator_new_array(name: str) -> bool:
    return name.startswith("operator new[](")


def _is_allocator(name: str) -> bool:
    return (
        _is_operator_new(name)
        or _is_operator_new_array(name)
        or name.startswith("malloc")
        or name.startswith("calloc")
        or name.startswith("realloc")
        or "chHeapAlloc" in name
    )


def _is_raw_heap_allocator(name: str) -> bool:
    return (
        name.startswith("malloc")
        or name.startswith("calloc")
        or name.startswith("realloc")
        or "chHeapAlloc" in name
    )


def _is_bulk_memory(name: str) -> bool:
    return (
        name == "memset"
        or name == "memcpy"
        or name == "memmove"
        or name.startswith("__aeabi_mem")
    )


def _immediate_argument_before_call(
    function: Function,
    call: Instruction,
    register: str,
) -> int:
    call_index = function.instructions.index(call)
    for instruction in reversed(function.instructions[:call_index]):
        if instruction.mnemonic in {"bl", "blx"}:
            break
        operands_without_comment = instruction.operands.split(";", 1)[0].strip()
        first_operand = operands_without_comment.split(",", 1)[0].strip()
        if first_operand != register:
            continue
        match = IMMEDIATE_MOVE.match(operands_without_comment)
        if instruction.mnemonic in {"mov", "movs", "mov.w", "movw"} and match:
            return int(match.group(2), 0)
        raise VerificationError(
            f"cannot recover constant {register} before call to {call.target} "
            f"in {function.name}; last writer is {instruction.mnemonic} "
            f"{instruction.operands}"
        )
    raise VerificationError(
        f"cannot find constant {register} before call to {call.target} in {function.name}"
    )


def _in_region(address: int, size: int, base: int, capacity: int) -> bool:
    return base <= address and address + size <= base + capacity


def _resource_report(
    sections: Sequence[Section],
    processor_bytes: int,
    capture_stream_bytes: int,
    supplemental_capture_stream_bytes: int,
    dma_buffer_bytes: int,
    config: GateConfig,
) -> dict[str, int]:
    flash_high_water = 0
    ram_high_water = 0
    ram_allocated = 0
    allocated_sections = [section for section in sections if "ALLOC" in section.flags]
    _require(bool(allocated_sections), "ELF has no ALLOC sections")

    for section in allocated_sections:
        if section.size == 0:
            continue
        if _in_region(
            section.vma,
            section.size,
            config.flash_base,
            config.flash_capacity_bytes,
        ):
            flash_high_water = max(
                flash_high_water,
                section.vma + section.size - config.flash_base,
            )
        elif _in_region(
            section.vma,
            section.size,
            config.ram_base,
            config.ram_capacity_bytes,
        ):
            ram_allocated += section.size
            ram_high_water = max(
                ram_high_water,
                section.vma + section.size - config.ram_base,
            )
        else:
            raise VerificationError(
                f"ALLOC section {section.name} at 0x{section.vma:x} size "
                f"0x{section.size:x} is outside the approved flash/RAM regions"
            )

        if "LOAD" in section.flags:
            if _in_region(
                section.lma,
                section.size,
                config.flash_base,
                config.flash_capacity_bytes,
            ):
                flash_high_water = max(
                    flash_high_water,
                    section.lma + section.size - config.flash_base,
                )
            elif not _in_region(
                section.lma,
                section.size,
                config.ram_base,
                config.ram_capacity_bytes,
            ):
                raise VerificationError(
                    f"LOAD section {section.name} at LMA 0x{section.lma:x} size "
                    f"0x{section.size:x} is outside the approved flash/RAM regions"
                )

    _require(
        flash_high_water <= config.flash_capacity_bytes,
        "flash high-water mark exceeds the Precision RX image region",
    )
    modeled_headroom = (
        config.ram_capacity_bytes
        - ram_high_water
        - processor_bytes
        - capture_stream_bytes
        - dma_buffer_bytes
        - config.heap_metadata_reserve_bytes
    )
    _require(
        modeled_headroom >= config.minimum_modeled_headroom_bytes,
        f"modeled RAM headroom is {modeled_headroom} bytes; "
        f"minimum is {config.minimum_modeled_headroom_bytes}",
    )
    return {
        "flash_capacity_bytes": config.flash_capacity_bytes,
        "flash_high_water_bytes": flash_high_water,
        "flash_headroom_bytes": config.flash_capacity_bytes - flash_high_water,
        "ram_capacity_bytes": config.ram_capacity_bytes,
        "static_ram_allocated_bytes": ram_allocated,
        "static_ram_high_water_bytes": ram_high_water,
        "processor_object_bytes": processor_bytes,
        "maximum_processor_object_bytes": config.max_processor_bytes,
        "capture_stream_bytes": capture_stream_bytes,
        "supplemental_capture_stream_bytes": supplemental_capture_stream_bytes,
        "combined_capture_stream_bytes": (
            capture_stream_bytes + supplemental_capture_stream_bytes
        ),
        "baseband_dma_buffer_bytes": dma_buffer_bytes,
        "heap_metadata_reserve_bytes": config.heap_metadata_reserve_bytes,
        "minimum_modeled_headroom_bytes": config.minimum_modeled_headroom_bytes,
        "modeled_ram_headroom_bytes": modeled_headroom,
    }


def verify_outputs(
    nm_text: str,
    disassembly_text: str,
    section_text: str,
    *,
    elf_sha256: str,
    nm_version: str = "fixture-nm",
    objdump_version: str = "fixture-objdump",
    config: GateConfig = GateConfig(),
    _legacy_p14_test_contract: bool = False,
) -> dict[str, object]:
    symbols = parse_nm(nm_text)
    functions = parse_disassembly(disassembly_text)
    sections = parse_sections(section_text)
    literal_words = parse_literal_words(disassembly_text)
    p12_metadata = _p12_metadata(
        symbols,
        (
            P14_TEST_ABSOLUTE_METADATA
            if _legacy_p14_test_contract
            else P12_ABSOLUTE_METADATA
        ),
    )
    p12_profile = p12_metadata is not None
    p15_profile = p12_profile and not _legacy_p14_test_contract
    p12_dma_irq_split = (
        _verify_p12_dma_irq_split(
            symbols=symbols,
            functions=functions,
            literal_words=literal_words,
        )
        if p12_profile
        else None
    )
    p12_shutdown_quiesce = (
        (
            _verify_p15_shutdown_quiesce(
                symbols=symbols,
                functions=functions,
                literal_words=literal_words,
            )
            if p15_profile
            else _verify_p12_shutdown_quiesce(
                symbols=symbols,
                functions=functions,
                literal_words=literal_words,
            )
        )
        if p12_profile
        else None
    )
    p14_control_active_drain = (
        (
            _verify_p15_control_active_drain(
                functions=functions,
                literal_words=literal_words,
            )
            if p15_profile
            else _verify_p14_control_active_drain(
                functions=functions,
                literal_words=literal_words,
            )
        )
        if p12_profile
        else None
    )
    p15_shutdown_mode_dispatch = (
        _verify_p15_shutdown_mode_dispatch(
            functions=functions,
            literal_words=literal_words,
        )
        if p15_profile
        else None
    )
    p13_energy_log10_safety = (
        _verify_p13_energy_log10_safety(
            symbols=symbols,
            functions=functions,
            literal_words=literal_words,
        )
        if p12_profile
        else None
    )
    operator_new_definitions = {
        (symbol.address, symbol.size)
        for symbol in symbols
        if _is_operator_new(symbol.name)
    }
    operator_new_array_definitions = {
        (symbol.address, symbol.size)
        for symbol in symbols
        if _is_operator_new_array(symbol.name)
    }
    allocator_alias_merged = (
        p12_profile
        and len(operator_new_definitions) == 1
        and operator_new_definitions == operator_new_array_definitions
    )
    stream_sealed_offset = 1008 if p12_profile else 984
    stream_config_offset = 1012 if p12_profile else 988
    active_capture_config_offset = 1020 if p12_profile else 996
    capture_command_offset = 1028 if p12_profile else 1004
    pending_capture_config_offset = 1032 if p12_profile else 1008

    main = _unique_function(functions, "main", lambda name: name == "main")
    rebind = _unique_function(functions, REBIND_NAME, lambda name: name == REBIND_NAME)
    acknowledge = _unique_function(
        functions,
        ACKNOWLEDGE_NAME,
        lambda name: name == ACKNOWLEDGE_NAME,
    )
    seal = _unique_function(functions, SEAL_NAME, lambda name: name == SEAL_NAME)
    drained = _unique_function(
        functions,
        DRAINED_NAME,
        lambda name: name == DRAINED_NAME,
    )
    service = _unique_function(functions, SERVICE_NAME, lambda name: name == SERVICE_NAME)
    execute = _unique_function(
        functions,
        "PrecisionRxProcessor::execute",
        lambda name: name.startswith(EXECUTE_PREFIX),
    )
    geometry_constructor = _unique_function(
        functions,
        "StreamInput geometry constructor",
        _is_geometry_constructor,
    )
    baseband_constructor = _unique_function(
        functions,
        "BasebandThread constructor",
        _is_baseband_constructor,
    )
    baseband_run = _unique_function(
        functions,
        BASEBAND_RUN_NAME,
        lambda name: name == BASEBAND_RUN_NAME,
    )
    descriptor_builder = _unique_function(
        functions,
        DMA_DESCRIPTOR_BUILDER_NAME,
        lambda name: name == DMA_DESCRIPTOR_BUILDER_NAME,
    )
    configure_lease = _unique_function(
        functions,
        "Precision RX lease configuration",
        lambda name: name.startswith(DMA_CONFIGURE_LEASE_PREFIX),
    )
    dma_set_geometry = _unique_function(
        functions,
        DMA_SET_GEOMETRY_NAME,
        lambda name: name == DMA_SET_GEOMETRY_NAME,
    )
    dma_enable = _unique_function(
        functions,
        DMA_ENABLE_NAME,
        lambda name: name == DMA_ENABLE_NAME,
    )
    dma_wait = _unique_function(
        functions,
        DMA_WAIT_NAME,
        lambda name: name == DMA_WAIT_NAME,
    )
    dma_loan = _unique_function(
        functions,
        DMA_LOAN_NAME,
        lambda name: name == DMA_LOAN_NAME,
    )
    dma_release = _unique_function(
        functions,
        DMA_RELEASE_NAME,
        lambda name: name == DMA_RELEASE_NAME,
    )
    dma_unbind_drained = _unique_function(
        functions,
        DMA_UNBIND_DRAINED_NAME,
        lambda name: name == DMA_UNBIND_DRAINED_NAME,
    )
    dma_force_unbind = _unique_function(
        functions,
        DMA_FORCE_UNBIND_NAME,
        lambda name: name == DMA_FORCE_UNBIND_NAME,
    )
    baseband_geometry = _unique_function(
        functions,
        BASEBAND_GEOMETRY_NAME,
        lambda name: name == BASEBAND_GEOMETRY_NAME,
    )
    transition_geometry = _unique_function(
        functions,
        TRANSITION_NAME,
        lambda name: name == TRANSITION_NAME,
    )
    finish_command = _unique_function(
        functions,
        FINISH_COMMAND_NAME,
        lambda name: name == FINISH_COMMAND_NAME,
    )
    processor_message: Function | None = None
    processor_constructor: Function | None = None
    processor_rate_resume: Function | None = None
    processor_publish_running: Function | None = None
    baseband_rate_prepare: Function | None = None
    baseband_rate_resume: Function | None = None
    dma_halt_disable: Function | None = None
    dma_fail_pending: Function | None = None
    dma_fast_latch: Function | None = None
    dma_complete_fault: Function | None = None
    dma_claim_completion: Function | None = None
    sgpio_streaming_disable: Function | None = None
    sgpio_streaming_enable: Function | None = None
    if p12_profile:
        processor_constructor = _unique_function(
            functions,
            "PrecisionRxProcessor constructor",
            lambda name: name.startswith(PROCESSOR_CONSTRUCTOR_PREFIX),
        )
        processor_message = _unique_function(
            functions,
            "PrecisionRxProcessor::on_message",
            lambda name: name.startswith(PROCESSOR_MESSAGE_PREFIX),
        )
        processor_rate_resume = _unique_function(
            functions,
            "PrecisionRxProcessor::resume_rate_change",
            lambda name: name.startswith(PROCESSOR_RATE_RESUME_PREFIX),
        )
        processor_publish_running = _unique_function(
            functions,
            "PrecisionRxProcessor::publish_running_if_dma_healthy",
            lambda name: name.startswith(PROCESSOR_PUBLISH_RUNNING_PREFIX),
        )
        baseband_rate_prepare = _unique_function(
            functions,
            BASEBAND_RATE_PREPARE_NAME,
            lambda name: name == BASEBAND_RATE_PREPARE_NAME,
        )
        baseband_rate_resume = _unique_function(
            functions,
            BASEBAND_RATE_RESUME_NAME,
            lambda name: name == BASEBAND_RATE_RESUME_NAME,
        )
        dma_halt_disable = _unique_function(
            functions,
            "p12 Precision RX HALT/disable helper",
            lambda name: name.startswith(DMA_HALT_DISABLE_PREFIX),
        )
        dma_fail_pending = _unique_function(
            functions,
            DMA_FAIL_PENDING_NAME,
            lambda name: name == DMA_FAIL_PENDING_NAME,
        )
        dma_fast_latch = _unique_function(
            functions,
            "p12 Precision RX fast fatal DMA latch",
            lambda name: name.startswith(DMA_FAST_LATCH_PREFIX),
        )
        dma_complete_fault = _unique_function(
            functions,
            "p12 Precision RX deferred fatal DMA completion",
            lambda name: name == DMA_COMPLETE_FAULT_NAME,
        )
        dma_claim_completion = _unique_function(
            functions,
            "p12 Precision RX completion-claim helper",
            lambda name: name == DMA_CLAIM_COMPLETION_NAME,
        )
        if not p15_profile:
            sgpio_streaming_disable = _unique_function(
                functions,
                "p12 SGPIO streaming-disable helper",
                lambda name: name.startswith(
                    SGPIO_STREAMING_DISABLE_PREFIX
                ),
            )
        sgpio_streaming_enable = _unique_function(
            functions,
            "p12 fail-closed SGPIO gate-open helper",
            lambda name: name == DMA_GATE_OPEN_NAME,
        )
    construction_function = processor_constructor or main

    rebind_size = _unique_symbol_size(
        symbols,
        REBIND_NAME,
        lambda name: name == REBIND_NAME,
    )
    service_size = _unique_symbol_size(
        symbols,
        SERVICE_NAME,
        lambda name: name == SERVICE_NAME,
    )
    execute_size = _unique_symbol_size(
        symbols,
        "PrecisionRxProcessor::execute",
        lambda name: name.startswith(EXECUTE_PREFIX),
    )
    descriptor_builder_size = _unique_symbol_size(
        symbols,
        DMA_DESCRIPTOR_BUILDER_NAME,
        lambda name: name == DMA_DESCRIPTOR_BUILDER_NAME,
    )
    _require(
        rebind_size <= config.max_rebind_code_bytes,
        f"{REBIND_NAME} grew to {rebind_size} bytes; maximum is "
        f"{config.max_rebind_code_bytes}",
    )
    _require(
        service_size <= config.max_service_code_bytes,
        f"{SERVICE_NAME} grew to {service_size} bytes; maximum is "
        f"{config.max_service_code_bytes}",
    )

    p12_linked_control: dict[str, object] | None = None
    p12_gate_open_proof: dict[str, object] | None = None
    if p12_profile:
        assert processor_message is not None
        assert baseband_rate_prepare is not None
        assert baseband_rate_resume is not None

        message_armed_paths = _reachable_call_paths(
            functions,
            processor_message,
            lambda name: name in {
                BASEBAND_RATE_ARMED_NAME,
                DMA_RATE_ARMED_NAME,
            },
        )
        message_resume_paths = _reachable_call_paths(
            functions,
            processor_message,
            lambda name: name == BASEBAND_RATE_RESUME_NAME,
        )
        execute_prepare_paths = _reachable_call_paths(
            functions,
            execute,
            lambda name: name == BASEBAND_RATE_PREPARE_NAME,
        )
        _require(
            bool(message_armed_paths),
            "p12 on_message must reach a normal DMA-waiter armed check before "
            "PREPARED",
        )
        _require(
            bool(message_resume_paths),
            "p12 on_message must reach a COMMIT/ABORT resume path",
        )
        _require(
            bool(execute_prepare_paths),
            "p12 execute must reach worker-side PREPARE at a completed-buffer "
            "boundary",
        )

        rate_pause_functions = [
            function
            for function in functions
            if function.name.startswith(PROCESSOR_RATE_PAUSE_PREFIX)
        ]
        if rate_pause_functions:
            _require(
                len(rate_pause_functions) == 1
                and bool(
                    _reachable_call_paths(
                        functions,
                        rate_pause_functions[0],
                        lambda name: name in {
                            BASEBAND_RATE_ARMED_NAME,
                            DMA_RATE_ARMED_NAME,
                        },
                    )
                ),
                "linked request_rate_pause must confirm the normal DMA waiter "
                "before acknowledging PREPARED",
            )

        rate_resume_functions = [
            function
            for function in functions
            if function.name.startswith(PROCESSOR_RATE_RESUME_PREFIX)
        ]
        if rate_resume_functions:
            resume_paths_from_helper = _reachable_call_paths(
                functions,
                rate_resume_functions[0],
                lambda name: name == BASEBAND_RATE_RESUME_NAME,
            )
            _require(
                len(rate_resume_functions) == 1
                and bool(resume_paths_from_helper),
                "linked resume_rate_change must reach the reviewed BasebandThread "
                "DMA/SGPIO resume wrapper",
            )
            resume_path, resume_terminal_call = resume_paths_from_helper[0]
            resume_call_owner = next(
                function
                for function in functions
                if function.name == resume_path[-1]
            )
            _require_ordered_instructions(
                resume_call_owner,
                (
                    (
                        "publish the requested target rate",
                        lambda ins: _store_at_offset(ins, 636),
                    ),
                    (
                        "release the target-rate transaction state",
                        _dmb,
                    ),
                    (
                        "release-publish the pending target rate",
                        lambda ins: _store_at_offset(ins, 620),
                    ),
                    (
                        "resume DMA only after target publication",
                        lambda ins: (
                            ins.address == resume_terminal_call.address
                        ),
                    ),
                ),
            )

        lower_pause_call = _require_one_call(
            baseband_rate_prepare,
            DMA_RATE_PAUSE_NAME,
            lambda name: name == DMA_RATE_PAUSE_NAME,
        )
        assert sgpio_streaming_enable is not None
        if not p15_profile:
            assert sgpio_streaming_disable is not None
            _require_ordered_instructions(
                sgpio_streaming_disable,
                (
                    (
                        "set the SGPIO gate bit",
                        lambda ins: ins.mnemonic.startswith("orr")
                        and _has_immediate(ins, 1 << 10),
                    ),
                    (
                        "publish the disabled SGPIO gate",
                        lambda ins: ins.mnemonic.startswith("str"),
                    ),
                ),
            )
        if any(
            symbol.name == DMA_RATE_STATE_BEGIN_NAME
            for symbol in symbols
        ):
            p12_gate_open_proof = _verify_p12_gate_open_helper(
                symbols=symbols,
                functions=functions,
            )
        else:
            _require_ordered_instructions(
                sgpio_streaming_enable,
                (
                    (
                        "clear the SGPIO gate bit",
                        lambda ins: ins.mnemonic.startswith("bic")
                        and _has_immediate(ins, 1 << 10),
                    ),
                    (
                        "publish the enabled SGPIO gate",
                        lambda ins: ins.mnemonic.startswith("str"),
                    ),
                ),
            )
            p12_gate_open_proof = {
                "function": sgpio_streaming_enable.name,
                "legacy_fixture_shape_only": True,
            }
        if p15_profile:
            _require(
                not _calls_matching(
                    baseband_rate_prepare,
                    lambda name: name.startswith(
                        SGPIO_STREAMING_DISABLE_PREFIX
                    )
                    or name == DMA_GATE_OPEN_NAME,
                )
                and not _literal_loads(
                    baseband_rate_prepare,
                    literal_words,
                    SGPIO_CONTROLLER_BASE_ADDRESS,
                )
                and not any(
                    instruction.mnemonic.startswith(("orr", "bic"))
                    and _has_immediate(instruction, 1 << 10)
                    for instruction
                    in baseband_rate_prepare.instructions
                ),
                "P15 PREPARE wrapper must not call or inline any SGPIO "
                "pre-gate/reopen operation",
            )
            prepare_lock_calls = _calls_matching(
                baseband_rate_prepare,
                lambda name: name in {
                    "dbg_check_lock",
                    "dbg_check_unlock",
                },
            )
            _require(
                len(prepare_lock_calls) == 2
                and prepare_lock_calls[0].target == "dbg_check_lock"
                and prepare_lock_calls[0].address
                < lower_pause_call.address
                < prepare_lock_calls[1].address
                and prepare_lock_calls[1].target
                == "dbg_check_unlock",
                "P15 PREPARE must delegate directly to the lower pause while "
                "holding the system lock",
            )
            dma_rate_pause = _unique_function(
                functions,
                DMA_RATE_PAUSE_NAME,
                lambda name: name == DMA_RATE_PAUSE_NAME,
            )
            pause_halt_call = _require_one_call(
                dma_rate_pause,
                "P15 rate-pause HALT helper",
                lambda name: name.startswith(
                    DMA_HALT_DISABLE_PREFIX
                ),
            )
            pause_result_move = _next_non_nop(
                dma_rate_pause,
                pause_halt_call.address,
            )
            pause_result_compare = (
                _next_non_nop(
                    dma_rate_pause,
                    pause_result_move.address,
                )
                if pause_result_move is not None
                else None
            )
            pause_result_branch = (
                _next_non_nop(
                    dma_rate_pause,
                    pause_result_compare.address,
                )
                if pause_result_compare is not None
                else None
            )
            _require(
                pause_result_move is not None
                and pause_result_move.mnemonic.startswith("mov")
                and _first_operand_register(pause_result_move) == "r4"
                and _operand_registers(pause_result_move)[1:] == ("r0",)
                and pause_result_compare is not None
                and pause_result_compare.mnemonic.startswith("cmp")
                and _first_operand_register(pause_result_compare) == "r0"
                and _has_immediate(pause_result_compare, 0)
                and pause_result_branch is not None
                and pause_result_branch.mnemonic.startswith("beq"),
                "P15 lower pause must branch on the exact HALT helper "
                "boolean",
            )
            pause_success_entry = _next_non_nop(
                dma_rate_pause,
                pause_result_branch.address,
            )
            pause_failure_entry = _instruction_at(
                dma_rate_pause,
                _branch_target_address(pause_result_branch),
            )
            pause_mutation_calls = [
                call
                for call in _calls(dma_rate_pause)
                if call.address > pause_result_branch.address
                and call.target is not None
                and (
                    "record_boundary_discard" in call.target
                    or "discard_completion_queue_for_boundary"
                    in call.target
                )
            ]
            _require(
                pause_success_entry is not None
                and pause_failure_entry is not None
                and len(pause_mutation_calls) == 2,
                "P15 pause mutation boundary is unresolved",
            )
            pause_successors = _control_flow_successors(
                dma_rate_pause,
                reject_thumb_it=False,
            )

            def pause_reachable(start: int) -> frozenset[int]:
                reached: set[int] = set()
                pending = [start]
                while pending:
                    address = pending.pop()
                    if (
                        address in reached
                        or address not in pause_successors
                    ):
                        continue
                    reached.add(address)
                    pending.extend(pause_successors[address] - reached)
                return frozenset(reached)

            pause_success_reachable = pause_reachable(
                pause_success_entry.address
            )
            pause_failure_reachable = pause_reachable(
                pause_failure_entry.address
            )
            pause_mutation_addresses = {
                call.address for call in pause_mutation_calls
            }
            _require(
                pause_mutation_addresses.issubset(
                    pause_success_reachable
                )
                and not pause_mutation_addresses.intersection(
                    pause_failure_reachable
                ),
                "P15 HALT failure must bypass rate queue/owner mutation",
            )
        else:
            prepare_disable_call = _require_one_call(
                baseband_rate_prepare,
                "SGPIO streaming-disable helper",
                lambda name: name.startswith(
                    SGPIO_STREAMING_DISABLE_PREFIX
                ),
            )
            prepare_enable_call = _require_one_call(
                baseband_rate_prepare,
                "fail-closed SGPIO gate-open helper",
                lambda name: name == DMA_GATE_OPEN_NAME,
            )
            prepare_gate_order = _require_ordered_instructions(
                baseband_rate_prepare,
                (
                    (
                        "gate SGPIO requests",
                        lambda ins: ins.address
                        == prepare_disable_call.address,
                    ),
                    (
                        "pause DMA after the SGPIO gate",
                        lambda ins: ins.address
                        == lower_pause_call.address,
                    ),
                    ("test the DMA pause result", _is_conditional_branch),
                    (
                        "load the durable DMA-fault latch",
                        lambda ins: ins.mnemonic.startswith("ldr"),
                    ),
                    (
                        "skip rollback when DMA faulted",
                        _is_conditional_branch,
                    ),
                    (
                        "restore SGPIO only after a clean PREPARE failure",
                        lambda ins: ins.address
                        == prepare_enable_call.address,
                    ),
                ),
            )
            prepare_success_target = _branch_target_address(
                prepare_gate_order[2]
            )
            prepare_fault_target = _branch_target_address(
                prepare_gate_order[4]
            )
            _require(
                prepare_success_target is not None
                and prepare_success_target
                > prepare_gate_order[-1].address,
                "successful p12 PREPARE must branch over the fail-closed "
                "SGPIO rollback path",
            )
            _require(
                prepare_fault_target is not None
                and prepare_fault_target
                > prepare_gate_order[-1].address,
                "faulted p12 PREPARE must keep SGPIO gated",
            )

        lower_resume_call = _require_one_call(
            baseband_rate_resume,
            DMA_RATE_RESUME_NAME,
            lambda name: name == DMA_RATE_RESUME_NAME,
        )
        resume_enable_call = _require_one_call(
            baseband_rate_resume,
            "fail-closed SGPIO gate-open helper",
            lambda name: name == DMA_GATE_OPEN_NAME,
        )
        resume_gate_order = _require_ordered_instructions(
            baseband_rate_resume,
            (
                (
                    "resume DMA before opening the SGPIO gate",
                    lambda ins: ins.address == lower_resume_call.address,
                ),
                ("test the DMA resume result", _is_conditional_branch),
                (
                    "open the SGPIO gate only after DMA resume",
                    lambda ins: ins.address == resume_enable_call.address,
                ),
            ),
        )
        resume_failure_target = _branch_target_address(resume_gate_order[1])
        _require(
            resume_failure_target is not None
            and resume_failure_target > resume_gate_order[-1].address,
            "failed p12 COMMIT/ABORT resume must branch over SGPIO enable",
        )

        p12_linked_control = {
            "processor_message_function": processor_message.name,
            "pause_armed_paths": [
                list(path) for path, _ in message_armed_paths
            ],
            "resume_paths": [
                list(path) for path, _ in message_resume_paths
            ],
            "worker_boundary_prepare_paths": [
                list(path) for path, _ in execute_prepare_paths
            ],
            "baseband_prepare_function": baseband_rate_prepare.name,
            "prepare_runs_from_worker_boundary": True,
            "dma_halt_precedes_sgpio_gate": p15_profile,
            "prepare_wrapper_pre_gates_sgpio": not p15_profile,
            "prepare_failure_restores_sgpio": not p15_profile,
            "baseband_resume_function": baseband_rate_resume.name,
            "dma_resume_precedes_sgpio_enable": True,
            "resume_failure_keeps_sgpio_gated": True,
            "target_publication_precedes_dma_resume": True,
        }

    rebind_calls = _calls(rebind)
    rebind_fifo_helper: dict[str, int | bool | str] | None = None
    if rebind_calls:
        _require(
            p12_profile
            and len(rebind_calls) == 1
            and rebind_calls[0].target == FIFO_STREAM_BUFFER_IN_NAME,
            f"{REBIND_NAME} must remain call-free except for exactly one "
            f"reviewed {FIFO_STREAM_BUFFER_IN_NAME} call; found: "
            + ", ".join(call.target or "<indirect>" for call in rebind_calls),
        )
        rebind_fifo_helper = _verify_rebind_fifo_helper(symbols, functions)

    _require_one_call(service, REBIND_NAME, lambda name: name == REBIND_NAME)
    _require_one_call(
        service,
        ACKNOWLEDGE_NAME,
        lambda name: name == ACKNOWLEDGE_NAME,
    )
    _require_one_call(
        service,
        BEGIN_CAPTURE_NAME,
        lambda name: name == BEGIN_CAPTURE_NAME,
    )
    _require_one_call(service, SEAL_NAME, lambda name: name == SEAL_NAME)
    _require_one_call(service, DRAINED_NAME, lambda name: name == DRAINED_NAME)
    for function in (service, execute):
        forbidden = [
            call
            for call in _calls(function)
            if call.target is None
            or _is_allocator(call.target)
            or _is_geometry_constructor(call.target)
        ]
        _require(
            not forbidden,
            f"{function.name} contains an allocator, StreamInput constructor, or "
            "indirect call: "
            + ", ".join(call.target or "<indirect>" for call in forbidden),
        )

    service_bulk_calls = [
        call
        for call in _calls(service)
        if call.target is not None and _is_bulk_memory(call.target)
    ]
    for call in service_bulk_calls:
        _require(
            call.target in {"memset", "memcpy", "memmove"},
            f"unreviewed bulk-memory helper in {SERVICE_NAME}: {call.target}",
        )
        bulk_bytes = _immediate_argument_before_call(service, call, "r2")
        _require(
            bulk_bytes <= config.max_service_bulk_bytes,
            f"{SERVICE_NAME} bulk-memory call {call.target} requests {bulk_bytes} "
            f"bytes; maximum is {config.max_service_bulk_bytes}",
        )

    constructor_new = _require_one_call(
        geometry_constructor,
        "operator new[] or its p12-proven identical operator new alias",
        lambda name: _is_operator_new_array(name)
        or (allocator_alias_merged and _is_operator_new(name)),
    )
    constructor_allocation_bytes = _immediate_argument_before_call(
        geometry_constructor,
        constructor_new,
        "r0",
    )
    _require(
        constructor_allocation_bytes == EXPECTED_STREAM_WRITE_SIZE
        * EXPECTED_STREAM_BUFFER_COUNT,
        "StreamInput geometry constructor allocation has the wrong linked size",
    )
    constructor_memsets = _calls_matching(
        geometry_constructor,
        lambda name: name == "memset",
    )
    constructor_value_initialization = "memset"
    if not any(
        call.address > constructor_new.address
        for call in constructor_memsets
    ):
        _require(
            p12_profile,
            "StreamInput geometry constructor must value-initialize its "
            "allocation before BasebandThread starts",
        )
        explicit_init_tail = [
            instruction
            for instruction in geometry_constructor.instructions
            if instruction.address > constructor_new.address
        ]
        end_pointer = next(
            (
                instruction
                for instruction in explicit_init_tail
                if instruction.mnemonic.startswith("add")
                and _has_immediate(
                    instruction,
                    constructor_allocation_bytes,
                )
            ),
            None,
        )
        zero_store = next(
            (
                instruction
                for instruction in explicit_init_tail
                if end_pointer is not None
                and instruction.address > end_pointer.address
                and instruction.mnemonic.startswith("strb")
                and _has_immediate(instruction, 1)
            ),
            None,
        )
        end_compare = next(
            (
                instruction
                for instruction in explicit_init_tail
                if zero_store is not None
                and instruction.address > zero_store.address
                and instruction.mnemonic.startswith("cmp")
            ),
            None,
        )
        init_loop = next(
            (
                instruction
                for instruction in explicit_init_tail
                if end_compare is not None
                and instruction.address > end_compare.address
                and _is_conditional_branch(instruction)
                and _branch_target_address(instruction)
                == zero_store.address
            ),
            None,
        )
        _require(
            end_pointer is not None
            and zero_store is not None
            and end_compare is not None
            and init_loop is not None,
            "p12 StreamInput geometry constructor lacks the bounded explicit "
            "value-initialization loop",
        )
        constructor_value_initialization = "bounded-explicit-byte-loop"

    main_stream_constructor = _require_one_call(
        construction_function,
        "StreamInput geometry constructor",
        _is_geometry_constructor,
    )
    main_baseband_constructor = _require_one_call(
        construction_function,
        "BasebandThread constructor",
        _is_baseband_constructor,
    )
    _require(
        main_stream_constructor.address < main_baseband_constructor.address,
        "StreamInput construction must precede BasebandThread construction in main",
    )

    stream_write_size = _immediate_argument_before_call(
        construction_function,
        main_stream_constructor,
        "r1",
    )
    stream_buffer_count = _immediate_argument_before_call(
        construction_function,
        main_stream_constructor,
        "r2",
    )
    _require(
        stream_write_size == config.expected_stream_write_size,
        f"linked stream write size is {stream_write_size}; expected "
        f"{config.expected_stream_write_size}",
    )
    _require(
        stream_buffer_count == config.expected_stream_buffer_count,
        f"linked stream buffer count is {stream_buffer_count}; expected "
        f"{config.expected_stream_buffer_count}",
    )

    # The metadata above is only useful if the linked control/data paths
    # consume it.  Prove the complete p11 lease chain and its ownership
    # barriers from the final disassembly, not from source declarations.
    loan_call = _require_one_call(
        construction_function,
        DMA_LOAN_NAME,
        lambda name: name == DMA_LOAN_NAME,
    )
    _require(
        main_stream_constructor.address < loan_call.address
        < main_baseband_constructor.address,
        "the fixed DMA loan must be acquired after StreamInput construction "
        "and before BasebandThread construction",
    )
    loan_callers = {
        function.name
        for function in functions
        if _calls_matching(function, lambda name: name == DMA_LOAN_NAME)
    }
    _require(
        loan_callers == {construction_function.name},
        "the construction-only DMA loan accessor has unexpected callers: "
        + ", ".join(sorted(loan_callers)),
    )
    _require_ordered_instructions(
        dma_loan,
        (
            ("config-null load", lambda ins: _load_at_offset(ins, 360)),
            ("sealed-state load", lambda ins: _load_at_offset(ins, 356)),
            ("allocation load", lambda ins: _load_at_offset(ins, 364)),
            (
                "fixed 64 KiB loan offset",
                lambda ins: ins.mnemonic.startswith("add")
                and _has_immediate(ins, 64 * 1024),
            ),
        ),
    )
    _require(
        len([ins for ins in dma_loan.instructions if _is_conditional_branch(ins)]) >= 2,
        f"{DMA_LOAN_NAME} must reject bound or null storage",
    )

    _require(
        not _calls(descriptor_builder),
        f"{DMA_DESCRIPTOR_BUILDER_NAME} must remain call-free",
    )
    builder_immediates = {
        value
        for instruction in descriptor_builder.instructions
        for value in _instruction_immediates(instruction)
    }
    _require(
        {2, 4, 2048, 4096}.issubset(builder_immediates),
        "linked descriptor builder does not encode the reviewed two-way split, "
        "four LLIs, and 2/4 KiB transfer geometries",
    )
    _require(
        len(
            [
                instruction
                for instruction in descriptor_builder.instructions
                if instruction.mnemonic.startswith("strd")
            ]
        )
        >= 2,
        "linked descriptor builder must write SRC/DEST and LLI/CONTROL pairs",
    )
    descriptor_stores = [
        instruction
        for instruction in descriptor_builder.instructions
        if instruction.mnemonic.startswith("strd")
    ]
    descriptor_loop_branches = [
        instruction
        for instruction in descriptor_builder.instructions
        if instruction.mnemonic.startswith("bne")
        and (_branch_target_address(instruction) or instruction.address)
        <= descriptor_stores[0].address
    ]
    builder_literals = {
        value
        for address, value in literal_words.items()
        if descriptor_builder.address
        <= address
        < descriptor_builder.address + descriptor_builder_size
    }
    _require(
        descriptor_loop_branches
        and descriptor_stores[-1].address < descriptor_loop_branches[-1].address,
        "descriptor CONTROL write must execute in the reviewed four-LLI loop",
    )
    control_literal_loads = [
        instruction
        for instruction in descriptor_builder.instructions
        if instruction.mnemonic.startswith("ldr")
        and (target := _pc_literal_target(instruction)) is not None
        and literal_words.get(target) == 0x8A480000
    ]
    _require(
        0x8A480000 in builder_literals and len(control_literal_loads) == 1,
        "linked RX descriptor CONTROL base must retain terminal-count interrupt "
        "bit I on every LLI",
    )
    control_register = _first_operand_register(control_literal_loads[0])
    control_stores = [
        instruction
        for instruction in descriptor_stores
        if _memory_location(instruction) is not None
        and _memory_location(instruction)[1] == 8
        and len(_operand_registers(instruction)) >= 2
        and _operand_registers(instruction)[1] == control_register
    ]
    _require(
        len(control_stores) == 1
        and control_stores[0].address < descriptor_loop_branches[-1].address,
        "the reviewed terminal-count CONTROL value must flow into every looped LLI",
    )
    control_load_index = descriptor_builder.instructions.index(
        control_literal_loads[0]
    )
    control_store_index = descriptor_builder.instructions.index(control_stores[0])
    control_clobbers = [
        instruction
        for instruction in descriptor_builder.instructions[
            control_load_index + 1 : control_store_index
        ]
        if _first_operand_register(instruction) == control_register
        and not (
            instruction.mnemonic.startswith("orr")
            and _operand_registers(instruction)[:2]
            == (control_register, control_register)
        )
    ]
    _require(
        not control_clobbers,
        "the linked terminal-count CONTROL register is clobbered before its LLI write",
    )
    _require(
        any(
            instruction.mnemonic.startswith("ldr")
            and "eq" in instruction.mnemonic
            for instruction in descriptor_builder.instructions
        )
        and any("lsl #4" in ins.operands for ins in descriptor_builder.instructions),
        "linked descriptor builder lacks the loan-base switch or 16-byte LLI stride",
    )

    _require_one_call(
        configure_lease,
        DMA_DESCRIPTOR_BUILDER_NAME,
        lambda name: name == DMA_DESCRIPTOR_BUILDER_NAME,
    )
    configure_builder_call = _calls_matching(
        configure_lease, lambda name: name == DMA_DESCRIPTOR_BUILDER_NAME
    )[0]
    _require(
        len(
            [
                instruction
                for instruction in configure_lease.instructions
                if instruction.address < configure_builder_call.address
                and instruction.mnemonic.startswith("str")
            ]
        )
        >= 2,
        "initial lease configuration must publish both owned and loan bases "
        "before building descriptors",
    )
    _require_one_call(
        dma_set_geometry,
        DMA_DESCRIPTOR_BUILDER_NAME,
        lambda name: name == DMA_DESCRIPTOR_BUILDER_NAME,
    )

    geometry_builder_call = _calls_matching(
        dma_set_geometry, lambda name: name == DMA_DESCRIPTOR_BUILDER_NAME
    )[0]
    if p12_profile:
        assert dma_halt_disable is not None
        halt_call = _require_one_call(
            dma_set_geometry,
            "p12 Precision RX HALT/disable helper",
            lambda name: name.startswith(DMA_HALT_DISABLE_PREFIX),
        )
        if p15_profile:
            result_move = _next_non_nop(
                dma_set_geometry,
                halt_call.address,
            )
            result_compare = (
                _next_non_nop(dma_set_geometry, result_move.address)
                if result_move is not None
                else None
            )
            result_branch = (
                _next_non_nop(dma_set_geometry, result_compare.address)
                if result_compare is not None
                else None
            )
            _require(
                result_move is not None
                and result_move.mnemonic.startswith("mov")
                and _first_operand_register(result_move) == "r4"
                and _operand_registers(result_move)[1:] == ("r0",)
                and result_compare is not None
                and result_compare.mnemonic.startswith("cmp")
                and _first_operand_register(result_compare) == "r0"
                and _has_immediate(result_compare, 0)
                and result_branch is not None
                and result_branch.mnemonic.startswith("beq"),
                "P15 geometry must branch on the exact HALT helper boolean",
            )
            geometry_success_entry = _next_non_nop(
                dma_set_geometry,
                result_branch.address,
            )
            geometry_failure_entry = _instruction_at(
                dma_set_geometry,
                _branch_target_address(result_branch),
            )
            geometry_success_mutations = [
                call
                for call in _calls(dma_set_geometry)
                if call.address > result_branch.address
                and (
                    call.target == DMA_DESCRIPTOR_BUILDER_NAME
                    or (
                        call.target is not None
                        and (
                            "discard_in_flight_for_boundary" in call.target
                            or "discard_completion_queue_for_boundary"
                            in call.target
                            or "ThreadWait::reset" in call.target
                        )
                    )
                )
            ]
            _require(
                geometry_success_entry is not None
                and geometry_failure_entry is not None
                and len(geometry_success_mutations) >= 3,
                "P15 geometry mutation boundary is unresolved",
            )
            geometry_successors = _control_flow_successors(
                dma_set_geometry,
            )

            def geometry_reachable(start: int) -> frozenset[int]:
                reached: set[int] = set()
                pending = [start]
                while pending:
                    address = pending.pop()
                    if (
                        address in reached
                        or address not in geometry_successors
                    ):
                        continue
                    reached.add(address)
                    pending.extend(
                        geometry_successors[address] - reached
                    )
                return frozenset(reached)

            geometry_success_reachable = geometry_reachable(
                geometry_success_entry.address
            )
            geometry_failure_reachable = geometry_reachable(
                geometry_failure_entry.address
            )
            mutation_addresses = {
                instruction.address
                for instruction in geometry_success_mutations
            }
            _require(
                mutation_addresses.issubset(
                    geometry_success_reachable
                )
                and not mutation_addresses.intersection(
                    geometry_failure_reachable
                )
                and geometry_builder_call.address
                in geometry_success_reachable
                and geometry_builder_call.address
                not in geometry_failure_reachable,
                "P15 HALT failure must bypass in-flight/queue/waiter/"
                "descriptor mutations",
            )
            _require_cfg_dominance(
                dma_set_geometry,
                start=halt_call,
                target=geometry_builder_call,
                required=(
                    ("HALT helper call", halt_call),
                    ("HALT result preservation", result_move),
                    ("HALT result comparison", result_compare),
                    ("HALT success branch", result_branch),
                    (
                        "discard in-flight owner",
                        geometry_success_mutations[0],
                    ),
                ),
            )
        else:
            halt_order = _require_ordered_instructions(
                dma_halt_disable,
                (
                    (
                        "set PL080 HALT",
                        lambda ins: ins.mnemonic.startswith("orr")
                        and _has_immediate(ins, 1 << 18),
                    ),
                    ("HALT publication DMB", _dmb),
                    (
                        "poll PL080 ACTIVE",
                        lambda ins: (
                            ins.mnemonic.startswith("and")
                            and _has_immediate(ins, 1 << 17)
                        )
                        or (
                            ins.mnemonic.startswith("lsl")
                            and _has_immediate(ins, 14)
                        ),
                    ),
                    (
                        "timeout clears HALT only",
                        lambda ins: ins.mnemonic.startswith("bic")
                        and _has_immediate(ins, 1 << 18),
                    ),
                    ("timeout rollback DMB", _dmb),
                    (
                        "timeout branches to the shared return without "
                        "descriptor rewrite",
                        lambda ins: ins.mnemonic in {"b", "b.n", "b.w"},
                    ),
                    (
                        "success clears channel enable",
                        lambda ins: ins.mnemonic.startswith("bic")
                        and _has_immediate(ins, 1),
                    ),
                    ("disable publication DMB", _dmb),
                    (
                        "clear terminal-count IRQ",
                        lambda ins: _store_at_offset(ins, 8),
                    ),
                    (
                        "clear error IRQ",
                        lambda ins: _store_at_offset(ins, 16),
                    ),
                ),
            )
            timeout_return_target = _branch_target_address(
                halt_order[5]
            )
            timeout_return_instruction = next(
                (
                    instruction
                    for instruction in dma_halt_disable.instructions
                    if instruction.address == timeout_return_target
                ),
                None,
            )
            _require(
                halt_order[5].address < halt_order[6].address
                and timeout_return_instruction is not None
                and _is_return_instruction(timeout_return_instruction),
                "PL080 ACTIVE timeout must return before E-clear and IRQ "
                "rewriting",
            )
            _require_ordered_instructions(
                dma_set_geometry,
                (
                    (
                        "quiesce the old DMA ring",
                        lambda ins: ins.address == halt_call.address,
                    ),
                    ("reject HALT timeout", _is_conditional_branch),
                    (
                        "rebuild lease descriptors",
                        lambda ins: ins.address
                        == geometry_builder_call.address,
                    ),
                    ("descriptor publication DMB", _dmb),
                    (
                        "re-clear terminal-count IRQ",
                        lambda ins: _store_at_offset(ins, 8),
                    ),
                    (
                        "re-clear error IRQ",
                        lambda ins: _store_at_offset(ins, 16),
                    ),
                ),
            )
    else:
        geometry_order = _require_ordered_instructions(
            dma_set_geometry,
            (
                (
                    "set PL080 HALT",
                    lambda ins: ins.mnemonic.startswith("orr")
                    and _has_immediate(ins, 1 << 18),
                ),
                ("HALT publication DMB", _dmb),
                (
                    "poll PL080 ACTIVE",
                    lambda ins: ins.mnemonic.startswith("and")
                    and _has_immediate(ins, 1 << 17),
                ),
                (
                    "timeout clears HALT only",
                    lambda ins: ins.mnemonic.startswith("bic")
                    and _has_immediate(ins, 1 << 18),
                ),
                ("timeout rollback DMB", _dmb),
                (
                    "timeout branch skips rewrite",
                    lambda ins: ins.mnemonic in {"b", "b.n", "b.w"},
                ),
                (
                    "success clears channel enable",
                    lambda ins: ins.mnemonic.startswith("bic")
                    and _has_immediate(ins, 1),
                ),
                ("disable publication DMB", _dmb),
                ("clear terminal-count IRQ", lambda ins: _store_at_offset(ins, 8)),
                ("clear error IRQ", lambda ins: _store_at_offset(ins, 16)),
                (
                    "rebuild lease descriptors",
                    lambda ins: ins.address == geometry_builder_call.address,
                ),
                ("descriptor publication DMB", _dmb),
                ("re-clear terminal-count IRQ", lambda ins: _store_at_offset(ins, 8)),
                ("re-clear error IRQ", lambda ins: _store_at_offset(ins, 16)),
            ),
        )
        timeout_target = _branch_target_address(geometry_order[5])
        _require(
            timeout_target is not None
            and timeout_target > geometry_builder_call.address,
            "PL080 ACTIVE timeout must bypass E-clear and all descriptor rewriting",
        )
    _require(
        not _calls_matching(dma_set_geometry, lambda name: name == DMA_ENABLE_NAME),
        "lower geometry switch must return while the channel remains disabled",
    )

    pending_error_proof: dict[str, object] | None = None
    if p12_profile:
        assert dma_fail_pending is not None
        assert dma_fast_latch is not None
        assert dma_complete_fault is not None
        pending_latch_call = _require_one_call(
            dma_fail_pending,
            "fast fatal DMA latch",
            lambda name: name == dma_fast_latch.name,
        )
        pending_complete_call = _require_one_call(
            dma_fail_pending,
            "deferred fatal DMA completion",
            lambda name: name == dma_complete_fault.name,
        )
        _require(
            len(_calls(dma_fail_pending)) == 2,
            f"{DMA_FAIL_PENDING_NAME} may call only the fast latch and "
            "deferred completion helpers",
        )
        pending_order = _require_ordered_instructions(
            dma_fail_pending,
            (
                (
                    "sample initial terminal-count status",
                    lambda ins: _load_at_offset(ins, 4),
                ),
                (
                    "sample initial DMA error status",
                    lambda ins: _load_at_offset(ins, 12),
                ),
                (
                    "sample initial enabled-channel status",
                    lambda ins: _load_at_offset(ins, 28),
                ),
                ("return clean when no error is pending", _is_conditional_branch),
                (
                    "exclude the priority-1 DMA vector",
                    lambda ins: _store_at_offset(ins, 128),
                ),
                ("publish vector exclusion", _dmb),
                (
                    "clear the pre-exclusion NVIC indication",
                    lambda ins: _store_at_offset(ins, 384),
                ),
                ("publish pending-bit retirement", _dmb),
                (
                    "sample final terminal-count status",
                    lambda ins: _load_at_offset(ins, 4),
                ),
                (
                    "sample final DMA error status",
                    lambda ins: _load_at_offset(ins, 12),
                ),
                (
                    "sample final enabled-channel status",
                    lambda ins: _load_at_offset(ins, 28),
                ),
                (
                    "latch fail-close through the priority-1-safe helper",
                    lambda ins: ins.address == pending_latch_call.address,
                ),
                ("clear terminal-count IRQ", lambda ins: _store_at_offset(ins, 8)),
                ("clear error IRQ", lambda ins: _store_at_offset(ins, 16)),
                (
                    "software-pend the deferred IRQ",
                    lambda ins: _store_at_offset(ins, 256),
                ),
                ("publish before vector re-enable", _dmb),
                (
                    "re-enable the priority-1 DMA vector",
                    lambda ins: _store_at_offset(ins, 0),
                ),
            ),
        )
        clean_branch = pending_order[3]
        clean_branch_mnemonic = clean_branch.mnemonic.lower().split(".", 1)[0]
        if clean_branch_mnemonic == "beq":
            clean_target = _branch_target_address(clean_branch)
        elif clean_branch_mnemonic == "bne":
            clean_fallthrough = _next_non_nop(
                dma_fail_pending,
                clean_branch.address,
            )
            clean_target = (
                clean_fallthrough.address
                if clean_fallthrough is not None
                else None
            )
        else:
            clean_target = None
        clean_zero = _instruction_at(dma_fail_pending, clean_target)
        clean_exit = (
            _next_non_nop(dma_fail_pending, clean_zero.address)
            if clean_zero is not None
            else None
        )
        if (
            clean_exit is not None
            and clean_exit.mnemonic in {"b", "b.n", "b.w"}
        ):
            clean_exit = _instruction_at(
                dma_fail_pending,
                _branch_target_address(clean_exit),
            )
        _require(
            clean_target is not None
            and clean_zero is not None
            and clean_zero.mnemonic.startswith("mov")
            and _first_operand_register(clean_zero) == "r0"
            and _has_immediate(clean_zero, 0)
            and clean_exit is not None
            and _is_return_instruction(clean_exit),
            "clean pending-error sample must return without clearing IRQ state",
        )
        complete_calls = _calls(dma_complete_fault)
        allowed_complete_targets = {
            "baseband::dma::record_unintentional_loss(unsigned long volatile&)",
            "baseband::dma::publish_queue_state()",
            "baseband::dma::reset_completion_queue_with_fast_irq_excluded()",
        }
        complete_transfer_targets = {
            instruction.target
            for instruction in _external_control_transfers(
                dma_complete_fault
            )
        }
        _require(
            complete_calls
            and all(
                call.target in allowed_complete_targets
                for call in complete_calls
            )
            and allowed_complete_targets.issubset(complete_transfer_targets)
            and any(
                target is not None
                and target.startswith("ThreadWait::wake_from_interrupt(")
                for target in complete_transfer_targets
            ),
            "deferred fatal DMA completion contains an indirect, allocating, "
            "or unreviewed call",
        )
        _require_ordered_instructions(
            dma_complete_fault,
            (
                (
                    "record invalidated completions",
                    lambda ins: ins.target
                    == "baseband::dma::record_unintentional_loss(unsigned long volatile&)",
                ),
                (
                    "reset the completion queue with fast IRQ exclusion",
                    lambda ins: ins.target
                    == "baseband::dma::reset_completion_queue_with_fast_irq_excluded()",
                ),
                (
                    "publish the reset completion queue",
                    lambda ins: ins.target
                    == "baseband::dma::publish_queue_state()",
                ),
            ),
        )
        enable_pending_call = _require_one_call(
            dma_enable,
            DMA_FAIL_PENDING_NAME,
            lambda name: name == DMA_FAIL_PENDING_NAME,
        )
        _require(
            len(_calls(dma_enable)) == 1,
            f"{DMA_ENABLE_NAME} may call only {DMA_FAIL_PENDING_NAME}",
        )
        enable_fault_branches = [
            instruction
            for instruction in dma_enable.instructions
            if instruction.address > enable_pending_call.address
            and instruction.mnemonic == "cbnz"
            and _branch_condition_register(instruction) == "r0"
        ]
        _require(
            len(enable_fault_branches) == 1,
            f"{DMA_ENABLE_NAME} must reject a pending DMA error before register "
            "writes",
        )
        enable_fault_target = _branch_target_address(
            enable_fault_branches[0]
        )
        enable_fault_return = next(
            (
                instruction
                for instruction in dma_enable.instructions
                if instruction.address == enable_fault_target
            ),
            None,
        )
        _require(
            enable_fault_return is not None
            and _is_return_instruction(enable_fault_return),
            f"{DMA_ENABLE_NAME} pending-error path must return without enabling",
        )
        pending_error_proof = {
            "status_sample_precedes_fatal_invalidation": (
                pending_order[0].address < pending_latch_call.address
            ),
            "fatal_invalidation_precedes_irq_clear": (
                pending_latch_call.address < pending_order[12].address
            ),
            "priority1_excluded_before_final_status_sample": True,
            "pre_exclusion_pending_bit_cleared_before_final_sample": True,
            "unexpected_channel_status_sampled": True,
            "simultaneous_tc_counted_through_fast_latch": True,
            "deferred_completion_after_vector_reenable": (
                pending_complete_call.address < pending_order[0].address
                or pending_complete_call.address > pending_order[-1].address
            ),
            "enable_rejects_pending_error_before_register_writes": True,
        }
    else:
        _require(
            not _calls(dma_enable),
            f"{DMA_ENABLE_NAME} must be the fixed-register, call-free RX path",
        )
    enable_order = _require_ordered_instructions(
        dma_enable,
        (
            ("clear terminal-count IRQ", lambda ins: _store_at_offset(ins, 8)),
            ("clear error IRQ", lambda ins: _store_at_offset(ins, 16)),
            ("write SRCADDR", lambda ins: _store_at_offset(ins, 0)),
            ("write DESTADDR", lambda ins: _store_at_offset(ins, 4)),
            ("write LLI", lambda ins: _store_at_offset(ins, 8)),
            ("write CONTROL", lambda ins: _store_at_offset(ins, 12)),
            (
                "write disabled RX CONFIG",
                lambda ins: _store_at_offset(ins, 16),
            ),
            (
                "set CONFIG.E",
                lambda ins: _bitwise_or_uses_constant(
                    dma_enable,
                    ins,
                    1,
                    literal_words=literal_words,
                ),
            ),
            ("publish enabled CONFIG", lambda ins: _store_at_offset(ins, 272)),
        ),
    )
    irq_locations = [_memory_location(instruction) for instruction in enable_order[:2]]
    channel_locations = [
        _memory_location(instruction) for instruction in enable_order[2:7]
    ]
    enabled_location = _memory_location(enable_order[-1])
    _require(
        None not in irq_locations
        and irq_locations[0][0] == irq_locations[1][0]
        and enabled_location is not None
        and enabled_location[0] == irq_locations[0][0],
        "fixed DMA enable IRQ clears and CONFIG.E publication must share the "
        "reviewed GPDMA base",
    )
    gpdma_base = irq_locations[0][0]
    _require(
        None not in channel_locations
        and len({location[0] for location in channel_locations}) == 1
        and channel_locations[0][0] != gpdma_base,
        "fixed DMA enable SRC/DEST/LLI/CONTROL/CONFIG writes must share one "
        "channel base distinct from the GPDMA base",
    )
    channel_base = channel_locations[0][0]
    descriptor_stores_by_offset = {
        offset: instruction
        for offset, instruction in zip((0, 4, 8, 12), enable_order[2:6])
    }
    loads = _load_records(dma_enable)
    descriptor_load_bases: set[str] | None = None
    for offset, store in descriptor_stores_by_offset.items():
        source_register = _first_operand_register(store)
        matching_bases = {
            base
            for _, register, base, load_offset in loads
            if register == source_register
            and load_offset == offset
            and base not in {gpdma_base, channel_base, "r15"}
        }
        descriptor_load_bases = (
            matching_bases
            if descriptor_load_bases is None
            else descriptor_load_bases & matching_bases
        )
    _require(
        descriptor_load_bases is not None
        and len(descriptor_load_bases) == 1,
        "fixed DMA enable must copy all four fields from one reviewed LLI base "
        "without source-register substitution",
    )
    disabled_config_store = enable_order[6]
    disabled_config_register = _first_operand_register(disabled_config_store)
    _require(
        any(
            instruction.address < disabled_config_store.address
            and _first_operand_register(instruction) == disabled_config_register
            and _has_immediate(instruction, 0xD000)
            for instruction in dma_enable.instructions
        ),
        "fixed DMA enable path must write the reviewed disabled RX CONFIG image",
    )
    enabled_store = enable_order[-1]
    enabled_register = _first_operand_register(enabled_store)
    enabled_store_index = dma_enable.instructions.index(enabled_store)
    enabled_loads = [
        instruction
        for instruction, register, base, offset in loads
        if register == enabled_register
        and base == gpdma_base
        and offset == 272
        and instruction.address < enabled_store.address
    ]
    _require(
        bool(enabled_loads)
        and any(
            enabled_loads[-1].address < instruction.address < enabled_store.address
            and instruction.mnemonic.startswith("orr")
            and _first_operand_register(instruction) == enabled_register
            and _last_register_writer(
                dma_enable,
                enabled_register,
                before=instruction,
            )
            == enabled_loads[-1]
            and _bitwise_or_uses_constant(
                dma_enable,
                instruction,
                1,
                literal_words=literal_words,
            )
            for instruction in dma_enable.instructions[:enabled_store_index]
        ),
        "fixed DMA enable must read the common GPDMA CONFIG, set E in that "
        "register, and publish it back to the same base",
    )

    lower_call = _require_one_call(
        baseband_geometry,
        DMA_SET_GEOMETRY_NAME,
        lambda name: name == DMA_SET_GEOMETRY_NAME,
    )
    enable_call = _require_one_call(
        baseband_geometry,
        DMA_ENABLE_NAME,
        lambda name: name == DMA_ENABLE_NAME,
    )
    _require(
        lower_call.address < enable_call.address
        and any(
            lower_call.address < instruction.address < enable_call.address
            and _is_conditional_branch(instruction)
            for instruction in baseband_geometry.instructions
        ),
        "BasebandThread must full-enable the rebuilt ring only on a successful "
        "lower geometry switch",
    )
    if p15_profile:
        geometry_gate_call = _require_one_call(
            baseband_geometry,
            "P15 post-enable SGPIO gate-open helper",
            lambda name: name == DMA_GATE_OPEN_NAME,
        )
        _require(
            not _calls_matching(
                baseband_geometry,
                lambda name: name.startswith(
                    SGPIO_STREAMING_DISABLE_PREFIX
                ),
            ),
            "P15 capture wrapper must not pre-gate SGPIO",
        )
        wrapper_result_move = _next_non_nop(
            baseband_geometry,
            lower_call.address,
        )
        wrapper_result_branch = (
            _next_non_nop(
                baseband_geometry,
                wrapper_result_move.address,
            )
            if wrapper_result_move is not None
            else None
        )
        _require(
            wrapper_result_move is not None
            and wrapper_result_move.mnemonic.startswith("mov")
            and _first_operand_register(wrapper_result_move) == "r4"
            and _operand_registers(wrapper_result_move)[1:] == ("r0",)
            and wrapper_result_branch is not None
            and wrapper_result_branch.mnemonic.startswith("cbnz")
            and _branch_condition_register(wrapper_result_branch) == "r0"
            and _branch_target_address(wrapper_result_branch)
            == enable_call.address
            and enable_call.address < geometry_gate_call.address,
            "P15 capture wrapper must branch on the exact lower result, "
            "then enable DMA before opening SGPIO",
        )
        wrapper_successors = _control_flow_successors(
            baseband_geometry,
            reject_thumb_it=False,
        )

        def wrapper_reachable(start: int | None) -> frozenset[int]:
            reached: set[int] = set()
            pending = [start] if start is not None else []
            while pending:
                address = pending.pop()
                if address in reached or address not in wrapper_successors:
                    continue
                reached.add(address)
                pending.extend(wrapper_successors[address] - reached)
            return frozenset(reached)

        wrapper_failure = wrapper_reachable(
            _next_non_nop(
                baseband_geometry,
                wrapper_result_branch.address,
            ).address
        )
        wrapper_success = wrapper_reachable(
            _branch_target_address(wrapper_result_branch)
        )
        _require(
            enable_call.address not in wrapper_failure
            and geometry_gate_call.address not in wrapper_failure
            and enable_call.address in wrapper_success
            and geometry_gate_call.address in wrapper_success,
            "P15 capture failure must leave the still-live old SGPIO/DMA "
            "transaction untouched; only success may restart and open",
        )

    transition_lower_call = _require_one_call(
        transition_geometry,
        BASEBAND_GEOMETRY_NAME,
        lambda name: name == BASEBAND_GEOMETRY_NAME,
    )
    transition_configure_call = _require_one_call(
        transition_geometry,
        "PrecisionRxProcessor::configure",
        lambda name: name.startswith(PROCESSOR_CONFIGURE_PREFIX),
    )
    if p12_profile:
        transition_failure_branches = [
            instruction
            for instruction in transition_geometry.instructions
            if transition_lower_call.address < instruction.address
            < transition_configure_call.address
            and instruction.mnemonic == "cbz"
            and _branch_condition_register(instruction) == "r0"
        ]
        _require(
            len(transition_failure_branches) == 1,
            "lower geometry switch must branch on a zero r0 result before "
            "configure",
        )
        transition_failure_branch = transition_failure_branches[0]
        transition_failure_target = _branch_target_address(
            transition_failure_branch
        )
        _require(
            transition_lower_call.address < transition_configure_call.address
            and transition_failure_target is not None
            and transition_failure_target > transition_configure_call.address,
            "failed geometry attempts must preserve the existing accounting "
            "epoch by branching over configure",
        )
    else:
        transition_between = [
            instruction
            for instruction in transition_geometry.instructions
            if transition_lower_call.address < instruction.address
            < transition_configure_call.address
        ]
        _require(
            transition_lower_call.address < transition_configure_call.address
            and not any(
                _is_branch(instruction)
                for instruction in transition_between
            ),
            "every geometry attempt in the legacy profile must establish a "
            "configured accounting epoch",
        )

    run_configure_call = _require_one_call(
        baseband_run,
        "Precision RX lease configuration",
        lambda name: name.startswith(DMA_CONFIGURE_LEASE_PREFIX),
    )
    run_enable_call = _require_one_call(
        baseband_run,
        DMA_ENABLE_NAME,
        lambda name: name == DMA_ENABLE_NAME,
    )
    run_wait_call = _require_one_call(
        baseband_run,
        DMA_WAIT_NAME,
        lambda name: name == DMA_WAIT_NAME,
    )
    run_sgpio_call = _require_one_call(
        baseband_run,
        SGPIO_CONFIGURE_NAME,
        lambda name: name == SGPIO_CONFIGURE_NAME,
    )
    _require(
        run_configure_call.address < run_sgpio_call.address
        < run_enable_call.address < run_wait_call.address,
        "BasebandThread must build the monitor lease, configure fixed RX SGPIO, "
        "full-enable LLI[0], then consume lease-aware buffers",
    )
    _require(
        _immediate_argument_before_call(baseband_run, run_sgpio_call, "r1") == 0,
        "Precision RX SGPIO direction must be the fixed receive value",
    )

    if p12_profile:
        assert dma_claim_completion is not None
        p12_completion_claim = _verify_p12_completion_claim(
            symbols=symbols,
            functions=functions,
            literal_words=literal_words,
            claim=dma_claim_completion,
            wait=dma_wait,
        )
        wait_claims = _calls_matching(
            dma_wait,
            lambda name: name == DMA_CLAIM_COMPLETION_NAME,
        )
        p12_wait_suffix = _require_ordered_instructions(
            dma_wait,
            (
                (
                    "claim a completion after locked wakeup",
                    lambda ins: ins.address == wait_claims[-1].address,
                ),
                (
                    "read queued RX descriptor DESTADDR",
                    lambda ins: _load_at_offset(ins, 4),
                ),
                (
                    "read queued RX descriptor CONTROL",
                    lambda ins: _load_at_offset(ins, 12),
                ),
                (
                    "derive byte/sample count from queued CONTROL",
                    lambda ins: ins.mnemonic.startswith("and")
                    and "lsl #1" in ins.operands,
                ),
            ),
        )
        descriptor_derivation = p12_wait_suffix[-1]
        post_wake_claim = p12_wait_suffix[0]
        queued_descriptor_loads = [
            instruction
            for instruction in dma_wait.instructions
            if post_wake_claim.address < instruction.address
            < descriptor_derivation.address
            and (
                _load_at_offset(instruction, 4)
                or _load_at_offset(instruction, 12)
            )
        ]
        _require(
            len(queued_descriptor_loads) == 2
            and any(
                _load_at_offset(instruction, 4)
                for instruction in queued_descriptor_loads
            )
            and any(
                _load_at_offset(instruction, 12)
                for instruction in queued_descriptor_loads
            ),
            "p12 wait path must read both queued RX descriptor DESTADDR and "
            "CONTROL after the post-wake claim and before count derivation",
        )
    else:
        p12_completion_claim = None
        _require_ordered_instructions(
            dma_wait,
            (
                ("read RX descriptor CONTROL", lambda ins: _load_at_offset(ins, 12)),
                ("read RX descriptor DESTADDR", lambda ins: _load_at_offset(ins, 4)),
                (
                    "derive byte/sample count from CONTROL",
                    lambda ins: ins.mnemonic.startswith("and")
                    and "lsl #1" in ins.operands,
                ),
            ),
        )
    _require(
        any(_has_immediate(ins, 8190) for ins in dma_wait.instructions),
        "lease-aware wait path must mask the 12-bit PL080 transfer count and "
        "convert words to complex<int8> samples",
    )

    drained_call = _require_one_call(
        dma_unbind_drained,
        DRAINED_NAME,
        lambda name: name == DRAINED_NAME,
    )
    drained_release_call = _require_one_call(
        dma_unbind_drained,
        DMA_RELEASE_NAME,
        lambda name: name == DMA_RELEASE_NAME,
    )
    _require(
        drained_call.address < drained_release_call.address
        and any(
            drained_call.address < instruction.address < drained_release_call.address
            and _dmb(instruction)
            for instruction in dma_unbind_drained.instructions
        ),
        "graceful DMA loan reclaim must acquire FIFO drain publication first",
    )
    abort_release_call = _require_one_call(
        dma_force_unbind,
        DMA_RELEASE_NAME,
        lambda name: name == DMA_RELEASE_NAME,
    )
    abort_order = _require_ordered_instructions(
        dma_force_unbind,
        (
            ("load abort request", lambda ins: _load_at_offset(ins, 57)),
            ("load consumer-release byte", lambda ins: _load_at_offset(ins, 58)),
            (
                "reject consumer-owned loan",
                lambda ins: _is_conditional_branch(ins),
            ),
            ("acquire consumer release", _dmb),
            (
                "reclaim DMA loan",
                lambda ins: ins.address == abort_release_call.address,
            ),
        ),
    )
    _require(
        abort_order[-1].address == abort_release_call.address,
        "abort loan reclaim ordering is incomplete",
    )
    _require(
        not _calls(dma_release)
        and dma_release.instructions
        and any(_dmb(ins) for ins in dma_release.instructions),
        "loan release must be a call-free state reset with a publication DMB",
    )
    release_dmb = max(
        ins.address for ins in dma_release.instructions if _dmb(ins)
    )
    _require(
        all(
            ins.address < release_dmb
            for ins in dma_release.instructions
            if ins.mnemonic.startswith("str")
        ),
        "loan release must publish only after all ownership state is reset",
    )

    _require_ordered_instructions(
        finish_command,
        (
            (
                "clear pending config",
                lambda ins: _store_at_offset(
                    ins, pending_capture_config_offset
                ),
            ),
            ("release command payload", _dmb),
            (
                "acknowledge command",
                lambda ins: _store_at_offset(ins, capture_command_offset),
            ),
        ),
    )
    _require(
        not any(
            _store_at_offset(ins, capture_command_offset)
            for ins in service.instructions
        ),
        "service must acknowledge commands only through the release-ordered helper",
    )
    _require_ordered_instructions(
        service,
        (
            (
                "load capture command",
                lambda ins: _load_at_offset(ins, capture_command_offset),
            ),
            ("acquire command payload", _dmb),
        ),
    )
    service_transitions = _calls_matching(
        service, lambda name: name == TRANSITION_NAME
    )
    _require(
        len(service_transitions) == 3,
        f"{SERVICE_NAME} must contain the reviewed OPEN, OPEN-rollback, and "
        f"CLOSE/return transition sites; found {len(service_transitions)}",
    )
    _require_one_call(
        service,
        DMA_UNBIND_DRAINED_NAME,
        lambda name: name == DMA_UNBIND_DRAINED_NAME,
    )
    _require_one_call(
        service,
        DMA_FORCE_UNBIND_NAME,
        lambda name: name == DMA_FORCE_UNBIND_NAME,
    )
    finish_calls = _calls_matching(
        service, lambda name: name == FINISH_COMMAND_NAME
    )
    _require(bool(finish_calls), f"{SERVICE_NAME} never acknowledges a command")

    sorted_transitions = sorted(service_transitions, key=lambda call: call.address)
    service_rate_guard = _find_unsigned_rate_limit_guard(
        service,
        object_offset=612,
        expected_limit=EXPECTED_DMA_CAPTURE_RATE_LIMIT_HZ,
        literal_words=literal_words,
        function_size=service_size,
        minimum_address=sorted_transitions[0].address,
        maximum_address=sorted_transitions[1].address,
    )
    service_allowed_target = _branch_target_address(service_rate_guard[-1])
    _require(
        service_allowed_target is not None
        and service_allowed_target <= sorted_transitions[1].address,
        "OPEN rate guard must reach capture geometry only for rates at or below "
        "the linked 2 Msps limit",
    )
    service_reject_branches = [
        instruction
        for instruction in service.instructions
        if service_rate_guard[-1].address < instruction.address
        < service_allowed_target
        and instruction.mnemonic in {"b", "b.n", "b.w"}
    ]
    _require(
        any(
            (target := _branch_target_address(branch)) is not None
            and any(abs(target - call.address) <= 8 for call in finish_calls)
            for branch in service_reject_branches
        ),
        "OPEN above 2 Msps must branch to command rejection before capture geometry",
    )

    execute_configure_call = _require_one_call(
        execute,
        "PrecisionRxProcessor::configure",
        lambda name: name.startswith(PROCESSOR_CONFIGURE_PREFIX),
    )
    execute_rate_guard = _find_unsigned_rate_limit_guard(
        execute,
        object_offset=620,
        expected_limit=EXPECTED_DMA_CAPTURE_RATE_LIMIT_HZ,
        literal_words=literal_words,
        function_size=execute_size + (16 if p12_profile else 0),
        maximum_load_distance=320 if p12_profile else 32,
    )
    pending_rate_register = _first_operand_register(execute_rate_guard[0])
    execute_allowed_target = _branch_target_address(execute_rate_guard[-1])
    _require(
        execute_allowed_target is not None
        and execute_allowed_target <= execute_configure_call.address,
        "sample-rate guard must dominate the linked configure call",
    )
    bound_loads = [
        instruction
        for instruction in execute.instructions
        if execute_rate_guard[-1].address < instruction.address
        < execute_allowed_target
        and _load_at_offset(instruction, stream_config_offset)
    ]
    _require(
        len(bound_loads) == 1,
        "high-rate sample change must test the StreamInput config pointer",
    )
    bound_load = bound_loads[0]
    bound_null_branch = _zero_branch_after_load(
        execute,
        bound_load,
        "high-rate sample change StreamInput config",
    )
    sealed_target = _branch_target_address(bound_null_branch)
    sealed_loads = [
        instruction
        for instruction in execute.instructions
        if sealed_target is not None
        and sealed_target <= instruction.address < execute_allowed_target
        and _load_at_offset(instruction, stream_sealed_offset)
    ]
    _require(
        len(sealed_loads) == 1,
        "high-rate sample change must test the StreamInput sealed/unbound state",
    )
    sealed_zero_branch = _zero_branch_after_load(
        execute,
        sealed_loads[0],
        "high-rate StreamInput sealed state",
    )
    rejection_stores = [
        instruction
        for instruction in execute.instructions
        if bound_null_branch.address < instruction.address < sealed_loads[0].address
        and _store_at_offset(instruction, 620)
    ]
    sealed_failure_target = _branch_target_address(sealed_zero_branch)
    _require(
        len(rejection_stores) == 1
        and any(
            bound_null_branch.address < instruction.address
            < rejection_stores[0].address
            and _dmb(instruction)
            for instruction in execute.instructions
        )
        and sealed_failure_target is not None
        and sealed_failure_target <= rejection_stores[0].address,
        "bound or incompletely unbound high-rate requests must be release-cleared "
        "without reconfiguration",
    )
    _require(
        any(
            execute_allowed_target <= instruction.address
            < execute_configure_call.address
            and _operand_registers(instruction)[:2]
            == ("r1", pending_rate_register)
            for instruction in execute.instructions
        ),
        "the accepted pending sample rate must flow into the configure argument",
    )
    if p12_profile:
        assert processor_message is not None
        assert processor_rate_resume is not None
        assert processor_publish_running is not None
        assert p12_linked_control is not None
        p12_linked_control.update(
            _verify_p12_commit_ack_dominance(
                symbols=symbols,
                functions=functions,
                literal_words=literal_words,
                processor_message=processor_message,
                processor_rate_resume=processor_rate_resume,
                processor_publish_running=processor_publish_running,
                execute=execute,
                execute_configure_call=execute_configure_call,
                baseband_run=baseband_run,
                run_wait_call=run_wait_call,
            )
        )

    open_rollback_transition = min(service_transitions, key=lambda call: call.address)
    open_rollback_prefix = [
        instruction
        for instruction in service.instructions
        if instruction.address < open_rollback_transition.address
    ]
    _require(
        any(
            _load_at_offset(ins, pending_capture_config_offset)
            for ins in open_rollback_prefix
        )
        and any(_is_conditional_branch(ins) for ins in open_rollback_prefix[-4:]),
        "OPEN rollback retry must be selected by the null pending-config sentinel",
    )
    open_success_branches = [
        instruction
        for instruction in service.instructions
        if open_rollback_transition.address < instruction.address
        < sorted(service_transitions, key=lambda call: call.address)[1].address
        and instruction.mnemonic in {"b", "b.n", "b.w"}
    ]
    _require(
        bool(open_success_branches)
        and (target := _branch_target_address(open_success_branches[0])) is not None
        and any(target <= call.address <= target + 8 for call in finish_calls),
        "OPEN rollback may acknowledge before monitor geometry succeeds",
    )

    close_transition = max(service_transitions, key=lambda call: call.address)
    close_prefix = [
        instruction
        for instruction in service.instructions
        if instruction.address < close_transition.address
    ]
    _require_ordered_instructions(
        Function(service.address, service.name, tuple(close_prefix)),
        (
            (
                "active config is null",
                lambda ins: _load_at_offset(
                    ins, active_capture_config_offset
                ),
            ),
            (
                "StreamInput config is null",
                lambda ins: _load_at_offset(ins, stream_config_offset),
            ),
            (
                "StreamInput is sealed",
                lambda ins: _load_at_offset(ins, stream_sealed_offset),
            ),
        ),
    )
    close_failure_branch = _require_zero_failure_branch_after_call(
        service,
        close_transition,
        "CLOSE monitor transition",
    )
    close_failure_target = _branch_target_address(close_failure_branch)
    _require(
        close_failure_target is not None
        and any(
            close_transition.address < call.address < close_failure_target
            for call in finish_calls
        ),
        "CLOSE command completion is not dominated by successful monitor return",
    )
    service_unbind_calls = _calls_matching(
        service,
        lambda name: name in {DMA_UNBIND_DRAINED_NAME, DMA_FORCE_UNBIND_NAME},
    )
    final_unbind_call = max(service_unbind_calls, key=lambda call: call.address)
    _require_zero_failure_branch_after_call(
        service,
        final_unbind_call,
        "StreamInput unbind",
    )
    post_unbind = [
        instruction
        for instruction in service.instructions
        if instruction.address > final_unbind_call.address
    ]
    _require(
        any(_is_conditional_branch(ins) for ins in post_unbind)
        and any(
            _store_at_offset(ins, active_capture_config_offset)
            for ins in post_unbind
        )
        and any(
            ins.mnemonic in {"b", "b.n", "b.w"}
            and _branch_target_address(ins) == close_transition.address
            for ins in post_unbind
        ),
        "successful loan release must clear active ownership and re-enter the "
        "monitor transition before command completion",
    )

    rebind_call = _calls_matching(service, lambda name: name == REBIND_NAME)[0]
    rebind_failure_tail = [
        instruction
        for instruction in service.instructions
        if instruction.address > rebind_call.address
    ]
    pending_clear = next(
        (
            ins
            for ins in rebind_failure_tail
            if _store_at_offset(ins, pending_capture_config_offset)
        ),
        None,
    )
    _require(pending_clear is not None, "rebind failure lacks OPEN rollback sentinel")
    final_finish_address = max(call.address for call in finish_calls)
    rebind_failure_exit = next(
        (
            ins
            for ins in rebind_failure_tail
            if ins.address > pending_clear.address
            and ins.mnemonic in {"b", "b.n", "b.w"}
        ),
        None,
    )
    _require(
        rebind_failure_exit is not None
        and (_branch_target_address(rebind_failure_exit) or 0)
        > final_finish_address,
        "rebind failure must leave OPEN pending for monitor-geometry retry",
    )

    implementation_geometry = _unique_symbol_value(symbols, IMPL_GEOMETRY_SYMBOL)
    mode_geometry = _unique_symbol_value(symbols, MODE_GEOMETRY_SYMBOL)
    mode_local_buffer_count = _unique_symbol_value(
        symbols, MODE_LOCAL_BUFFER_COUNT_SYMBOL
    )
    mode_spill_buffer_count = _unique_symbol_value(
        symbols, MODE_SPILL_BUFFER_COUNT_SYMBOL
    )
    mode_total_buffer_count = _unique_symbol_value(
        symbols, MODE_TOTAL_BUFFER_COUNT_SYMBOL
    )
    dma_metadata_buffer_bytes = _unique_symbol_value(
        symbols, DMA_BUFFER_BYTES_SYMBOL
    )
    dma_transfer_bytes = _unique_symbol_value(symbols, DMA_TRANSFER_BYTES_SYMBOL)
    dma_transfer_count = _unique_symbol_value(symbols, DMA_TRANSFER_COUNT_SYMBOL)
    dma_loan_bytes = _unique_symbol_value(symbols, DMA_LOAN_BYTES_SYMBOL)
    dma_monitor_ring_bytes = _unique_symbol_value(
        symbols, DMA_MONITOR_RING_BYTES_SYMBOL
    )
    dma_monitor_transfer_bytes = _unique_symbol_value(
        symbols, DMA_MONITOR_TRANSFER_BYTES_SYMBOL
    )
    dma_monitor_transfer_samples = _unique_symbol_value(
        symbols, DMA_MONITOR_TRANSFER_SAMPLES_SYMBOL
    )
    dma_capture_ring_bytes = _unique_symbol_value(
        symbols, DMA_CAPTURE_RING_BYTES_SYMBOL
    )
    dma_capture_transfer_bytes = _unique_symbol_value(
        symbols, DMA_CAPTURE_TRANSFER_BYTES_SYMBOL
    )
    dma_capture_transfer_samples = _unique_symbol_value(
        symbols, DMA_CAPTURE_TRANSFER_SAMPLES_SYMBOL
    )
    dma_monitor_owned_lli_count = _unique_symbol_value(
        symbols, DMA_MONITOR_OWNED_LLI_COUNT_SYMBOL
    )
    dma_monitor_loan_lli_count = _unique_symbol_value(
        symbols, DMA_MONITOR_LOAN_LLI_COUNT_SYMBOL
    )
    dma_loan_local_buffer_index = _unique_symbol_value(
        symbols, DMA_LOAN_LOCAL_BUFFER_INDEX_SYMBOL
    )
    dma_terminal_count_interrupt_count = _unique_symbol_value(
        symbols, DMA_TERMINAL_COUNT_INTERRUPT_COUNT_SYMBOL
    )
    dma_capture_rate_limit_hz = _unique_symbol_value(
        symbols, DMA_CAPTURE_RATE_LIMIT_HZ_SYMBOL
    )
    dma_transition_discards = _unique_symbol_value(
        symbols, DMA_TRANSITION_DISCARDS_SYMBOL
    )
    dma_transition_resets_epoch = _unique_symbol_value(
        symbols, DMA_TRANSITION_RESETS_EPOCH_SYMBOL
    )
    dma_high_rate_bound_rejected = _unique_symbol_value(
        symbols, DMA_HIGH_RATE_BOUND_REJECTED_SYMBOL
    )
    dma_abort_force_unbind = _unique_symbol_value(
        symbols, DMA_ABORT_FORCE_UNBIND_SYMBOL
    )
    dma_abort_requires_release = _unique_symbol_value(
        symbols, DMA_ABORT_REQUIRES_RELEASE_SYMBOL
    )
    dma_scheduler_backlog_depth = _unique_symbol_value(
        symbols, DMA_SCHEDULER_BACKLOG_DEPTH_SYMBOL
    )
    dma_service_deadline_ns_at_20m = _unique_symbol_value(
        symbols, DMA_SERVICE_DEADLINE_SYMBOL
    )
    dma_physical_retention_ns_at_20m = _unique_symbol_value(
        symbols, DMA_PHYSICAL_RETENTION_SYMBOL
    )
    dma_lli_bytes = _unique_symbol_size(
        symbols,
        "Precision RX DMA LLI array",
        lambda name: name == DMA_LLI_LOOP_SYMBOL,
    )
    _require(
        implementation_geometry == EXPECTED_STREAM_BUFFER_COUNT_LOG2,
        f"linked StreamInput implementation geometry is 2^{implementation_geometry}; "
        f"expected 2^{EXPECTED_STREAM_BUFFER_COUNT_LOG2}",
    )
    _require(
        mode_geometry == EXPECTED_STREAM_BUFFER_COUNT_LOG2,
        f"linked Precision RX mode geometry is 2^{mode_geometry}; "
        f"expected 2^{EXPECTED_STREAM_BUFFER_COUNT_LOG2}",
    )
    _require(
        mode_local_buffer_count == config.expected_stream_buffer_count,
        f"linked Precision RX local buffer count is {mode_local_buffer_count}; "
        f"expected {config.expected_stream_buffer_count}",
    )
    _require(
        mode_total_buffer_count == EXPECTED_STREAM_TOTAL_BUFFER_COUNT,
        f"linked Precision RX total buffer count is {mode_total_buffer_count}; "
        f"expected {EXPECTED_STREAM_TOTAL_BUFFER_COUNT}",
    )
    _require(
        mode_spill_buffer_count
        == EXPECTED_STREAM_TOTAL_BUFFER_COUNT - config.expected_stream_buffer_count,
        f"linked Precision RX spill buffer count is {mode_spill_buffer_count}; "
        f"expected {EXPECTED_STREAM_TOTAL_BUFFER_COUNT - config.expected_stream_buffer_count}",
    )
    _require(
        mode_local_buffer_count + mode_spill_buffer_count
        == mode_total_buffer_count,
        "linked Precision RX local/spill counts do not sum to total count",
    )
    _require(
        dma_metadata_buffer_bytes == config.expected_dma_buffer_bytes,
        f"linked Precision RX DMA buffer metadata is {dma_metadata_buffer_bytes} "
        f"bytes; expected {config.expected_dma_buffer_bytes}",
    )
    _require(
        dma_transfer_bytes == config.expected_dma_transfer_bytes,
        f"linked Precision RX DMA transfer is {dma_transfer_bytes} bytes; "
        f"expected {config.expected_dma_transfer_bytes}",
    )
    _require(
        dma_transfer_count == config.expected_dma_transfer_count,
        f"linked Precision RX DMA transfer count is {dma_transfer_count}; "
        f"expected {config.expected_dma_transfer_count}",
    )
    _require(
        dma_transfer_bytes * dma_transfer_count == dma_metadata_buffer_bytes,
        "linked Precision RX DMA transfers do not span the DMA buffer",
    )
    _require(
        dma_lli_bytes == config.expected_dma_lli_bytes,
        f"linked Precision RX DMA LLI array is {dma_lli_bytes} bytes; expected "
        f"{config.expected_dma_lli_bytes}",
    )
    _require(
        dma_loan_bytes == config.expected_dma_loan_bytes,
        f"linked Precision RX DMA loan is {dma_loan_bytes} bytes; expected "
        f"{config.expected_dma_loan_bytes}",
    )
    _require(
        dma_monitor_ring_bytes == config.expected_dma_monitor_ring_bytes,
        f"linked monitor DMA ring is {dma_monitor_ring_bytes} bytes; expected "
        f"{config.expected_dma_monitor_ring_bytes}",
    )
    _require(
        dma_monitor_transfer_bytes == config.expected_dma_monitor_transfer_bytes,
        f"linked monitor DMA transfer is {dma_monitor_transfer_bytes} bytes; "
        f"expected {config.expected_dma_monitor_transfer_bytes}",
    )
    _require(
        dma_monitor_transfer_samples == config.expected_dma_monitor_transfer_samples,
        f"linked monitor DMA transfer is {dma_monitor_transfer_samples} samples; "
        f"expected {config.expected_dma_monitor_transfer_samples}",
    )
    _require(
        dma_capture_ring_bytes == config.expected_dma_capture_ring_bytes,
        f"linked capture DMA ring is {dma_capture_ring_bytes} bytes; expected "
        f"{config.expected_dma_capture_ring_bytes}",
    )
    _require(
        dma_capture_transfer_bytes == config.expected_dma_capture_transfer_bytes,
        f"linked capture DMA transfer is {dma_capture_transfer_bytes} bytes; "
        f"expected {config.expected_dma_capture_transfer_bytes}",
    )
    _require(
        dma_capture_transfer_samples == config.expected_dma_capture_transfer_samples,
        f"linked capture DMA transfer is {dma_capture_transfer_samples} samples; "
        f"expected {config.expected_dma_capture_transfer_samples}",
    )
    _require(
        dma_monitor_owned_lli_count == EXPECTED_DMA_MONITOR_OWNED_LLI_COUNT
        and dma_monitor_loan_lli_count == EXPECTED_DMA_MONITOR_LOAN_LLI_COUNT,
        "linked monitor DMA LLI ownership is not the reviewed two-owned/two-loan split",
    )
    _require(
        dma_loan_local_buffer_index == EXPECTED_DMA_LOAN_LOCAL_BUFFER_INDEX,
        f"linked DMA loan buffer index is {dma_loan_local_buffer_index}; expected "
        f"{EXPECTED_DMA_LOAN_LOCAL_BUFFER_INDEX}",
    )
    _require(
        dma_terminal_count_interrupt_count == dma_transfer_count
        and dma_terminal_count_interrupt_count == config.expected_dma_transfer_count,
        "linked DMA terminal-count interrupt count must equal the four-LLI count",
    )
    _require(
        dma_capture_rate_limit_hz == EXPECTED_DMA_CAPTURE_RATE_LIMIT_HZ,
        f"linked capture DMA rate limit is {dma_capture_rate_limit_hz}; expected "
        f"{EXPECTED_DMA_CAPTURE_RATE_LIMIT_HZ}",
    )
    _require(
        dma_transition_discards == 1
        and dma_transition_resets_epoch == 1
        and dma_high_rate_bound_rejected == 1
        and dma_abort_force_unbind == 1
        and dma_abort_requires_release == 1,
        "linked DMA lease transition/abort policy metadata is incomplete",
    )
    _require(
        dma_scheduler_backlog_depth
        == (
            EXPECTED_P12_DMA_SCHEDULER_BACKLOG_DEPTH
            if p12_profile
            else EXPECTED_DMA_SCHEDULER_BACKLOG_DEPTH
        )
        and dma_service_deadline_ns_at_20m
        == (
            EXPECTED_P12_DMA_SERVICE_DEADLINE_NS_AT_20M
            if p12_profile
            else EXPECTED_DMA_SERVICE_DEADLINE_NS_AT_20M
        )
        and dma_physical_retention_ns_at_20m
        == EXPECTED_DMA_PHYSICAL_RETENTION_NS_AT_20M,
        (
            "linked p12 scheduler contract must provide a three-completion "
            "queue, a fail-closed 204.8 us claim deadline, and 307.2 us "
            "physical retention"
            if p12_profile
            else "linked scheduler contract must distinguish the zero-backlog "
            "102.4 us service deadline from 307.2 us of physical descriptor "
            "retention"
        ),
    )
    if p12_profile:
        assert p12_metadata is not None
        _require(
            p12_metadata[DMA_COMPLETION_QUEUE_DEPTH_SYMBOL]
            == dma_scheduler_backlog_depth
            and p12_metadata[DMA_COMPLETION_PERIOD_SYMBOL]
            * p12_metadata[DMA_CLAIM_GUARD_AGE_SYMBOL]
            == p12_metadata[DMA_OLDEST_CLAIM_DEADLINE_SYMBOL]
            and p12_metadata[DMA_OLDEST_CLAIM_DEADLINE_SYMBOL]
            == dma_service_deadline_ns_at_20m
            and p12_metadata[DMA_COMPLETION_PERIOD_SYMBOL]
            * p12_metadata[DMA_COMPLETION_QUEUE_DEPTH_SYMBOL]
            == dma_physical_retention_ns_at_20m,
            "linked p12 queue depth, fail-closed claim age, completion period, "
            "service deadline, and physical retention are internally inconsistent",
        )
    _require(
        dma_monitor_ring_bytes == dma_metadata_buffer_bytes + dma_loan_bytes
        and dma_monitor_transfer_bytes * dma_transfer_count
        == dma_monitor_ring_bytes
        and dma_capture_ring_bytes == dma_metadata_buffer_bytes
        and dma_capture_transfer_bytes * dma_transfer_count
        == dma_capture_ring_bytes
        and dma_monitor_transfer_samples * 2 == dma_monitor_transfer_bytes
        and dma_capture_transfer_samples * 2 == dma_capture_transfer_bytes,
        "linked DMA lease geometry is internally inconsistent",
    )
    _require(
        dma_loan_bytes == stream_write_size
        and dma_loan_local_buffer_index + 1 == mode_local_buffer_count,
        "linked DMA loan is not exactly the final M4-local capture descriptor",
    )
    capture_stream_bytes = stream_write_size * stream_buffer_count
    supplemental_capture_stream_bytes = stream_write_size * (
        mode_total_buffer_count - mode_local_buffer_count
    )

    main_processor_new = _require_one_call(main, "operator new", _is_operator_new)
    processor_bytes = _immediate_argument_before_call(
        main,
        main_processor_new,
        "r0",
    )
    _require(
        processor_bytes <= config.max_processor_bytes,
        f"PrecisionRxProcessor allocation is {processor_bytes} bytes; maximum is "
        f"{config.max_processor_bytes}",
    )

    baseband_dma_new = _require_one_call(
        baseband_run,
        "operator new",
        _is_operator_new,
    )
    dma_buffer_bytes = _immediate_argument_before_call(
        baseband_run,
        baseband_dma_new,
        "r0",
    )
    _require(
        dma_buffer_bytes == config.expected_dma_buffer_bytes,
        f"linked BasebandThread DMA allocation is {dma_buffer_bytes} bytes; "
        f"expected {config.expected_dma_buffer_bytes}",
    )
    _require(
        dma_buffer_bytes == dma_metadata_buffer_bytes,
        "BasebandThread allocation and Precision RX DMA metadata disagree",
    )

    allocator_callers: dict[str, set[str]] = {"operator new": set(), "operator new[]": set()}
    for function in functions:
        for call in _calls(function):
            if call.target is None:
                continue
            if _is_operator_new_array(call.target):
                allocator_callers["operator new[]"].add(function.name)
            elif _is_operator_new(call.target):
                allocator_callers["operator new"].add(function.name)
    expected_new_callers = {main.name, baseband_run.name}
    expected_new_array_callers = {geometry_constructor.name}
    if allocator_alias_merged:
        expected_new_callers |= expected_new_array_callers
        expected_new_array_callers = set()
    _require(
        allocator_callers["operator new[]"] == expected_new_array_callers,
        "unexpected operator new[] callers: "
        + ", ".join(sorted(allocator_callers["operator new[]"])),
    )
    _require(
        allocator_callers["operator new"] == expected_new_callers,
        "unexpected operator new callers: "
        + ", ".join(sorted(allocator_callers["operator new"])),
    )

    raw_heap_callers: dict[str, set[str]] = {}
    for function in functions:
        for call in _calls(function):
            if call.target is None or not _is_raw_heap_allocator(call.target):
                continue
            raw_heap_callers.setdefault(call.target, set()).add(function.name)
    _require(
        set(raw_heap_callers) == {"chHeapAlloc"},
        "unexpected raw heap allocator targets: "
        + ", ".join(sorted(raw_heap_callers)),
    )
    expected_heap_wrappers = (
        {"operator new(unsigned int)"}
        if allocator_alias_merged
        else {"operator new(unsigned int)", "operator new[](unsigned int)"}
    )
    _require(
        raw_heap_callers["chHeapAlloc"] == expected_heap_wrappers,
        "unexpected chHeapAlloc callers: "
        + ", ".join(sorted(raw_heap_callers["chHeapAlloc"])),
    )

    resources = _resource_report(
        sections,
        processor_bytes,
        capture_stream_bytes,
        supplemental_capture_stream_bytes,
        dma_buffer_bytes,
        config,
    )
    return {
        "contract": (
            "precision-rx-linked-rate-transaction-v6"
            if p15_profile
            else "precision-rx-linked-rate-transaction-v5"
            if p12_profile
            else "precision-rx-linked-dma-lease-v5"
        ),
        "profile": (
            "p15-drain-before-sgpio-gate"
            if p15_profile
            else "p14-dwt-rate-quiesce"
            if p12_profile
            else "p11-dma-lease"
        ),
        "elf_sha256": elf_sha256,
        "result": "PASS",
        "verification_scope": {
            "classification": "diagnostic-regression-shape",
            "complete_cfg_proof": False,
            "complete_def_use_proof": False,
            "release_authority": "frozen-full-elf-sha256",
            "limitation": (
                "Instruction-pattern checks are not a complete control-flow "
                "or register def-use proof."
            ),
        },
        "tool_versions": {
            "nm": nm_version,
            "objdump": objdump_version,
        },
        "open_path": {
            "service_calls_rebind": True,
            "service_calls_begin_capture_interval": True,
            "service_calls_acknowledge_open": True,
            "service_allocator_call_count": 0,
            "rebind_code_bytes": rebind_size,
            "maximum_rebind_code_bytes": config.max_rebind_code_bytes,
            "rebind_internal_call_count": len(rebind_calls),
            "rebind_fifo_helper": rebind_fifo_helper,
            "geometry_constructor_allocator_alias_merged": (
                allocator_alias_merged
            ),
            "geometry_constructor_value_initialization": (
                constructor_value_initialization
            ),
            "service_code_bytes": service_size,
            "maximum_service_code_bytes": config.max_service_code_bytes,
            "maximum_service_bulk_bytes": config.max_service_bulk_bytes,
            "service_bulk_call_sizes": [
                {
                    "bytes": _immediate_argument_before_call(service, call, "r2"),
                    "target": call.target,
                }
                for call in service_bulk_calls
            ],
            "stream_constructor_precedes_baseband_thread": True,
            "construction_only_dma_loan_callers": sorted(loan_callers),
            "initial_descriptor_builder_linked": True,
            "initial_fixed_rx_full_enable_linked": True,
            "stream_write_size": stream_write_size,
            "stream_buffer_count": stream_buffer_count,
            "implementation_buffer_count_log2": implementation_geometry,
            "mode_buffer_count_log2": mode_geometry,
            "mode_local_buffer_count": mode_local_buffer_count,
            "mode_spill_buffer_count": mode_spill_buffer_count,
            "mode_total_buffer_count": mode_total_buffer_count,
            "dma_buffer_bytes": dma_metadata_buffer_bytes,
            "dma_transfer_bytes": dma_transfer_bytes,
            "dma_transfer_count": dma_transfer_count,
            "dma_lli_bytes": dma_lli_bytes,
            "dma_loan_bytes": dma_loan_bytes,
            "dma_monitor_ring_bytes": dma_monitor_ring_bytes,
            "dma_monitor_transfer_bytes": dma_monitor_transfer_bytes,
            "dma_monitor_transfer_samples": dma_monitor_transfer_samples,
            "dma_capture_ring_bytes": dma_capture_ring_bytes,
            "dma_capture_transfer_bytes": dma_capture_transfer_bytes,
            "dma_capture_transfer_samples": dma_capture_transfer_samples,
            "dma_monitor_owned_lli_count": dma_monitor_owned_lli_count,
            "dma_monitor_loan_lli_count": dma_monitor_loan_lli_count,
            "dma_loan_local_buffer_index": dma_loan_local_buffer_index,
            "dma_terminal_count_interrupt_count": (
                dma_terminal_count_interrupt_count
            ),
            "dma_capture_rate_limit_hz": dma_capture_rate_limit_hz,
            "dma_transition_discards_old_block": bool(dma_transition_discards),
            "dma_transition_resets_epoch": bool(dma_transition_resets_epoch),
            "dma_high_rate_bound_request_rejected": bool(
                dma_high_rate_bound_rejected
            ),
            "dma_abort_force_unbind": bool(dma_abort_force_unbind),
            "dma_abort_requires_consumer_release": bool(
                dma_abort_requires_release
            ),
            "all_heap_allocations_modeled": True,
            "operator_new_callers": sorted(allocator_callers["operator new"]),
            "operator_new_array_callers": sorted(
                allocator_callers["operator new[]"]
            ),
        },
        "close_path": {
            "service_calls_seal": True,
            "service_calls_drained": True,
            "service_calls_graceful_unbind": True,
            "service_calls_abort_unbind": True,
            "consumer_release_acquire_before_reclaim": True,
            "monitor_return_precedes_command_ack": True,
            "failed_monitor_return_remains_pending": True,
        },
        "dma_lease_implementation": {
            "descriptor_builder_linked_from_initial_and_transition_paths": True,
            "terminal_count_control_dataflow_linked": True,
            "pl080_halt_then_active_then_disable_order": True,
            "pl080_timeout_clears_halt_without_descriptor_rewrite": True,
            "fixed_rx_enable_writes_full_disabled_register_image_before_e": True,
            "fixed_rx_enable_common_base_and_lli_dataflow_linked": True,
            "wait_reads_rx_destaddr_and_lli_control_count": True,
            "geometry_attempt_always_starts_new_accounting_epoch": (
                not p12_profile
            ),
            "geometry_success_starts_new_accounting_epoch": True,
            "geometry_timeout_preserves_existing_epoch": p12_profile,
            "service_and_execute_2msps_rejection_linked": True,
            "open_rebind_failure_retries_monitor_return": True,
            "close_release_retries_monitor_return": True,
            "close_transition_result_consumes_r0": True,
            "scheduler_backlog_depth": dma_scheduler_backlog_depth,
            "service_deadline_ns_at_20m": dma_service_deadline_ns_at_20m,
            "physical_retention_ns_at_20m": dma_physical_retention_ns_at_20m,
            "pending_error_fail_closed_proof": pending_error_proof,
        },
        "rate_transaction": (
            {
                "protocol_version": p12_metadata[
                    RATE_TRANSACTION_PROTOCOL_VERSION_SYMBOL
                ],
                "completion_queue_depth": p12_metadata[
                    DMA_COMPLETION_QUEUE_DEPTH_SYMBOL
                ],
                "completion_period_ns_at_20m": p12_metadata[
                    DMA_COMPLETION_PERIOD_SYMBOL
                ],
                "oldest_claim_deadline_ns_at_20m": p12_metadata[
                    DMA_OLDEST_CLAIM_DEADLINE_SYMBOL
                ],
                "claim_guard_age": p12_metadata[
                    DMA_CLAIM_GUARD_AGE_SYMBOL
                ],
                "queue_drops_oldest": bool(
                    p12_metadata[DMA_QUEUE_DROPS_OLDEST_SYMBOL]
                ),
                "queue_spsc": bool(
                    p12_metadata[DMA_QUEUE_SPSC_SYMBOL]
                ),
                "queue_full_fail_closed": bool(
                    p12_metadata[DMA_QUEUE_FULL_FAIL_CLOSED_SYMBOL]
                ),
                "fast_irq_priority": p12_metadata[
                    DMA_FAST_IRQ_PRIORITY_SYMBOL
                ],
                "deferred_irq": p12_metadata[DMA_DEFERRED_IRQ_SYMBOL],
                "deferred_irq_priority": p12_metadata[
                    DMA_DEFERRED_IRQ_PRIORITY_SYMBOL
                ],
                "fast_tc_w1c_first": bool(
                    p12_metadata[DMA_FAST_TC_W1C_FIRST_SYMBOL]
                ),
                "fast_error_gate_first": bool(
                    p12_metadata[DMA_FAST_ERROR_GATE_FIRST_SYMBOL]
                ),
                "unexpected_channel_fail_closed": bool(
                    p12_metadata[
                        DMA_UNEXPECTED_CHANNEL_FAIL_CLOSED_SYMBOL
                    ]
                ),
                "worker_claim_irq_exclusion": bool(
                    p12_metadata[DMA_WORKER_CLAIM_IRQ_EXCLUSION_SYMBOL]
                ),
                "software_descriptor_phase": bool(
                    p12_metadata[DMA_SOFTWARE_DESCRIPTOR_PHASE_SYMBOL]
                ),
                "gate_open_irq_exclusion": bool(
                    p12_metadata[DMA_GATE_OPEN_IRQ_EXCLUSION_SYMBOL]
                ),
                "gate_open_requires_channel_enabled": bool(
                    p12_metadata[
                        DMA_GATE_OPEN_REQUIRES_CHANNEL_ENABLED_SYMBOL
                    ]
                ),
                "rate_state_irq_exclusion": bool(
                    p12_metadata[DMA_RATE_STATE_IRQ_EXCLUSION_SYMBOL]
                ),
                "rate_state_scheduler_exclusion": bool(
                    p12_metadata[
                        DMA_RATE_STATE_SCHEDULER_EXCLUSION_SYMBOL
                    ]
                ),
                "claim_preserves_own_tc": bool(
                    p12_metadata[DMA_CLAIM_PRESERVES_OWN_TC_SYMBOL]
                ),
                "rate_state_preserves_own_tc": bool(
                    p12_metadata[DMA_RATE_STATE_PRESERVES_OWN_TC_SYMBOL]
                ),
                "exclusion_preserves_nvic_pending": bool(
                    p12_metadata[
                        DMA_EXCLUSION_PRESERVES_NVIC_PENDING_SYMBOL
                    ]
                ),
                "shutdown_active_drain": bool(
                    p12_metadata[DMA_SHUTDOWN_ACTIVE_DRAIN_SYMBOL]
                ),
                "shutdown_active_spin_limit": p12_metadata[
                    DMA_SHUTDOWN_ACTIVE_SPIN_LIMIT_SYMBOL
                ],
                "shutdown_timeout_halts": bool(
                    p12_metadata[DMA_SHUTDOWN_TIMEOUT_HALTS_SYMBOL]
                ),
                "control_active_drain_timeout_us": p12_metadata[
                    DMA_CONTROL_ACTIVE_DRAIN_TIMEOUT_US_SYMBOL
                ],
                "control_active_drain_ticks_at_200m": p12_metadata[
                    DMA_CONTROL_ACTIVE_DRAIN_TICKS_AT_200M_SYMBOL
                ],
                "control_active_drain_uses_dwt": bool(
                    p12_metadata[DMA_CONTROL_ACTIVE_DRAIN_USES_DWT_SYMBOL]
                ),
                "control_active_drain_counter_guard": bool(
                    p12_metadata[
                        DMA_CONTROL_ACTIVE_DRAIN_COUNTER_GUARD_SYMBOL
                    ]
                ),
                "control_slowest_descriptor_ticks_at_200m": p12_metadata[
                    DMA_CONTROL_SLOWEST_DESCRIPTOR_TICKS_AT_200M_SYMBOL
                ],
                "lifetime_loss_counter_bits": p12_metadata[
                    DMA_LIFETIME_LOSS_COUNTER_BITS_SYMBOL
                ],
                "lifetime_loss_saturating": bool(
                    p12_metadata[DMA_LIFETIME_LOSS_SATURATING_SYMBOL]
                ),
                "prepare_gates_sgpio_before_dma_pause": bool(
                    p12_metadata[RATE_PREPARE_GATES_SGPIO_SYMBOL]
                ),
                "prepare_ack_requires_pause_armed": bool(
                    p12_metadata[RATE_PREPARE_ACK_REQUIRES_ARMED_SYMBOL]
                ),
                "commit_publishes_target_before_dma_resume": bool(
                    p12_metadata[RATE_COMMIT_PUBLISHES_TARGET_SYMBOL]
                ),
                "commit_ack_requires_first_new_rate_completion": bool(
                    p12_metadata[RATE_COMMIT_ACK_REQUIRES_COMPLETION_SYMBOL]
                ),
                "fail_closed_on_prepare_failure": bool(
                    p12_metadata[RATE_FAIL_CLOSED_PREPARE_SYMBOL]
                ),
                "fail_closed_on_commit_failure": bool(
                    p12_metadata[RATE_FAIL_CLOSED_COMMIT_SYMBOL]
                ),
                "linked_control": p12_linked_control,
                "dma_irq_split": p12_dma_irq_split,
                "completion_claim": p12_completion_claim,
                "gate_open": p12_gate_open_proof,
                "shutdown_quiesce": p12_shutdown_quiesce,
                "shutdown_mode_dispatch": p15_shutdown_mode_dispatch,
                "control_active_drain": p14_control_active_drain,
                "energy_log10_safety": p13_energy_log10_safety,
                "post_build_instruction_calibration_required": [],
            }
            if p12_profile and p12_metadata is not None
            else None
        ),
        "resources": resources,
    }


def _run_tool(command: Sequence[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as error:
        raise VerificationError(f"cannot execute {command[0]}: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise VerificationError(
            f"{' '.join(command)} failed with exit status {completed.returncode}: {detail}"
        )
    return completed.stdout


def _tool_version(tool: str) -> str:
    output = _run_tool([tool, "--version"])
    first_line = output.splitlines()[0].strip() if output.splitlines() else ""
    _require(bool(first_line), f"{tool} --version returned no version line")
    return first_line


def verify_elf(
    elf: Path,
    *,
    nm_tool: str,
    objdump_tool: str,
    config: GateConfig,
) -> dict[str, object]:
    _require(elf.is_file(), f"ELF does not exist or is not a regular file: {elf}")
    _require(elf.stat().st_size > 0, f"ELF is empty: {elf}")
    elf_sha256 = hashlib.sha256(elf.read_bytes()).hexdigest()
    nm_text = _run_tool([nm_tool, "-C", "-S", "--defined-only", str(elf)])
    disassembly_text = _run_tool([objdump_tool, "-drC", str(elf)])
    section_text = _run_tool([objdump_tool, "-h", str(elf)])
    return verify_outputs(
        nm_text,
        disassembly_text,
        section_text,
        elf_sha256=elf_sha256,
        nm_version=_tool_version(nm_tool),
        objdump_version=_tool_version(objdump_tool),
        config=config,
    )


def _positive_int(value: str) -> int:
    parsed = int(value, 0)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return parsed


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path, help="unstripped baseband_precision_rx.elf")
    parser.add_argument("--nm", default="arm-none-eabi-nm", help="GNU Arm nm executable")
    parser.add_argument(
        "--objdump",
        default="arm-none-eabi-objdump",
        help="GNU Arm objdump executable",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="also write the deterministic JSON receipt to this path",
    )
    parser.add_argument(
        "--minimum-ram-headroom",
        type=_positive_int,
        default=MINIMUM_MODELED_HEADROOM_BYTES,
        help="minimum modeled runtime RAM headroom in bytes",
    )
    parser.add_argument(
        "--heap-metadata-reserve",
        type=_positive_int,
        default=HEAP_METADATA_RESERVE_BYTES,
        help="bytes reserved for heap metadata/unmodeled allocator overhead",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    config = GateConfig(
        minimum_modeled_headroom_bytes=args.minimum_ram_headroom,
        heap_metadata_reserve_bytes=args.heap_metadata_reserve,
    )
    try:
        report = verify_elf(
            args.elf,
            nm_tool=args.nm,
            objdump_tool=args.objdump,
            config=config,
        )
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.json_output:
            args.json_output.parent.mkdir(parents=True, exist_ok=True)
            args.json_output.write_text(encoded, encoding="utf-8")
        print("precision-rx-elf: PASS")
        print(encoded, end="")
        return 0
    except (OSError, ValueError, VerificationError) as error:
        print(f"precision-rx-elf: FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
