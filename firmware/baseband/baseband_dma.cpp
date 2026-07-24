/*
 * Copyright (C) 2014 Jared Boone, ShareBrained Technology, Inc.
 *
 * This file is part of PortaPack.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#include "baseband_dma.hpp"
#include "portapack_shared_memory.hpp"

#include <cstdint>
#include <cstddef>
#include <array>

#include "hal.h"
#include "gpdma.hpp"
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
#include "precision_rx_dma_lease.hpp"
#if !defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
#error "Precision RX DMA leasing requires the p10 hybrid-pool geometry"
#endif
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
#include "precision_rx_dma_completion_queue.hpp"
#include "precision_rx_dma_quiesce.hpp"
#if !defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
#error "Precision RX rate transactions require the p11 DMA lease"
#endif
#endif

using namespace lpc43xx;

#include "portapack_dma.hpp"

#include "thread_wait.hpp"

namespace baseband {
namespace dma {

constexpr uint32_t gpdma_ahb_master_sgpio = 0;
constexpr uint32_t gpdma_ahb_master_memory = 1;
constexpr uint32_t gpdma_ahb_master_lli_fetch = 0;

constexpr uint32_t gpdma_src_peripheral = 0x0;
constexpr uint32_t gpdma_dest_peripheral = 0x0;

constexpr gpdma::channel::LLIPointer lli_pointer(const void* lli) {
    return {
        .lm = gpdma_ahb_master_lli_fetch,
        .r = 0,
        .lli = reinterpret_cast<uint32_t>(lli),
    };
}

constexpr gpdma::channel::Control control(const baseband::Direction direction, const size_t buffer_words) {
    return {
        .transfersize = buffer_words,
        .sbsize = 0, /* Burst size: 1 */
        .dbsize = 0, /* Burst size: 1 */
        .swidth = 2, /* Source transfer width: word (32 bits) */
        .dwidth = 2, /* Destination transfer width: word (32 bits) */
        .s = (direction == baseband::Direction::Transmit) ? gpdma_ahb_master_memory : gpdma_ahb_master_sgpio,
        .d = (direction == baseband::Direction::Transmit) ? gpdma_ahb_master_sgpio : gpdma_ahb_master_memory,
        .si = (direction == baseband::Direction::Transmit) ? 1U : 0U,
        .di = (direction == baseband::Direction::Transmit) ? 0U : 1U,
        .prot1 = 0,
        .prot2 = 0,
        .prot3 = 0,
        .i = 1,
    };
}

constexpr gpdma::channel::Config config(const baseband::Direction direction) {
    return {
        .e = 0,
        .srcperipheral = gpdma_src_peripheral,
        .destperipheral = gpdma_dest_peripheral,
        .flowcntrl = (direction == baseband::Direction::Transmit)
                         ? gpdma::FlowControl::MemoryToPeripheral_DMAControl
                         : gpdma::FlowControl::PeripheralToMemory_DMAControl,
        .ie = 1,
        .itc = 1,
        .l = 0,
        .a = 0,
        .h = 0,
    };
}

constexpr size_t transfers_per_buffer_log2n = 2;
constexpr size_t transfers_per_buffer = (1 << transfers_per_buffer_log2n);
constexpr size_t transfer_samples = buffer_samples / transfers_per_buffer;
constexpr size_t transfers_mask = transfers_per_buffer - 1;

constexpr size_t buffer_bytes = buffer_samples * sizeof(baseband::sample_t);
constexpr size_t transfer_bytes = transfer_samples * sizeof(baseband::sample_t);

constexpr size_t msg_count = transfers_per_buffer - 1;

static_assert(buffer_samples % transfers_per_buffer == 0U);

#if defined(__arm__) && \
    defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
/* Absolute linked metadata for the p10 DMA-geometry verifier. */
__asm__(
    ".global hackrf_edge_precision_rx_dma_buffer_bytes\n"
    ".type hackrf_edge_precision_rx_dma_buffer_bytes, %object\n"
    ".set hackrf_edge_precision_rx_dma_buffer_bytes, 8192\n"
    ".size hackrf_edge_precision_rx_dma_buffer_bytes, 4\n"
    ".global hackrf_edge_precision_rx_dma_transfer_bytes\n"
    ".type hackrf_edge_precision_rx_dma_transfer_bytes, %object\n"
    ".set hackrf_edge_precision_rx_dma_transfer_bytes, 2048\n"
    ".size hackrf_edge_precision_rx_dma_transfer_bytes, 4\n"
    ".global hackrf_edge_precision_rx_dma_transfer_count\n"
    ".type hackrf_edge_precision_rx_dma_transfer_count, %object\n"
    ".set hackrf_edge_precision_rx_dma_transfer_count, 4\n"
    ".size hackrf_edge_precision_rx_dma_transfer_count, 1\n");
#endif

#if defined(__arm__) && \
    defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
/* Absolute linked metadata for the p11 discontiguous lease verifier. */
__asm__(
    ".global hackrf_edge_precision_rx_dma_loan_bytes\n"
    ".type hackrf_edge_precision_rx_dma_loan_bytes, %object\n"
    ".set hackrf_edge_precision_rx_dma_loan_bytes, 8192\n"
    ".size hackrf_edge_precision_rx_dma_loan_bytes, 4\n"
    ".global hackrf_edge_precision_rx_dma_monitor_ring_bytes\n"
    ".type hackrf_edge_precision_rx_dma_monitor_ring_bytes, %object\n"
    ".set hackrf_edge_precision_rx_dma_monitor_ring_bytes, 16384\n"
    ".size hackrf_edge_precision_rx_dma_monitor_ring_bytes, 4\n"
    ".global hackrf_edge_precision_rx_dma_monitor_transfer_bytes\n"
    ".type hackrf_edge_precision_rx_dma_monitor_transfer_bytes, %object\n"
    ".set hackrf_edge_precision_rx_dma_monitor_transfer_bytes, 4096\n"
    ".size hackrf_edge_precision_rx_dma_monitor_transfer_bytes, 4\n"
    ".global hackrf_edge_precision_rx_dma_monitor_transfer_samples\n"
    ".type hackrf_edge_precision_rx_dma_monitor_transfer_samples, %object\n"
    ".set hackrf_edge_precision_rx_dma_monitor_transfer_samples, 2048\n"
    ".size hackrf_edge_precision_rx_dma_monitor_transfer_samples, 4\n"
    ".global hackrf_edge_precision_rx_dma_capture_ring_bytes\n"
    ".type hackrf_edge_precision_rx_dma_capture_ring_bytes, %object\n"
    ".set hackrf_edge_precision_rx_dma_capture_ring_bytes, 8192\n"
    ".size hackrf_edge_precision_rx_dma_capture_ring_bytes, 4\n"
    ".global hackrf_edge_precision_rx_dma_capture_transfer_bytes\n"
    ".type hackrf_edge_precision_rx_dma_capture_transfer_bytes, %object\n"
    ".set hackrf_edge_precision_rx_dma_capture_transfer_bytes, 2048\n"
    ".size hackrf_edge_precision_rx_dma_capture_transfer_bytes, 4\n"
    ".global hackrf_edge_precision_rx_dma_capture_transfer_samples\n"
    ".type hackrf_edge_precision_rx_dma_capture_transfer_samples, %object\n"
    ".set hackrf_edge_precision_rx_dma_capture_transfer_samples, 1024\n"
    ".size hackrf_edge_precision_rx_dma_capture_transfer_samples, 4\n"
    ".global hackrf_edge_precision_rx_dma_monitor_owned_lli_count\n"
    ".type hackrf_edge_precision_rx_dma_monitor_owned_lli_count, %object\n"
    ".set hackrf_edge_precision_rx_dma_monitor_owned_lli_count, 2\n"
    ".size hackrf_edge_precision_rx_dma_monitor_owned_lli_count, 1\n"
    ".global hackrf_edge_precision_rx_dma_monitor_loan_lli_count\n"
    ".type hackrf_edge_precision_rx_dma_monitor_loan_lli_count, %object\n"
    ".set hackrf_edge_precision_rx_dma_monitor_loan_lli_count, 2\n"
    ".size hackrf_edge_precision_rx_dma_monitor_loan_lli_count, 1\n"
    ".global hackrf_edge_precision_rx_dma_loan_local_buffer_index\n"
    ".type hackrf_edge_precision_rx_dma_loan_local_buffer_index, %object\n"
    ".set hackrf_edge_precision_rx_dma_loan_local_buffer_index, 8\n"
    ".size hackrf_edge_precision_rx_dma_loan_local_buffer_index, 1\n"
    ".global hackrf_edge_precision_rx_dma_terminal_count_interrupt_count\n"
    ".type hackrf_edge_precision_rx_dma_terminal_count_interrupt_count, %object\n"
    ".set hackrf_edge_precision_rx_dma_terminal_count_interrupt_count, 4\n"
    ".size hackrf_edge_precision_rx_dma_terminal_count_interrupt_count, 1\n"
    ".global hackrf_edge_precision_rx_dma_scheduler_backlog_depth\n"
    ".type hackrf_edge_precision_rx_dma_scheduler_backlog_depth, %object\n"
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    ".set hackrf_edge_precision_rx_dma_scheduler_backlog_depth, 3\n"
#else
    ".set hackrf_edge_precision_rx_dma_scheduler_backlog_depth, 0\n"
#endif
    ".size hackrf_edge_precision_rx_dma_scheduler_backlog_depth, 1\n"
    ".global hackrf_edge_precision_rx_dma_service_deadline_ns_at_20m\n"
    ".type hackrf_edge_precision_rx_dma_service_deadline_ns_at_20m, %object\n"
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    ".set hackrf_edge_precision_rx_dma_service_deadline_ns_at_20m, 204800\n"
#else
    ".set hackrf_edge_precision_rx_dma_service_deadline_ns_at_20m, 102400\n"
#endif
    ".size hackrf_edge_precision_rx_dma_service_deadline_ns_at_20m, 4\n"
    ".global hackrf_edge_precision_rx_dma_physical_retention_ns_at_20m\n"
    ".type hackrf_edge_precision_rx_dma_physical_retention_ns_at_20m, %object\n"
    ".set hackrf_edge_precision_rx_dma_physical_retention_ns_at_20m, 307200\n"
    ".size hackrf_edge_precision_rx_dma_physical_retention_ns_at_20m, 4\n");
#endif

#if defined(__arm__) && \
    defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
__asm__(
    ".global hackrf_edge_precision_rx_dma_completion_queue_depth\n"
    ".type hackrf_edge_precision_rx_dma_completion_queue_depth, %object\n"
    ".set hackrf_edge_precision_rx_dma_completion_queue_depth, 3\n"
    ".size hackrf_edge_precision_rx_dma_completion_queue_depth, 1\n"
    ".global hackrf_edge_precision_rx_dma_completion_period_ns_at_20m\n"
    ".type hackrf_edge_precision_rx_dma_completion_period_ns_at_20m, %object\n"
    ".set hackrf_edge_precision_rx_dma_completion_period_ns_at_20m, 102400\n"
    ".size hackrf_edge_precision_rx_dma_completion_period_ns_at_20m, 4\n"
    ".global hackrf_edge_precision_rx_dma_oldest_claim_deadline_ns_at_20m\n"
    ".type hackrf_edge_precision_rx_dma_oldest_claim_deadline_ns_at_20m, %object\n"
    ".set hackrf_edge_precision_rx_dma_oldest_claim_deadline_ns_at_20m, 204800\n"
    ".size hackrf_edge_precision_rx_dma_oldest_claim_deadline_ns_at_20m, 4\n"
    ".global hackrf_edge_precision_rx_dma_claim_guard_age\n"
    ".type hackrf_edge_precision_rx_dma_claim_guard_age, %object\n"
    ".set hackrf_edge_precision_rx_dma_claim_guard_age, 2\n"
    ".size hackrf_edge_precision_rx_dma_claim_guard_age, 1\n"
    ".global hackrf_edge_precision_rx_dma_queue_drops_oldest\n"
    ".type hackrf_edge_precision_rx_dma_queue_drops_oldest, %object\n"
    ".set hackrf_edge_precision_rx_dma_queue_drops_oldest, 0\n"
    ".size hackrf_edge_precision_rx_dma_queue_drops_oldest, 1\n"
    ".global hackrf_edge_precision_rx_dma_queue_spsc\n"
    ".type hackrf_edge_precision_rx_dma_queue_spsc, %object\n"
    ".set hackrf_edge_precision_rx_dma_queue_spsc, 1\n"
    ".size hackrf_edge_precision_rx_dma_queue_spsc, 1\n"
    ".global hackrf_edge_precision_rx_dma_queue_full_fail_closed\n"
    ".type hackrf_edge_precision_rx_dma_queue_full_fail_closed, %object\n"
    ".set hackrf_edge_precision_rx_dma_queue_full_fail_closed, 1\n"
    ".size hackrf_edge_precision_rx_dma_queue_full_fail_closed, 1\n"
    ".global hackrf_edge_precision_rx_dma_fast_irq_priority\n"
    ".type hackrf_edge_precision_rx_dma_fast_irq_priority, %object\n"
    ".set hackrf_edge_precision_rx_dma_fast_irq_priority, 1\n"
    ".size hackrf_edge_precision_rx_dma_fast_irq_priority, 1\n"
    ".global hackrf_edge_precision_rx_dma_deferred_irq\n"
    ".type hackrf_edge_precision_rx_dma_deferred_irq, %object\n"
    ".set hackrf_edge_precision_rx_dma_deferred_irq, 31\n"
    ".size hackrf_edge_precision_rx_dma_deferred_irq, 1\n"
    ".global hackrf_edge_precision_rx_dma_deferred_irq_priority\n"
    ".type hackrf_edge_precision_rx_dma_deferred_irq_priority, %object\n"
    ".set hackrf_edge_precision_rx_dma_deferred_irq_priority, 3\n"
    ".size hackrf_edge_precision_rx_dma_deferred_irq_priority, 1\n"
    ".global hackrf_edge_precision_rx_dma_fast_tc_w1c_first\n"
    ".type hackrf_edge_precision_rx_dma_fast_tc_w1c_first, %object\n"
    ".set hackrf_edge_precision_rx_dma_fast_tc_w1c_first, 1\n"
    ".size hackrf_edge_precision_rx_dma_fast_tc_w1c_first, 1\n"
    ".global hackrf_edge_precision_rx_dma_fast_error_gate_first\n"
    ".type hackrf_edge_precision_rx_dma_fast_error_gate_first, %object\n"
    ".set hackrf_edge_precision_rx_dma_fast_error_gate_first, 1\n"
    ".size hackrf_edge_precision_rx_dma_fast_error_gate_first, 1\n"
    ".global hackrf_edge_precision_rx_dma_unexpected_channel_fail_closed\n"
    ".type hackrf_edge_precision_rx_dma_unexpected_channel_fail_closed, %object\n"
    ".set hackrf_edge_precision_rx_dma_unexpected_channel_fail_closed, 1\n"
    ".size hackrf_edge_precision_rx_dma_unexpected_channel_fail_closed, 1\n"
    ".global hackrf_edge_precision_rx_dma_worker_claim_irq_exclusion\n"
    ".type hackrf_edge_precision_rx_dma_worker_claim_irq_exclusion, %object\n"
    ".set hackrf_edge_precision_rx_dma_worker_claim_irq_exclusion, 1\n"
    ".size hackrf_edge_precision_rx_dma_worker_claim_irq_exclusion, 1\n"
    ".global hackrf_edge_precision_rx_dma_claim_preserves_own_tc\n"
    ".type hackrf_edge_precision_rx_dma_claim_preserves_own_tc, %object\n"
    ".set hackrf_edge_precision_rx_dma_claim_preserves_own_tc, 1\n"
    ".size hackrf_edge_precision_rx_dma_claim_preserves_own_tc, 1\n"
    ".global hackrf_edge_precision_rx_dma_software_descriptor_phase\n"
    ".type hackrf_edge_precision_rx_dma_software_descriptor_phase, %object\n"
    ".set hackrf_edge_precision_rx_dma_software_descriptor_phase, 1\n"
    ".size hackrf_edge_precision_rx_dma_software_descriptor_phase, 1\n"
    ".global hackrf_edge_precision_rx_dma_gate_open_irq_exclusion\n"
    ".type hackrf_edge_precision_rx_dma_gate_open_irq_exclusion, %object\n"
    ".set hackrf_edge_precision_rx_dma_gate_open_irq_exclusion, 1\n"
    ".size hackrf_edge_precision_rx_dma_gate_open_irq_exclusion, 1\n"
    ".global hackrf_edge_precision_rx_dma_gate_open_requires_channel_enabled\n"
    ".type hackrf_edge_precision_rx_dma_gate_open_requires_channel_enabled, %object\n"
    ".set hackrf_edge_precision_rx_dma_gate_open_requires_channel_enabled, 1\n"
    ".size hackrf_edge_precision_rx_dma_gate_open_requires_channel_enabled, 1\n"
    ".global hackrf_edge_precision_rx_dma_rate_state_irq_exclusion\n"
    ".type hackrf_edge_precision_rx_dma_rate_state_irq_exclusion, %object\n"
    ".set hackrf_edge_precision_rx_dma_rate_state_irq_exclusion, 1\n"
    ".size hackrf_edge_precision_rx_dma_rate_state_irq_exclusion, 1\n"
    ".global hackrf_edge_precision_rx_dma_rate_state_preserves_own_tc\n"
    ".type hackrf_edge_precision_rx_dma_rate_state_preserves_own_tc, %object\n"
    ".set hackrf_edge_precision_rx_dma_rate_state_preserves_own_tc, 1\n"
    ".size hackrf_edge_precision_rx_dma_rate_state_preserves_own_tc, 1\n"
    ".global hackrf_edge_precision_rx_dma_exclusion_preserves_nvic_pending\n"
    ".type hackrf_edge_precision_rx_dma_exclusion_preserves_nvic_pending, %object\n"
    ".set hackrf_edge_precision_rx_dma_exclusion_preserves_nvic_pending, 1\n"
    ".size hackrf_edge_precision_rx_dma_exclusion_preserves_nvic_pending, 1\n"
    ".global hackrf_edge_precision_rx_dma_rate_state_scheduler_exclusion\n"
    ".type hackrf_edge_precision_rx_dma_rate_state_scheduler_exclusion, %object\n"
    ".set hackrf_edge_precision_rx_dma_rate_state_scheduler_exclusion, 1\n"
    ".size hackrf_edge_precision_rx_dma_rate_state_scheduler_exclusion, 1\n"
    ".global hackrf_edge_precision_rx_dma_shutdown_active_drain\n"
    ".type hackrf_edge_precision_rx_dma_shutdown_active_drain, %object\n"
    ".set hackrf_edge_precision_rx_dma_shutdown_active_drain, 1\n"
    ".size hackrf_edge_precision_rx_dma_shutdown_active_drain, 1\n"
    ".global hackrf_edge_precision_rx_dma_shutdown_active_spin_limit\n"
    ".type hackrf_edge_precision_rx_dma_shutdown_active_spin_limit, %object\n"
    ".set hackrf_edge_precision_rx_dma_shutdown_active_spin_limit, 65536\n"
    ".size hackrf_edge_precision_rx_dma_shutdown_active_spin_limit, 4\n"
    ".global hackrf_edge_precision_rx_dma_shutdown_timeout_halts\n"
    ".type hackrf_edge_precision_rx_dma_shutdown_timeout_halts, %object\n"
    ".set hackrf_edge_precision_rx_dma_shutdown_timeout_halts, 1\n"
    ".size hackrf_edge_precision_rx_dma_shutdown_timeout_halts, 1\n"
    ".global hackrf_edge_precision_rx_dma_control_active_drain_timeout_us\n"
    ".type hackrf_edge_precision_rx_dma_control_active_drain_timeout_us, %object\n"
    ".set hackrf_edge_precision_rx_dma_control_active_drain_timeout_us, 10000\n"
    ".size hackrf_edge_precision_rx_dma_control_active_drain_timeout_us, 4\n"
    ".global hackrf_edge_precision_rx_dma_control_active_drain_ticks_at_200m\n"
    ".type hackrf_edge_precision_rx_dma_control_active_drain_ticks_at_200m, %object\n"
    ".set hackrf_edge_precision_rx_dma_control_active_drain_ticks_at_200m, 2000000\n"
    ".size hackrf_edge_precision_rx_dma_control_active_drain_ticks_at_200m, 4\n"
    ".global hackrf_edge_precision_rx_dma_control_active_drain_uses_dwt\n"
    ".type hackrf_edge_precision_rx_dma_control_active_drain_uses_dwt, %object\n"
    ".set hackrf_edge_precision_rx_dma_control_active_drain_uses_dwt, 1\n"
    ".size hackrf_edge_precision_rx_dma_control_active_drain_uses_dwt, 1\n"
    ".global hackrf_edge_precision_rx_dma_control_active_drain_counter_guard\n"
    ".type hackrf_edge_precision_rx_dma_control_active_drain_counter_guard, %object\n"
    ".set hackrf_edge_precision_rx_dma_control_active_drain_counter_guard, 1\n"
    ".size hackrf_edge_precision_rx_dma_control_active_drain_counter_guard, 1\n"
    ".global hackrf_edge_precision_rx_dma_control_slowest_descriptor_ticks_at_200m\n"
    ".type hackrf_edge_precision_rx_dma_control_slowest_descriptor_ticks_at_200m, %object\n"
    ".set hackrf_edge_precision_rx_dma_control_slowest_descriptor_ticks_at_200m, 409600\n"
    ".size hackrf_edge_precision_rx_dma_control_slowest_descriptor_ticks_at_200m, 4\n"
    ".global hackrf_edge_precision_rx_dma_lifetime_loss_counter_bits\n"
    ".type hackrf_edge_precision_rx_dma_lifetime_loss_counter_bits, %object\n"
    ".set hackrf_edge_precision_rx_dma_lifetime_loss_counter_bits, 32\n"
    ".size hackrf_edge_precision_rx_dma_lifetime_loss_counter_bits, 1\n"
    ".global hackrf_edge_precision_rx_dma_lifetime_loss_saturating\n"
    ".type hackrf_edge_precision_rx_dma_lifetime_loss_saturating, %object\n"
    ".set hackrf_edge_precision_rx_dma_lifetime_loss_saturating, 1\n"
    ".size hackrf_edge_precision_rx_dma_lifetime_loss_saturating, 1\n");
#endif

static std::array<gpdma::channel::LLI, transfers_per_buffer> lli_loop;
static constexpr auto& gpdma_channel_sgpio = gpdma::channels[portapack::sgpio_gpdma_channel_number];

static_assert((buffer_samples & (buffer_samples - 1U)) == 0U);
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
static_assert(
    precision_rx::dma_quiesce::descriptor_ticks(
        precision_rx::dma_lease::monitor_transfer_samples,
        1'000'000U,
        LPC43XX_M4_CLK) == 409'600U);
static_assert(
    precision_rx::dma_quiesce::control_active_drain_timeout_ticks(
        LPC43XX_M4_CLK) >
    precision_rx::dma_quiesce::descriptor_ticks(
        precision_rx::dma_lease::monitor_transfer_samples,
        1'000'000U,
        LPC43XX_M4_CLK));
#endif
static_assert((transfers_per_buffer & (transfers_per_buffer - 1U)) == 0U);
static_assert(sizeof(gpdma::channel::LLI) == 16U);
static_assert(sizeof(lli_loop) == 64U);
static_assert(transfer_bytes % sizeof(uint32_t) == 0U);
static_assert(transfer_bytes / sizeof(uint32_t) <= 0xfffU);
static_assert(control(Direction::Receive, 1U).i == 1U);
static_assert(control(Direction::Transmit, 1U).i == 1U);
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
static_assert(buffer_samples == 4096U);
static_assert(transfer_samples == 1024U);
static_assert(transfer_bytes == 2048U);
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
static_assert(buffer_bytes == precision_rx::dma_lease::owned_bytes);
static_assert(transfers_per_buffer == precision_rx::dma_lease::lli_count);
static_assert(transfer_bytes ==
              precision_rx::dma_lease::capture_transfer_bytes);
static_assert(sizeof(baseband::sample_t) ==
              precision_rx::dma_lease::sample_bytes);
#endif

static ThreadWait thread_wait;

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
constexpr size_t completion_queue_depth = transfers_per_buffer - 1U;
constexpr uint32_t completed_buffer_safe_age = transfers_per_buffer - 1U;
static_assert(completion_queue_depth == 3U);

static PrecisionRxDmaCompletionQueue<completion_queue_depth> completion_queue;
static uint32_t volatile completion_sequence = 0;
static uint32_t volatile completion_descriptor_index = 0;
static uint32_t volatile buffer_in_flight = 0;
static uint32_t volatile in_flight_sequence = 0;
static bool dma_error_pending = false;
static uint32_t volatile dma_fatal_latched = 0;
static uint32_t volatile dma_fast_accepting = 0;
static uint32_t volatile dma_fault_additional_invalidated = 0;
static uint32_t volatile dma_fault_in_flight_reuse = 0;
static uint32_t volatile dma_fault_accounted = 0;
static bool rate_paused = false;
static uint8_t volatile rate_pause_wait_armed = 0;

enum class DmaPhase : uint8_t {
    Wait = 0,
    Execute = 1,
    Rate = 2,
    Capture = 3,
    Error = 4,
};

static void publish_queue_state() {
    shared_memory.m4_dma_queue_depth =
        static_cast<uint8_t>(completion_queue.size());
    const auto queue_high_water = static_cast<uint8_t>(
        completion_queue.high_water_mark());
    if (queue_high_water > shared_memory.m4_dma_queue_high_water)
        shared_memory.m4_dma_queue_high_water = queue_high_water;
}

static void record_unintentional_loss(uint32_t volatile& component) {
    precision_rx_dma_saturating_increment(component);
    precision_rx_dma_saturating_increment(
        shared_memory.m4_dma_missed_lifetime);
    const uint32_t lifetime = shared_memory.m4_dma_missed_lifetime;
    shared_memory.m4_buffer_missed = static_cast<uint16_t>(
        lifetime > UINT16_MAX ? UINT16_MAX : lifetime);
}

static void record_boundary_discard(const uint32_t count = 1U) {
    for (uint32_t i = 0; i < count; ++i)
        precision_rx_dma_saturating_increment(
            shared_memory.m4_dma_boundary_discarded);
}

constexpr uint32_t precision_rx_dma_irq_mask =
    1U << static_cast<uint32_t>(DMA_IRQn);
constexpr uint32_t precision_rx_deferred_irq_mask =
    1U << static_cast<uint32_t>(SGPIO_IRQn);
static_assert(DMA_IRQn < 32);
static_assert(SGPIO_IRQn < 32);

/*
 * The producer is excluded only around the reset itself. DMA is already
 * stopped by every caller. Direct NVIC/MMIO operations keep this window
 * instruction-bounded and independent of both ChibiOS and callable helpers.
 */
__attribute__((noinline, noclone, optimize("Os")))
static uint32_t reset_completion_queue_with_fast_irq_excluded() {
    NVIC_ICER(0) = precision_rx_dma_irq_mask;
    __DMB();
    dma_fast_accepting = 0U;
    const uint32_t discarded =
        static_cast<uint32_t>(completion_queue.size());
    completion_queue.reset();
    completion_descriptor_index = 0U;
    LPC_GPDMA->INTTCCLR =
        1U << portapack::sgpio_gpdma_channel_number;
    LPC_GPDMA->INTERRCLR =
        1U << portapack::sgpio_gpdma_channel_number;
    NVIC_ICPR(0) =
        precision_rx_dma_irq_mask | precision_rx_deferred_irq_mask;
    __DMB();
    NVIC_ISER(0) = precision_rx_dma_irq_mask;
    return discarded;
}

static void discard_completion_queue_for_boundary() {
    const uint32_t discarded =
        reset_completion_queue_with_fast_irq_excluded();
    record_boundary_discard(discarded);
    publish_queue_state();
}

static void discard_in_flight_for_boundary() {
    if (buffer_in_flight) {
        record_boundary_discard();
        buffer_in_flight = false;
    }
}

/*
 * Safe at priority 1: no RTOS call, allocation, lock, or unbounded loop.
 * The SGPIO request gate and PL080 channel close before the durable fault is
 * published; the generic IRQ therefore clears ERR only after hardware stop.
 */
__attribute__((noinline, noclone, optimize("Os")))
static void latch_precision_rx_dma_fault_fast(
    const uint32_t additional_invalidated,
    const bool in_flight_reuse) {
    /*
     * Reassert the physical fail-close even for an already latched fault.
     * This makes every exceptional validation path self-contained and keeps a
     * stale SGPIO gate RMW from reopening requests over the stopped channel.
     */
    LPC_SGPIO->GPIO_OUTREG |= (1U << 10U);
    LPC_GPDMA->CH[portapack::sgpio_gpdma_channel_number].CONFIG &=
        ~(1U << 0U);
    dma_fast_accepting = 0U;
    if (dma_fatal_latched != 0U) {
        if (additional_invalidated != 0U &&
            dma_fault_additional_invalidated != UINT32_MAX)
            ++dma_fault_additional_invalidated;
        if (in_flight_reuse)
            dma_fault_in_flight_reuse = 1U;
        return;
    }

    dma_fault_additional_invalidated = additional_invalidated;
    dma_fault_in_flight_reuse = in_flight_reuse ? 1U : 0U;
    shared_memory.m4_dma_phase =
        static_cast<uint8_t>(DmaPhase::Error);
    shared_memory.m4_dma_rate_state = 5U;
    dma_fatal_latched = 1U;
    __DMB();
}

/*
 * The caller holds the ChibiOS system lock. The fast ISR has already gated
 * and disabled DMA; this deferred half performs accounting and is the only
 * fatal path allowed to wake the worker.
 */
static void complete_precision_rx_dma_fault_locked() {
    if (dma_fault_accounted) {
        dma_error_pending = true;
        thread_wait.wake_from_interrupt(-1);
        return;
    }

    uint32_t invalidated =
        dma_fault_additional_invalidated +
        static_cast<uint32_t>(completion_queue.size());
    if (buffer_in_flight) {
        if (dma_fault_in_flight_reuse != 0U) {
            /*
             * The gate is already closed. Classify the claimed descriptor by
             * its root cause while all other buffers invalidated by this
             * fail-close remain DMA-error drops.
             */
            record_unintentional_loss(
                shared_memory.m4_dma_reuse_dropped);
        } else {
            ++invalidated;
        }
    }
    for (uint32_t i = 0; i < invalidated; ++i)
        record_unintentional_loss(
            shared_memory.m4_dma_error_dropped);
    reset_completion_queue_with_fast_irq_excluded();
    buffer_in_flight = 0U;
    dma_fault_accounted = true;
    dma_error_pending = true;
    publish_queue_state();
    thread_wait.wake_from_interrupt(-1);
}

static bool fail_if_precision_rx_dma_error_pending_locked() {
    constexpr uint32_t precision_rx_channel_mask =
        1U << portapack::sgpio_gpdma_channel_number;
    if (dma_fatal_latched != 0U) {
        complete_precision_rx_dma_fault_locked();
        return true;
    }
    const uint32_t initial_tc_stat = LPC_GPDMA->INTTCSTAT;
    const uint32_t initial_err_stat = LPC_GPDMA->INTERRSTAT;
    const uint32_t initial_enabled_channels = LPC_GPDMA->ENBLDCHNS;
    const bool initial_unexpected_channel =
        ((initial_tc_stat | initial_err_stat |
          initial_enabled_channels) &
         ~precision_rx_channel_mask) != 0U;
    if ((initial_err_stat & precision_rx_channel_mask) == 0U &&
        !initial_unexpected_channel)
        return false;

    /*
     * Priority 1 normally wins this race. Exclude it while directly closing
     * the exceptional pending-status window, then account after re-enable.
     */
    NVIC_ICER(0) = precision_rx_dma_irq_mask;
    __DMB();
    /*
     * Retire only the NVIC indication that preceded exclusion. A new request
     * after the final PL080 sample must remain pending for vector re-enable.
     */
    NVIC_ICPR(0) = precision_rx_dma_irq_mask;
    __DMB();
    const uint32_t tc_stat = LPC_GPDMA->INTTCSTAT;
    const uint32_t err_stat = LPC_GPDMA->INTERRSTAT;
    const uint32_t enabled_channels = LPC_GPDMA->ENBLDCHNS;
    const bool unexpected_channel =
        ((tc_stat | err_stat | enabled_channels) &
         ~precision_rx_channel_mask) != 0U;
    const bool fault =
        dma_fatal_latched != 0U ||
        (err_stat & precision_rx_channel_mask) != 0U ||
        unexpected_channel;
    if (fault) {
        latch_precision_rx_dma_fault_fast(
            (tc_stat & precision_rx_channel_mask) != 0U ? 1U : 0U,
            false);
        LPC_GPDMA->INTTCCLR = tc_stat;
        LPC_GPDMA->INTERRCLR = err_stat;
        NVIC_ISPR(0) = precision_rx_deferred_irq_mask;
    }
    __DMB();
    NVIC_ISER(0) = precision_rx_dma_irq_mask;
    if (fault) {
        complete_precision_rx_dma_fault_locked();
        return true;
    }
    return false;
}
#endif

#if !defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
/*
 * ThreadWait has no completed-transfer queue: a TC arriving while the worker
 * is awake does not create scheduler backlog.  At 20 Msps the zero-drop
 * service deadline is therefore one 4096-byte LLI interval (102.4 us).
 * Three completed descriptors remain physically distinct for 307.2 us, but
 * that retention is overwrite geometry, not extra processing time.  p11
 * qualification consequently requires the 20 Msps zero-D hardware lane;
 * queued-drain scheduling remains a later-profile change.
 */
#endif

volatile uint32_t buffer_transfered = 0;
volatile uint32_t buffer_handled = 0;

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
static sample_t* lease_owned_base = nullptr;
static sample_t* lease_loan_base = nullptr;

__attribute__((optimize("Os"))) static void configure_lease_descriptors(
    const bool capture) {
    const auto geometry = capture
                              ? precision_rx::dma_lease::Geometry::Capture
                              : precision_rx::dma_lease::Geometry::Monitor;
    const size_t bytes = precision_rx::dma_lease::transfer_bytes(geometry);
    const auto control_value = control(
        Direction::Receive, gpdma::buffer_words(bytes, 4));
    const auto peripheral = reinterpret_cast<uint32_t>(&LPC_SGPIO->REG_SS[0]);
    auto* memory = reinterpret_cast<uint8_t*>(lease_owned_base);
    const size_t stride = capture
                              ? precision_rx::dma_lease::capture_transfer_bytes
                              : precision_rx::dma_lease::monitor_transfer_bytes;
    for (size_t i = 0; i < lli_loop.size(); ++i) {
        if (!capture && i == precision_rx::dma_lease::monitor_owned_lli_count)
            memory = reinterpret_cast<uint8_t*>(lease_loan_base);
        lli_loop[i].srcaddr = peripheral;
        lli_loop[i].destaddr = reinterpret_cast<uint32_t>(memory);
        lli_loop[i].lli = lli_pointer(&lli_loop[(i + 1U) & transfers_mask]);
        lli_loop[i].control = control_value;
        memory += stride;
    }
}
#endif

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
extern "C" __attribute__((noinline, noclone, used, externally_visible, optimize("Os")))
void hackrf_edge_precision_rx_dma_fast_terminal_count() {
    if (dma_fatal_latched != 0U)
        return;
    bool in_flight_reuse = false;
    uint32_t sequence = 0U;
    uint32_t free_index = 0U;
    PrecisionRxDmaCompletion oldest{};
    PrecisionRxDmaCompletionQueue<completion_queue_depth>::PushResult
        push_result{};
    if (dma_fast_accepting == 0U)
        goto fault;

    sequence = completion_sequence + 1U;
    completion_sequence = sequence;
    free_index = completion_descriptor_index;
    completion_descriptor_index =
        (free_index + 1U) & transfers_mask;
    precision_rx_dma_saturating_increment(shared_memory.m4_dma_tc_total);
    buffer_transfered++;
#ifdef PRALINE
    shared_memory.m4_dma_xfr_count++;
#endif

    if (buffer_in_flight != 0U &&
        precision_rx_dma_in_flight_must_fail_close(
            sequence,
            in_flight_sequence,
            completed_buffer_safe_age)) {
        /*
         * Gate/fail before the next LLI can reach the physical reuse age.
         * Continuing the current execute() while its descriptor is recycled
         * would permit corrupt capture/metrics publication.
         */
        in_flight_reuse = true;
        goto fault;
    }

    if (completion_queue.peek(oldest) &&
        precision_rx_dma_claim_too_late(
            sequence,
            oldest.completion_sequence,
            completed_buffer_safe_age)) {
        /*
         * The oldest unclaimed descriptor has reached the last TC at which
         * the request gate can stop its next reuse. Do not wait for a worker
         * dequeue or for the physical overwrite to begin.
         */
        goto fault;
    }

    push_result = completion_queue.push({free_index, sequence});
    if (!push_result.accepted)
        goto fault;

    __DMB();
    return;

fault:
    latch_precision_rx_dma_fault_fast(1U, in_flight_reuse);
}

extern "C" __attribute__((noinline, noclone, used, externally_visible, optimize("Os")))
void hackrf_edge_precision_rx_dma_fast_fault(
    const uint32_t pending_terminal_count) {
    latch_precision_rx_dma_fault_fast(
        pending_terminal_count, false);
}

extern "C" __attribute__((noinline, noclone, used, externally_visible, optimize("Os")))
void hackrf_edge_precision_rx_dma_deferred_interrupt() {
    if (dma_fatal_latched != 0U) {
        complete_precision_rx_dma_fault_locked();
    } else {
        publish_queue_state();
        thread_wait.wake_from_interrupt(0);
    }
}
#else
static void transfer_complete() {
    const auto next_lli_index = gpdma_channel_sgpio.next_lli() - &lli_loop[0];
    buffer_transfered++;
#ifdef PRALINE
    shared_memory.m4_dma_xfr_count++;  // Phase 0 instrumentation
#endif
    thread_wait.wake_from_interrupt(next_lli_index);
}

static void dma_error() {
    thread_wait.wake_from_interrupt(-1);
    disable();
}
#endif

void init() {
#if !defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    gpdma_channel_sgpio.set_handlers(transfer_complete, dma_error);
#endif
#if defined(PORTAPACK_BASEBAND_DMA_NO_SYNC)
    /* Disable synchronization logic to improve(?) DMA response time.
     * SGPIO (peripheral) must be on same clock as GPDMA peripheral.
     * SGPIO runs from BASE_PERIPH_CLK, which is set to PLL1 in normal
     * operation, same as the M4 and M0 cores. Memory, of course, is
     * running from the same clock as the cores.
     */
    LPC_GPDMA->SYNC |= (1 << gpdma_src_peripheral);
    LPC_GPDMA->SYNC |= (1 << gpdma_dest_peripheral);
#endif
}

void configure(
    baseband::sample_t* const buffer_base,
    const baseband::Direction direction) {
    const auto peripheral = reinterpret_cast<uint32_t>(&LPC_SGPIO->REG_SS[0]);
    const auto control_value = control(direction, gpdma::buffer_words(transfer_bytes, 4));
    for (size_t i = 0; i < lli_loop.size(); i++) {
        const auto memory = reinterpret_cast<uint32_t>(&buffer_base[i * transfer_samples]);
        lli_loop[i].srcaddr = (direction == Direction::Transmit) ? memory : peripheral;
        lli_loop[i].destaddr = (direction == Direction::Transmit) ? peripheral : memory;
        lli_loop[i].lli = lli_pointer(&lli_loop[(i + 1) % lli_loop.size()]);
        lli_loop[i].control = control_value;
    }
}

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
bool configure_precision_rx_lease(
    sample_t* const owned_base,
    sample_t* const loan_base) {
    if (!owned_base || !loan_base || gpdma_channel_sgpio.is_enabled())
        return false;
    lease_owned_base = owned_base;
    lease_loan_base = loan_base;
    configure_lease_descriptors(false);
    return true;
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
static void publish_precision_rx_quiesce_failure(
    const precision_rx::dma_telemetry::QuiesceFailure reason) {
    shared_memory.m4_dma_transition_failures =
        precision_rx::dma_telemetry::with_quiesce_failure(
            shared_memory.m4_dma_transition_failures,
            reason);
    __DMB();
}

__attribute__((noinline, noclone, optimize("Os")))
static bool halt_and_disable_precision_rx(bool& pending_terminal_count) {
    constexpr uint32_t active_mask = 1U << 17U;
    constexpr uint32_t halt_mask = 1U << 18U;
    constexpr uint32_t sgpio_gate_mask = 1U << 10U;
    constexpr uint32_t active_drain_timeout_ticks =
        precision_rx::dma_quiesce::control_active_drain_timeout_ticks(
            LPC43XX_M4_CLK);
    constexpr uint32_t channel_mask =
        1U << portapack::sgpio_gpdma_channel_number;
    auto& channel_config =
        LPC_GPDMA->CH[portapack::sgpio_gpdma_channel_number].CONFIG;

    publish_precision_rx_quiesce_failure(
        precision_rx::dma_telemetry::QuiesceFailure::None);

    /*
     * Never let the transition path erase a real channel error with the
     * unconditional TC/ERR clear below. This test must precede even the
     * disabled-channel fast paths in every caller.
     */
    if (fail_if_precision_rx_dma_error_pending_locked()) {
        publish_precision_rx_quiesce_failure(
            precision_rx::dma_telemetry::QuiesceFailure::
                DmaErrorBeforeHalt);
        return false;
    }

    /*
     * M4 HAL enables CYCCNT before baseband starts.  If that invariant is ever
     * lost, reject before touching H so a disabled counter cannot make this
     * system-locked control path unbounded.
     */
    if ((SCS_DEMCR & SCS_DEMCR_TRCENA) == 0U ||
        (DWT_CTRL & DWT_CTRL_CYCCNTENA) == 0U) {
        publish_precision_rx_quiesce_failure(
            precision_rx::dma_telemetry::QuiesceFailure::
                CounterUnavailable);
        return false;
    }

    channel_config |= halt_mask;
    __DMB();
    const uint32_t active_drain_start = halGetCounterValue();
    while ((channel_config & active_mask) != 0U &&
           !precision_rx::dma_quiesce::
               control_active_drain_deadline_reached(
                   active_drain_start,
                   halGetCounterValue(),
                   active_drain_timeout_ticks)) {
    }
    if ((channel_config & active_mask) != 0U) {
        if (fail_if_precision_rx_dma_error_pending_locked()) {
            publish_precision_rx_quiesce_failure(
                precision_rx::dma_telemetry::QuiesceFailure::
                    DmaErrorDuringDrain);
            return false;
        }
        /* Preserve the old enabled ring when ACTIVE cannot drain. */
        channel_config &= ~halt_mask;
        __DMB();
        publish_precision_rx_quiesce_failure(
            precision_rx::dma_telemetry::QuiesceFailure::
                ActiveDrainTimeout);
        return false;
    }

    if (fail_if_precision_rx_dma_error_pending_locked()) {
        publish_precision_rx_quiesce_failure(
            precision_rx::dma_telemetry::QuiesceFailure::
                DmaErrorAfterDrain);
        return false;
    }
    /*
     * PL080 HALT must see the live SGPIO request source until ACTIVE drains.
     * Close HOST_DISABLE only after the final deadline sample proves A==0.
     * Read the gate back, then recheck ACTIVE before E is cleared so neither
     * a posted SGPIO write nor a violated HALT invariant can be hidden.
     */
    LPC_SGPIO->GPIO_OUTREG |= sgpio_gate_mask;
    __DMB();
    (void)LPC_SGPIO->GPIO_OUTREG;
    if ((channel_config & active_mask) != 0U) {
        /*
         * This is not the ordinary timeout path: ACTIVE was observed clear
         * before the gate write. Reassertion with H still set violates the
         * PL080 ownership invariant, so keep the gate closed and enter the
         * existing fatal path instead of reporting a recoverable rejection.
         */
        publish_precision_rx_quiesce_failure(
            precision_rx::dma_telemetry::QuiesceFailure::
                ActiveReassertedAfterGate);
        latch_precision_rx_dma_fault_fast(0U, false);
        NVIC_ISPR(0) = precision_rx_deferred_irq_mask;
        __DMB();
        return false;
    }
    pending_terminal_count =
        (LPC_GPDMA->INTTCSTAT & channel_mask) != 0U;
    gpdma_channel_sgpio.disable();
    dma_fast_accepting = 0U;
    __DMB();
    if (fail_if_precision_rx_dma_error_pending_locked()) {
        publish_precision_rx_quiesce_failure(
            precision_rx::dma_telemetry::QuiesceFailure::
                DmaErrorAfterDisable);
        return false;
    }
    gpdma_channel_sgpio.clear_interrupts();
    return true;
}
#endif

__attribute__((noinline, noclone, optimize("Os")))
bool set_precision_rx_capture_geometry(
    const bool capture) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    publish_precision_rx_quiesce_failure(
        precision_rx::dma_telemetry::QuiesceFailure::None);
    /*
     * The caller holds the system lock. Sample ERR before the enabled-channel
     * fast path so a stopped channel can never hide and clear a pending fault.
     */
    if (fail_if_precision_rx_dma_error_pending_locked() ||
        dma_fatal_latched) {
        publish_precision_rx_quiesce_failure(
            precision_rx::dma_telemetry::QuiesceFailure::
                DmaErrorBeforeHalt);
        return false;
    }
#endif
    /* An enabled p11 channel implies successful one-time lease setup. */
    if (!gpdma_channel_sgpio.is_enabled()) {
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
        publish_precision_rx_quiesce_failure(
            precision_rx::dma_telemetry::QuiesceFailure::
                ChannelDisabled);
        latch_precision_rx_dma_fault_fast(0U, false);
        NVIC_ISPR(0) = precision_rx_deferred_irq_mask;
        __DMB();
#endif
        return false;
    }
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    bool pending_terminal_count = false;
    const bool halted =
        halt_and_disable_precision_rx(pending_terminal_count);
    if (!halted)
        return false;
    /*
     * Geometry commands are serviced before this claimed block is consumed,
     * Classify that deliberate discard at the successful boundary and release
     * its lease before a restarted ring can age it into a false reuse loss.
     * A HALT timeout leaves every software owner and queue entry untouched.
     */
    discard_in_flight_for_boundary();
    shared_memory.m4_dma_phase =
        static_cast<uint8_t>(DmaPhase::Capture);
    if (pending_terminal_count)
        record_boundary_discard();
    discard_completion_queue_for_boundary();
    thread_wait.reset();
    configure_lease_descriptors(capture);
    buffer_transfered = 0;
    buffer_handled = 0;
    __DMB();
    if (fail_if_precision_rx_dma_error_pending_locked()) {
        publish_precision_rx_quiesce_failure(
            precision_rx::dma_telemetry::QuiesceFailure::
                DmaErrorAfterDisable);
        return false;
    }
    gpdma_channel_sgpio.clear_interrupts();
    return true;
#else
    constexpr uint32_t active_mask = 1U << 17U;
    constexpr uint32_t halt_mask = 1U << 18U;
    auto& channel_config =
        LPC_GPDMA->CH[portapack::sgpio_gpdma_channel_number].CONFIG;

    /*
     * PL080 channels must be halted and allowed to drain before E is cleared;
     * clearing E while ACTIVE discards FIFO state. SGPIO requests are already
     * gated by the caller. Timeout clears H only, preserving the old channel.
     */
    channel_config |= halt_mask;
    __DMB();
    uint32_t quiesce_spins = 65536U;
    while ((channel_config & active_mask) != 0U &&
           --quiesce_spins != 0U) {
    }
    if (quiesce_spins == 0U) {
        /* E was never cleared, so dropping H safely resumes the old ring. */
        channel_config &= ~halt_mask;
        __DMB();
        return false;
    }
    gpdma_channel_sgpio.disable();
    __DMB();
    gpdma_channel_sgpio.clear_interrupts();
    thread_wait.reset();
    configure_lease_descriptors(capture);
    buffer_transfered = 0;
    buffer_handled = 0;
    shared_memory.m4_buffer_missed = 0;
    __DMB();
    gpdma_channel_sgpio.clear_interrupts();
    return true;
#endif
}

void enable_precision_rx() {
    constexpr auto receive_config = config(Direction::Receive);
    /*
     * Fixed-channel RX specialization of Channel::configure().  Keep the
     * complete disabled-register image before setting E: both initial setup
     * and every geometry switch must restart from LLI[0], not a stale link.
     */
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    if (fail_if_precision_rx_dma_error_pending_locked())
        return;
    NVIC_ICER(0) = precision_rx_dma_irq_mask;
    __DMB();
    dma_fast_accepting = 0U;
#endif
    gpdma_channel_sgpio.clear_interrupts();
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    NVIC_ICPR(0) =
        precision_rx_dma_irq_mask | precision_rx_deferred_irq_mask;
#endif
    auto& channel =
        LPC_GPDMA->CH[portapack::sgpio_gpdma_channel_number];
    channel.SRCADDR = lli_loop[0].srcaddr;
    channel.DESTADDR = lli_loop[0].destaddr;
    channel.LLI = lli_loop[0].lli;
    channel.CONTROL = lli_loop[0].control;
    channel.CONFIG = receive_config;
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    completion_descriptor_index = 0U;
    dma_fast_accepting = 1U;
    __DMB();
#endif
    gpdma_channel_sgpio.enable();
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    __DMB();
    NVIC_ISER(0) = precision_rx_dma_irq_mask;
#endif
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
__attribute__((noinline, noclone, optimize("Os")))
bool pause_precision_rx_rate_change() {
    publish_precision_rx_quiesce_failure(
        precision_rx::dma_telemetry::QuiesceFailure::None);
    /*
     * A bounded control timeout can race the worker's successful PREPARE.
     * Treat an already-disabled paused ring as idempotent success so the
     * wrapper never re-enables SGPIO requests over a quiesced DMA channel.
     */
    if (fail_if_precision_rx_dma_error_pending_locked() ||
        dma_fatal_latched) {
        publish_precision_rx_quiesce_failure(
            precision_rx::dma_telemetry::QuiesceFailure::
                DmaErrorBeforeHalt);
        return false;
    }
    if (rate_paused)
        return !gpdma_channel_sgpio.is_enabled();
    if (!gpdma_channel_sgpio.is_enabled()) {
        publish_precision_rx_quiesce_failure(
            precision_rx::dma_telemetry::QuiesceFailure::
                ChannelDisabled);
        latch_precision_rx_dma_fault_fast(0U, false);
        NVIC_ISPR(0) = precision_rx_deferred_irq_mask;
        __DMB();
        return false;
    }

    bool pending_terminal_count = false;
    if (!halt_and_disable_precision_rx(pending_terminal_count))
        return false;

    shared_memory.m4_dma_phase =
        static_cast<uint8_t>(DmaPhase::Rate);
    if (pending_terminal_count)
        record_boundary_discard();
    discard_completion_queue_for_boundary();
    /*
     * A timeout recovery can quiesce the channel while the worker is already
     * suspended in its ordinary waiter. Preserve that installed waiter as an
     * armed pause; the normal worker-boundary PREPARE path reaches this point
     * while executing and therefore still publishes zero until wait_for_buffer
     * installs the waiter.
     */
    rate_pause_wait_armed =
        thread_wait.is_waiting_locked() ? 1U : 0U;
    rate_paused = true;
    dma_error_pending = false;
    __DMB();
    return true;
}

__attribute__((noinline, noclone, optimize("Os")))
bool resume_precision_rx_rate_change() {
    if (fail_if_precision_rx_dma_error_pending_locked() ||
        dma_fatal_latched || !rate_paused ||
        gpdma_channel_sgpio.is_enabled() ||
        !completion_queue.empty())
        return false;

    enable_precision_rx();
    if (dma_fatal_latched)
        return false;
    rate_paused = false;
    rate_pause_wait_armed = 0U;
    dma_error_pending = false;
    shared_memory.m4_dma_phase =
        static_cast<uint8_t>(DmaPhase::Wait);
    __DMB();
    return true;
}

bool precision_rx_rate_pause_armed() {
    chSysLock();
    const bool armed = rate_paused && rate_pause_wait_armed != 0U &&
                       thread_wait.is_waiting_locked();
    chSysUnlock();
    return armed;
}

bool precision_rx_rate_paused() {
    chSysLock();
    const bool paused = rate_paused;
    chSysUnlock();
    return paused;
}

bool precision_rx_dma_faulted_locked() {
    return dma_fatal_latched;
}

bool precision_rx_dma_faulted() {
    chSysLock();
    const bool faulted = precision_rx_dma_faulted_locked();
    chSysUnlock();
    return faulted;
}

/*
 * Priority-1 DMA can preempt a ChibiOS system lock. Exclude only that vector
 * while a non-fatal rate state is reduced and published. Preserve both the
 * NVIC indication and the PL080 TC bit for an ordinary own-channel completion:
 * the priority-1 ISR retires and publishes it after the caller ends the
 * update. ERR, unexpected-channel state, and an existing fatal latch still
 * close the gate before any exceptional status is retired.
 */
__attribute__((noinline, noclone, optimize("Os")))
bool begin_precision_rx_rate_state_update() {
    NVIC_ICER(0) = precision_rx_dma_irq_mask;
    __DMB();

    const uint32_t precision_rx_channel_mask =
        1U << portapack::sgpio_gpdma_channel_number;
    const uint32_t tc_stat = LPC_GPDMA->INTTCSTAT;
    const uint32_t err_stat = LPC_GPDMA->INTERRSTAT;
    const uint32_t enabled_channels = LPC_GPDMA->ENBLDCHNS;
    const bool unexpected_channel =
        ((tc_stat | err_stat | enabled_channels) &
         ~precision_rx_channel_mask) != 0U;
    const bool healthy =
        dma_fatal_latched == 0U &&
        !unexpected_channel &&
        (err_stat & precision_rx_channel_mask) == 0U;
    if (!healthy) {
        latch_precision_rx_dma_fault_fast(
            (tc_stat & precision_rx_channel_mask) != 0U ? 1U : 0U,
            false);
        if ((tc_stat | err_stat) != 0U) {
            LPC_GPDMA->INTTCCLR = tc_stat;
            LPC_GPDMA->INTERRCLR = err_stat;
        }
        NVIC_ISPR(0) = precision_rx_deferred_irq_mask;
        __DMB();
        NVIC_ISER(0) = precision_rx_dma_irq_mask;
    }
    return healthy;
}

__attribute__((noinline, noclone, optimize("Os")))
void end_precision_rx_rate_state_update() {
    __DMB();
    NVIC_ISER(0) = precision_rx_dma_irq_mask;
}

__attribute__((noinline, noclone, optimize("Os")))
bool open_precision_rx_sgpio_gate_locked() {
    /*
     * Callers hold the ChibiOS lock, but priority 1 can still preempt it.
     * Exclude only DMA while the gate RMW is committed. The shared exclusion
     * helper preserves an ordinary own-channel completion for the fast ISR;
     * only exceptional state prevents the gate from opening.
     */
    if (!begin_precision_rx_rate_state_update())
        return false;
    if (!gpdma_channel_sgpio.is_enabled()) {
        latch_precision_rx_dma_fault_fast(0U, false);
        NVIC_ISPR(0) = precision_rx_deferred_irq_mask;
        end_precision_rx_rate_state_update();
        return false;
    }
    LPC_SGPIO->GPIO_OUTREG &= ~(1U << 10U);
    end_precision_rx_rate_state_update();
    return true;
}

/*
 * The PL080 manual requires HALT, ACTIVE==0, then E-clear before descriptor
 * storage can be reclaimed. Fast fail-close clears E immediately to stop the
 * product, but the current AHB transfer can still finish; this worker-only
 * confirmation therefore remains mandatory on every thread exit.
 */
__attribute__((noinline, noclone, used, externally_visible, optimize("Os")))
bool quiesce_precision_rx_for_shutdown() {
    constexpr uint32_t active_mask = 1U << 17U;
    constexpr uint32_t halt_mask = 1U << 18U;
    constexpr uint32_t sgpio_gate_mask = 1U << 10U;
    constexpr uint32_t shutdown_irq_mask =
        precision_rx_dma_irq_mask | precision_rx_deferred_irq_mask;
    auto& channel_config =
        LPC_GPDMA->CH[portapack::sgpio_gpdma_channel_number].CONFIG;

    NVIC_ICER(0) = shutdown_irq_mask;
    __DMB();
    channel_config |= halt_mask;
    __DMB();

    uint32_t quiesce_spins = 65536U;
    while ((channel_config & active_mask) != 0U &&
           --quiesce_spins != 0U) {
    }
    if (quiesce_spins == 0U) {
        /*
         * Shutdown is terminal, so preserve DMA ownership/E for the caller's
         * fail-stop while still closing the physical SGPIO request source.
         */
        LPC_SGPIO->GPIO_OUTREG |= sgpio_gate_mask;
        __DMB();
        (void)LPC_SGPIO->GPIO_OUTREG;
        return false;
    }

    LPC_SGPIO->GPIO_OUTREG |= sgpio_gate_mask;
    __DMB();
    (void)LPC_SGPIO->GPIO_OUTREG;
    if ((channel_config & active_mask) != 0U)
        return false;

    channel_config &= ~(1U << 0U);
    __DMB();
    /*
     * Both vectors stay disabled after this terminal operation. A following
     * baseband image clears PL080 status while reinitializing its channel.
     */
    NVIC_ICPR(0) = shutdown_irq_mask;
    __DMB();
    return true;
}

__attribute__((noinline, noclone, optimize("Os")))
void wake_precision_rx_worker_for_shutdown() {
    chSysLock();
    /*
     * Keep a durable predicate alongside the one-shot scheduler wake. This
     * closes the terminate-check / waiter-install race without closing SGPIO,
     * clearing DMA E, retiring queues, or changing descriptor ownership.
     */
    dma_error_pending = true;
    __DMB();
    thread_wait.wake_from_interrupt(-1);
    chSysUnlock();
}

void stop_precision_rx_for_shutdown() {
    chSysLock();
    const bool faulted_from_pending_error =
        fail_if_precision_rx_dma_error_pending_locked();
    if (!faulted_from_pending_error) {
        gpdma_channel_sgpio.disable();
        __DMB();
        if (!fail_if_precision_rx_dma_error_pending_locked())
            gpdma_channel_sgpio.clear_interrupts();
    }
    discard_completion_queue_for_boundary();
    discard_in_flight_for_boundary();
    rate_paused = false;
    rate_pause_wait_armed = 0U;
    dma_error_pending = true;
    thread_wait.wake_from_interrupt(-1);
    chSysUnlock();
}

void release_buffer() {
    chSysLock();
    buffer_in_flight = false;
    chSysUnlock();
}
#endif
#endif

void enable(const baseband::Direction direction) {
    const auto gpdma_config = config(direction);
    gpdma_channel_sgpio.configure(lli_loop[0], gpdma_config);
    gpdma_channel_sgpio.enable();
}

bool is_enabled() {
    return gpdma_channel_sgpio.is_enabled();
}

void disable() {
    gpdma_channel_sgpio.disable();
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
enum class PrecisionRxClaimResult : uint8_t {
    Empty,
    Claimed,
    Fault,
};

/*
 * The priority-1 producer can preempt a ChibiOS system lock. Exclude only its
 * NVIC line while consumer head publication and the 32-bit aligned in-flight
 * claim become one ordered operation. Preserve an ordinary own-channel TC
 * (including its NVIC pending indication) for the normal fast ISR after
 * vector re-enable. ERR, unexpected-channel state, and a TC concurrent with
 * an already-failed claim remain fail-closed before exceptional W1C.
 */
__attribute__((noinline, noclone, optimize("Os")))
static PrecisionRxClaimResult claim_precision_rx_completion(
    PrecisionRxDmaCompletion& completion) {
    NVIC_ICER(0) = precision_rx_dma_irq_mask;
    __DMB();

    PrecisionRxClaimResult result = PrecisionRxClaimResult::Empty;
    if (dma_fatal_latched != 0U) {
        result = PrecisionRxClaimResult::Fault;
    } else if (completion_queue.pop(completion)) {
        buffer_in_flight = 1U;
        in_flight_sequence = completion.completion_sequence;
        __DMB();
        if (completion.descriptor_index >= lli_loop.size() ||
            precision_rx_dma_claim_too_late(
                completion_sequence,
                completion.completion_sequence,
                completed_buffer_safe_age)) {
            latch_precision_rx_dma_fault_fast(0U, true);
            result = PrecisionRxClaimResult::Fault;
        } else {
            result = PrecisionRxClaimResult::Claimed;
        }
    }

    const uint32_t precision_rx_channel_mask =
        1U << portapack::sgpio_gpdma_channel_number;
    const uint32_t tc_stat = LPC_GPDMA->INTTCSTAT;
    const uint32_t err_stat = LPC_GPDMA->INTERRSTAT;
    const uint32_t enabled_channels = LPC_GPDMA->ENBLDCHNS;
    const bool unexpected_channel =
        ((tc_stat | err_stat | enabled_channels) &
         ~precision_rx_channel_mask) != 0U;
    const bool own_channel_error =
        (err_stat & precision_rx_channel_mask) != 0U;
    const bool failed_claim_with_pending_terminal_count =
        result == PrecisionRxClaimResult::Fault &&
        (tc_stat & precision_rx_channel_mask) != 0U;
    if (own_channel_error || unexpected_channel ||
        failed_claim_with_pending_terminal_count) {
        /*
         * Exceptional state may coincide with a channel advance while the
         * vector is masked. Gate and stop before W1C; the claimed buffer, if
         * any, remains explicitly owned and is included in deferred error
         * accounting. A sole own-channel TC never enters this branch.
         */
        latch_precision_rx_dma_fault_fast(
            (tc_stat & precision_rx_channel_mask) != 0U ? 1U : 0U,
            false);
        LPC_GPDMA->INTTCCLR = tc_stat;
        LPC_GPDMA->INTERRCLR = err_stat;
        NVIC_ISPR(0) = precision_rx_deferred_irq_mask;
        result = PrecisionRxClaimResult::Fault;
    }

    __DMB();
    NVIC_ISER(0) = precision_rx_dma_irq_mask;
    return result;
}

__attribute__((noinline, noclone, optimize("Os")))
#endif
baseband::buffer_t wait_for_buffer() {
#ifdef PRALINE
    shared_memory.m4_dma_wait_count++;  // Phase 0 instrumentation
#endif

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
    while (true) {
        chSysLock();
        if (dma_fatal_latched) {
            chSysUnlock();
            return {};
        }
        if (dma_error_pending) {
            dma_error_pending = false;
            chSysUnlock();
            return {};
        }

        PrecisionRxDmaCompletion completion{};
        PrecisionRxClaimResult claim =
            claim_precision_rx_completion(completion);
        while (claim == PrecisionRxClaimResult::Empty) {
            publish_queue_state();
            shared_memory.m4_dma_phase =
                static_cast<uint8_t>(DmaPhase::Wait);
            const auto wake_result = thread_wait.sleep_locked(
                rate_paused ? &rate_pause_wait_armed : nullptr);
            if (wake_result < 0 || dma_error_pending) {
                dma_error_pending = false;
                chSysUnlock();
                return {};
            }
            claim = claim_precision_rx_completion(completion);
        }
        publish_queue_state();

        if (claim == PrecisionRxClaimResult::Fault) {
            complete_precision_rx_dma_fault_locked();
            chSysUnlock();
            return {};
        }

        ++buffer_handled;
        shared_memory.m4_dma_phase =
            static_cast<uint8_t>(DmaPhase::Execute);
        const size_t free_index = completion.descriptor_index;
        const auto p = lli_loop[free_index].destaddr;
        const size_t count =
            (lli_loop[free_index].control & 0xfffU) << 1U;
        chSysUnlock();
        return {reinterpret_cast<sample_t*>(p), count};
    }
#else
    const auto next_index = thread_wait.sleep();
    buffer_handled++;

    auto buffer_missed = buffer_transfered - buffer_handled;
    shared_memory.m4_buffer_missed = buffer_missed;

    if (next_index >= 0) {
        const size_t free_index = (next_index + transfers_per_buffer - 2) & transfers_mask;
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        /* The p11 lease is deliberately RX-only; every LLI writes destaddr. */
        const auto p = lli_loop[free_index].destaddr;
#else
        const auto src = lli_loop[free_index].srcaddr;
        const auto dst = lli_loop[free_index].destaddr;
        const auto p = (src == reinterpret_cast<uint32_t>(&LPC_SGPIO->REG_SS[0])) ? dst : src;
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
        return {
            reinterpret_cast<sample_t*>(p),
            (lli_loop[free_index].control & 0xfffU) << 1U};
#else
        return {reinterpret_cast<sample_t*>(p), transfer_samples};
#endif
    } else {
        return {};
    }
#endif
}

} /* namespace dma */
} /* namespace baseband */
