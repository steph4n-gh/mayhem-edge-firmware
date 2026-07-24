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

#ifndef __BASEBAND_DMA_H__
#define __BASEBAND_DMA_H__

#include <cstddef>
#include <array>

#include "complex.hpp"
#include "baseband.hpp"

namespace baseband {
namespace dma {

#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
constexpr size_t buffer_samples = 4096U;
#else
constexpr size_t buffer_samples = 8192U;
#endif

void init();
void configure(
    baseband::sample_t* const buffer_base,
    const baseband::Direction direction);
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
bool configure_precision_rx_lease(
    baseband::sample_t* owned_base,
    baseband::sample_t* loan_base);
bool set_precision_rx_capture_geometry(bool capture);
void enable_precision_rx();
#endif
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
bool pause_precision_rx_rate_change();
bool resume_precision_rx_rate_change();
bool precision_rx_rate_pause_armed();
bool precision_rx_rate_paused();
bool precision_rx_dma_faulted_locked();
bool precision_rx_dma_faulted();
bool begin_precision_rx_rate_state_update();
void end_precision_rx_rate_state_update();
bool open_precision_rx_sgpio_gate_locked();
bool quiesce_precision_rx_for_shutdown();
void wake_precision_rx_worker_for_shutdown();
void stop_precision_rx_for_shutdown();
void release_buffer();
#endif

void enable(const baseband::Direction direction);
bool is_enabled();

void disable();

baseband::buffer_t wait_for_buffer();

} /* namespace dma */
} /* namespace baseband */

#endif /*__BASEBAND_DMA_H__*/
