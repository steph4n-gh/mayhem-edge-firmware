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

#ifndef __PRECISION_RX_DMA_LEASE_H__
#define __PRECISION_RX_DMA_LEASE_H__

#include <cstddef>
#include <cstdint>

namespace precision_rx {
namespace dma_lease {

enum class Geometry : uint8_t {
    Monitor,
    Capture,
};

constexpr size_t lli_count = 4U;
constexpr size_t owned_bytes = 8U * 1024U;
constexpr size_t loan_bytes = 8U * 1024U;
constexpr size_t loan_local_buffer_index = 8U;
constexpr size_t sample_bytes = 2U;
constexpr uint32_t capture_rate_limit_hz = 2'000'000U;

constexpr size_t monitor_ring_bytes = owned_bytes + loan_bytes;
constexpr size_t monitor_owned_lli_count = 2U;
constexpr size_t monitor_loan_lli_count = 2U;
constexpr size_t monitor_transfer_bytes = monitor_ring_bytes / lli_count;
constexpr size_t monitor_transfer_samples =
    monitor_transfer_bytes / sample_bytes;

constexpr size_t capture_ring_bytes = owned_bytes;
constexpr size_t capture_transfer_bytes = capture_ring_bytes / lli_count;
constexpr size_t capture_transfer_samples =
    capture_transfer_bytes / sample_bytes;

constexpr bool monitor_lli_uses_loan(const size_t lli_index) {
    return lli_index >= monitor_owned_lli_count && lli_index < lli_count;
}

constexpr size_t monitor_lli_offset(const size_t lli_index) {
    return (lli_index % monitor_owned_lli_count) * monitor_transfer_bytes;
}

constexpr size_t capture_lli_offset(const size_t lli_index) {
    return lli_index * capture_transfer_bytes;
}

constexpr size_t transfer_bytes(const Geometry geometry) {
    return geometry == Geometry::Capture
               ? capture_transfer_bytes
               : monitor_transfer_bytes;
}

constexpr size_t transfer_samples(const Geometry geometry) {
    return transfer_bytes(geometry) / sample_bytes;
}

constexpr bool capture_rate_allowed(const uint32_t sample_rate_hz) {
    return sample_rate_hz <= capture_rate_limit_hz;
}

constexpr bool transition_discards_old_block(
    const Geometry from,
    const Geometry to) {
    return from != to;
}

static_assert(lli_count == 4U);
static_assert(owned_bytes == 8192U);
static_assert(loan_bytes == 8192U);
static_assert(monitor_ring_bytes == 16384U);
static_assert(monitor_owned_lli_count + monitor_loan_lli_count == lli_count);
static_assert(monitor_transfer_bytes == 4096U);
static_assert(monitor_transfer_samples == 2048U);
static_assert(monitor_lli_offset(0U) == 0U);
static_assert(monitor_lli_offset(1U) == 4096U);
static_assert(monitor_lli_offset(2U) == 0U);
static_assert(monitor_lli_offset(3U) == 4096U);
static_assert(!monitor_lli_uses_loan(1U));
static_assert(monitor_lli_uses_loan(2U));
static_assert(capture_ring_bytes == 8192U);
static_assert(capture_transfer_bytes == 2048U);
static_assert(capture_transfer_samples == 1024U);
static_assert(capture_lli_offset(3U) + capture_transfer_bytes ==
              capture_ring_bytes);
static_assert(capture_rate_allowed(2'000'000U));
static_assert(!capture_rate_allowed(2'000'001U));
static_assert(transition_discards_old_block(
    Geometry::Monitor, Geometry::Capture));

}  // namespace dma_lease
}  // namespace precision_rx

#endif /*__PRECISION_RX_DMA_LEASE_H__*/
