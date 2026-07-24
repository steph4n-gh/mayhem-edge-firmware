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

#include "stream_input.hpp"
#include "precision_rx_evidence.hpp"
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
#include "precision_rx_dma_lease.hpp"
#endif

#include "doctest.h"

#include <array>
#include <cstdint>
#include <cstring>

namespace {

StreamBuffer* take_full(CaptureConfig& config) {
    StreamBuffer* buffer = nullptr;
    REQUIRE(config.fifo_buffers_full != nullptr);
    REQUIRE(config.fifo_buffers_full->out(buffer));
    REQUIRE(buffer != nullptr);
    return buffer;
}

void recycle(CaptureConfig& config, StreamBuffer* buffer) {
    REQUIRE(buffer != nullptr);
    buffer->empty();
    REQUIRE(config.fifo_buffers_empty != nullptr);
    REQUIRE(config.fifo_buffers_empty->in(buffer));
}

template <size_t Size>
void attach_supplemental(
    CaptureConfig& config,
    std::array<uint8_t, Size>& storage) {
    if constexpr (Size != 0U) {
        config.supplemental_buffer_count =
            static_cast<uint8_t>(Size / config.write_size);
        config.precision_rx_evidence.supplemental_buffer_data = storage.data();
    }
}

}  // namespace

TEST_CASE("StreamInput rebind separates preparation from open acknowledgement") {
    constexpr size_t write_size = 16;
    constexpr size_t buffer_count = 2;
    StreamInput stream{write_size, buffer_count};
    CaptureConfig config{write_size, buffer_count};

    REQUIRE(stream.rebind(&config));
    CHECK_FALSE(config.baseband_open_succeeded);
    REQUIRE(config.fifo_buffers_empty != nullptr);
    REQUIRE(config.fifo_buffers_full != nullptr);
    CHECK(config.fifo_buffers_empty->len() == buffer_count);
    CHECK(config.fifo_buffers_full->is_empty());

    REQUIRE(stream.acknowledge_open());
    CHECK(config.baseband_open_succeeded);
}

TEST_CASE("StreamInput legacy constructor wraps uninitialized FIFO backing safely") {
    constexpr size_t write_size = 4;
    constexpr size_t buffer_count = 2;
    CaptureConfig config{write_size, buffer_count};
    StreamInput stream{&config};
    REQUIRE(config.baseband_open_succeeded);

    for (size_t sequence = 0; sequence < 40; ++sequence) {
        const std::array<uint8_t, write_size> payload{{
            static_cast<uint8_t>(sequence),
            static_cast<uint8_t>(sequence + 1U),
            static_cast<uint8_t>(sequence + 2U),
            static_cast<uint8_t>(sequence + 3U)}};
        REQUIRE(stream.write(payload.data(), payload.size()) == payload.size());
        StreamBuffer* const full = take_full(config);
        CHECK(full->size() == payload.size());
        CHECK(std::memcmp(full->data(), payload.data(), payload.size()) == 0);
        recycle(config, full);
    }

    REQUIRE(stream.seal());
    StreamBuffer* const terminal = take_full(config);
    CHECK(terminal->size() == 0U);
    recycle(config, terminal);
    CHECK(stream.drained());
}

TEST_CASE("StreamInput retains storage and clears stale buffer state on rebind") {
    constexpr size_t write_size = 16;
    constexpr size_t buffer_count = 2;
    StreamInput stream{write_size, buffer_count};
    CaptureConfig first{write_size, buffer_count};
    REQUIRE(stream.rebind(&first));
    REQUIRE(stream.acknowledge_open());

    std::array<uint8_t, write_size> old_payload{};
    old_payload.fill(0xa5);
    REQUIRE(stream.write(old_payload.data(), old_payload.size()) ==
            old_payload.size());
    StreamBuffer* old_buffer = take_full(first);
    const void* const retained_address = old_buffer->data();
    CHECK(old_buffer->size() == old_payload.size());
    CHECK(std::memcmp(old_buffer->data(), old_payload.data(), old_payload.size()) == 0);
    recycle(first, old_buffer);

    CaptureConfig second{write_size, buffer_count};
    REQUIRE(stream.rebind(&second));
    CHECK_FALSE(second.baseband_open_succeeded);
    REQUIRE(stream.acknowledge_open());

    const std::array<uint8_t, 3> new_payload{{0x11, 0x22, 0x33}};
    REQUIRE(stream.write(new_payload.data(), new_payload.size()) ==
            new_payload.size());
    CHECK_FALSE(stream.seal());
    CHECK_FALSE(second.baseband_producer_sealed);
    StreamBuffer* partial = take_full(second);
    CHECK(partial->data() == retained_address);
    CHECK(partial->size() == new_payload.size());
    CHECK(std::memcmp(partial->data(), new_payload.data(), new_payload.size()) == 0);
    const auto* retained_bytes = static_cast<const uint8_t*>(partial->data());
    for (size_t index = new_payload.size(); index < write_size; ++index) {
        CHECK(retained_bytes[index] == 0xa5);
    }
    recycle(second, partial);
    REQUIRE(stream.seal());
    StreamBuffer* const terminal = take_full(second);
    CHECK(terminal->size() == 0U);
    recycle(second, terminal);
    CHECK(stream.drained());
}

TEST_CASE("StreamInput rebind discards aborted full and partial state") {
    constexpr size_t write_size = 16;
    constexpr size_t buffer_count = 2;
    StreamInput stream{write_size, buffer_count};
    CaptureConfig aborted{write_size, buffer_count};
    REQUIRE(stream.rebind(&aborted));
    REQUIRE(stream.acknowledge_open());

    std::array<uint8_t, write_size + 5> old_payload{};
    old_payload.fill(0xcc);
    REQUIRE(stream.write(old_payload.data(), old_payload.size()) ==
            old_payload.size());
    CHECK(aborted.fifo_buffers_full->len() == 1);
    CHECK(aborted.fifo_buffers_empty->is_empty());
    aborted.baseband_bytes_received = 1234;
    aborted.baseband_bytes_dropped = 56;
    aborted.baseband_producer_sealed = true;
    aborted.application_abort_requested = true;

    CaptureConfig clean{write_size, buffer_count};
    REQUIRE(stream.rebind(&clean));
    CHECK_FALSE(clean.baseband_open_succeeded);
    CHECK(clean.baseband_bytes_received == 0);
    CHECK(clean.baseband_bytes_dropped == 0);
    CHECK_FALSE(clean.baseband_producer_sealed);
    CHECK_FALSE(clean.application_abort_requested);
    CHECK(clean.fifo_buffers_empty->len() == buffer_count);
    CHECK(clean.fifo_buffers_full->is_empty());
    REQUIRE(stream.acknowledge_open());

    const std::array<uint8_t, 3> new_payload{{0x31, 0x32, 0x33}};
    REQUIRE(stream.write(new_payload.data(), new_payload.size()) ==
            new_payload.size());
    CHECK_FALSE(stream.seal());
    StreamBuffer* partial = take_full(clean);
    CHECK(partial->size() == new_payload.size());
    CHECK(std::memcmp(partial->data(), new_payload.data(), new_payload.size()) == 0);
    recycle(clean, partial);
    REQUIRE(stream.seal());
    StreamBuffer* const terminal = take_full(clean);
    CHECK(terminal->size() == 0U);
    recycle(clean, terminal);
    CHECK(stream.drained());
}

#if STREAM_INPUT_BUFFER_COUNT_MAX_LOG2 == 4
TEST_CASE("StreamInput max-capacity rebind ignores every stale FIFO backing slot") {
    constexpr size_t write_size = 16;
    constexpr size_t buffer_count = 16;
    StreamInput stream{write_size, buffer_count};
    CaptureConfig aborted{write_size, buffer_count};
    REQUIRE(stream.rebind(&aborted));
    REQUIRE(stream.acknowledge_open());

    std::array<uint8_t, write_size * buffer_count> old_payload{};
    old_payload.fill(0xcc);
    REQUIRE(stream.write(old_payload.data(), old_payload.size()) ==
            old_payload.size());
    CHECK(aborted.fifo_buffers_full->len() == buffer_count);
    CHECK(aborted.fifo_buffers_empty->is_empty());

    CaptureConfig clean{write_size, buffer_count};
    REQUIRE(stream.rebind(&clean));
    CHECK(clean.fifo_buffers_empty->len() == buffer_count);
    CHECK(clean.fifo_buffers_full->is_empty());
    REQUIRE(stream.acknowledge_open());

    const std::array<uint8_t, 3> new_payload{{0x31, 0x32, 0x33}};
    REQUIRE(stream.write(new_payload.data(), new_payload.size()) ==
            new_payload.size());
    CHECK_FALSE(stream.seal());
    StreamBuffer* partial = take_full(clean);
    CHECK(partial->size() == new_payload.size());
    CHECK(std::memcmp(partial->data(), new_payload.data(), new_payload.size()) == 0);
    recycle(clean, partial);
    REQUIRE(stream.seal());
    StreamBuffer* const terminal = take_full(clean);
    CHECK(terminal->size() == 0U);
    recycle(clean, terminal);
    CHECK(stream.drained());
}
#endif

TEST_CASE("StreamInput repeatedly reuses one allocation across clean and aborted captures") {
    constexpr size_t write_size = 16;
    constexpr size_t buffer_count = 2;
    StreamInput stream{write_size, buffer_count};

    for (size_t attempt = 0; attempt < 64; ++attempt) {
        CaptureConfig config{write_size, buffer_count};
        REQUIRE(stream.rebind(&config));
        REQUIRE(stream.acknowledge_open());

        std::array<uint8_t, write_size * buffer_count + 1> payload{};
        payload.fill(static_cast<uint8_t>(attempt));
        if ((attempt % 3) == 0) {
            CHECK(stream.write(payload.data(), payload.size()) ==
                  write_size * buffer_count);
            CHECK(stream.write(payload.data(), 1) == 0);
            continue;
        }

        const size_t length = 1 + (attempt % (write_size - 1));
        REQUIRE(stream.write(payload.data(), length) == length);
        CHECK_FALSE(stream.seal());
        StreamBuffer* partial = take_full(config);
        CHECK(partial->size() == length);
        CHECK(std::memcmp(partial->data(), payload.data(), length) == 0);
        recycle(config, partial);
        REQUIRE(stream.seal());
        StreamBuffer* const terminal = take_full(config);
        CHECK(terminal->size() == 0U);
        recycle(config, terminal);
        CHECK(stream.drained());
    }
}

TEST_CASE("StreamInput rebind after FIFO wrap discards queued and active state") {
    constexpr size_t write_size = 4;
    constexpr size_t buffer_count = 2;
    StreamInput stream{write_size, buffer_count};
    CaptureConfig first{write_size, buffer_count};
    REQUIRE(stream.rebind(&first));
    REQUIRE(stream.acknowledge_open());

    for (size_t sequence = 0; sequence < 40; ++sequence) {
        const std::array<uint8_t, write_size> payload{{
            static_cast<uint8_t>(sequence), 0xa1, 0xb2, 0xc3}};
        REQUIRE(stream.write(payload.data(), payload.size()) == payload.size());
        StreamBuffer* const full = take_full(first);
        CHECK(std::memcmp(full->data(), payload.data(), payload.size()) == 0);
        recycle(first, full);
    }

    const std::array<uint8_t, 6> abandoned{{1, 2, 3, 4, 5, 6}};
    REQUIRE(stream.write(abandoned.data(), abandoned.size()) == abandoned.size());
    CHECK(first.fifo_buffers_full->len() == 1U);
    CHECK(first.fifo_buffers_empty->is_empty());

    CaptureConfig second{write_size, buffer_count};
    REQUIRE(stream.rebind(&second));
    CHECK(second.fifo_buffers_empty->len() == buffer_count);
    CHECK(second.fifo_buffers_full->is_empty());
    REQUIRE(stream.acknowledge_open());

    const std::array<uint8_t, write_size * buffer_count> replacement{{
        0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23}};
    REQUIRE(stream.write(replacement.data(), replacement.size()) ==
            replacement.size());
    StreamBuffer* const first_full = take_full(second);
    StreamBuffer* const second_full = take_full(second);
    CHECK(first_full != second_full);
    CHECK(std::memcmp(first_full->data(), replacement.data(), write_size) == 0);
    CHECK(std::memcmp(
              second_full->data(),
              replacement.data() + write_size,
              write_size) == 0);
    recycle(second, first_full);
    recycle(second, second_full);

    REQUIRE(stream.seal());
    StreamBuffer* const terminal = take_full(second);
    CHECK(terminal->size() == 0U);
    recycle(second, terminal);
    CHECK(stream.drained());
}

TEST_CASE("StreamInput rejects mismatched reusable geometry") {
    StreamInput stream{16, 2};
    CaptureConfig wrong_write_size{8, 2};
    CaptureConfig wrong_buffer_count{16, 1};
    CaptureConfig missing_supplemental{16, 2};
    CaptureConfig misaligned_supplemental{16, 2};
    alignas(uint32_t) std::array<uint8_t, 17> misaligned_storage{};
    missing_supplemental.supplemental_buffer_count = 1;
    misaligned_supplemental.supplemental_buffer_count = 1;
    misaligned_supplemental.precision_rx_evidence.supplemental_buffer_data =
        misaligned_storage.data() + 1U;

    CHECK_FALSE(stream.rebind(&wrong_write_size));
    CHECK_FALSE(wrong_write_size.baseband_open_succeeded);
    CHECK(wrong_write_size.fifo_buffers_empty == nullptr);
    CHECK(wrong_write_size.fifo_buffers_full == nullptr);
    CHECK_FALSE(stream.acknowledge_open());

    CHECK_FALSE(stream.rebind(&wrong_buffer_count));
    CHECK_FALSE(wrong_buffer_count.baseband_open_succeeded);
    CHECK(wrong_buffer_count.fifo_buffers_empty == nullptr);
    CHECK(wrong_buffer_count.fifo_buffers_full == nullptr);
    CHECK_FALSE(stream.acknowledge_open());

    CHECK_FALSE(stream.rebind(&missing_supplemental));
    CHECK_FALSE(missing_supplemental.baseband_open_succeeded);
    CHECK(missing_supplemental.fifo_buffers_empty == nullptr);
    CHECK(missing_supplemental.fifo_buffers_full == nullptr);
    CHECK_FALSE(stream.acknowledge_open());

    CHECK_FALSE(stream.rebind(&misaligned_supplemental));
    CHECK_FALSE(misaligned_supplemental.baseband_open_succeeded);
    CHECK(misaligned_supplemental.fifo_buffers_empty == nullptr);
    CHECK(misaligned_supplemental.fifo_buffers_full == nullptr);
    CHECK_FALSE(stream.acknowledge_open());

    CaptureConfig valid{16, 2};
    REQUIRE(stream.rebind(&valid));
    REQUIRE(stream.acknowledge_open());
    const std::array<uint8_t, 3> payload{{0x41, 0x42, 0x43}};
    REQUIRE(stream.write(payload.data(), payload.size()) == payload.size());
    CHECK_FALSE(stream.seal());
    StreamBuffer* const partial = take_full(valid);
    CHECK(partial->size() == payload.size());
    CHECK(std::memcmp(partial->data(), payload.data(), payload.size()) == 0);
    recycle(valid, partial);
    REQUIRE(stream.seal());
    StreamBuffer* const terminal = take_full(valid);
    CHECK(terminal->size() == 0U);
    recycle(valid, terminal);
    CHECK(stream.drained());
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
TEST_CASE("StreamInput exact write rejects without counter or FIFO mutation") {
    constexpr size_t write_size = 16;
    constexpr size_t buffer_count = 4;
    constexpr size_t reserve = 2;
    StreamInput stream{write_size, buffer_count};
    CaptureConfig config{write_size, buffer_count};
    REQUIRE(stream.rebind(&config));
    REQUIRE(stream.acknowledge_open());

    std::array<uint8_t, write_size * 2 + 1> payload{};
    payload.fill(0x5a);
    CHECK_FALSE(
        stream.try_write_exact(payload.data(), payload.size(), reserve));
    CHECK(config.baseband_bytes_received == 0U);
    CHECK(config.baseband_bytes_dropped == 0U);
    CHECK(config.fifo_buffers_empty->len() == buffer_count);
    CHECK(config.fifo_buffers_full->is_empty());

    REQUIRE(stream.try_write_exact(
        payload.data(), write_size, reserve));
    REQUIRE(stream.try_write_exact(
        payload.data() + write_size, write_size, reserve));
    CHECK(config.baseband_bytes_received == write_size * 2);
    CHECK(config.baseband_bytes_dropped == 0U);
    CHECK(config.fifo_buffers_empty->len() == reserve);
    CHECK(config.fifo_buffers_full->len() == 2U);

    CHECK_FALSE(stream.try_write_exact(payload.data(), 1U, reserve));
    CHECK(config.baseband_bytes_received == write_size * 2);
    CHECK(config.baseband_bytes_dropped == 0U);
    CHECK(config.fifo_buffers_empty->len() == reserve);
    CHECK(config.fifo_buffers_full->len() == 2U);
}

TEST_CASE("StreamInput reserve-two partial close seals in two bounded calls") {
    constexpr size_t write_size = 16;
    constexpr size_t buffer_count = 4;
    constexpr size_t reserve = 2;
    const std::array<uint8_t, 5> payload{{1, 2, 3, 4, 5}};
    StreamInput stream{write_size, buffer_count};
    CaptureConfig config{write_size, buffer_count};
    REQUIRE(stream.rebind(&config));
    REQUIRE(stream.acknowledge_open());

    REQUIRE(stream.try_write_exact(payload.data(), payload.size(), reserve));
    CHECK(config.fifo_buffers_empty->len() == buffer_count - 1U);
    CHECK(config.fifo_buffers_full->is_empty());

    CHECK_FALSE(stream.seal());
    CHECK_FALSE(config.baseband_producer_sealed);
    REQUIRE(stream.seal());
    CHECK(config.baseband_producer_sealed);
    CHECK(config.fifo_buffers_empty->len() == buffer_count - 2U);
    CHECK(config.fifo_buffers_full->len() == 2U);

    StreamBuffer* const partial = take_full(config);
    CHECK(partial->size() == payload.size());
    CHECK(std::memcmp(partial->data(), payload.data(), payload.size()) == 0);
    recycle(config, partial);
    StreamBuffer* const terminal = take_full(config);
    CHECK(terminal->size() == 0U);
    recycle(config, terminal);
    CHECK(stream.drained());
}
#endif

#if STREAM_INPUT_BUFFER_COUNT_MAX_LOG2 == 4
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
TEST_CASE("Precision RX p11 plans discontiguous monitor and compact capture DMA") {
    namespace plan = precision_rx::dma_lease;
    CHECK(plan::owned_bytes == 8192U);
    CHECK(plan::loan_bytes == 8192U);
    CHECK(plan::monitor_ring_bytes == 16384U);
    CHECK(plan::monitor_transfer_bytes == 4096U);
    CHECK(plan::monitor_transfer_samples == 2048U);
    CHECK(plan::monitor_owned_lli_count == 2U);
    CHECK(plan::monitor_loan_lli_count == 2U);
    CHECK_FALSE(plan::monitor_lli_uses_loan(1U));
    CHECK(plan::monitor_lli_uses_loan(2U));
    CHECK(plan::monitor_lli_offset(1U) == 4096U);
    CHECK(plan::monitor_lli_offset(2U) == 0U);
    CHECK(plan::capture_ring_bytes == 8192U);
    CHECK(plan::capture_transfer_bytes == 2048U);
    CHECK(plan::capture_transfer_samples == 1024U);
    CHECK(plan::capture_rate_allowed(2'000'000U));
    CHECK_FALSE(plan::capture_rate_allowed(2'000'001U));
    CHECK(plan::transition_discards_old_block(
        plan::Geometry::Monitor, plan::Geometry::Capture));
}

TEST_CASE("Precision RX p11 loan exists only across a clean unbound lifecycle") {
    constexpr size_t write_size = precision_rx::capture_write_size;
    constexpr size_t local_count = precision_rx::capture_local_buffer_count;
    alignas(uint32_t) std::array<
        uint8_t,
        precision_rx::capture_spill_buffer_count * write_size> supplemental{};
    StreamInput stream{write_size, local_count};
    auto* const initial_loan = stream.dma_loan_buffer();
    REQUIRE(initial_loan != nullptr);

    CaptureConfig config{write_size, local_count};
    attach_supplemental(config, supplemental);
    REQUIRE(stream.rebind(&config));
    CHECK(stream.dma_loan_buffer() == nullptr);
    CHECK_FALSE(stream.unbind_if_drained());
    REQUIRE(stream.acknowledge_open());
    REQUIRE(stream.seal());
    StreamBuffer* const terminal = take_full(config);
    CHECK(terminal->size() == 0U);
    recycle(config, terminal);
    REQUIRE(stream.drained());
    REQUIRE(stream.unbind_if_drained());
    CHECK(stream.unbound());
    CHECK(stream.dma_loan_buffer() == initial_loan);
}

TEST_CASE("Precision RX p11 force-unbind is explicit for detached abort cleanup") {
    constexpr size_t write_size = precision_rx::capture_write_size;
    constexpr size_t local_count = precision_rx::capture_local_buffer_count;
    alignas(uint32_t) std::array<
        uint8_t,
        precision_rx::capture_spill_buffer_count * write_size> supplemental{};
    StreamInput stream{write_size, local_count};
    auto* const initial_loan = stream.dma_loan_buffer();
    CaptureConfig config{write_size, local_count};
    attach_supplemental(config, supplemental);
    REQUIRE(stream.rebind(&config));
    REQUIRE(stream.acknowledge_open());
    const std::array<uint8_t, 17U> partial{};
    REQUIRE(stream.write(partial.data(), partial.size()) == partial.size());
    CHECK_FALSE(stream.drained());
    config.application_abort_requested = true;
    CHECK_FALSE(stream.force_unbind_after_abort());
    config.baseband_open_succeeded = false;
    REQUIRE(stream.force_unbind_after_abort());
    CHECK(stream.unbound());
    CHECK(stream.dma_loan_buffer() == initial_loan);
}
#endif

TEST_CASE("Precision RX coalesces two producer quanta into one transfer block") {
    constexpr size_t producer_quantum =
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
        2U * 1024U;
#else
        4U * 1024U;
#endif
    constexpr size_t write_size = precision_rx::capture_write_size;
    constexpr size_t producer_blocks = write_size / producer_quantum;
    static_assert(write_size == producer_blocks * producer_quantum);

    constexpr size_t local_buffer_count =
        precision_rx::capture_local_buffer_count;
    alignas(uint32_t) std::array<
        uint8_t,
        precision_rx::capture_spill_buffer_count * write_size> supplemental{};
    StreamInput stream{write_size, local_buffer_count};
    CaptureConfig config{write_size, local_buffer_count};
    attach_supplemental(config, supplemental);
    REQUIRE(stream.rebind(&config));
    REQUIRE(stream.acknowledge_open());

    std::array<uint8_t, producer_quantum> quantum{};
    for (size_t sequence = 0; sequence < producer_blocks; ++sequence) {
        quantum.fill(static_cast<uint8_t>(0x20U + sequence));
        REQUIRE(stream.write(quantum.data(), quantum.size()) == quantum.size());
        CHECK(config.fifo_buffers_full->len() ==
              (sequence + 1U == producer_blocks ? 1U : 0U));
    }

    StreamBuffer* const full = take_full(config);
    REQUIRE(full->size() == write_size);
    const auto* const bytes = static_cast<const uint8_t*>(full->data());
    for (size_t sequence = 0; sequence < producer_blocks; ++sequence) {
        for (size_t offset = 0; offset < producer_quantum; ++offset) {
            CHECK(bytes[sequence * producer_quantum + offset] ==
                  static_cast<uint8_t>(0x20U + sequence));
        }
    }
    CHECK(config.baseband_bytes_received == write_size);
    CHECK(config.baseband_bytes_dropped == 0U);

    recycle(config, full);
    REQUIRE(stream.seal());
    StreamBuffer* const terminal = take_full(config);
    CHECK(terminal->size() == 0U);
    recycle(config, terminal);
    CHECK(stream.drained());
}

#if defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC)
TEST_CASE("Precision RX appends ordered M0-owned spill descriptors") {
    constexpr size_t write_size = precision_rx::capture_write_size;
    constexpr size_t local_buffer_count =
        precision_rx::capture_local_buffer_count;
    constexpr size_t buffer_count = precision_rx::capture_total_buffer_count;
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
    static_assert(local_buffer_count == 9U);
    static_assert(precision_rx::capture_spill_buffer_count == 2U);
#else
    static_assert(local_buffer_count == 8U);
    static_assert(precision_rx::capture_spill_buffer_count == 3U);
#endif
    static_assert(buffer_count == 11U);

    alignas(uint32_t) std::array<
        uint8_t,
        precision_rx::capture_spill_buffer_count * write_size> supplemental{};
    StreamInput stream{write_size, local_buffer_count};
    CaptureConfig config{write_size, local_buffer_count};
    attach_supplemental(config, supplemental);
    REQUIRE(stream.rebind(&config));
    REQUIRE(stream.acknowledge_open());

    std::array<uint8_t, write_size> quantum{};
    for (size_t sequence = 0; sequence < buffer_count; ++sequence) {
        quantum.fill(static_cast<uint8_t>(sequence));
        REQUIRE(stream.write(quantum.data(), quantum.size()) == quantum.size());
    }
    CHECK(config.fifo_buffers_full->len() == buffer_count);
    CHECK(config.fifo_buffers_empty->is_empty());

    for (size_t sequence = 0; sequence < buffer_count; ++sequence) {
        StreamBuffer* const full = take_full(config);
        REQUIRE(full->size() == write_size);
        const auto* const bytes = static_cast<const uint8_t*>(full->data());
        CHECK(bytes[0] == static_cast<uint8_t>(sequence));
        CHECK(bytes[write_size - 1U] == static_cast<uint8_t>(sequence));
        if (sequence >= local_buffer_count) {
            CHECK(
                full->data() ==
                supplemental.data() +
                    (sequence - local_buffer_count) * write_size);
        }
        recycle(config, full);
    }
    REQUIRE(stream.seal());
    StreamBuffer* const terminal = take_full(config);
    CHECK(terminal->size() == 0U);
    recycle(config, terminal);
    CHECK(stream.drained());
}
#endif

TEST_CASE("Precision RX geometry saturates only after every bound descriptor") {
    constexpr size_t write_size = precision_rx::capture_write_size;
    constexpr size_t buffer_count = precision_rx::capture_total_buffer_count;
    constexpr size_t local_buffer_count =
        precision_rx::capture_local_buffer_count;
    static_assert(write_size == 8U * 1024U);

    alignas(uint32_t) std::array<
        uint8_t,
        precision_rx::capture_spill_buffer_count * write_size> supplemental{};
    StreamInput stream{write_size, local_buffer_count};
    CaptureConfig config{write_size, local_buffer_count};
    attach_supplemental(config, supplemental);
    REQUIRE(stream.rebind(&config));
    REQUIRE(stream.acknowledge_open());

    std::array<uint8_t, write_size> quantum{};
    REQUIRE(stream.write(quantum.data(), quantum.size()) == quantum.size());
    StreamBuffer* const writer_held = take_full(config);

    for (size_t index = 0; index < buffer_count - 1U; ++index) {
        REQUIRE(stream.write(quantum.data(), quantum.size()) == quantum.size());
    }
    CHECK(config.fifo_buffers_full->len() == buffer_count - 1U);
    CHECK(config.fifo_buffers_empty->is_empty());

    CHECK(stream.write(quantum.data(), quantum.size()) == 0U);
    CHECK(config.baseband_bytes_received ==
          (buffer_count + 1U) * write_size);
    CHECK(config.baseband_bytes_dropped == write_size);

    /*
     * The writer-held buffer must return before seal can enqueue the empty
     * terminal wake sentinel behind the remaining complete data buffers.
     */
    CHECK_FALSE(stream.seal());
    CHECK_FALSE(config.baseband_producer_sealed);
    CHECK(config.fifo_buffers_full->len() == buffer_count - 1U);

    recycle(config, writer_held);
    REQUIRE(stream.seal());
    CHECK(config.baseband_producer_sealed);
    CHECK(config.fifo_buffers_full->len() == buffer_count);

    for (size_t index = 0; index < buffer_count - 1U; ++index) {
        StreamBuffer* const data_buffer = take_full(config);
        CHECK(data_buffer->size() == write_size);
        recycle(config, data_buffer);
    }
    StreamBuffer* const terminal_buffer = take_full(config);
    CHECK(terminal_buffer->size() == 0U);
    recycle(config, terminal_buffer);
    CHECK(stream.drained());
}

TEST_CASE("Precision RX saturated partial close appends sentinel in FIFO order") {
    constexpr size_t write_size = precision_rx::capture_write_size;
    constexpr size_t buffer_count = precision_rx::capture_total_buffer_count;
    constexpr size_t partial_size = 17U;

    constexpr size_t local_buffer_count =
        precision_rx::capture_local_buffer_count;
    alignas(uint32_t) std::array<
        uint8_t,
        precision_rx::capture_spill_buffer_count * write_size> supplemental{};
    StreamInput stream{write_size, local_buffer_count};
    CaptureConfig config{write_size, local_buffer_count};
    attach_supplemental(config, supplemental);
    REQUIRE(stream.rebind(&config));
    REQUIRE(stream.acknowledge_open());

    std::array<uint8_t, write_size> quantum{};
    REQUIRE(stream.write(quantum.data(), quantum.size()) == quantum.size());
    StreamBuffer* const writer_held = take_full(config);

    for (size_t index = 0; index < buffer_count - 2U; ++index) {
        REQUIRE(stream.write(quantum.data(), quantum.size()) == quantum.size());
    }
    const std::array<uint8_t, partial_size> partial_payload{{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}};
    REQUIRE(stream.write(partial_payload.data(), partial_payload.size()) ==
            partial_payload.size());
    CHECK(config.fifo_buffers_full->len() == buffer_count - 2U);
    CHECK(config.fifo_buffers_empty->is_empty());

    CHECK_FALSE(stream.seal());
    CHECK(config.fifo_buffers_full->len() == buffer_count - 1U);
    CHECK_FALSE(config.baseband_producer_sealed);
    CHECK_FALSE(stream.seal());

    recycle(config, writer_held);
    REQUIRE(stream.seal());
    CHECK(config.baseband_producer_sealed);
    CHECK(config.fifo_buffers_full->len() == buffer_count);

    for (size_t index = 0; index < buffer_count - 2U; ++index) {
        StreamBuffer* const full = take_full(config);
        CHECK(full->size() == write_size);
        recycle(config, full);
    }
    StreamBuffer* const partial = take_full(config);
    CHECK(partial->size() == partial_payload.size());
    CHECK(std::memcmp(
              partial->data(), partial_payload.data(), partial_payload.size()) == 0);
    recycle(config, partial);

    StreamBuffer* const terminal = take_full(config);
    CHECK(terminal->size() == 0U);
    recycle(config, terminal);
    CHECK(stream.drained());
}
#endif
