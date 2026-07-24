/*
 * Copyright (C) 2026 HackRF Edge contributors.
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

#ifndef __PRECISION_RX_DMA_COMPLETION_QUEUE_H__
#define __PRECISION_RX_DMA_COMPLETION_QUEUE_H__

#include <array>
#include <cstddef>
#include <cstdint>

namespace baseband {
namespace dma {

struct PrecisionRxDmaCompletion {
    std::size_t descriptor_index{};
    uint32_t completion_sequence{};
};

__attribute__((always_inline)) inline void precision_rx_dma_saturating_increment(
    uint32_t volatile& value) noexcept {
    if (value != UINT32_MAX) {
        ++value;
    }
}

inline bool precision_rx_dma_descriptor_reused(
    const uint32_t completion_sequence,
    const uint32_t claimed_sequence,
    const uint32_t safe_age) noexcept {
    return completion_sequence - claimed_sequence >= safe_age;
}

/*
 * The terminal-count ISR is the last deterministic point at which it can
 * gate the ring before the descriptor following the current completion can
 * begin overwriting an in-flight claim. Fail closed one completion before
 * the physical reuse age; merely recording the later reuse would allow the
 * worker to continue consuming memory while DMA overwrites it.
 */
inline bool precision_rx_dma_claim_too_late(
    const uint32_t completion_sequence,
    const uint32_t claimed_sequence,
    const uint32_t safe_age) noexcept {
    return safe_age <= 1U ||
           completion_sequence - claimed_sequence >= safe_age - 1U;
}

inline bool precision_rx_dma_in_flight_must_fail_close(
    const uint32_t completion_sequence,
    const uint32_t claimed_sequence,
    const uint32_t safe_age) noexcept {
    return precision_rx_dma_claim_too_late(
        completion_sequence, claimed_sequence, safe_age);
}

/*
 * This queue crosses a priority-1 fast ISR and an ordinary ChibiOS worker.
 * ChibiOS's system lock does not mask that ISR, so publication must not rely
 * on the kernel lock. A DMB gives the producer's entry write release ordering
 * before tail publication and the consumer acquire ordering after observing
 * that tail. The compiler-only host form lets the exact production helper be
 * exercised by unit tests without pulling target headers into them.
 */
inline void precision_rx_dma_queue_barrier() noexcept {
#if defined(__arm__)
    __asm__ volatile("dmb" ::: "memory");
#else
    __asm__ volatile("" ::: "memory");
#endif
}

/*
 * Fixed-storage, true single-producer/single-consumer FIFO. The fast DMA ISR
 * owns producer_sequence_ and the worker owns consumer_sequence_. A full
 * producer never edits consumer state or evicts an older descriptor: its
 * caller must fail closed because continuing would hide a scheduler overrun.
 * reset() is legal only after DMA has stopped and its fast IRQ is excluded.
 */
template <std::size_t Capacity>
class PrecisionRxDmaCompletionQueue {
   public:
    static_assert(Capacity > 0U, "DMA completion queue capacity must be positive");

    using Entry = PrecisionRxDmaCompletion;

    struct PushResult {
        bool accepted{};
    };

    static constexpr std::size_t capacity() noexcept {
        return Capacity;
    }

    bool empty() const noexcept {
        return producer_sequence_ == consumer_sequence_;
    }

    std::size_t size() const noexcept {
        const uint32_t producer = producer_sequence_;
        precision_rx_dma_queue_barrier();
        const uint32_t consumer = consumer_sequence_;
        const uint32_t depth = producer - consumer;
        return depth > Capacity ? Capacity : depth;
    }

    std::size_t high_water_mark() const noexcept {
        return high_water_mark_;
    }

    PushResult push(const Entry& entry) noexcept {
        const uint32_t producer = producer_sequence_;
        const uint32_t consumer = consumer_sequence_;
        if (producer - consumer >= Capacity)
            return {false};

        entries_[producer % Capacity] = entry;
        precision_rx_dma_queue_barrier();
        producer_sequence_ = producer + 1U;

        const uint32_t depth = producer + 1U - consumer;
        if (depth > high_water_mark_)
            high_water_mark_ = depth;
        return {true};
    }

    bool pop(Entry& entry) noexcept {
        const uint32_t consumer = consumer_sequence_;
        const uint32_t producer = producer_sequence_;
        if (producer == consumer) {
            return false;
        }

        precision_rx_dma_queue_barrier();
        entry = entries_[consumer % Capacity];
        precision_rx_dma_queue_barrier();
        consumer_sequence_ = consumer + 1U;
        return true;
    }

    bool peek(Entry& entry) const noexcept {
        const uint32_t consumer = consumer_sequence_;
        const uint32_t producer = producer_sequence_;
        if (producer == consumer)
            return false;

        precision_rx_dma_queue_barrier();
        entry = entries_[consumer % Capacity];
        return true;
    }

    void reset() noexcept {
        producer_sequence_ = 0U;
        consumer_sequence_ = 0U;
        high_water_mark_ = 0U;
        precision_rx_dma_queue_barrier();
    }

   private:
    std::array<Entry, Capacity> entries_{};
    uint32_t volatile producer_sequence_{};
    uint32_t volatile consumer_sequence_{};
    uint32_t volatile high_water_mark_{};
};

} /* namespace dma */
} /* namespace baseband */

#endif /*__PRECISION_RX_DMA_COMPLETION_QUEUE_H__*/
