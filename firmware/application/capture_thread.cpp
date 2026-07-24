/*
 * Copyright (C) 2016 Jared Boone, ShareBrained Technology, Inc.
 * Modified for HackRF Edge in 2026 by HackRF Edge contributors.
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

#include "capture_thread.hpp"

#include "baseband_api.hpp"
#include "buffer_exchange.hpp"
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
#include "precision_rx_evidence.hpp"
#endif
#if defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC)
#include "hal.h"
#endif

#include <cstring>

#if defined(__arm__)
static_assert(sizeof(CaptureThread) == 0xd8U);
#endif

#if defined(__arm__) && defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC)
/* Absolute linked metadata for the p9/p10 M0 allocation verifier. */
__asm__(
    ".global hackrf_edge_precision_rx_app_local_buffer_count\n"
    ".type hackrf_edge_precision_rx_app_local_buffer_count, %object\n"
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
    ".set hackrf_edge_precision_rx_app_local_buffer_count, 9\n"
#else
    ".set hackrf_edge_precision_rx_app_local_buffer_count, 8\n"
#endif
    ".size hackrf_edge_precision_rx_app_local_buffer_count, 1\n"
    ".global hackrf_edge_precision_rx_app_spill_buffer_count\n"
    ".type hackrf_edge_precision_rx_app_spill_buffer_count, %object\n"
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
    ".set hackrf_edge_precision_rx_app_spill_buffer_count, 2\n"
#else
    ".set hackrf_edge_precision_rx_app_spill_buffer_count, 3\n"
#endif
    ".size hackrf_edge_precision_rx_app_spill_buffer_count, 1\n"
    ".global hackrf_edge_precision_rx_app_spill_bytes\n"
    ".type hackrf_edge_precision_rx_app_spill_bytes, %object\n"
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
    ".set hackrf_edge_precision_rx_app_spill_bytes, 16384\n"
#else
    ".set hackrf_edge_precision_rx_app_spill_bytes, 24576\n"
#endif
    ".size hackrf_edge_precision_rx_app_spill_bytes, 4\n"
    ".global hackrf_edge_precision_rx_app_thread_stack_bytes\n"
    ".type hackrf_edge_precision_rx_app_thread_stack_bytes, %object\n"
    ".set hackrf_edge_precision_rx_app_thread_stack_bytes, 1024\n"
    ".size hackrf_edge_precision_rx_app_thread_stack_bytes, 4\n"
    ".global hackrf_edge_precision_rx_app_capture_config_bytes\n"
    ".type hackrf_edge_precision_rx_app_capture_config_bytes, %object\n"
    ".set hackrf_edge_precision_rx_app_capture_config_bytes, 144\n"
    ".size hackrf_edge_precision_rx_app_capture_config_bytes, 4\n"
    ".global hackrf_edge_precision_rx_app_capture_thread_bytes\n"
    ".type hackrf_edge_precision_rx_app_capture_thread_bytes, %object\n"
    ".set hackrf_edge_precision_rx_app_capture_thread_bytes, 216\n"
    ".size hackrf_edge_precision_rx_app_capture_thread_bytes, 4\n"
#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    ".global hackrf_edge_precision_rx_app_dma_abort_requires_consumer_release\n"
    ".type hackrf_edge_precision_rx_app_dma_abort_requires_consumer_release, %object\n"
    ".set hackrf_edge_precision_rx_app_dma_abort_requires_consumer_release, 1\n"
    ".size hackrf_edge_precision_rx_app_dma_abort_requires_consumer_release, 1\n"
#endif
);
#endif

#if defined(__arm__) && \
    defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
/*
 * Keep the cross-core ownership release as a stable linked function.  The
 * application ELF gate verifies both its zero-byte store/DMB sequence and
 * that BufferExchange::~BufferExchange() is called first on the same path.
 */
extern "C" __attribute__((noinline, noclone, used, optimize("Os")))
void hackrf_edge_precision_rx_publish_dma_consumer_release(
    bool volatile* const consumer_owned) {
    unsigned zero;
    __asm__ volatile(
        "dmb\n\t"
        "movs %0, #0\n\t"
        "strb %0, [%1]\n\t"
        "dmb\n\t"
        : "=&l"(zero)
        : "l"(consumer_owned)
        : "memory");
}
#endif

// CaptureThread //////////////////////////////////////////////////////////

CaptureThread::CaptureThread(
    std::unique_ptr<stream::Writer> writer,
    size_t write_size,
    size_t buffer_count,
    std::function<void()> success_callback,
    std::function<void(File::Error)> error_callback,
    bool graceful_stop,
    PrecisionRxSnapshotRecord* precision_rx_final_report)
    : config{write_size, buffer_count, precision_rx_final_report},
      writer{std::move(writer)},
      success_callback{std::move(success_callback)},
      error_callback{std::move(error_callback)},
      graceful_stop_{graceful_stop} {
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
    if (precision_rx_final_report != nullptr) {
        if (write_size != precision_rx::capture_write_size ||
            buffer_count != precision_rx::capture_buffer_count)
            return;
#if defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC)
        constexpr size_t spill_bytes =
            precision_rx::capture_spill_stream_bytes;
#if defined(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
        static_assert(spill_bytes == 16U * 1024U);
#else
        static_assert(spill_bytes == 24U * 1024U);
#endif
        precision_spill_ =
            static_cast<uint8_t*>(chHeapAlloc(nullptr, spill_bytes));
        if (!precision_spill_)
            return;
        config.supplemental_buffer_count =
            precision_rx::capture_spill_buffer_count;
        config.precision_rx_evidence.supplemental_buffer_data =
            precision_spill_;
        /* Publish the shared-SRAM loan before the worker can send OPEN. */
        __DMB();
#else
        precision_spill_ =
            static_cast<uint8_t*>(chHeapAlloc(
                nullptr, precision_rx::capture_write_size));
        if (!precision_spill_)
            return;
#endif
    }
#endif
    // Need significant stack for FATFS
    thread = chThdCreateFromHeap(NULL, 1024, NORMALPRIO + 10, CaptureThread::static_fn, this);
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
    if (!thread && precision_spill_) {
        config.supplemental_buffer_count = 0;
        config.precision_rx_evidence.supplemental_buffer_data = nullptr;
        chHeapFree(precision_spill_);
        precision_spill_ = nullptr;
    }
#endif
}

CaptureThread::~CaptureThread() {
    stop();
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
    if (precision_spill_) {
        config.supplemental_buffer_count = 0;
        config.precision_rx_evidence.supplemental_buffer_data = nullptr;
        chHeapFree(precision_spill_);
        precision_spill_ = nullptr;
    }
#endif
}

void CaptureThread::stop() {
    if (thread) {
        if (!graceful_stop_) {
            chThdTerminate(thread);
            chThdWait(thread);
            thread = nullptr;
            return;
        }
        stop_requested_ = true;
        while (!capture_started_ && !thread_done_) {
            chThdYield();
        }
        if (capture_started_ && claim_capture_stop()) {
            baseband::capture_stop(true);
        }
        chThdWait(thread);
        thread = nullptr;
    }
}

msg_t CaptureThread::static_fn(void* arg) {
    auto obj = static_cast<CaptureThread*>(arg);
    const auto error = obj->run();
    obj->write_error_ = error.is_valid();
    obj->error_code_ = error.is_valid() ? error.value().code() : 0;
    obj->thread_done_ = true;
    if (error.is_valid() && obj->error_callback) {
        obj->error_callback(error.value());
    } else {
        if (obj->success_callback) {
            obj->success_callback();
        }
    }
    return 0;
}

Optional<File::Error> CaptureThread::run() {
    /* Release all CaptureConfig and spill-buffer publication before OPEN. */
    __DMB();
    baseband::capture_start(&config);
    if (!config.baseband_open_succeeded) {
        return File::Error{FR_UNEXPECTED};
    }
    capture_started_ = true;
#if defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC)
    const bool sd_timing_diagnostic =
        config.precision_rx_final_report != nullptr;
    if (sd_timing_diagnostic) {
        sdc_lld_capture_timing_begin();
    }
#endif
    Optional<File::Error> run_error{};
    {
        /*
         * BufferExchange must unregister its ISR-visible FIFO pointers before
         * any processor receives CaptureConfig(nullptr) and frees StreamInput.
         * This preserves the destruction order of the former RAII capture
         * guard for all legacy CaptureThread users.
         */
        BufferExchange buffers{&config};
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
        /*
         * The first producer-risk interval starts when the exchange becomes
         * live.  Omitting it would hide a slow first card-ready/write cycle.
         */
        uint32_t prior_recycle_tick = halGetCounterValue();
#endif

        while (true) {
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
            const bool precision_capture = precision_spill_ != nullptr;
#if defined(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC)
            constexpr bool stage_copy = false;
#else
            const bool stage_copy = precision_capture;
#endif
            uint32_t pre_ready_ticks = 0U;
            uint32_t fifo_depth = 0U;
            if (precision_capture) {
                fifo_depth = buffers.queued();
                const uint32_t pre_ready_start = halGetCounterValue();
                const bool_t ready_result =
                    sdc_lld_capture_wait_ready(&SDCD1);
                pre_ready_ticks =
                    halGetCounterValue() - pre_ready_start;
                if (ready_result == CH_FAILED) {
                    sdc_lld_capture_timing_record_cycle(
                        pre_ready_ticks, 0U, fifo_depth);
                    config.application_abort_requested = true;
                    __DMB();
                    run_error = File::Error{FR_DISK_ERR};
                    break;
                }
                const uint32_t ready_fifo_depth = buffers.queued();
                if (ready_fifo_depth > fifo_depth)
                    fifo_depth = ready_fifo_depth;
            }
#else
            constexpr bool stage_copy = false;
#endif
            auto buffer = buffers.get();
#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
            if (!buffer) {
                /*
                 * P12 fatal-DMA cancellation: M4 published abort+sealed and
                 * woke this consumer without transferring a descriptor.
                 */
                run_error = File::Error{FR_UNEXPECTED};
                break;
            }
#endif
            const size_t buffer_size = buffer->size();
            const bool terminal_buffer =
                graceful_stop_ && buffer_size == 0U;
#if defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC) && \
    !defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
            const uint32_t write_start =
                sd_timing_diagnostic ? halGetCounterValue() : 0U;
#endif

            const void* write_data = buffer->data();
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
            if (precision_capture && buffer_size > config.write_size) {
                sdc_lld_capture_timing_record_cycle(
                    pre_ready_ticks, 0U, fifo_depth);
                config.application_abort_requested = true;
                __DMB();
                run_error = File::Error{FR_UNEXPECTED};
                break;
            }
            if (precision_capture && terminal_buffer) {
                buffer->empty();
                if (!buffers.put(buffer)) {
                    sdc_lld_capture_timing_record_cycle(
                        pre_ready_ticks, 0U, fifo_depth);
                    config.application_abort_requested = true;
                    __DMB();
                    run_error = File::Error{FR_UNEXPECTED};
                    break;
                }
                const uint32_t recycle_tick = halGetCounterValue();
                const uint32_t recycle_gap =
                    recycle_tick - prior_recycle_tick;
                prior_recycle_tick = recycle_tick;
                sdc_lld_capture_timing_record_cycle(
                    pre_ready_ticks, recycle_gap, fifo_depth);
                break;
            }
            if (stage_copy) {
                if (buffer_size != 0U)
                    memcpy(precision_spill_, buffer->data(), buffer_size);
                __DMB();
                buffer->empty();
                if (!buffers.put(buffer)) {
                    sdc_lld_capture_timing_record_cycle(
                        pre_ready_ticks, 0U, fifo_depth);
                    config.application_abort_requested = true;
                    __DMB();
                    run_error = File::Error{FR_UNEXPECTED};
                    break;
                }
                buffer = nullptr;
                write_data = precision_spill_;
                const uint32_t recycle_tick = halGetCounterValue();
                const uint32_t recycle_gap =
                    recycle_tick - prior_recycle_tick;
                prior_recycle_tick = recycle_tick;
                sdc_lld_capture_timing_record_cycle(
                    pre_ready_ticks, recycle_gap, fifo_depth);
            }
#endif

            auto write_result = writer->write(write_data, buffer_size);
#if defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC) && \
    !defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
            if (sd_timing_diagnostic) {
                sdc_lld_capture_timing_record_write(
                    halGetCounterValue() - write_start);
            }
#endif
            if (write_result.is_error()) {
                run_error = write_result.error();
            } else if (write_result.value() != buffer_size) {
                run_error = File::Error{FR_UNEXPECTED};
            }
            if (run_error.is_valid()) {
                /* Fail closed before returning any descriptor capacity. */
                config.application_abort_requested = true;
                __DMB();
                break;
            }
            file_bytes_written_ += write_result.value();
            if (!stage_copy) {
                buffer->empty();
                if (!buffers.put(buffer)) {
                    config.application_abort_requested = true;
                    __DMB();
                    run_error = File::Error{FR_UNEXPECTED};
                    break;
                }
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
                if (precision_capture) {
                    const uint32_t recycle_tick = halGetCounterValue();
                    const uint32_t recycle_gap =
                        recycle_tick - prior_recycle_tick;
                    prior_recycle_tick = recycle_tick;
                    sdc_lld_capture_timing_record_cycle(
                        pre_ready_ticks, recycle_gap, fifo_depth);
                }
#endif
            }
            if (!graceful_stop_ && chThdShouldTerminate()) {
                break;
            }
            if (terminal_buffer) {
                break;
            }
        }
    }

#if defined(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
    /* Prove BufferExchange no longer retains any capture descriptor. */
#if defined(__arm__)
    hackrf_edge_precision_rx_publish_dma_consumer_release(
        &config.baseband_open_succeeded);
#else
    config.baseband_open_succeeded = false;
    __DMB();
#endif
#endif

    if (claim_capture_stop()) {
        baseband::capture_stop(false);
    }
#if defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC)
    if (sd_timing_diagnostic) {
        const auto* const timing = sdc_lld_capture_timing_end();
        auto& evidence = config.precision_rx_evidence;

        /*
         * The M4 is stopped, so publish one final M0-owned seqlock update.
         * PRX1 keeps its v1 ABI: its eight RF aggregate words carry raw
         * uint32_t timing evidence in this hash-identified diagnostic image.
         * The 16-second capture limit keeps cumulative counter ticks below
         * uint32_t wrap for every qualified M0 clock below 268 MHz.
         */
        ++evidence.update_sequence;
        __DMB();
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
        evidence.minimum_rms_dbfs_x10 = timing->recycle_gap_total_ticks;
        evidence.minimum_robust_rms_dbfs_x10 = timing->recycle_gap_max_ticks;
        evidence.maximum_robust_rms_dbfs_x10 = timing->pre_ready_total_ticks;
        evidence.maximum_peak_dbfs_x10 = timing->pre_ready_max_ticks;
        evidence.minimum_carrier_mod_hz_x10 =
            timing->residual_ready_max_ticks;
        evidence.maximum_carrier_mod_hz_x10 = timing->transfer_max_ticks;
        evidence.minimum_coherence_ppm = timing->packed_counts;
#else
        evidence.minimum_rms_dbfs_x10 = timing->writer_total_ticks;
        evidence.minimum_robust_rms_dbfs_x10 = timing->writer_max_ticks;
        evidence.maximum_robust_rms_dbfs_x10 = timing->ready_total_ticks;
        evidence.maximum_peak_dbfs_x10 = timing->ready_max_ticks;
        evidence.minimum_carrier_mod_hz_x10 = timing->transfer_total_ticks;
        evidence.maximum_carrier_mod_hz_x10 = timing->transfer_max_ticks;
        evidence.minimum_coherence_ppm = timing->transaction_count;
#endif
        evidence.valid_carrier_report_count = timing->counter_frequency_hz;
        __DMB();
        ++evidence.update_sequence;
    }
#endif
    if (run_error.is_valid()) {
        return run_error;
    }
    return writer->sync();
}

bool CaptureThread::claim_capture_stop() {
    chSysLock();
    const bool claimed = !capture_stopped_;
    capture_stopped_ = true;
    chSysUnlock();
    return claimed;
}
