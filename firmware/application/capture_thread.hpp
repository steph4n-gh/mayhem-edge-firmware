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

#ifndef __CAPTURE_THREAD_H__
#define __CAPTURE_THREAD_H__

#include "ch.h"

#include "event_m0.hpp"

#include "io.hpp"
#include "optional.hpp"

#include <cstdint>
#include <cstddef>
#include <utility>

class CaptureThread {
   public:
    CaptureThread(
        std::unique_ptr<stream::Writer> writer,
        size_t write_size,
        size_t buffer_count,
        std::function<void()> success_callback,
        std::function<void(File::Error)> error_callback,
        bool graceful_stop = false,
        PrecisionRxSnapshotRecord* precision_rx_final_report = nullptr);
    ~CaptureThread();

    CaptureThread(const CaptureThread&) = delete;
    CaptureThread(CaptureThread&&) = delete;
    CaptureThread& operator=(const CaptureThread&) = delete;
    CaptureThread& operator=(CaptureThread&&) = delete;

    const CaptureConfig& state() const {
        return config;
    }

    void stop();
    uint64_t file_bytes_written() const { return file_bytes_written_; }
    bool write_error() const { return write_error_; }
    uint32_t error_code() const { return error_code_; }
    bool started() const { return capture_started_; }
    bool done() const { return thread_done_; }
    bool worker_created() const { return thread != nullptr; }

   private:
    CaptureConfig config;
    std::unique_ptr<stream::Writer> writer;
    std::function<void()> success_callback;
    std::function<void(File::Error)> error_callback;
    const bool graceful_stop_{false};
    Thread* thread{nullptr};
    uint64_t file_bytes_written_{0};
    bool write_error_{false};
    uint32_t error_code_{0};
    bool volatile stop_requested_{false};
    bool volatile capture_started_{false};
    bool volatile capture_stopped_{false};
    bool volatile thread_done_{false};
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
    uint8_t* precision_spill_{nullptr};
#endif

    static msg_t static_fn(void* arg);

    bool claim_capture_stop();
    Optional<File::Error> run();
};

#endif /*__CAPTURE_THREAD_H__*/
