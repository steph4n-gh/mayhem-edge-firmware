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

#ifndef __PRECISION_RX_CAPTURE_WRITER_H__
#define __PRECISION_RX_CAPTURE_WRITER_H__

#include "io.hpp"
#include "precision_rx_evidence.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace precision_rx {

/*
 * p9 uses eight M4-owned and three M0-owned 8 KiB buffers; p10 moves one
 * descriptor to M4 and uses two M0 buffers. Both expose an eleven-descriptor,
 * 88 KiB cross-core pool. Each block is one two-descriptor SD transaction, and two writes span
 * one 16 KiB FAT cluster. The 16-second limit has an 18-second reservation
 * guard so UI/event latency cannot push the writer back into live FAT
 * allocation before capture stops.
 */
/* Eight SD sectors per scrub write in the normal confidentiality-safe path. */
constexpr size_t capture_scrub_write_size = 4U * 1024U;
#if defined(HACKRF_EDGE_SD_FAST_RESERVE_EXPERIMENT)
constexpr bool capture_metadata_only_reservation = true;
/* The metadata path has no 4 KiB stack scrub block. */
constexpr size_t preparation_thread_usable_stack_size = 2U * 1024U;
#else
constexpr bool capture_metadata_only_reservation = false;
/* Scrub storage plus 2 KiB of usable call-stack headroom. */
constexpr size_t preparation_thread_usable_stack_size =
    capture_scrub_write_size + 2U * 1024U;
#endif
constexpr size_t preparation_thread_working_area_size =
    THD_WA_SIZE(preparation_thread_usable_stack_size);
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
constexpr uint32_t capture_limit_seconds = capture_duration_seconds;
constexpr uint32_t capture_reserve_seconds = 18U;
#else
constexpr uint32_t capture_limit_seconds = 16U;
constexpr uint32_t capture_reserve_seconds = 18U;
constexpr uint32_t complex8_bytes_per_sample = 2U;
#endif

/* Compact, user-visible provenance for a failed SD preparation operation. */
enum class CapturePreparationStage : uint8_t {
    None = 0,
    Create = 1,
    Reserve = 2,
    Map = 3,
    Sync = 4,
    Rewind = 5,
    Rollback = 6,
    Worker = 7,
};

constexpr uint32_t capture_preparation_diagnostic(
    const CapturePreparationStage stage,
    const uint32_t error_code,
    const uint32_t detail = 0) {
    return static_cast<uint32_t>(stage) * 100'000'000U +
           (error_code < 1'000U ? error_code : 999U) * 100'000U +
           (detail < 100'000U ? detail : 99'999U);
}

static_assert(
    capture_write_size == 2U * capture_scrub_write_size,
    "capture blocks must remain one two-descriptor SD transaction");
static_assert(
    preparation_thread_working_area_size ==
        THD_WA_SIZE(preparation_thread_usable_stack_size),
    "preparation worker allocation must include ChibiOS WA overhead");

constexpr File::Size capture_limit_bytes(const uint32_t sample_rate_hz) {
    return static_cast<File::Size>(sample_rate_hz) *
           complex8_bytes_per_sample * capture_limit_seconds;
}

constexpr File::Size capture_reserve_bytes(const uint32_t sample_rate_hz) {
    const File::Size unaligned = static_cast<File::Size>(sample_rate_hz) *
                                 complex8_bytes_per_sample * capture_reserve_seconds;
    return ((unaligned + capture_write_size - 1U) / capture_write_size) *
           capture_write_size;
}

} /* namespace precision_rx */

namespace ui::external_app::precision_rx {

/*
 * One-shot writer for Precision RX captures.
 *
 * The normal create() path makes an explicitly incomplete file, fills the
 * entire reserve with zeroes, syncs it, and rewinds before the producer
 * starts.  Sequential zero-fill both allocates clusters outside the real-time
 * path and makes a reset/card-removal orphan confidentiality-safe.
 *
 * A hash-identified, nonpromotable experiment substitutes metadata-only
 * expansion followed by a bounded FatFs CLMT proof.  It removes the
 * foreground scrub load for a controlled A/B, but an interrupted full-size
 * PART file can expose stale sectors.  That mode must never be promoted as
 * the default or described as confidentiality-safe.
 *
 * sync() is intentionally terminal: it seeks to the number of wholly
 * accepted bytes, truncates there, and syncs the result.  Seeking to the
 * accounted byte count also removes any partial data left by a failed
 * low-level write.
 *
 * The FileType parameter permits deterministic host tests.  Production uses
 * File through the PrecisionRxCaptureWriter alias below.
 */
template <
    typename FileType,
    bool MetadataOnlyReservation =
        ::precision_rx::capture_metadata_only_reservation>
class BasicPrecisionRxCaptureWriter final : public stream::Writer {
   public:
    BasicPrecisionRxCaptureWriter() = default;

    explicit BasicPrecisionRxCaptureWriter(FileType file)
        : file_{std::move(file)} {
    }

    ~BasicPrecisionRxCaptureWriter() override {
        if (prepared_ && !finalized_) {
            (void)sync();
        }
        file_.disable_fast_seek();
    }

    BasicPrecisionRxCaptureWriter(const BasicPrecisionRxCaptureWriter&) = delete;
    BasicPrecisionRxCaptureWriter& operator=(const BasicPrecisionRxCaptureWriter&) = delete;
    BasicPrecisionRxCaptureWriter(BasicPrecisionRxCaptureWriter&&) = delete;
    BasicPrecisionRxCaptureWriter& operator=(BasicPrecisionRxCaptureWriter&&) = delete;

    Optional<File::Error> create(
        const std::filesystem::path& filename,
        const File::Size reserve_bytes,
        const bool volatile* const cancel_requested = nullptr) {
        preparation_stage_ =
            ::precision_rx::CapturePreparationStage::Create;
        preparation_detail_ = 0;
        if (created_ || filename.empty()) {
            return File::Error{FR_INVALID_OBJECT};
        }

        const auto create_error = file_.create_new(filename);
        if (create_error.is_valid()) {
            return create_error;
        }
        created_ = true;

        if (reserve_bytes != 0) {
            if constexpr (MetadataOnlyReservation) {
                if (cancel_requested && *cancel_requested) {
                    preparation_stage_ =
                        ::precision_rx::CapturePreparationStage::Rollback;
                    const auto cleanup_error = rollback_preparation();
                    if (cleanup_error.is_valid()) {
                        return cleanup_error;
                    }
                    preparation_stage_ =
                        ::precision_rx::CapturePreparationStage::None;
                    prepared_ = true;
                    finalized_ = true;
                    return {};
                }

                /*
                 * FatFs write-mode seek allocates the complete cluster chain
                 * without issuing payload writes.  The bounded CLMT keeps
                 * live capture away from FAT traversal while permitting a
                 * modestly fragmented allocation.  More fragmented files
                 * still fail closed and are rolled back before capture.
                 */
                preparation_stage_ =
                    ::precision_rx::CapturePreparationStage::Reserve;
                const auto reserve_result = file_.seek(reserve_bytes);
                if (reserve_result.is_error()) {
                    return fail_preparation(reserve_result.error());
                }
                if (cancel_requested && *cancel_requested) {
                    preparation_stage_ =
                        ::precision_rx::CapturePreparationStage::Rollback;
                    const auto cleanup_error = rollback_preparation();
                    if (cleanup_error.is_valid()) {
                        return cleanup_error;
                    }
                    preparation_stage_ =
                        ::precision_rx::CapturePreparationStage::None;
                    prepared_ = true;
                    finalized_ = true;
                    return {};
                }

                preparation_stage_ =
                    ::precision_rx::CapturePreparationStage::Map;
                const auto map_error = file_.enable_bounded_fast_seek(
                    fast_seek_table_.data(), fast_seek_table_.size());
                if (map_error.is_valid()) {
                    preparation_detail_ = fast_seek_table_[0];
                    return fail_preparation(map_error.value());
                }
            } else {
                /*
                 * Keep the scrub block in the enlarged preparation worker's
                 * stack.  This preserves multi-sector writes without
                 * requiring another large contiguous heap allocation.
                 */
                alignas(uint32_t) uint8_t zeroes[
                    ::precision_rx::capture_scrub_write_size]{};
                File::Size remaining = reserve_bytes;
                while (remaining != 0) {
                    if (cancel_requested && *cancel_requested) {
                        preparation_stage_ =
                            ::precision_rx::CapturePreparationStage::Rollback;
                        const auto cleanup_error = rollback_preparation();
                        if (cleanup_error.is_valid()) {
                            return cleanup_error;
                        }
                        preparation_stage_ =
                            ::precision_rx::CapturePreparationStage::None;
                        prepared_ = true;
                        finalized_ = true;
                        return {};
                    }
                    const File::Size chunk =
                        std::min<File::Size>(
                            remaining,
                            ::precision_rx::capture_scrub_write_size);
                    preparation_stage_ =
                        ::precision_rx::CapturePreparationStage::Reserve;
                    const auto write_result = file_.write(zeroes, chunk);
                    if (write_result.is_error()) {
                        return fail_preparation(write_result.error());
                    }
                    if (write_result.value() != chunk) {
                        return fail_preparation(File::Error{FR_UNEXPECTED});
                    }
                    remaining -= chunk;
                    ++preparation_detail_;
                }
            }

            preparation_stage_ =
                ::precision_rx::CapturePreparationStage::Sync;
            const auto reserve_sync_error = file_.sync();
            if (reserve_sync_error.is_valid()) {
                return fail_preparation(reserve_sync_error.value());
            }

            preparation_stage_ =
                ::precision_rx::CapturePreparationStage::Rewind;
            const auto rewind_result = file_.seek(0);
            if (rewind_result.is_error()) {
                return fail_preparation(rewind_result.error());
            }
        }

        reserved_bytes_ = reserve_bytes;
        prepared_ = true;
        preparation_stage_ =
            ::precision_rx::CapturePreparationStage::None;
        return {};
    }

    File::Result<File::Size> write(
        const void* const buffer,
        const File::Size bytes) override {
        if (!prepared_ || finalized_) {
            return File::Error{FR_INVALID_OBJECT};
        }

        if (bytes > reserved_bytes_ || bytes_written_ > reserved_bytes_ - bytes) {
            return File::Error{FR_DISK_FULL};
        }

        auto result = file_.write(buffer, bytes);
        if (result.is_ok()) {
            bytes_written_ += result.value();
        } else {
            write_failed_ = true;
        }
        return result;
    }

    Optional<File::Error> sync() override {
        if (!prepared_) {
            return File::Error{FR_INVALID_OBJECT};
        }
        if (finalized_) {
            return {};
        }

        if (write_failed_) {
            /* FatFs otherwise rejects the cleanup seek on its sticky FIL::err. */
            file_.clear_error();
        }

        const auto end_result = file_.seek(bytes_written_);
        if (end_result.is_error()) {
            return end_result.error();
        }

        const auto truncate_result = file_.truncate();
        if (truncate_result.is_error()) {
            return truncate_result.error();
        }

        const auto sync_error = file_.sync();
        if (sync_error.is_valid()) {
            return sync_error;
        }

        finalized_ = true;
        return {};
    }

    File::Size bytes_written() const { return bytes_written_; }
    File::Size reserved_bytes() const { return reserved_bytes_; }
    bool prepared() const { return prepared_; }
    bool finalized() const { return finalized_; }
    bool created() const { return created_; }
    ::precision_rx::CapturePreparationStage preparation_stage() const {
        return preparation_stage_;
    }
    uint32_t preparation_detail() const { return preparation_detail_; }
    const FileType& file() const& { return file_; }

   private:
    Optional<File::Error> rollback_preparation() {
        file_.clear_error();
        const auto rewind_result = file_.seek(0);
        if (rewind_result.is_error()) {
            return rewind_result.error();
        }
        const auto truncate_result = file_.truncate();
        if (truncate_result.is_error()) {
            return truncate_result.error();
        }
        return file_.sync();
    }

    Optional<File::Error> fail_preparation(const File::Error error) {
        /* Preserve the first media error; rollback is best-effort. */
        (void)rollback_preparation();
        return error;
    }

    /* Keep hot file/counter state at Thumb-friendly offsets. */
    FileType file_{};
    File::Size bytes_written_{0};
    File::Size reserved_bytes_{0};
    bool created_{false};
    bool prepared_{false};
    bool finalized_{false};
    bool write_failed_{false};
    ::precision_rx::CapturePreparationStage preparation_stage_{
        ::precision_rx::CapturePreparationStage::None};
    uint32_t preparation_detail_{0};
    /* 256 DWORDs encode at most 127 fragments plus size and terminator. */
    static constexpr size_t fast_seek_table_entries = 256U;
    /* Detached in the destructor before this caller-owned storage expires. */
    std::array<DWORD, fast_seek_table_entries> fast_seek_table_{};
};

using PrecisionRxCaptureWriter = BasicPrecisionRxCaptureWriter<File>;

} /* namespace ui::external_app::precision_rx */

#endif /*__PRECISION_RX_CAPTURE_WRITER_H__*/
