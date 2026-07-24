/*
 * Copyright (C) 2015 Jared Boone, ShareBrained Technology, Inc.
 * Copyright (C) 2016 Furrtek
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

#ifndef __FILE_H__
#define __FILE_H__

#include "ff.h"

#include "optional.hpp"
#include "result.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <array>
#include <memory>
#include <iterator>
#include <vector>

namespace std {
namespace filesystem {

struct filesystem_error {
    constexpr filesystem_error() = default;

    constexpr filesystem_error(
        FRESULT fatfs_error)
        : err{fatfs_error} {
    }

    constexpr filesystem_error(
        unsigned int other_error)
        : err{other_error} {
    }

    uint32_t code() const {
        return err;
    }

    std::string what() const;

    bool ok() const {
        return err == FR_OK;
    }

   private:
    uint32_t err{FR_OK};
};

struct path {
    using string_type = std::u16string;
    using value_type = string_type::value_type;

    static constexpr value_type preferred_separator = u'/';

    path()
        : _s{} {
    }

    path(const path& p)
        : _s{p._s} {
    }

    path(path&& p)
        : _s{std::move(p._s)} {
    }

    template <class Source>
    path(const Source& source)
        : path{std::begin(source), std::end(source)} {
    }

    template <class InputIt>
    path(InputIt first,
         InputIt last)
        : _s{first, last} {
    }

    path(const char16_t* const s)
        : _s{s} {
    }

    path(const TCHAR* const s)
        : _s{reinterpret_cast<const std::filesystem::path::value_type*>(s)} {
    }

    path& operator=(const path& p) {
        _s = p._s;
        return *this;
    }

    path& operator=(path&& p) {
        _s = std::move(p._s);
        return *this;
    }

    path parent_path() const;
    path extension() const;
    path filename() const;
    path stem() const;

    bool empty() const {
        return _s.empty();
    }

    const value_type* c_str() const {
        return native().c_str();
    }

    const TCHAR* tchar() const {
        return reinterpret_cast<const TCHAR*>(native().c_str());
    }

    const string_type& native() const {
        return _s;
    }

    std::string string() const;

    path& operator+=(const path& p) {
        _s += p._s;
        return *this;
    }

    path& operator+=(const string_type& str) {
        _s += str;
        return *this;
    }

    path& operator/=(const path& p) {
        if (_s.back() != preferred_separator && p._s.front() != preferred_separator)
            _s += preferred_separator;
        _s += p._s;
        return *this;
    }

    path& replace_extension(const path& replacement = path());

    path& append_filename(const string_type& str);

   private:
    string_type _s;
};

bool operator==(const path& lhs, const path& rhs);
bool operator!=(const path& lhs, const path& rhs);
bool operator<(const path& lhs, const path& rhs);
bool operator>(const path& lhs, const path& rhs);
path operator+(const path& lhs, const path& rhs);
path operator/(const path& lhs, const path& rhs);

/* Case insensitive path equality on underlying "native" string. */
bool path_iequal(const path& lhs, const path& rhs);
bool is_cxx_capture_file(const path& filename);
uint8_t capture_file_sample_size(const path& filename);

using file_status = BYTE;

/* The largest block that can be read/written to a file. */
constexpr uint16_t max_file_block_size = 512;

static_assert(sizeof(path::value_type) == 2, "sizeof(std::filesystem::path::value_type) != 2");
static_assert(sizeof(path::value_type) == sizeof(TCHAR), "FatFs TCHAR size != std::filesystem::path::value_type");

struct space_info {
    static_assert(sizeof(std::uintmax_t) >= 8, "std::uintmax_t too small (<uint64_t)");

    std::uintmax_t capacity;
    std::uintmax_t free;
    std::uintmax_t available;
};

struct directory_entry : public FILINFO {
    file_status status() const {
        return fattrib;
    }

    std::uintmax_t size() const {
        return fsize;
    };

    const std::filesystem::path path() const noexcept { return {fname}; };
};

class directory_iterator {
    struct Impl {
        DIR dir;
        directory_entry filinfo;

        ~Impl() {
            f_closedir(&dir);
        }
    };

    std::shared_ptr<Impl> impl{};
    std::filesystem::path path_{};
    std::filesystem::path wild_{};

    friend bool operator!=(const directory_iterator& lhs, const directory_iterator& rhs);

   public:
    using difference_type = std::ptrdiff_t;
    using value_type = directory_entry;
    using pointer = const directory_entry*;
    using reference = const directory_entry&;
    using iterator_category = std::input_iterator_tag;

    directory_iterator() noexcept {};
    directory_iterator(const std::filesystem::path& path,
                       const std::filesystem::path& wild);

    ~directory_iterator() {}

    directory_iterator& operator++();

    reference operator*() const {
        // TODO: Exception or assert if impl == nullptr.
        return impl->filinfo;
    }
};

inline const directory_iterator& begin(const directory_iterator& iter) noexcept {
    return iter;
};
inline directory_iterator end(const directory_iterator&) noexcept {
    return {};
};

inline bool operator!=(const directory_iterator& lhs, const directory_iterator& rhs) {
    return lhs.impl != rhs.impl;
};

bool is_directory(const file_status s);
bool is_regular_file(const file_status s);
bool file_exists(const path& file_path);
bool is_directory(const path& file_path);
bool is_empty_directory(const path& file_path);

int file_count(const path& dir_path);

space_info space(const path& p);

} /* namespace filesystem */
} /* namespace std */

struct FATTimestamp {
    uint16_t FAT_date;
    uint16_t FAT_time;
};

std::filesystem::filesystem_error delete_file(const std::filesystem::path& file_path);
std::filesystem::filesystem_error rename_file(const std::filesystem::path& file_path, const std::filesystem::path& new_name);
std::filesystem::filesystem_error copy_file(const std::filesystem::path& file_path, const std::filesystem::path& dest_path);

FATTimestamp file_created_date(const std::filesystem::path& file_path);
std::filesystem::filesystem_error file_update_date(const std::filesystem::path& file_path, FATTimestamp timestamp);
std::filesystem::filesystem_error make_new_file(const std::filesystem::path& file_path);
std::filesystem::filesystem_error make_new_directory(const std::filesystem::path& dir_path);
std::filesystem::filesystem_error ensure_directory(const std::filesystem::path& dir_path);

template <typename TCallback>
void scan_root_files(const std::filesystem::path& directory, const std::filesystem::path& extension, const TCallback& fn) {
    for (const auto& entry : std::filesystem::directory_iterator(directory, extension)) {
        if (std::filesystem::is_regular_file(entry.status()))
            fn(entry.path());
    }
}
std::vector<std::filesystem::path> scan_root_files(const std::filesystem::path& directory, const std::filesystem::path& extension);
std::vector<std::filesystem::path> scan_root_directories(const std::filesystem::path& directory);

/* Gets an auto incrementing filename stem.
 * Pattern should be like "FOO_???.txt" where ??? will be replaced by digits.
 * Pattern may also contain a folder path like "LOGS/FOO_???.txt".
 * Pattern '?' must be contiguous (bad: "FOO?_??")
 * Returns empty path if a filename could not be created. */
std::filesystem::path next_filename_matching_pattern(const std::filesystem::path& pattern);
#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
std::filesystem::path next_filename_matching_pattern(
    const std::filesystem::path& pattern,
    const std::filesystem::path& result_suffix);
#endif

/* Values added to FatFs FRESULT enum, values outside the FRESULT data type */
static_assert(sizeof(FIL::err) == 1, "FatFs FIL::err size not expected.");

/* Dangerous to expose these, as FatFs native error values are byte-sized. However,
 * my filesystem_error implementation is fine with it. */
#define FR_DISK_FULL (0x100)
#define FR_EOF (0x101)
#define FR_BAD_SEEK (0x102)
#define FR_UNEXPECTED (0x103)

namespace file_detail {

/*
 * Validate the bounded FatFs cluster-link map produced by CREATE_LINKMAP.
 * Keeping this structural check independent of FIL makes the fail-closed
 * contract host-testable without emulating FatFs allocation behavior.
 */
inline bool bounded_fast_seek_table_valid(
    const DWORD* const table,
    const size_t table_entries) {
    if (!table || table_entries < 4U) {
        return false;
    }

    const size_t used_entries = table[0];
    if (used_entries < 4U || used_entries > table_entries ||
        (used_entries & 1U) != 0U || table[used_entries - 1U] != 0U) {
        return false;
    }
    for (size_t index = 1U; index + 1U < used_entries; index += 2U) {
        const DWORD cluster_count = table[index];
        const DWORD first_cluster = table[index + 1U];
        if (cluster_count == 0U || first_cluster < 2U) {
            return false;
        }
    }
    return true;
}

} /* namespace file_detail */

/* NOTE: sizeof(File) == 556 bytes because of the FIL's buf member. */
class File {
   public:
    using Size = uint64_t;
    using Offset = uint64_t;
    using Timestamp = uint32_t;
    using Error = std::filesystem::filesystem_error;

    template <typename T>
    using Result = Result<T, Error>;

    File() {};
    ~File();

    File(File&& other) {
        std::swap(f, other.f);
    }
    File& operator=(File&& other) {
        std::swap(f, other.f);
        return *this;
    }

    /* Prevent copies */
    File(const File&) = delete;
    File& operator=(const File&) = delete;

    // TODO: Return Result<>.
    Optional<Error> open(const std::filesystem::path& filename, bool read_only = true, bool create = false);
    void close();
    Optional<Error> append(const std::filesystem::path& filename);
    Optional<Error> create(const std::filesystem::path& filename);
    Optional<Error> create_new(const std::filesystem::path& filename) {
        return open_fatfs(filename, FA_WRITE | FA_CREATE_NEW);
    }

    Result<Size> read(void* data, const Size bytes_to_read);
    Result<Size> write(const void* data, Size bytes_to_write);

    Offset tell() const;
    Result<Offset> seek(uint64_t Offset);

    /*
     * Attach a caller-bounded FatFs cluster-link map to an existing file.
     * The map storage is caller-owned and must outlive this File.  Reject
     * malformed or over-capacity maps rather than entering the real-time path
     * with ordinary FAT traversal.
     *
     * Keep only the raw FatFs map builder resident.  The fail-closed wrapper
     * stays with its external-app caller so neither the fixed 32 KiB PPMA slot
     * nor the aggregate SPI image pays for the whole operation twice.
     */
    inline Optional<Error> enable_bounded_fast_seek(
        DWORD* const table,
        const size_t table_entries) {
#if _USE_FASTSEEK
        if (!table || table_entries < 4U ||
            table_entries > static_cast<size_t>(UINT32_MAX)) {
            return Error{FR_INVALID_PARAMETER};
        }

        const auto result = build_fast_seek_linkmap(
            table, static_cast<DWORD>(table_entries));
        if (result != FR_OK) {
            return Error{result};
        }
        if (!file_detail::bounded_fast_seek_table_valid(
                table, table_entries)) {
            f.cltbl = nullptr;
            return Error{FR_DENIED};
        }
        return {};
#else
        (void)table;
        (void)table_entries;
        return Error{FR_NOT_ENABLED};
#endif
    }

    /* Detach caller-owned CLMT storage before that storage's lifetime ends. */
    inline void disable_fast_seek() {
#if _USE_FASTSEEK
        f.cltbl = nullptr;
#endif
    }

    Result<Offset> truncate();
    Size size() const;
    Result<bool> eof();

    /*
     * FatFs latches low-level I/O failures in FIL::err and then refuses seek
     * or truncate.  A caller recovering a failed aligned write may clear that
     * latch before attempting best-effort rollback to a previously committed
     * file offset.  The subsequent filesystem operations still report any
     * persistent media failure.
     */
    void clear_error() { f_error(&f) = 0; }

    template <size_t N>
    Result<Size> write(const std::array<uint8_t, N>& data) {
        return write(data.data(), N);
    }

    Optional<Error> write_line(const std::string& s);

    // TODO: Return Result<>.
    Optional<Error> sync();

    /* Reads the entire file contents to a string.
     * NB: This will likely fail for files larger than ~10kB. */
    static Result<std::string> read_file(const std::filesystem::path& filename);

   private:
    FIL f{};

    Optional<Error> open_fatfs(const std::filesystem::path& filename, BYTE mode);
    __attribute__((noinline)) FRESULT build_fast_seek_linkmap(
        DWORD* table,
        DWORD table_entries);
};

#if defined(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC)
/* Close an owned new file and remove it if its contents are incomplete. */
bool finish_new_file(
    File& file,
    const std::filesystem::path& path,
    bool contents_complete);
#endif

#endif /*__FILE_H__*/
