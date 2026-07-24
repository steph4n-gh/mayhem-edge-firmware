/*
 * Copyright (C) 2023 Kyle Reed
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

/* This file contains stub functions necessary to enable linking.
 * Try to minimize dependecies by breaking code into separate files
 * or using templates and mock types. Because the test code is built
 * and executed on the dev machine, a lot of core firmware code
 * will not or cannot work (e.g. filesystem). We could build abstractions
 * but that's just device overhead that only supports testing. */

#include "fatfs_test_fixture.hpp"

#include <algorithm>
#include <string>

/* FatFS stubs */
#include "ff.h"

namespace {

fatfs_test::State fatfs_state{};

std::u16string from_tchar(const TCHAR* const text) {
    if (!text) {
        return {};
    }
    static_assert(
        sizeof(TCHAR) == sizeof(char16_t),
        "test fixture expects the firmware Unicode FatFS configuration");
    return {
        reinterpret_cast<const char16_t*>(text)};
}

void set_find_result(
    FILINFO* const info,
    const std::u16string* const filename) {
    info->fattrib = 0;
    if (!filename) {
        info->fname[0] = 0;
        return;
    }

    const auto copy_count = std::min(
        filename->size(),
        static_cast<size_t>(_MAX_LFN));
    for (size_t index = 0; index < copy_count; ++index) {
        info->fname[index] = static_cast<TCHAR>((*filename)[index]);
    }
    info->fname[copy_count] = 0;
}

} /* namespace */

namespace fatfs_test {

State& state() {
    return fatfs_state;
}

void reset() {
    fatfs_state = {};
}

} /* namespace fatfs_test */

FRESULT f_close(FIL*) {
    fatfs_state.calls.push_back(fatfs_test::Call::Close);
    return fatfs_state.close_result;
}
FRESULT f_closedir(DIR*) {
    return FR_OK;
}
FRESULT f_findfirst(
    DIR*,
    FILINFO* const info,
    const TCHAR* const path,
    const TCHAR* const pattern) {
    fatfs_state.calls.push_back(fatfs_test::Call::FindFirst);
    fatfs_state.find_path = from_tchar(path);
    fatfs_state.find_pattern = from_tchar(pattern);
    fatfs_state.next_directory_entry = 0;
    if (fatfs_state.find_first_result != FR_OK) {
        set_find_result(info, nullptr);
        return fatfs_state.find_first_result;
    }
    if (fatfs_state.directory_entries.empty()) {
        set_find_result(info, nullptr);
    } else {
        set_find_result(info, &fatfs_state.directory_entries.front());
        fatfs_state.next_directory_entry = 1;
    }
    return FR_OK;
}
FRESULT f_findnext(DIR*, FILINFO* const info) {
    fatfs_state.calls.push_back(fatfs_test::Call::FindNext);
    if (fatfs_state.find_next_result != FR_OK) {
        set_find_result(info, nullptr);
        return fatfs_state.find_next_result;
    }
    if (fatfs_state.next_directory_entry >=
        fatfs_state.directory_entries.size()) {
        set_find_result(info, nullptr);
    } else {
        set_find_result(
            info,
            &fatfs_state.directory_entries[
                fatfs_state.next_directory_entry++]);
    }
    return FR_OK;
}
FRESULT f_getfree(const TCHAR*, DWORD*, FATFS**) {
    return FR_OK;
}
FRESULT f_lseek(FIL*, FSIZE_t) {
    return FR_OK;
}
FRESULT f_mkdir(const TCHAR*) {
    return FR_OK;
}
FRESULT f_open(FIL*, const TCHAR*, BYTE) {
    return FR_OK;
}
FRESULT f_read(FIL*, void*, UINT, UINT*) {
    return FR_OK;
}
FRESULT f_rename(
    const TCHAR* const from,
    const TCHAR* const to) {
    fatfs_state.calls.push_back(fatfs_test::Call::Rename);
    fatfs_state.rename_calls.push_back({
        from_tchar(from),
        from_tchar(to)});
    return fatfs_state.rename_result;
}
FRESULT f_stat(const TCHAR*, FILINFO*) {
    return FR_OK;
}
FRESULT f_sync(FIL*) {
    fatfs_state.calls.push_back(fatfs_test::Call::Sync);
    return fatfs_state.sync_result;
}
FRESULT f_truncate(FIL*) {
    return FR_OK;
}
FRESULT f_unlink(const TCHAR* const path) {
    fatfs_state.calls.push_back(fatfs_test::Call::Unlink);
    fatfs_state.unlinked_paths.push_back(from_tchar(path));
    return fatfs_state.unlink_result;
}
FRESULT f_utime(const TCHAR*, const FILINFO*) {
    return FR_OK;
}
FRESULT f_write(FIL*, const void*, UINT, UINT*) {
    return FR_OK;
}

/* Debug */
void __debug_log(const std::string&) {}
