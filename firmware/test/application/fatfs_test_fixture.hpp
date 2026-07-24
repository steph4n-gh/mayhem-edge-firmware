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

#ifndef __FATFS_TEST_FIXTURE_H__
#define __FATFS_TEST_FIXTURE_H__

#include "ff.h"

#include <cstddef>
#include <string>
#include <vector>

namespace fatfs_test {

enum class Call {
    FindFirst,
    FindNext,
    Sync,
    Close,
    Unlink,
    Rename,
};

struct RenameCall {
    std::u16string from{};
    std::u16string to{};
};

struct State {
    std::vector<std::u16string> directory_entries{};
    size_t next_directory_entry{0};
    FRESULT find_first_result{FR_OK};
    FRESULT find_next_result{FR_OK};
    FRESULT sync_result{FR_OK};
    FRESULT close_result{FR_OK};
    FRESULT unlink_result{FR_OK};
    FRESULT rename_result{FR_OK};
    std::vector<Call> calls{};
    std::u16string find_path{};
    std::u16string find_pattern{};
    std::vector<std::u16string> unlinked_paths{};
    std::vector<RenameCall> rename_calls{};
};

State& state();
void reset();

} /* namespace fatfs_test */

#endif /*__FATFS_TEST_FIXTURE_H__*/
