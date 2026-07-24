/*
 * Copyright (C) 2026 HackRF Edge contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "doctest.h"
#include "sd_acmd23_policy.h"

#include <cstdint>

namespace {
constexpr uint32_t error_mask = 0xFDFFE008U;
constexpr uint32_t illegal_command = 1U << 22;
constexpr uint32_t app_cmd = 1U << 5;
}  // namespace

TEST_SUITE_BEGIN("SD ACMD23 pre-erase policy");

TEST_CASE("CMD55 must be transported cleanly and acknowledge APP_CMD") {
    CHECK(sdc_acmd23_cmd55_accepted(
        true, app_cmd, error_mask, app_cmd));
    CHECK_FALSE(sdc_acmd23_cmd55_accepted(
        false, app_cmd, error_mask, app_cmd));
    CHECK_FALSE(sdc_acmd23_cmd55_accepted(
        true, 0U, error_mask, app_cmd));
    CHECK_FALSE(sdc_acmd23_cmd55_accepted(
        true, app_cmd | illegal_command, error_mask, app_cmd));
}

TEST_CASE("only first-use illegal-command falls back") {
    CHECK_EQ(
        sdc_acmd23_classify(
            SDC_ACMD23_UNKNOWN, true, illegal_command,
            error_mask, illegal_command),
        SDC_ACMD23_FALLBACK);
    CHECK_EQ(
        sdc_acmd23_classify(
            SDC_ACMD23_SUPPORTED, true, illegal_command,
            error_mask, illegal_command),
        SDC_ACMD23_FATAL);
    CHECK_EQ(
        sdc_acmd23_classify(
            SDC_ACMD23_UNKNOWN, true, illegal_command | (1U << 19),
            error_mask, illegal_command),
        SDC_ACMD23_FATAL);
}

TEST_CASE("clean acceptance is sticky and transport faults are fatal") {
    const auto accepted = sdc_acmd23_classify(
        SDC_ACMD23_UNKNOWN, true, app_cmd, error_mask, illegal_command);
    CHECK_EQ(accepted, SDC_ACMD23_ACCEPTED);
    CHECK_EQ(
        sdc_acmd23_next_state(SDC_ACMD23_UNKNOWN, accepted),
        SDC_ACMD23_SUPPORTED);
    CHECK_EQ(
        sdc_acmd23_classify(
            SDC_ACMD23_UNKNOWN, false, 0U,
            error_mask, illegal_command),
        SDC_ACMD23_FATAL);
}

TEST_CASE("unsupported state bypass remains sticky") {
    const auto unsupported = sdc_acmd23_next_state(
        SDC_ACMD23_UNKNOWN, SDC_ACMD23_FALLBACK);
    CHECK_EQ(unsupported, SDC_ACMD23_UNSUPPORTED);
    CHECK_EQ(
        sdc_acmd23_next_state(unsupported, SDC_ACMD23_FALLBACK),
        SDC_ACMD23_UNSUPPORTED);
}

TEST_SUITE_END();
