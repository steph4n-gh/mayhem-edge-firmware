/*
 * Copyright (C) 2026 HackRF Edge contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SD_ACMD23_POLICY_H
#define SD_ACMD23_POLICY_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    SDC_ACMD23_UNKNOWN = 0,
    SDC_ACMD23_SUPPORTED,
    SDC_ACMD23_UNSUPPORTED
} sdc_acmd23_state_t;

typedef enum {
    SDC_ACMD23_FATAL = -1,
    SDC_ACMD23_FALLBACK = 0,
    SDC_ACMD23_ACCEPTED = 1
} sdc_acmd23_result_t;

static inline bool sdc_acmd23_cmd55_accepted(
    const bool transport_ok,
    const uint32_t r1,
    const uint32_t error_mask,
    const uint32_t app_cmd_mask) {
    return transport_ok && (r1 & error_mask) == 0U &&
           (r1 & app_cmd_mask) != 0U;
}

static inline sdc_acmd23_result_t sdc_acmd23_classify(
    const sdc_acmd23_state_t state,
    const bool transport_ok,
    const uint32_t r1,
    const uint32_t error_mask,
    const uint32_t illegal_command_mask) {
    if (!transport_ok)
        return SDC_ACMD23_FATAL;
    if ((r1 & error_mask) == 0U)
        return SDC_ACMD23_ACCEPTED;
    if (state == SDC_ACMD23_UNKNOWN &&
        (r1 & error_mask) == illegal_command_mask)
        return SDC_ACMD23_FALLBACK;
    return SDC_ACMD23_FATAL;
}

static inline sdc_acmd23_state_t sdc_acmd23_next_state(
    const sdc_acmd23_state_t state,
    const sdc_acmd23_result_t result) {
    if (result == SDC_ACMD23_ACCEPTED)
        return SDC_ACMD23_SUPPORTED;
    if (state == SDC_ACMD23_UNKNOWN && result == SDC_ACMD23_FALLBACK)
        return SDC_ACMD23_UNSUPPORTED;
    return state;
}

#endif /* SD_ACMD23_POLICY_H */
