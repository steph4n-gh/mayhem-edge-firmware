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

#ifndef SD_CMD6_WORKAROUND_H
#define SD_CMD6_WORKAROUND_H

#include <stddef.h>
#include <stdint.h>

/*
 * LPC4320 erratum SD/MMC.1 requires the 64-byte CMD6 status plus the four
 * interleaved 16-bit data-line CRCs to be captured as one 72-byte DMA span.
 * The peripheral's DCRC flag is accepted only after these helpers verify all
 * four CRCs in software.
 */

typedef enum {
    SDC_CMD6_STATUS_INVALID = -1,
    SDC_CMD6_STATUS_UNSUPPORTED = 0,
    SDC_CMD6_STATUS_READY = 1,
    SDC_CMD6_STATUS_BUSY = 2,
    SDC_CMD6_STATUS_SELECTED = 3
} sdc_cmd6_status_result_t;

typedef enum {
    SDC_CMD6_NEGOTIATION_ERROR = -1,
    SDC_CMD6_NEGOTIATION_UNSUPPORTED = 0,
    SDC_CMD6_NEGOTIATION_ENABLED = 1,
    SDC_CMD6_NEGOTIATION_RECOVERED = 2,
    SDC_CMD6_NEGOTIATION_BUSY = 3
} sdccmd6result_t;

typedef enum {
    SDC_CMD6_CONNECT_FAIL = -1,
    SDC_CMD6_CONNECT_KEEP_DEFAULT = 0,
    SDC_CMD6_CONNECT_ENABLE_HIGH_SPEED = 1,
    SDC_CMD6_CONNECT_RETRY_DEFAULT = 2
} sdc_cmd6_connect_action_t;

#define SDC_CMD6_DIAG_OUTCOME_SHIFT 5U
#define SDC_CMD6_DIAG_OUTCOME_MASK (7U << SDC_CMD6_DIAG_OUTCOME_SHIFT)
#define SDC_CMD6_DIAG_OUTCOME(result) \
    ((uint32_t)((int32_t)(result) + 2) << SDC_CMD6_DIAG_OUTCOME_SHIFT)

enum {
    /* CMD6 adds SWITCH_ERROR to the legacy ChibiOS R1 error mask. */
    SDC_CMD6_R1_SWITCH_ERROR = (1U << 7),
    SDC_CMD6_RINT_DTO = (1U << 3),
    SDC_CMD6_RINT_DCRC = (1U << 7),
    SDC_CMD6_RINT_FATAL_MASK =
        (1U << 1)   /* RE: Response error */
        | (1U << 6) /* RCRC: Response CRC error */
        | (1U << 8) /* RTO: Response time-out */
        | (1U << 9) /* DRTO: Data read time-out */
        | (1U << 10) /* HTO: Data starvation-by-host time-out */
        | (1U << 11) /* FRUN: FIFO underrun/overrun */
        | (1U << 12) /* HLE: Hardware locked write error */
        | (1U << 13) /* SBE: Start-bit error */
        | (1U << 15), /* EBE: End-bit error */
    SDC_CMD6_IDSTS_RI = (1U << 1),
    SDC_CMD6_IDSTS_FATAL_MASK = (1U << 2) | (1U << 4),
    SDC_CMD6_DESC_OWN = (1U << 31)
};

static inline int sdc_cmd6_r1_has_error(
    const uint32_t response,
    const uint32_t legacy_error_mask) {
    return (response &
            (legacy_error_mask | SDC_CMD6_R1_SWITCH_ERROR)) != 0U;
}

static inline int sdc_cmd6_r1_is_illegal_only(
    const uint32_t response,
    const uint32_t legacy_error_mask,
    const uint32_t illegal_command_mask) {
    const uint32_t cmd6_error_mask =
        legacy_error_mask | SDC_CMD6_R1_SWITCH_ERROR;
    return (response & illegal_command_mask) != 0U &&
           (response & (cmd6_error_mask & ~illegal_command_mask)) == 0U;
}

/*
 * A failed CMD6 transaction is ambiguous: the card may have switched even
 * when the host could not validate its status.  Exactly one new CMD0-based
 * connection at Default Speed is therefore allowed within the same public
 * sdcConnect() call.
 */
static inline int sdc_cmd6_should_retry_default_speed(
    const int negotiation_failed,
    const int default_speed_attempt) {
    return negotiation_failed && !default_speed_attempt;
}

static inline sdc_cmd6_connect_action_t sdc_cmd6_connect_action(
    const sdccmd6result_t result,
    const int default_speed_attempt) {
    if (result == SDC_CMD6_NEGOTIATION_ENABLED)
        return SDC_CMD6_CONNECT_ENABLE_HIGH_SPEED;
    if (result == SDC_CMD6_NEGOTIATION_UNSUPPORTED ||
        result == SDC_CMD6_NEGOTIATION_BUSY)
        return SDC_CMD6_CONNECT_KEEP_DEFAULT;
    if (result == SDC_CMD6_NEGOTIATION_ERROR &&
        sdc_cmd6_should_retry_default_speed(1, default_speed_attempt))
        return SDC_CMD6_CONNECT_RETRY_DEFAULT;
    return SDC_CMD6_CONNECT_FAIL;
}

/*
 * SD/MMC.1 makes DCRC an expected terminal indication for CMD6.  It is not a
 * success by itself: all unrelated controller/IDMAC faults remain fatal and
 * the DMA descriptor must show receive progress.  The caller separately
 * validates the complete 72-byte span with all four software CRCs.
 */
static inline int sdc_cmd6_completion_status_valid(
    const uint32_t raw_status,
    const uint32_t dma_status,
    const uint32_t descriptor_status,
    const uint32_t transferred_fifo_bytes) {
    const uint32_t terminal = SDC_CMD6_RINT_DTO | SDC_CMD6_RINT_DCRC;
    const int dma_progress =
        !(descriptor_status & SDC_CMD6_DESC_OWN) ||
        (dma_status & SDC_CMD6_IDSTS_RI);

    return (raw_status & terminal) &&
           !(raw_status & SDC_CMD6_RINT_FATAL_MASK) &&
           !(dma_status & SDC_CMD6_IDSTS_FATAL_MASK) &&
           dma_progress &&
           transferred_fifo_bytes == 72U;
}

static inline uint16_t sdc_cmd6_be16(const uint8_t* const p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static inline uint16_t sdc_cmd6_crc16_bit(
    uint16_t crc,
    const uint8_t bit) {
    const uint8_t feedback = (uint8_t)(((crc >> 15) & 1U) ^ (bit & 1U));
    crc = (uint16_t)(crc << 1);
    if (feedback)
        crc ^= 0x1021U;
    return crc;
}

static inline uint16_t sdc_cmd6_lane_crc(
    const uint8_t* const data,
    const size_t byte_count,
    const unsigned lane) {
    uint16_t crc = 0;
    size_t i;
    for (i = 0; i < byte_count; ++i) {
        const uint8_t lane_bits = (uint8_t)(data[i] >> lane);
        crc = sdc_cmd6_crc16_bit(
            crc, (uint8_t)(lane_bits >> 4));
        crc = sdc_cmd6_crc16_bit(
            crc, lane_bits);
    }
    return crc;
}

static inline uint16_t sdc_cmd6_payload_lane_crc(
    const uint8_t status[64],
    const unsigned lane) {
    return sdc_cmd6_lane_crc(status, 64U, lane);
}

static inline int sdc_cmd6_software_crc_valid(
    const uint8_t transfer[72]) {
    unsigned lane;
    for (lane = 0; lane < 4U; ++lane) {
        /* Appending a valid wire CRC leaves the CCITT register at zero. */
        if (sdc_cmd6_lane_crc(transfer, 72U, lane) != 0U)
            return 0;
    }
    return 1;
}

static inline sdc_cmd6_status_result_t sdc_cmd6_query_high_speed(
    const uint8_t status[64]) {
    const uint16_t supported = sdc_cmd6_be16(&status[12]);
    const uint8_t selected = (uint8_t)(status[16] & 0x0FU);
    const uint8_t structure_version = status[17];
    if (structure_version > 1U)
        return SDC_CMD6_STATUS_INVALID;
    if (!(supported & (1U << 1)))
        return SDC_CMD6_STATUS_UNSUPPORTED;
    if (structure_version == 1U &&
        (sdc_cmd6_be16(&status[28]) & (1U << 1)))
        return SDC_CMD6_STATUS_BUSY;
    return selected == 1U ? SDC_CMD6_STATUS_READY
                          : SDC_CMD6_STATUS_UNSUPPORTED;
}

static inline sdc_cmd6_status_result_t sdc_cmd6_confirm_high_speed(
    const uint8_t status[64]) {
    const uint8_t selected = (uint8_t)(status[16] & 0x0FU);
    const uint8_t structure_version = status[17];
    if (structure_version > 1U)
        return SDC_CMD6_STATUS_INVALID;
    if (selected == 1U)
        return SDC_CMD6_STATUS_SELECTED;
    if (structure_version == 1U &&
        (sdc_cmd6_be16(&status[28]) & (1U << 1)))
        return SDC_CMD6_STATUS_BUSY;
    if (selected == 0x0FU)
        return SDC_CMD6_STATUS_UNSUPPORTED;
    return SDC_CMD6_STATUS_INVALID;
}

#endif /* SD_CMD6_WORKAROUND_H */
