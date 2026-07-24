/*
    ChibiOS/RT - Copyright (C) 2006-2013 Giovanni Di Sirio
                 Copyright (C) 2014 Jared Boone, ShareBrained Technology

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

/**
 * @file    LPC43xx/sdc_lld.c
 * @brief   LPC43xx SDC Driver subsystem low level driver source.
 *
 * @addtogroup SDC
 * @{
 */

#include "ch.h"
#include "hal.h"
#if defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC)
#include "sd_cmd6_workaround.h"
#endif
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
#include "sd_acmd23_policy.h"
#endif

#if HAL_USE_SDC || defined(__DOXYGEN__)

/*===========================================================================*/
/* Driver local definitions.                                                 */
/*===========================================================================*/

/*===========================================================================*/
/* Driver exported variables.                                                */
/*===========================================================================*/

/**
 * @brief   SDCD1 driver identifier.
 */
#if LPC_SDC_USE_SDC1 || defined(__DOXYGEN__)
SDCDriver SDCD1;
#endif

#if defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC)
volatile sdccmd6diagnostic_t SDCD1_cmd6_diagnostic;
#endif

/*===========================================================================*/
/* Driver local variables and types.                                         */
/*===========================================================================*/

#if LPC_SDC_USE_SDC1
static const sdio_resources_t sdio_resources = {
    .base = {.clk = &LPC_CGU->BASE_SDIO_CLK, .stat = &LPC_CCU2->BASE_STAT, .stat_mask = 0},
    .branch_register_if = {.cfg = &LPC_CCU1->CLK_M4_SDIO_CFG, .stat = &LPC_CCU1->CLK_M4_SDIO_STAT},
    .branch_peripheral = {.cfg = &LPC_CCU2->CLK_SDIO_CFG, .stat = &LPC_CCU2->CLK_SDIO_STAT},
    .reset = {.output_index = 20},
    .interrupt = {.irq = SDIO_IRQn, .priority_mask = CORTEX_PRIORITY_MASK(LPC_SDC_SDIO_IRQ_PRIORITY)},
};
#endif

#if defined(LPC43XX_M0) && defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC)
static sdccapturetiming_t sdc_capture_timing;
static bool sdc_capture_timing_active;
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
static sdc_acmd23_state_t sdc_capture_acmd23_state;
#endif

void sdc_lld_capture_timing_begin(void) {
    sdc_capture_timing = (sdccapturetiming_t){
        .counter_frequency_hz = halGetCounterFrequency(),
    };
    sdc_capture_timing_active = true;
}

#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
void sdc_lld_capture_timing_record_cycle(
    uint32_t pre_ready_ticks,
    uint32_t recycle_gap_ticks,
    uint32_t fifo_depth) {
    if (sdc_capture_timing_active) {
        const uint32_t prior_depth =
            (sdc_capture_timing.packed_counts &
             SDC_CAPTURE_TIMING_FIFO_MASK) >>
            SDC_CAPTURE_TIMING_FIFO_SHIFT;

        sdc_capture_timing.recycle_gap_total_ticks += recycle_gap_ticks;
        sdc_capture_timing.pre_ready_total_ticks += pre_ready_ticks;
        if (recycle_gap_ticks > sdc_capture_timing.recycle_gap_max_ticks)
            sdc_capture_timing.recycle_gap_max_ticks = recycle_gap_ticks;
        if (pre_ready_ticks > sdc_capture_timing.pre_ready_max_ticks)
            sdc_capture_timing.pre_ready_max_ticks = pre_ready_ticks;
        if (fifo_depth > 0xFU)
            fifo_depth = 0xFU;
        if (fifo_depth > prior_depth) {
            sdc_capture_timing.packed_counts =
                (sdc_capture_timing.packed_counts &
                 ~SDC_CAPTURE_TIMING_FIFO_MASK) |
                (fifo_depth << SDC_CAPTURE_TIMING_FIFO_SHIFT);
        }
    }
}
#else
void sdc_lld_capture_timing_record_write(uint32_t ticks) {
    if (sdc_capture_timing_active) {
        sdc_capture_timing.writer_total_ticks += ticks;
        if (ticks > sdc_capture_timing.writer_max_ticks)
            sdc_capture_timing.writer_max_ticks = ticks;
    }
}
#endif

const sdccapturetiming_t* sdc_lld_capture_timing_end(void) {
    sdc_capture_timing_active = false;
#if defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC)
    if (SDCD1.cardmode & SDC_MODE_HIGH_SPEED)
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
        sdc_capture_timing.packed_counts |=
            SDC_CAPTURE_TIMING_HIGH_SPEED_FLAG;
#else
        sdc_capture_timing.transaction_count |=
            SDC_CAPTURE_TIMING_HIGH_SPEED_FLAG;
#endif
#endif
    return &sdc_capture_timing;
}
#endif

#if defined(LPC43XX_M0) && defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
void sdc_lld_capture_preerase_reset(void) {
    sdc_capture_acmd23_state = SDC_ACMD23_UNKNOWN;
}

bool_t sdc_lld_capture_wait_ready(SDCDriver* sdcp) {
    const uint32_t start = halGetCounterValue();
    const uint32_t timeout_ticks = halGetCounterFrequency() / 4U;
    uint32_t resp[1];

    while (TRUE) {
        if (sdc_lld_send_cmd_short_crc(
                sdcp, MMCSD_CMD_SEND_STATUS, sdcp->rca, resp) ||
            MMCSD_R1_ERROR(resp[0]))
            return CH_FAILED;
        switch (MMCSD_R1_STS(resp[0])) {
        case MMCSD_STS_TRAN:
            return CH_SUCCESS;
        case MMCSD_STS_DATA:
        case MMCSD_STS_RCV:
        case MMCSD_STS_PRG:
            if ((uint32_t)(halGetCounterValue() - start) >= timeout_ticks)
                return CH_FAILED;
            chThdSleepMilliseconds(1);
            break;
        default:
            return CH_FAILED;
        }
    }
}
#endif

/*===========================================================================*/
/* Driver local functions.                                                   */
/*===========================================================================*/

static bool sdio_status_command_done(void) {
    return (LPC_SDMMC->RINTSTS & (1U << 2)) != 0;
}

static void sdio_status_command_done_clear(void) {
    LPC_SDMMC->RINTSTS = (1U << 2);
}

static void sdio_wait_for_command_done(void) {
    while (!sdio_status_command_done())
        ;
    sdio_status_command_done_clear();
}

static bool sdio_status_data_transfer_over(void) {
    return (LPC_SDMMC->RINTSTS & (1U << 3)) != 0;
}

static bool sdio_status_hardware_locked_write_error(void) {
    return (LPC_SDMMC->RINTSTS & (1U << 12)) != 0;
}

static void sdio_status_hardware_locked_write_error_clear(void) {
    LPC_SDMMC->RINTSTS = (1U << 12);
}

static bool sdio_status_response_error(void) {
    return LPC_SDMMC->RINTSTS & ((1U << 1)   /* RE: Response error */
                                 | (1U << 6) /* RCRC: Response CRC error */
                                 | (1U << 8) /* RTO: Response time-out error */
                                );
}

static void sdio_status_response_error_clear(void) {
    LPC_SDMMC->RINTSTS |=
        (1U << 1)   /* RE: Response error */
        | (1U << 6) /* RCRC: Response CRC error */
        | (1U << 8) /* RTO: Response time-out error */
        ;
}

// static void sdio_reset_rgu(void) {
//   LPC_RGU->RESET_CTRL[0] |= (1U << 20);
// }

// static void sdio_reset_controller(void) {
//   LPC_SDMMC->CTRL |= (1U << 0);
//   while( LPC_SDMMC->CTRL & (1U << 0) );
// }

// static void sdio_reset_fifo(void) {
//   LPC_SDMMC->CTRL |= (1U << 1);
//   while( LPC_SDMMC->CTRL & (1U << 1) );
// }

// static void sdio_reset_dma(void) {
//   LPC_SDMMC->CTRL |= (1U << 2);
//   while( LPC_SDMMC->CTRL & (1U << 2) );
// }

static void sdio_reset_dma_and_fifo(void) {
    LPC_SDMMC->CTRL |=
        (1U << 1)   /* FIFO */
        | (1U << 2) /* DMA */
        ;
    while (LPC_SDMMC->CTRL & ((1U << 1) | (1U << 2)))
        ;
}

static void sdio_reset(void) {
    LPC_SDMMC->BMOD = (1U << 0);

    LPC_SDMMC->CTRL = 0x7U;
    while (LPC_SDMMC->CTRL & 0x7U)
        ;
}

static void sdio_reset_card(void) {
    /* Controls SD_RST signal, for MMC4.4 cards */
    LPC_SDMMC->RST_N = 0;
    halPolledDelay(10);
    LPC_SDMMC->RST_N = 1;
}

static void sdio_interrupts_set_mask(const uint32_t mask) {
    LPC_SDMMC->INTMASK = mask;
}

static void sdio_interrupts_clear(void) {
    LPC_SDMMC->RINTSTS = 0xffffffffU;
}

static void sdio_wait_for_command_accepted(void) {
    while (LPC_SDMMC->CMD & (1U << 31))
        ;
}

static void sdio_update_clock_registers_only(void) {
    LPC_SDMMC->CMDARG = 0;
    LPC_SDMMC->CMD =
        (1U << 13)   /* WAIT_PRVDATA_COMPLETE */
        | (1U << 21) /* UPDATE_CLOCK_REGISTERS_ONLY */
        | (1U << 31) /* START_CMD */
        ;
    sdio_wait_for_command_accepted();
}

static void sdio_cclk_enable(void) {
    LPC_SDMMC->CLKENA |= (1U << 0);
}

static void sdio_cclk_disable(void) {
    LPC_SDMMC->CLKENA &= ~(1U << 0);
}

static void sdio_clkdiv_set(
    const size_t divider_0) {
    LPC_SDMMC->CLKDIV = ((uint32_t)divider_0 & 0xff) << 0;
}

static void sdio_clksrc_set(const size_t divider_index) {
    LPC_SDMMC->CLKSRC = ((divider_index & 3) << 0);
}

void sdio_cclk_set(const size_t divider_value) {
    /* "Before issuing a new data transfer command, the software should
     * ensure that the card is not busy due to any previous data
     * transfer command. Before changing the card clock frequency, the
     * software must ensure that there are no data or command transfers
     * in progress."
     */
    /* "To avoid glitches in the card clock outputs (cclk_out), the
     * software should use the following steps when changing the card
     * clock frequency:"
     */
    sdio_cclk_disable();
    sdio_clksrc_set(0);
    sdio_update_clock_registers_only();

    sdio_clkdiv_set(divider_value);
    sdio_update_clock_registers_only();

    sdio_cclk_enable();
    sdio_update_clock_registers_only();
}

static void sdio_cclk_set_400khz(void) {
    sdio_cclk_set(255);
}

static void sdio_cclk_set_fast(void) {
#if defined(PORTAPACK_FAST_SDIO) && \
    !defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC) && \
    !defined(HACKRF_EDGE_SD_SAFE_DEFAULT_SPEED)
    /* Preserve the upstream opt-in behavior outside the CMD6 experiment. */
    /* 200MHz / (2 * 2) = 50MHz */
    sdio_cclk_set(2);
#else
    /* CMD6 must begin at Default Speed and switch only after validation. */
    /* 200MHz / (2 * 4) = 25MHz */
    sdio_cclk_set(4);
#endif
}

#if defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC)
static void sdio_cclk_set_high_speed(void) {
    /* 200MHz / (2 * 2) = 50MHz, only after a verified CMD6 switch. */
    sdio_cclk_set(2);
}
#endif

static void sdio_width_set_1bit(void) {
    LPC_SDMMC->CTYPE =
        (0U << 0)    /* CARD_WIDTH0 */
        | (0U << 16) /* CARD_WIDTH1 */
        ;
}

static void sdio_width_set_4bit(void) {
    LPC_SDMMC->CTYPE =
        (1U << 0)    /* CARD_WIDTH0 */
        | (0U << 16) /* CARD_WIDTH1 */
        ;
}

static void sdio_width_set_8bit(void) {
    LPC_SDMMC->CTYPE =
        (0U << 0)    /* CARD_WIDTH0 */
        | (1U << 16) /* CARD_WIDTH1 */
        ;
}

static void sdio_dma_disable(void) {
    LPC_SDMMC->BMOD &= ~(1U << 7);
}

#if defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC)
static void sdio_dma_enable(void) {
    LPC_SDMMC->BMOD |= (1U << 7);
}
#endif

static void sdio_dma_interrupts_clear(void) {
    LPC_SDMMC->IDSTS =
        (1U << 0)   /* TI: Transmit interrupt */
        | (1U << 1) /* RI: Receive interrupt */
        | (1U << 2) /* FBE: Fatal bus error interrupt */
        | (1U << 4) /* DU: Descriptor unavailable interrupt */
        | (1U << 5) /* CES: Card error summary */
        | (1U << 8) /* NIS: Normal interrupt summary */
        | (1U << 9) /* AIS: Abnormal interrupt summary */
        ;
}

static bool_t sdc_llc_prepare_descriptors_chained(LPC_SDMMC_DESC_Type desc[],
                                                  const uint32_t desc_count,
                                                  const uint8_t* const buffer,
                                                  uint32_t byte_count) {
    const uint32_t buffer_size = LPC_SDC_SDIO_MAX_DESCRIPTOR_BYTES;
    uint32_t p = (uint32_t)buffer;

    for (uint32_t i = 0; i < desc_count; i++) {
        uint32_t buffer_1_size = (byte_count > buffer_size) ? buffer_size : byte_count;
        desc[i].DESC2 = p;  //(buffer_1_size == 0) ? 0 : p;
        p += buffer_1_size;
        byte_count -= buffer_1_size;

        uint32_t buffer_2_size = 0;
        desc[i].DESC1 =
            (buffer_1_size << 0) | (buffer_2_size << 13);

        desc[i].DESC3 = (uint32_t)&desc[i + 1];

        const bool_t first_descriptor = (i == 0);
        const bool_t last_descriptor = (byte_count == 0);
        desc[i].DESC0 =
            (last_descriptor ? 0 : (1U << 1))    /* Disable interrupt on completion */
            | (last_descriptor ? (1U << 2) : 0)  /* Last descriptor */
            | (first_descriptor ? (1U << 3) : 0) /* First descriptor */
            | (1U << 4)                          /* ! Second address chained */
            | (1U << 31)                         /* Descriptor is owned by DMA controller */
            ;
    }

    return (byte_count == 0) ? CH_SUCCESS : CH_FAILED;
}

/**
 * @brief   Wait end of data transaction and performs finalizations.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] n         number of blocks in transaction
 * @param[in] resp      pointer to the response buffer
 *
 * @return              The operation status.
 * @retval CH_SUCCESS   operation succeeded.
 * @retval CH_FAILED    operation failed.
 */
static bool_t sdc_lld_wait_transaction_end(SDCDriver* sdcp, uint32_t n, uint32_t* resp) {
    /* Note the mask is checked before going to sleep because the interrupt
       may have occurred before reaching the critical zone.*/
    chSysLock();
    if (LPC_SDMMC->INTMASK != 0) {
        chDbgAssert(sdcp->thread == NULL,
                    "sdc_lld_start_data_transaction(), #1", "not NULL");
        sdcp->thread = chThdSelf();
        chSchGoSleepS(THD_STATE_SUSPENDED);
        chDbgAssert(sdcp->thread == NULL,
                    "sdc_lld_start_data_transaction(), #2", "not NULL");
    }
    if (!sdio_status_data_transfer_over()) {
        chSysUnlock();
        return CH_FAILED;
    }

    /* TODO: Check that DMA is completed? */

    sdio_interrupts_clear();
    chSysUnlock();

    /* Finalize transaction.*/
    if (n > 1)
        return sdc_lld_send_cmd_short_crc(sdcp, MMCSD_CMD_STOP_TRANSMISSION, 0, resp);

    return CH_SUCCESS;
}

/**
 * @brief   Gets SDC errors.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] sta       value of the STA register
 *
 * @notapi
 */
static void sdc_lld_collect_errors(SDCDriver* sdcp, uint32_t sta) {
    uint32_t errors = SDC_NO_ERROR;

    if (sta & (1U << 6))
        errors |= SDC_CMD_CRC_ERROR;
    if (sta & (1U << 7))
        errors |= SDC_DATA_CRC_ERROR;
    if (sta & (1U << 8))
        errors |= SDC_COMMAND_TIMEOUT;
    if (sta & (1U << 9))
        errors |= SDC_DATA_TIMEOUT;
    if (sta & (1U << 11))
        errors |= (SDC_TX_UNDERRUN | SDC_RX_OVERRUN);
    if (sta & (1U << 13))
        errors |= SDC_STARTBIT_ERROR;
    if (sta & ((1U << 10) | (1U << 12) | (1U << 15))) /* HTO, HLE, EBE */
        errors |= SDC_UNHANDLED_ERROR;

    sdcp->errors |= errors;
}

/**
 * @brief   Performs clean transaction stopping in case of errors.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] n         number of blocks in transaction
 * @param[in] resp      pointer to the response buffer
 *
 * @notapi
 */
static void sdc_lld_error_cleanup(SDCDriver* sdcp,
                                  uint32_t n,
                                  uint32_t* resp) {
    uint32_t sta = LPC_SDMMC->RINTSTS;

    sdio_dma_interrupts_clear();
    sdio_dma_disable();

    sdio_interrupts_clear();
    sdio_interrupts_set_mask(0);

    sdc_lld_collect_errors(sdcp, sta);
    if (n > 1)
        sdc_lld_send_cmd_short_crc(sdcp, MMCSD_CMD_STOP_TRANSMISSION, 0, resp);
}

#if defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC)
/* Retain one command-issue call site while collecting CMD6 HIL evidence. */
__attribute__((noinline))
#endif
static bool_t sdio_send_command(
    SDCDriver* sdcp,
    const uint32_t cmd_and_flags,
    const uint32_t arg) {
    uint32_t data_state_flag = (1U << 13); /* WAIT_PRVDATA_COMPLETE */
    if ((cmd_and_flags & 0x3fU) == MMCSD_CMD_STOP_TRANSMISSION) {
        /* CMD12 requires STOP_ABORT_CMD instead of WAIT_PRVDATA_COMPLETE. */
        data_state_flag = (1U << 14);
    }

    LPC_SDMMC->CMDARG = arg;
    LPC_SDMMC->CMD =
        cmd_and_flags | data_state_flag
        | (1U << 31) /* START_CMD */
        ;

    /* TODO: If waiting for command done, and not caring about HLE, why not
     * just wait for command done?
     * Or is it a matter of the status flags being relevant to the last
     * command if we're still waiting for this one to be accepted?
     */
    sdio_wait_for_command_accepted();

    /* TODO: Is HLE even possible if the stack is correct? Maybe make this a
     * debug-only block of code?
     */
    if (sdio_status_hardware_locked_write_error()) {
        sdc_lld_collect_errors(sdcp, LPC_SDMMC->RINTSTS);
        sdio_status_hardware_locked_write_error_clear();
        return CH_FAILED;
    }

    sdio_wait_for_command_done();

    /* TODO: If no response expected, why check for response errors? */
    if (sdio_status_response_error()) {
        sdc_lld_collect_errors(sdcp, LPC_SDMMC->RINTSTS);
        sdio_status_response_error_clear();
        return CH_FAILED;
    }

    /* TODO: Clear interrupt? Wait for completion? */
    return CH_SUCCESS;
}

static bool_t sdc_lld_send_cmd_data(SDCDriver* sdcp, uint32_t cmd_and_flags, uint32_t arg, uint32_t* resp) {
    (void)sdcp;

    const uint32_t status = sdio_send_command(
        sdcp,
        /* RESPONSE_EXPECT | CHECK_RESPONSE_CRC | DATA_EXPECTED */
        cmd_and_flags | (1U << 6) | (1U << 8) | (1U << 9),
        arg);

    if (status == CH_SUCCESS) {
        *resp = LPC_SDMMC->RESP0;
    }

    return status;
}

static bool_t sdc_lld_send_cmd_data_read(SDCDriver* sdcp, uint8_t cmd, uint32_t arg, uint32_t* resp) {
    return sdc_lld_send_cmd_data(sdcp, cmd | (0U << 10), arg, resp);
}

static bool_t sdc_lld_send_cmd_data_write(SDCDriver* sdcp, uint8_t cmd, uint32_t arg, uint32_t* resp) {
    return sdc_lld_send_cmd_data(sdcp, cmd | (1U << 10), arg, resp);
}

/**
 * @brief   Prepares card to handle read transaction.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] startblk  first block to read
 * @param[in] n         number of blocks to read
 * @param[in] resp      pointer to the response buffer
 *
 * @return              The operation status.
 * @retval CH_SUCCESS   operation succeeded.
 * @retval CH_FAILED    operation failed.
 *
 * @notapi
 */
static bool_t sdc_lld_prepare_read(SDCDriver* sdcp, uint32_t startblk, uint32_t n, uint32_t* resp) {
    /* Driver handles data in 512 bytes blocks (just like HC cards). But if we
       have not HC card than we must convert address from blocks to bytes.*/
    if (!(sdcp->cardmode & SDC_MODE_HIGH_CAPACITY))
        startblk *= MMCSD_BLOCK_SIZE;

    if (n > 1) {
        /* Send read multiple blocks command to card.*/
        if (sdc_lld_send_cmd_data_read(sdcp, MMCSD_CMD_READ_MULTIPLE_BLOCK,
                                       startblk, resp) ||
            MMCSD_R1_ERROR(resp[0]))
            return CH_FAILED;
    } else {
        /* Send read single block command.*/
        if (sdc_lld_send_cmd_data_read(sdcp, MMCSD_CMD_READ_SINGLE_BLOCK,
                                       startblk, resp) ||
            MMCSD_R1_ERROR(resp[0]))
            return CH_FAILED;
    }

    return CH_SUCCESS;
}

#if defined(LPC43XX_M0) && \
    defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC) && \
    defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
static sdc_acmd23_result_t sdc_lld_capture_preerase(
    SDCDriver* sdcp,
    const uint32_t block_count) {
    uint32_t resp[1] = {0};

    if (sdc_capture_acmd23_state == SDC_ACMD23_UNSUPPORTED)
        return SDC_ACMD23_FALLBACK;

    if (sdc_lld_send_cmd_short_crc(
            sdcp, MMCSD_CMD_APP_CMD, sdcp->rca, resp) ||
        !sdc_acmd23_cmd55_accepted(
            true, resp[0], MMCSD_R1_ERROR_MASK, MMCSD_R1_APP_CMD))
        return SDC_ACMD23_FATAL;

    const bool transport_ok =
        sdc_lld_send_cmd_short_crc(
            sdcp, MMCSD_ACMD_SET_WR_BLK_ERASE_COUNT,
            block_count, resp) == CH_SUCCESS;
    const sdc_acmd23_result_t result = sdc_acmd23_classify(
        sdc_capture_acmd23_state,
        transport_ok,
        resp[0],
        MMCSD_R1_ERROR_MASK,
        MMCSD_R1_ILLEGAL_COMMAND);
    sdc_capture_acmd23_state =
        sdc_acmd23_next_state(sdc_capture_acmd23_state, result);
    return result;
}

static void sdc_lld_capture_count_preerase(
    const sdc_acmd23_result_t result) {
    const uint32_t shift =
        result == SDC_ACMD23_ACCEPTED
            ? 0U
            : SDC_CAPTURE_TIMING_FALLBACK_SHIFT;
    const uint32_t count =
        (sdc_capture_timing.packed_counts >> shift) &
        SDC_CAPTURE_TIMING_COUNT_MASK;
    if (count < SDC_CAPTURE_TIMING_COUNT_MASK)
        sdc_capture_timing.packed_counts += 1U << shift;
}
#endif

/**
 * @brief   Prepares card to handle write transaction.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] startblk  first block to read
 * @param[in] n         number of blocks to write
 * @param[in] resp      pointer to the response buffer
 *
 * @return              The operation status.
 * @retval CH_SUCCESS   operation succeeded.
 * @retval CH_FAILED    operation failed.
 *
 * @notapi
 */
static bool_t sdc_lld_prepare_write(SDCDriver* sdcp, uint32_t startblk, uint32_t n, uint32_t* resp) {
    /* Driver handles data in 512 bytes blocks (just like HC cards). But if we
       have not HC card than we must convert address from blocks to bytes.*/
    if (!(sdcp->cardmode & SDC_MODE_HIGH_CAPACITY))
        startblk *= MMCSD_BLOCK_SIZE;

    if (n > 1) {
        /* Write multiple blocks command.*/
        if (sdc_lld_send_cmd_data_write(sdcp, MMCSD_CMD_WRITE_MULTIPLE_BLOCK,
                                        startblk, resp) ||
            MMCSD_R1_ERROR(resp[0]))
            return CH_FAILED;
    } else {
        /* Write single block command.*/
        if (sdc_lld_send_cmd_data_write(sdcp, MMCSD_CMD_WRITE_BLOCK,
                                        startblk, resp) ||
            MMCSD_R1_ERROR(resp[0]))
            return CH_FAILED;
    }

    return CH_SUCCESS;
}

#if defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC)
typedef enum {
    SDC_CMD6_TRANSFER_ERROR = -1,
    SDC_CMD6_TRANSFER_OK = 0,
    SDC_CMD6_TRANSFER_ILLEGAL = 1
} sdc_cmd6_transfer_result_t;

static void sdc_lld_cmd6_diagnostic_begin(const uint32_t argument) {
    const uint32_t sequence = SDCD1_cmd6_diagnostic.sequence + 1U;

    SDCD1_cmd6_diagnostic.argument = argument;
    SDCD1_cmd6_diagnostic.response = 0;
    SDCD1_cmd6_diagnostic.raw_status = 0;
    SDCD1_cmd6_diagnostic.dma_status = 0;
    SDCD1_cmd6_diagnostic.transferred_card_bytes = 0;
    SDCD1_cmd6_diagnostic.transferred_fifo_bytes = 0;
    SDCD1_cmd6_diagnostic.descriptor_status = 0;
    SDCD1_cmd6_diagnostic.block_size = MMCSD_CMD6_STATUS_BYTES;
    SDCD1_cmd6_diagnostic.byte_count = MMCSD_CMD6_ERRATUM_TRANSFER_BYTES;
    SDCD1_cmd6_diagnostic.flags = 0;
    __DMB();
    SDCD1_cmd6_diagnostic.sequence = sequence;
}

static void sdc_lld_cmd6_diagnostic_capture(
    const uint32_t response,
    const uint32_t raw_status,
    const uint32_t dma_status,
    const uint32_t descriptor_status,
    const uint32_t flags) {
    SDCD1_cmd6_diagnostic.response = response;
    SDCD1_cmd6_diagnostic.raw_status = raw_status;
    SDCD1_cmd6_diagnostic.dma_status = dma_status;
    SDCD1_cmd6_diagnostic.transferred_card_bytes = LPC_SDMMC->TCBCNT;
    SDCD1_cmd6_diagnostic.transferred_fifo_bytes = LPC_SDMMC->TBBCNT;
    SDCD1_cmd6_diagnostic.descriptor_status = descriptor_status;
    SDCD1_cmd6_diagnostic.block_size = LPC_SDMMC->BLKSIZ;
    SDCD1_cmd6_diagnostic.byte_count = LPC_SDMMC->BYTCNT;
    SDCD1_cmd6_diagnostic.flags = flags;
    __DMB();
}

static bool_t sdc_lld_cmd6_wait_raw_status(
    SDCDriver* sdcp,
    uint32_t* const status) {
    bool_t timed_out = FALSE;

    chSysLock();
    if (LPC_SDMMC->INTMASK != 0) {
        sdcp->thread = chThdSelf();
        if (chSchGoSleepTimeoutS(
                THD_STATE_SUSPENDED, MS2ST(100)) == RDY_TIMEOUT) {
            sdcp->thread = NULL;
            timed_out = TRUE;
        }
    }
    *status = LPC_SDMMC->RINTSTS;
    sdio_interrupts_set_mask(0);
    chSysUnlock();
    return timed_out ? CH_FAILED : CH_SUCCESS;
}

/*
 * LPC4320 erratum SD/MMC.1: a correct 64-byte CMD6 status always raises
 * DCRC.  Receiving 72 bytes captures the four interleaved data-line CRCs so
 * they can be verified in software.  DCRC is an expected terminal interrupt,
 * but it is accepted only when DMA completion evidence and all four software
 * CRCs agree.  Every unrelated data-path fault remains fatal.
 */
static sdc_cmd6_transfer_result_t sdc_lld_cmd6_transfer(
    SDCDriver* sdcp,
    const uint32_t argument,
    uint8_t transfer[MMCSD_CMD6_ERRATUM_TRANSFER_BYTES]) {
    LPC_SDMMC_DESC_Type desc[1];
    uint32_t resp[1] = {0};
    uint32_t raw_status = 0;
    uint32_t dma_status = 0;
    uint32_t diagnostic_flags = 0;
    bool_t wait_failed;
    bool_t status_valid;
    bool_t crc_valid;
    size_t i;

    sdc_lld_cmd6_diagnostic_begin(argument);
    for (i = 0; i < MMCSD_CMD6_ERRATUM_TRANSFER_BYTES; ++i)
        transfer[i] = (uint8_t)(0xA5U ^ (uint8_t)i);

    if (_sdc_wait_for_transfer_state(sdcp))
        return SDC_CMD6_TRANSFER_ERROR;

    sdio_reset_dma_and_fifo();
    sdio_dma_interrupts_clear();
    if (sdc_llc_prepare_descriptors_chained(
            desc, 1U, transfer, MMCSD_CMD6_ERRATUM_TRANSFER_BYTES) == CH_FAILED)
        return SDC_CMD6_TRANSFER_ERROR;

    LPC_SDMMC->DBADDR = (uint32_t)&desc;
    sdio_interrupts_clear();
    sdio_interrupts_set_mask(
        (1U << 3)     /* DTO: Data transfer over */
        | (1U << 7)   /* DCRC: expected SD/MMC.1 terminal indication */
        | (1U << 9)   /* DRTO: Data read time-out */
        | (1U << 10)  /* HTO: Data starvation-by-host time-out */
        | (1U << 11)  /* FRUN: FIFO underrun/overrun */
        | (1U << 12)  /* HLE: Hardware locked write error */
        | (1U << 13)  /* SBE: Start-bit error */
        | (1U << 15)  /* EBE: End-bit error */
    );
    LPC_SDMMC->BLKSIZ = MMCSD_CMD6_STATUS_BYTES;
    LPC_SDMMC->BYTCNT = MMCSD_CMD6_ERRATUM_TRANSFER_BYTES;

    if (sdc_lld_send_cmd_data_read(
            sdcp, MMCSD_CMD_SWITCH_FUNC, argument, resp) == CH_FAILED) {
        __DMB();
        sdc_lld_cmd6_diagnostic_capture(
            resp[0], LPC_SDMMC->RINTSTS, LPC_SDMMC->IDSTS,
            desc[0].DESC0, 0);
        goto error;
    }

    if (sdc_cmd6_r1_is_illegal_only(
            resp[0], MMCSD_R1_ERROR_MASK, MMCSD_R1_ILLEGAL_COMMAND)) {
        __DMB();
        sdc_lld_cmd6_diagnostic_capture(
            resp[0], LPC_SDMMC->RINTSTS, LPC_SDMMC->IDSTS,
            desc[0].DESC0, SDC_CMD6_DIAG_ILLEGAL_COMMAND);
        sdio_interrupts_set_mask(0);
        sdio_interrupts_clear();
        sdio_dma_interrupts_clear();
        sdio_reset_dma_and_fifo();
        return SDC_CMD6_TRANSFER_ILLEGAL;
    }
    if (sdc_cmd6_r1_has_error(resp[0], MMCSD_R1_ERROR_MASK)) {
        __DMB();
        sdc_lld_cmd6_diagnostic_capture(
            resp[0], LPC_SDMMC->RINTSTS, LPC_SDMMC->IDSTS,
            desc[0].DESC0, 0);
        goto error;
    }

    wait_failed =
        sdc_lld_cmd6_wait_raw_status(sdcp, &raw_status) == CH_FAILED;
    __DMB();
    dma_status = LPC_SDMMC->IDSTS;
    if (wait_failed)
        diagnostic_flags |= SDC_CMD6_DIAG_WAIT_TIMEOUT;

    status_valid = sdc_cmd6_completion_status_valid(
        raw_status, dma_status, desc[0].DESC0, LPC_SDMMC->TBBCNT);
    if (status_valid)
        diagnostic_flags |= SDC_CMD6_DIAG_STATUS_VALID;

    crc_valid = sdc_cmd6_software_crc_valid(transfer);
    if (crc_valid)
        diagnostic_flags |= SDC_CMD6_DIAG_SOFTWARE_CRC_VALID;

    if (!wait_failed && status_valid && crc_valid)
        diagnostic_flags |= SDC_CMD6_DIAG_ACCEPTED;

    sdc_lld_cmd6_diagnostic_capture(
        resp[0], raw_status, dma_status, desc[0].DESC0, diagnostic_flags);

    if (wait_failed) {
        sdcp->errors |= SDC_DATA_TIMEOUT;
        goto error;
    }
    if (!status_valid) {
        sdc_lld_collect_errors(sdcp, raw_status);
        goto error;
    }
    if (!crc_valid) {
        sdcp->errors |= SDC_DATA_CRC_ERROR;
        goto error;
    }

    /* DCRC and IDMAC CES summarize the documented LPC4320 false positive. */
    sdio_interrupts_clear();
    sdio_dma_interrupts_clear();
    return SDC_CMD6_TRANSFER_OK;

error:
    sdc_lld_error_cleanup(sdcp, 1U, resp);
    /* A forced-25 MHz reconnect must retain a usable internal DMA engine. */
    sdio_reset_dma_and_fifo();
    sdio_dma_enable();
    return SDC_CMD6_TRANSFER_ERROR;
}
#endif

/*===========================================================================*/
/* Driver interrupt handlers.                                                */
/*===========================================================================*/

CH_IRQ_HANDLER(SDIO_IRQHandler) {
    CH_IRQ_PROLOGUE();

    /* Don't clear interrupt flags, just mask off flags to disable interrupts
     * until the the handler thread can deal with them.
     */
    /* TODO: Does this kill future interrupts if thread is ever NULL? In that
     * case, would it be wise in that case to clear the interrupts instead of
     * masking them?
     */
    sdio_interrupts_set_mask(0);

    chSysLockFromIsr();
    if (SDCD1.thread != NULL) {
        chSchReadyI(SDCD1.thread);
        SDCD1.thread = NULL;
    }
    chSysUnlockFromIsr();

    CH_IRQ_EPILOGUE();
}

/*===========================================================================*/
/* Driver exported functions.                                                */
/*===========================================================================*/

/**
 * @brief   Low level SDC driver initialization.
 *
 * @notapi
 */
void sdc_lld_init(void) {
    sdcObjectInit(&SDCD1);
    SDCD1.resources = &sdio_resources;
    SDCD1.thread = NULL;

    /* Assuming there's a global reset when the hardware is initialized.
     */
    /* sdio_reset_rgu(); */
}

/**
 * @brief   Configures and activates the SDC peripheral.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 *
 * @notapi
 */
void sdc_lld_start(SDCDriver* sdcp) {
    if (sdcp->state == BLK_STOP) {
        base_clock_enable(&sdcp->resources->base);
        branch_clock_enable(&sdcp->resources->branch_register_if);
        branch_clock_enable(&sdcp->resources->branch_peripheral);
        peripheral_reset(&sdcp->resources->reset);

        LPC_SDMMC->CLKENA = (1U << 16); /* CCLK_LOW_POWER */

        sdio_reset();
        sdio_reset_card();

        // Test jig tests:
        // SAMPLE_DELAY  Write    Read      SDC    FAIL    OK
        //       0        OK       OK       OK             3
        //       2        OK       OK       OK             1
        //       3        OK       OK       OK             1
        //       4        OK     f_read 1   0x2      3     2 (20170424 fails, 20170522 OK)
        //       5        OK     f_read 1   0x2      1
        // UM10503 recommendation: SAMPLE_DELAY=0x8, DRV_DELAY=0xF
        // Datasheet recommendation: SAMPLE_DELAY=0x9, DRV_DELAY=0xD
        LPC_SCU->SDDELAY =
            (0x0 << 0) | (0xa << 8) /* >6ns hold with low clk/dat/cmd output drive */
            ;
        LPC_SDMMC->CTRL =
            (1U << 4)    /* INT_ENABLE */
            | (1U << 25) /* USE_INTERNAL_DMAC */
            ;

        const uint32_t fifo_depth = 32;
        LPC_SDMMC->FIFOTH =
            (((fifo_depth / 2) - 0) << 0)    /* TX watermark */
            | (((fifo_depth / 2) - 1) << 16) /* RX watermark */
            | (1U << 28)                     /* DMA multiple transaction burst size: 4 transfers */
            ;

        LPC_SDMMC->BMOD =
            (4U << 2)   /* Descriptor skip length = 4 */
            | (1U << 7) /* DE: DMA Enable */
            | (1U << 8) /* Burst length = 4 */
            ;

        sdio_cclk_set_400khz();

        /* TODO: Choose which interrupts to enable! */
        sdio_interrupts_set_mask(0);
        sdio_interrupts_clear();

        interrupt_enable(&sdcp->resources->interrupt);
    }
}

/**
 * @brief   Deactivates the SDC peripheral.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 *
 * @notapi
 */
void sdc_lld_stop(SDCDriver* sdcp) {
    if (sdcp->state != BLK_STOP) {
        interrupt_disable(&sdcp->resources->interrupt);

        /* Quickest way to return peripheral and card to known (and low power)
         * state is to reset both. Right?
         */
        sdio_reset();
        sdio_reset_card();

        peripheral_reset(&sdcp->resources->reset);
        branch_clock_disable(&sdcp->resources->branch_peripheral);
        branch_clock_disable(&sdcp->resources->branch_register_if);
        base_clock_disable(&sdcp->resources->base);
    }
}

/**
 * @brief   Starts the SDIO clock and sets it to init mode (400kHz or less).
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 *
 * @notapi
 */
void sdc_lld_start_clk(SDCDriver* sdcp) {
    (void)sdcp;
    sdio_cclk_set_400khz();
    /* TODO: Reset card using CMD0 + init flag? */
    if (sdio_send_command(sdcp, 0 | (1U << 15), 0) != CH_SUCCESS)
        for (;;)
            ;
}

/**
 * @brief   Sets the SDIO clock to data mode (25MHz or less).
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 *
 * @notapi
 */
void sdc_lld_set_data_clk(SDCDriver* sdcp) {
    (void)sdcp;
    sdio_cclk_set_fast();
}

#if defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC)
sdccmd6result_t sdc_lld_try_high_speed(SDCDriver* sdcp) {
    uint8_t transfer[MMCSD_CMD6_ERRATUM_TRANSFER_BYTES]
        __attribute__((aligned(4)));
    sdc_cmd6_transfer_result_t transfer_result;
    sdc_cmd6_status_result_t status_result;
    unsigned query_attempt;

    for (query_attempt = 0; query_attempt < 10U; ++query_attempt) {
        transfer_result = sdc_lld_cmd6_transfer(
            sdcp, MMCSD_CMD6_CHECK_HIGH_SPEED, transfer);
        if (transfer_result == SDC_CMD6_TRANSFER_ILLEGAL)
            return SDC_CMD6_NEGOTIATION_UNSUPPORTED;
        if (transfer_result != SDC_CMD6_TRANSFER_OK)
            return SDC_CMD6_NEGOTIATION_ERROR;

        status_result = sdc_cmd6_query_high_speed(transfer);
        if (status_result != SDC_CMD6_STATUS_BUSY)
            break;
        if (query_attempt != 9U)
            chThdSleepMilliseconds(10);
    }
    if (status_result == SDC_CMD6_STATUS_BUSY)
        return SDC_CMD6_NEGOTIATION_BUSY;
    if (status_result == SDC_CMD6_STATUS_UNSUPPORTED)
        return SDC_CMD6_NEGOTIATION_UNSUPPORTED;
    if (status_result != SDC_CMD6_STATUS_READY)
        return SDC_CMD6_NEGOTIATION_ERROR;

    transfer_result = sdc_lld_cmd6_transfer(
        sdcp, MMCSD_CMD6_SWITCH_HIGH_SPEED, transfer);
    if (transfer_result != SDC_CMD6_TRANSFER_OK)
        return SDC_CMD6_NEGOTIATION_ERROR;

    status_result = sdc_cmd6_confirm_high_speed(transfer);
    if (status_result == SDC_CMD6_STATUS_SELECTED)
        return SDC_CMD6_NEGOTIATION_ENABLED;
    if (status_result == SDC_CMD6_STATUS_UNSUPPORTED)
        return SDC_CMD6_NEGOTIATION_UNSUPPORTED;
    return SDC_CMD6_NEGOTIATION_ERROR;
}

void sdc_lld_set_high_speed_clk(SDCDriver* sdcp) {
    (void)sdcp;
    /*
     * Eight 25 MHz card clocks are 320 ns. The SDIO divider and the M0 run
     * from the same fixed 200 MHz application clock, so 200 counter ticks
     * provide a conservative one-microsecond settling interval.
     */
    halPolledDelay(200U);
    sdio_cclk_set_high_speed();
}

#endif

/**
 * @brief   Stops the SDIO clock.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 *
 * @notapi
 */
void sdc_lld_stop_clk(SDCDriver* sdcp) {
    (void)sdcp;
    sdio_cclk_disable();
}

/**
 * @brief   Switches the bus to 4 bits mode.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] mode      bus mode
 *
 * @notapi
 */
void sdc_lld_set_bus_mode(SDCDriver* sdcp, sdcbusmode_t mode) {
    (void)sdcp;

    switch (mode) {
        case SDC_MODE_1BIT:
            sdio_width_set_1bit();
            break;

        case SDC_MODE_4BIT:
            sdio_width_set_4bit();
            break;

        case SDC_MODE_8BIT:
            sdio_width_set_8bit();
            break;
    }
}

/**
 * @brief   Sends an SDIO command with no response expected.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] cmd       card command
 * @param[in] arg       command argument
 *
 * @notapi
 */
void sdc_lld_send_cmd_none(SDCDriver* sdcp, uint8_t cmd, uint32_t arg) {
    (void)sdcp;

    const uint32_t status = sdio_send_command(sdcp, cmd, arg);

    if (status != CH_SUCCESS) {
        chSysHalt();
    }
}

/**
 * @brief   Sends an SDIO command with a short response expected.
 * @note    The CRC is not verified.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] cmd       card command
 * @param[in] arg       command argument
 * @param[out] resp     pointer to the response buffer (one word)
 *
 * @return              The operation status.
 * @retval CH_SUCCESS   operation succeeded.
 * @retval CH_FAILED    operation failed.
 *
 * @notapi
 */
bool_t sdc_lld_send_cmd_short(SDCDriver* sdcp, uint8_t cmd, uint32_t arg, uint32_t* resp) {
    (void)sdcp;

    const uint32_t status = sdio_send_command(
        sdcp,
        /* RESPONSE_EXPECT */
        cmd | (1U << 6),
        arg);

    if (status == CH_SUCCESS) {
        *resp = LPC_SDMMC->RESP0;
    }

    return status;
}

/**
 * @brief   Sends an SDIO command with a short response expected and CRC.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] cmd       card command
 * @param[in] arg       command argument
 * @param[out] resp     pointer to the response buffer (one word)
 *
 * @return              The operation status.
 * @retval CH_SUCCESS   operation succeeded.
 * @retval CH_FAILED    operation failed.
 *
 * @notapi
 */
bool_t sdc_lld_send_cmd_short_crc(SDCDriver* sdcp, uint8_t cmd, uint32_t arg, uint32_t* resp) {
    (void)sdcp;

    const uint32_t status = sdio_send_command(
        sdcp,
        /* RESPONSE_EXPECT | CHECK_RESPONSE_CRC */
        cmd | (1U << 6) | (1U << 8),
        arg);

    if (status == CH_SUCCESS) {
        *resp = LPC_SDMMC->RESP0;
    }

    return status;
}

/**
 * @brief   Sends an SDIO command with a long response expected and CRC.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] cmd       card command
 * @param[in] arg       command argument
 * @param[out] resp     pointer to the response buffer (four words)
 *
 * @return              The operation status.
 * @retval CH_SUCCESS   operation succeeded.
 * @retval CH_FAILED    operation failed.
 *
 * @notapi
 */
bool_t sdc_lld_send_cmd_long_crc(SDCDriver* sdcp, uint8_t cmd, uint32_t arg, uint32_t* resp) {
    (void)sdcp;

    const uint32_t status = sdio_send_command(
        sdcp,
        /* RESPONSE_EXPECT | RESPONSE_LENGTH | CHECK_RESPONSE_CRC */
        cmd | (1U << 6) | (1U << 7) | (1U << 8),
        arg);

    if (status == CH_SUCCESS) {
        *(resp++) = LPC_SDMMC->RESP0;
        *(resp++) = LPC_SDMMC->RESP1;
        *(resp++) = LPC_SDMMC->RESP2;
        *(resp) = LPC_SDMMC->RESP3;
    }

    return status;
}

/**
 * @brief   Reads one or more blocks.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] startblk  first block to read
 * @param[out] buf      pointer to the read buffer
 * @param[in] n         number of blocks to read
 *
 * @return              The operation status.
 * @retval CH_SUCCESS   operation succeeded.
 * @retval CH_FAILED    operation failed.
 *
 * @notapi
 */
bool_t sdc_lld_read_aligned(SDCDriver* sdcp, uint32_t startblk, uint8_t* buf, uint32_t n) {
    chDbgCheck((n <= (LPC_SDC_SDIO_DESCRIPTOR_COUNT * LPC_SDC_SDIO_MAX_DESCRIPTOR_BYTES / MMCSD_BLOCK_SIZE)), "max transaction size");

    /* TODO: Handle SDHC block indexing? */

    /* Checks for errors and waits for the card to be ready for reading.*/
    if (_sdc_wait_for_transfer_state(sdcp))
        return CH_FAILED;

    sdio_reset_dma_and_fifo();

    /* Prepares the DMA channel for writing.*/
    LPC_SDMMC_DESC_Type desc[LPC_SDC_SDIO_DESCRIPTOR_COUNT];
    if (sdc_llc_prepare_descriptors_chained(desc, sizeof(desc) / sizeof(desc[0]), buf, n * MMCSD_BLOCK_SIZE) == TRUE)
        goto error;

    LPC_SDMMC->DBADDR = (uint32_t)&desc; /* DMA is now armed? */

    /* Setting up data transfer.*/
    sdio_interrupts_clear();
    sdio_interrupts_set_mask(
        (1U << 3)    /* DTO: Data transfer over */
        | (1U << 7)  /* DCRC: Data CRC error */
        | (1U << 9)  /* DRTO: Data read time-out */
        | (1U << 10) /* HTO: Data starvation-by-host time-out */
        | (1U << 11) /* FRUN: FIFO underrun/overrun */
        | (1U << 13) /* SBE: Start-bit error */
        | (1U << 15) /* EBE: End-bit error / write no CRC */
    );

    /* TODO: Initialize once, not every time? */
    LPC_SDMMC->BLKSIZ = MMCSD_BLOCK_SIZE;

    LPC_SDMMC->BYTCNT = n * MMCSD_BLOCK_SIZE;

    /* Talk to card what we want from it.*/
    uint32_t resp[1];
    if (sdc_lld_prepare_read(sdcp, startblk, n, resp) == TRUE)
        goto error;
    if (sdc_lld_wait_transaction_end(sdcp, n, resp) == TRUE)
        goto error;

    return CH_SUCCESS;

error:
    sdc_lld_error_cleanup(sdcp, n, resp);
    return CH_FAILED;
}

/**
 * @brief   Writes one or more blocks.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] startblk  first block to write
 * @param[out] buf      pointer to the write buffer
 * @param[in] n         number of blocks to write
 *
 * @return              The operation status.
 * @retval CH_SUCCESS   operation succeeded.
 * @retval CH_FAILED    operation failed.
 *
 * @notapi
 */
bool_t sdc_lld_write_aligned(SDCDriver* sdcp, uint32_t startblk, const uint8_t* buf, uint32_t n) {
    chDbgCheck((n <= (LPC_SDC_SDIO_DESCRIPTOR_COUNT * LPC_SDC_SDIO_MAX_DESCRIPTOR_BYTES / MMCSD_BLOCK_SIZE)), "max transaction size");

#if defined(LPC43XX_M0) && defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC)
    const bool capture_timing_write = sdc_capture_timing_active;
    const uint32_t capture_ready_start =
        capture_timing_write ? halGetCounterValue() : 0U;
#endif
#if defined(LPC43XX_M0) && \
    defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC) && \
    defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
    const bool capture_preerase_write = capture_timing_write && n > 1U;
    sdc_acmd23_result_t capture_preerase_result = SDC_ACMD23_FALLBACK;
#endif

    /* Checks for errors and waits for the card to be ready for writing.*/
    if (_sdc_wait_for_transfer_state(sdcp))
        return CH_FAILED;

#if defined(LPC43XX_M0) && defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC)
    const uint32_t capture_transfer_start =
        capture_timing_write ? halGetCounterValue() : 0U;
    const uint32_t capture_ready_ticks =
        capture_transfer_start - capture_ready_start;
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
    if (capture_timing_write &&
        capture_ready_ticks > sdc_capture_timing.residual_ready_max_ticks)
        sdc_capture_timing.residual_ready_max_ticks = capture_ready_ticks;
#endif
#endif

#if defined(LPC43XX_M0) && \
    defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC) && \
    defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
    if (capture_preerase_write) {
        capture_preerase_result = sdc_lld_capture_preerase(sdcp, n);
        if (capture_preerase_result == SDC_ACMD23_FATAL) {
            sdc_capture_timing.packed_counts |=
                SDC_CAPTURE_TIMING_HINT_FATAL_FLAG;
            return CH_FAILED;
        }
    }
#endif

    sdio_reset_dma_and_fifo();

    /* Prepares the DMA channel for writing.*/
    LPC_SDMMC_DESC_Type desc[LPC_SDC_SDIO_DESCRIPTOR_COUNT];
    if (sdc_llc_prepare_descriptors_chained(desc, sizeof(desc) / sizeof(desc[0]), buf, n * MMCSD_BLOCK_SIZE) == TRUE)
        goto error;

    LPC_SDMMC->DBADDR = (uint32_t)&desc; /* DMA is now armed? */

    /* Setting up data transfer.*/
    sdio_interrupts_clear();
    sdio_interrupts_set_mask(
        (1U << 3)    /* DTO: Data transfer over */
        | (1U << 7)  /* DCRC: Data CRC error */
        | (1U << 9)  /* DRTO: Data read time-out */
        | (1U << 10) /* HTO: Data starvation-by-host time-out */
        | (1U << 11) /* FRUN: FIFO underrun/overrun */
        | (1U << 13) /* SBE: Start-bit error */
        | (1U << 15) /* EBE: End-bit error / write no CRC */
    );

    /* TODO: Initialize once, not every time? */
    LPC_SDMMC->BLKSIZ = MMCSD_BLOCK_SIZE;

    LPC_SDMMC->BYTCNT = n * MMCSD_BLOCK_SIZE;

    /* Talk to card what we want from it.*/
    uint32_t resp[1];
    if (sdc_lld_prepare_write(sdcp, startblk, n, resp) == TRUE)
        goto error;
    if (sdc_lld_wait_transaction_end(sdcp, n, resp) == TRUE)
        goto error;

#if defined(LPC43XX_M0) && defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC)
    if (capture_timing_write) {
        const uint32_t transfer_ticks =
            halGetCounterValue() - capture_transfer_start;
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
        if (transfer_ticks > sdc_capture_timing.transfer_max_ticks)
            sdc_capture_timing.transfer_max_ticks = transfer_ticks;
#else
        sdc_capture_timing.ready_total_ticks += capture_ready_ticks;
        sdc_capture_timing.transfer_total_ticks += transfer_ticks;
        if (capture_ready_ticks > sdc_capture_timing.ready_max_ticks)
            sdc_capture_timing.ready_max_ticks = capture_ready_ticks;
        if (transfer_ticks > sdc_capture_timing.transfer_max_ticks)
            sdc_capture_timing.transfer_max_ticks = transfer_ticks;
        ++sdc_capture_timing.transaction_count;
#endif
    }
#endif
#if defined(LPC43XX_M0) && \
    defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC) && \
    defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
    if (capture_preerase_write)
        sdc_lld_capture_count_preerase(capture_preerase_result);
#endif

    return CH_SUCCESS;

error:
    sdc_lld_error_cleanup(sdcp, n, resp);
    return CH_FAILED;
}

/**
 * @brief   Reads one or more blocks.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] startblk  first block to read
 * @param[out] buf      pointer to the read buffer
 * @param[in] n         number of blocks to read
 *
 * @return              The operation status.
 * @retval CH_SUCCESS   operation succeeded.
 * @retval CH_FAILED    operation failed.
 *
 * @notapi
 */
bool_t sdc_lld_read(SDCDriver* sdcp, uint32_t startblk, uint8_t* buf, uint32_t n) {
    return sdc_lld_read_aligned(sdcp, startblk, buf, n);
}

/**
 * @brief   Writes one or more blocks.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 * @param[in] startblk  first block to write
 * @param[out] buf      pointer to the write buffer
 * @param[in] n         number of blocks to write
 *
 * @return              The operation status.
 * @retval CH_SUCCESS  operation succeeded.
 * @retval CH_FAILED    operation failed.
 *
 * @notapi
 */
bool_t sdc_lld_write(SDCDriver* sdcp, uint32_t startblk, const uint8_t* buf, uint32_t n) {
    return sdc_lld_write_aligned(sdcp, startblk, buf, n);
}

/**
 * @brief   Waits for card idle condition.
 *
 * @param[in] sdcp      pointer to the @p SDCDriver object
 *
 * @return              The operation status.
 * @retval CH_SUCCESS   the operation succeeded.
 * @retval CH_FAILED    the operation failed.
 *
 * @api
 */
bool_t sdc_lld_sync(SDCDriver* sdcp) {
    (void)sdcp;

    return CH_SUCCESS;
}

bool_t sdc_lld_is_card_inserted(SDCDriver* sdcp) {
    (void)sdcp;
    return (LPC_SDMMC->CDETECT & (1U << 0)) ? FALSE : TRUE;
}

bool_t sdc_lld_is_write_protected(SDCDriver* sdcp) {
    (void)sdcp;
    return (LPC_SDMMC->WRTPRT & (1U << 0)) ? TRUE : FALSE;
}

#endif /* HAL_USE_SDC */

/** @} */
