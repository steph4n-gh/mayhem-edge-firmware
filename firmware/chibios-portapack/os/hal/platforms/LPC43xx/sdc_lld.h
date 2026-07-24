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
 * @file    LPC43xx/sdc_lld.h
 * @brief   LPC43xx SDC subsystem low level driver header.
 *
 * @addtogroup SDC
 * @{
 */

#ifndef _SDC_LLD_H_
#define _SDC_LLD_H_

#if defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC)
#include "sd_cmd6_workaround.h"
#endif

#if HAL_USE_SDC || defined(__DOXYGEN__)

/*===========================================================================*/
/* Driver constants.                                                         */
/*===========================================================================*/

/*===========================================================================*/
/* Driver pre-compile time settings.                                         */
/*===========================================================================*/

/**
 * @name    Configuration options
 * @{
 */
/**
 * @brief   SDC driver enable switch.
 * @details If set to @p TRUE the support for SDC1 is included.
 */
#if !defined(LPC_SDC_USE_SDC1) || defined(__DOXYGEN__)
#define LPC_SDC_USE_SDC1               TRUE
#endif

 /**
 * @brief   SDIO interrupt priority level setting.
 */
#if !defined(LPC_SDC_SDIO_IRQ_PRIORITY) || defined(__DOXYGEN__)
#define LPC_SDC_SDIO_IRQ_PRIORITY         7
#endif

/**
 * @brief   SDIO read/write descriptor count.
 */
#if !defined(LPC_SDC_SDIO_DESCRIPTOR_COUNT) || defined(__DOXYGEN__)
#define LPC_SDC_SDIO_DESCRIPTOR_COUNT     4
#endif

/** @} */

/*===========================================================================*/
/* Derived constants and error checks.                                       */
/*===========================================================================*/

#if !CORTEX_IS_VALID_KERNEL_PRIORITY(LPC_SDC_SDIO_IRQ_PRIORITY)
#error "Invalid IRQ priority assigned to SDIO"
#endif

/*===========================================================================*/
/* Driver data structures and types.                                         */
/*===========================================================================*/

/**
 * @brief   Type of SDIO bus mode.
 */
typedef enum {
  SDC_MODE_1BIT = 0,
  SDC_MODE_4BIT,
  SDC_MODE_8BIT
} sdcbusmode_t;

/**
 * @brief   Type of card flags.
 */
typedef uint32_t sdcmode_t;

/**
 * @brief   SDC Driver condition flags type.
 */
typedef uint32_t sdcflags_t;

#if defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC)
/**
 * @brief Retained evidence from the most recent CMD6 data transaction.
 * @note  This diagnostic is captured before error cleanup clears the
 *        controller and IDMAC status registers.
 */
typedef struct {
  uint32_t sequence;
  uint32_t argument;
  uint32_t response;
  uint32_t raw_status;
  uint32_t dma_status;
  uint32_t transferred_card_bytes;
  uint32_t transferred_fifo_bytes;
  uint32_t descriptor_status;
  uint32_t block_size;
  uint32_t byte_count;
  uint32_t flags;
} sdccmd6diagnostic_t;

#define SDC_CMD6_DIAG_WAIT_TIMEOUT       (1U << 0)
#define SDC_CMD6_DIAG_SOFTWARE_CRC_VALID (1U << 1)
#define SDC_CMD6_DIAG_STATUS_VALID       (1U << 2)
#define SDC_CMD6_DIAG_ACCEPTED           (1U << 3)
#define SDC_CMD6_DIAG_ILLEGAL_COMMAND    (1U << 4)

extern volatile sdccmd6diagnostic_t SDCD1_cmd6_diagnostic;
#endif

#if defined(LPC43XX_M0) && defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC)
/**
 * @brief Raw counter evidence for Precision RX capture SD writes.
 * @note  The signed RF aggregate fields in PRX1 carry these words verbatim in
 *        the diagnostic build; the host decoder reinterprets them as uint32_t.
 */
typedef struct {
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
  uint32_t recycle_gap_total_ticks;
  uint32_t recycle_gap_max_ticks;
  uint32_t pre_ready_total_ticks;
  uint32_t pre_ready_max_ticks;
  uint32_t residual_ready_max_ticks;
  uint32_t transfer_max_ticks;
  uint32_t packed_counts;
  uint32_t counter_frequency_hz;
#else
  uint32_t writer_total_ticks;
  uint32_t writer_max_ticks;
  uint32_t ready_total_ticks;
  uint32_t ready_max_ticks;
  uint32_t transfer_total_ticks;
  uint32_t transfer_max_ticks;
  uint32_t transaction_count;
  uint32_t counter_frequency_hz;
#endif
} sdccapturetiming_t;

#define SDC_CAPTURE_TIMING_HIGH_SPEED_FLAG (1U << 31)
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
#define SDC_CAPTURE_TIMING_HINT_FATAL_FLAG  (1U << 30)
#define SDC_CAPTURE_TIMING_FIFO_SHIFT       26U
#define SDC_CAPTURE_TIMING_FIFO_MASK        (0xFU << SDC_CAPTURE_TIMING_FIFO_SHIFT)
#define SDC_CAPTURE_TIMING_FALLBACK_SHIFT   13U
#define SDC_CAPTURE_TIMING_COUNT_MASK       0x1FFFU
#endif
#endif

/**
 * @brief   Type of a structure representing an SDC driver.
 */
typedef struct SDCDriver SDCDriver;

/**
 * @brief   Driver configuration structure.
 * @note    It could be empty on some architectures.
 */
typedef struct {
  uint32_t                  dummy;
} SDCConfig;

/**
 * @brief   @p SDCDriver specific methods.
 */
#define _sdc_driver_methods                                                 \
  _mmcsd_block_device_methods

/**
 * @extends MMCSDBlockDeviceVMT
 *
 * @brief   @p SDCDriver virtual methods table.
 */
struct SDCDriverVMT {
  _sdc_driver_methods
};

/**
 * @brief   Structure representing an SDC driver.
 */
struct SDCDriver {
  /**
   * @brief Virtual Methods Table.
   */
  const struct SDCDriverVMT *vmt;
  _mmcsd_block_device_data
  /**
   * @brief Current configuration data.
   */
  const SDCConfig           *config;
  /**
   * @brief Various flags regarding the mounted card.
   */
  sdcmode_t                 cardmode;
  /**
   * @brief Errors flags.
   */
  sdcflags_t                errors;
  /**
   * @brief Card RCA.
   */
  uint32_t                  rca;
  /* End of the mandatory fields.*/
  /**
   * @brief Pointer to the non-peripheral SDIO resources.
   */
  const sdio_resources_t * resources;
  /**
   * @brief Thread waiting for I/O completion IRQ.
   */
  Thread                    *thread;
};

/*===========================================================================*/
/* Driver macros.                                                            */
/*===========================================================================*/

/**
 * @name    R1 response utilities
 * @{
 */
/**
 * @brief   Evaluates to @p TRUE if the R1 response contains error flags.
 *
 * @param[in] r1        the r1 response
 */
#define MMCSD_R1_ERROR(r1)              (((r1) & MMCSD_R1_ERROR_MASK) != 0)

/**
 * @brief   Returns the status field of an R1 response.
 *
 * @param[in] r1        the r1 response
 */
#define MMCSD_R1_STS(r1)                (((r1) >> 9) & 15)

/**
 * @brief   Evaluates to @p TRUE if the R1 response indicates a locked card.
 *
 * @param[in] r1        the r1 response
 */
#define MMCSD_R1_IS_CARD_LOCKED(r1)     (((r1) >> 21) & 1)
/** @} */

#define LPC_SDC_SDIO_MAX_DESCRIPTOR_BYTES 0x1000

/*===========================================================================*/
/* External declarations.                                                    */
/*===========================================================================*/

#if LPC_SDC_USE_SDC1 && !defined(__DOXYGEN__)
extern SDCDriver SDCD1;
#endif

#ifdef __cplusplus
extern "C" {
#endif
  void sdc_lld_init(void);
  void sdc_lld_start(SDCDriver *sdcp);
  void sdc_lld_stop(SDCDriver *sdcp);
  void sdc_lld_start_clk(SDCDriver *sdcp);
  void sdc_lld_set_data_clk(SDCDriver *sdcp);
#if defined(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC)
  sdccmd6result_t sdc_lld_try_high_speed(SDCDriver *sdcp);
  void sdc_lld_set_high_speed_clk(SDCDriver *sdcp);
#endif
  void sdc_lld_stop_clk(SDCDriver *sdcp);
  void sdc_lld_set_bus_mode(SDCDriver *sdcp, sdcbusmode_t mode);
  void sdc_lld_send_cmd_none(SDCDriver *sdcp, uint8_t cmd, uint32_t arg);
  bool_t sdc_lld_send_cmd_short(SDCDriver *sdcp, uint8_t cmd, uint32_t arg,
                                uint32_t *resp);
  bool_t sdc_lld_send_cmd_short_crc(SDCDriver *sdcp, uint8_t cmd, uint32_t arg,
                                    uint32_t *resp);
  bool_t sdc_lld_send_cmd_long_crc(SDCDriver *sdcp, uint8_t cmd, uint32_t arg,
                                   uint32_t *resp);
  bool_t sdc_lld_read(SDCDriver *sdcp, uint32_t startblk,
                      uint8_t *buf, uint32_t n);
  bool_t sdc_lld_write(SDCDriver *sdcp, uint32_t startblk,
                       const uint8_t *buf, uint32_t n);
#if defined(LPC43XX_M0) && defined(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC)
  void sdc_lld_capture_timing_begin(void);
#if defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
  void sdc_lld_capture_timing_record_cycle(uint32_t pre_ready_ticks,
                                           uint32_t recycle_gap_ticks,
                                           uint32_t fifo_depth);
#else
  void sdc_lld_capture_timing_record_write(uint32_t ticks);
#endif
  const sdccapturetiming_t *sdc_lld_capture_timing_end(void);
#endif
#if defined(LPC43XX_M0) && defined(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC)
  void sdc_lld_capture_preerase_reset(void);
  bool_t sdc_lld_capture_wait_ready(SDCDriver *sdcp);
#endif
  bool_t sdc_lld_sync(SDCDriver *sdcp);
  bool_t sdc_lld_is_card_inserted(SDCDriver *sdcp);
  bool_t sdc_lld_is_write_protected(SDCDriver *sdcp);
#ifdef __cplusplus
}
#endif

#endif /* HAL_USE_SDC */

#endif /* _SDC_LLD_H_ */

/** @} */
