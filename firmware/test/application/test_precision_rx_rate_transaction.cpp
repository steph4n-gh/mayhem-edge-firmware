/*
 * Copyright (C) 2026 HackRF Edge contributors.
 *
 * This file is part of PortaPack.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */

#include "doctest.h"

#include "message.hpp"

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)

/*
 * baseband_api.hpp only needs the SPI image tag in a function declaration.
 * Avoid the target-only memory-map definitions when compiling this host test.
 */
#define __SPI_IMAGE_H__
namespace portapack::spi_flash {
struct image_tag_t;
}
#include "baseband_api.hpp"
#undef __SPI_IMAGE_H__

TEST_CASE("Precision RX rate transaction preserves the ID 115 wire contract") {
    const PrecisionRxConfigMessage rate{20'000'000U};

    CHECK(static_cast<uint32_t>(rate.id) == 115U);
    CHECK(sizeof(rate) == 8U);
    CHECK(rate.input_sample_rate_hz == 20'000'000U);
}

TEST_CASE("Precision RX rate transaction control words remain outside valid rates") {
    using namespace precision_rx::rate_control;

    CHECK(request_commit == 0x80000001U);
    CHECK(request_abort == 0x80000002U);
    CHECK(ack_configured == 0xC0000001U);
    CHECK(ack_prepared == 0xC0000002U);
    CHECK(ack_committed == 0xC0000003U);
    CHECK(ack_aborted == 0xC0000004U);
    CHECK(reject_invalid_rate == 0xE0000001U);
    CHECK(reject_state == 0xE0000002U);
    CHECK(reject_capture_active == 0xE0000003U);
    CHECK(reject_halt_timeout == 0xE0000004U);
    CHECK(reject_arm_timeout == 0xE0000005U);
    CHECK(reject_resume_timeout == 0xE0000006U);
    CHECK(reject_dma_loss == 0xE0000007U);
}

TEST_CASE("Precision RX M0 recognizes only explicit rate rejection words") {
    using baseband::is_precision_rx_rate_rejection;
    using namespace precision_rx::rate_control;

    CHECK(is_precision_rx_rate_rejection(reject_invalid_rate));
    CHECK(is_precision_rx_rate_rejection(reject_state));
    CHECK(is_precision_rx_rate_rejection(reject_capture_active));
    CHECK(is_precision_rx_rate_rejection(reject_halt_timeout));
    CHECK(is_precision_rx_rate_rejection(reject_arm_timeout));
    CHECK(is_precision_rx_rate_rejection(reject_resume_timeout));
    CHECK(is_precision_rx_rate_rejection(reject_dma_loss));

    CHECK_FALSE(is_precision_rx_rate_rejection(request_commit));
    CHECK_FALSE(is_precision_rx_rate_rejection(request_abort));
    CHECK_FALSE(is_precision_rx_rate_rejection(ack_configured));
    CHECK_FALSE(is_precision_rx_rate_rejection(ack_prepared));
    CHECK_FALSE(is_precision_rx_rate_rejection(ack_committed));
    CHECK_FALSE(is_precision_rx_rate_rejection(ack_aborted));
    CHECK_FALSE(is_precision_rx_rate_rejection(2'000'000U));
    CHECK_FALSE(is_precision_rx_rate_rejection(0xDEADBEEFU));
}

#endif
