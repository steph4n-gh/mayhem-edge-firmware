/*
 * Copyright (C) 2026 HackRF Edge contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "doctest.h"
#include "sd_cmd6_workaround.h"

#include <algorithm>
#include <array>
#include <cstdint>

TEST_SUITE_BEGIN("LPC4320 SD CMD6 workaround");

TEST_CASE("ambiguous CMD6 failure permits exactly one Default Speed retry") {
    CHECK(sdc_cmd6_should_retry_default_speed(true, false));
    CHECK_FALSE(sdc_cmd6_should_retry_default_speed(true, true));
    CHECK_FALSE(sdc_cmd6_should_retry_default_speed(false, false));
    CHECK_FALSE(sdc_cmd6_should_retry_default_speed(false, true));
}

TEST_CASE("CMD6 connect actions fail closed across negotiation outcomes") {
    struct Case {
        sdccmd6result_t result;
        bool default_speed_attempt;
        sdc_cmd6_connect_action_t expected;
    };
    constexpr std::array<Case, 7> cases{{
        {SDC_CMD6_NEGOTIATION_ENABLED, false,
         SDC_CMD6_CONNECT_ENABLE_HIGH_SPEED},
        {SDC_CMD6_NEGOTIATION_UNSUPPORTED, false,
         SDC_CMD6_CONNECT_KEEP_DEFAULT},
        {SDC_CMD6_NEGOTIATION_BUSY, false,
         SDC_CMD6_CONNECT_KEEP_DEFAULT},
        {SDC_CMD6_NEGOTIATION_ERROR, false,
         SDC_CMD6_CONNECT_RETRY_DEFAULT},
        {SDC_CMD6_NEGOTIATION_ERROR, true, SDC_CMD6_CONNECT_FAIL},
        {SDC_CMD6_NEGOTIATION_RECOVERED, false, SDC_CMD6_CONNECT_FAIL},
        {static_cast<sdccmd6result_t>(99), false, SDC_CMD6_CONNECT_FAIL},
    }};

    for (const auto& test : cases) {
        CHECK_EQ(
            sdc_cmd6_connect_action(test.result, test.default_speed_attempt),
            test.expected);
    }
}

TEST_CASE("CMD6 retained outcome codes are unique and preserve transport bits") {
    constexpr std::array<sdccmd6result_t, 5> results{{
        SDC_CMD6_NEGOTIATION_ERROR,
        SDC_CMD6_NEGOTIATION_UNSUPPORTED,
        SDC_CMD6_NEGOTIATION_ENABLED,
        SDC_CMD6_NEGOTIATION_RECOVERED,
        SDC_CMD6_NEGOTIATION_BUSY,
    }};
    std::array<uint32_t, results.size()> encoded{};
    for (size_t index = 0; index < results.size(); ++index) {
        encoded[index] = SDC_CMD6_DIAG_OUTCOME(results[index]);
        CHECK(encoded[index] != 0U);
        CHECK((encoded[index] & ~SDC_CMD6_DIAG_OUTCOME_MASK) == 0U);
        for (size_t prior = 0; prior < index; ++prior) {
            CHECK(encoded[index] != encoded[prior]);
        }
    }
    CHECK((SDC_CMD6_DIAG_OUTCOME_MASK & 0x1FU) == 0U);
}

TEST_CASE("CMD6 R1 validation includes SWITCH_ERROR omitted by legacy mask") {
    constexpr uint32_t legacy_error_mask = 0xFDFFE008U;
    constexpr uint32_t illegal_command = 1U << 22;

    static_assert((legacy_error_mask & SDC_CMD6_R1_SWITCH_ERROR) == 0U);
    CHECK_FALSE(sdc_cmd6_r1_has_error(0U, legacy_error_mask));
    CHECK(sdc_cmd6_r1_has_error(
        SDC_CMD6_R1_SWITCH_ERROR, legacy_error_mask));
    CHECK(sdc_cmd6_r1_has_error(illegal_command, legacy_error_mask));

    CHECK(sdc_cmd6_r1_is_illegal_only(
        illegal_command, legacy_error_mask, illegal_command));
    CHECK_FALSE(sdc_cmd6_r1_is_illegal_only(
        illegal_command | SDC_CMD6_R1_SWITCH_ERROR,
        legacy_error_mask,
        illegal_command));
}

TEST_CASE("expected DCRC is terminal only with clean DMA completion evidence") {
    constexpr uint32_t dcrc = SDC_CMD6_RINT_DCRC;
    constexpr uint32_t dto = SDC_CMD6_RINT_DTO;
    constexpr uint32_t receive = SDC_CMD6_IDSTS_RI;
    constexpr uint32_t descriptor_done = 0;

    CHECK(sdc_cmd6_completion_status_valid(
        dcrc, receive, descriptor_done, 72));
    CHECK(sdc_cmd6_completion_status_valid(
        dto | dcrc, receive, descriptor_done, 72));
    CHECK(sdc_cmd6_completion_status_valid(
        dto, receive, descriptor_done, 72));

    CHECK_FALSE(sdc_cmd6_completion_status_valid(
        0, receive, descriptor_done, 72));
    CHECK_FALSE(sdc_cmd6_completion_status_valid(
        dcrc | (1U << 9), receive, descriptor_done, 72));
    CHECK_FALSE(sdc_cmd6_completion_status_valid(
        dcrc, receive | (1U << 2), descriptor_done, 72));
    CHECK_FALSE(sdc_cmd6_completion_status_valid(
        dcrc, 0, SDC_CMD6_DESC_OWN, 72));
    CHECK_FALSE(sdc_cmd6_completion_status_valid(
        dcrc, receive, descriptor_done, 64));
}

TEST_CASE("CMD6 query accepts only supported ready High Speed") {
    std::array<uint8_t, 64> status{};
    CHECK_EQ(
        sdc_cmd6_query_high_speed(status.data()),
        SDC_CMD6_STATUS_UNSUPPORTED);

    status[13] = 0x02;
    status[16] = 0x01;
    CHECK_EQ(
        sdc_cmd6_query_high_speed(status.data()),
        SDC_CMD6_STATUS_READY);

    status[17] = 0x01;
    status[29] = 0x02;
    status[16] = 0x00;
    CHECK_EQ(
        sdc_cmd6_query_high_speed(status.data()),
        SDC_CMD6_STATUS_BUSY);

    status[17] = 0x02;
    CHECK_EQ(
        sdc_cmd6_query_high_speed(status.data()),
        SDC_CMD6_STATUS_INVALID);

    status = {};
    status[12] = 0x02;
    status[16] = 0x01;
    CHECK_EQ(
        sdc_cmd6_query_high_speed(status.data()),
        SDC_CMD6_STATUS_UNSUPPORTED);

    status = {};
    status[13] = 0x02;
    status[16] = 0x01;
    status[28] = 0x02;
    status[17] = 0x01;
    CHECK_EQ(
        sdc_cmd6_query_high_speed(status.data()),
        SDC_CMD6_STATUS_READY);

    status[29] = 0x02;
    status[17] = 0x00;
    CHECK_EQ(
        sdc_cmd6_query_high_speed(status.data()),
        SDC_CMD6_STATUS_READY);
}

TEST_CASE("CMD6 switch requires confirmed group-one selection") {
    std::array<uint8_t, 64> status{};
    CHECK_EQ(
        sdc_cmd6_confirm_high_speed(status.data()),
        SDC_CMD6_STATUS_INVALID);
    status[16] = 0x01;
    CHECK_EQ(
        sdc_cmd6_confirm_high_speed(status.data()),
        SDC_CMD6_STATUS_SELECTED);

    status[17] = 0x01;
    status[29] = 0x02;
    CHECK_EQ(
        sdc_cmd6_confirm_high_speed(status.data()),
        SDC_CMD6_STATUS_SELECTED);

    status[16] = 0x00;
    CHECK_EQ(
        sdc_cmd6_confirm_high_speed(status.data()),
        SDC_CMD6_STATUS_BUSY);

    status[29] = 0x00;
    status[16] = 0x0F;
    CHECK_EQ(
        sdc_cmd6_confirm_high_speed(status.data()),
        SDC_CMD6_STATUS_UNSUPPORTED);

    status[16] = 0x00;
    CHECK_EQ(
        sdc_cmd6_confirm_high_speed(status.data()),
        SDC_CMD6_STATUS_INVALID);

    status[17] = 0x02;
    CHECK_EQ(
        sdc_cmd6_confirm_high_speed(status.data()),
        SDC_CMD6_STATUS_INVALID);
}

TEST_CASE("software CRC validates four interleaved data lines") {
    std::array<uint8_t, 72> transfer{};
    CHECK(sdc_cmd6_software_crc_valid(transfer.data()));

    transfer.fill(0xFF);
    transfer[64] = 0x00;
    transfer[65] = 0x00;
    transfer[66] = 0x00;
    transfer[67] = 0x00;
    transfer[68] = 0x0F;
    transfer[69] = 0x00;
    transfer[70] = 0x00;
    transfer[71] = 0x0F;
    CHECK(sdc_cmd6_software_crc_valid(transfer.data()));

    transfer[0] ^= 0x01;
    CHECK_FALSE(sdc_cmd6_software_crc_valid(transfer.data()));
}

TEST_CASE("DMA poison pattern cannot masquerade as a complete transfer") {
    std::array<uint8_t, 72> transfer{};
    for (size_t i = 0; i < transfer.size(); ++i)
        transfer[i] = static_cast<uint8_t>(0xA5U ^ i);
    CHECK_FALSE(sdc_cmd6_software_crc_valid(transfer.data()));
}

TEST_CASE("software CRC preserves asymmetric DAT lane and nibble order") {
    std::array<uint8_t, 72> transfer{};
    for (size_t i = 0; i < 64; ++i)
        transfer[i] = static_cast<uint8_t>(i);

    CHECK_EQ(sdc_cmd6_payload_lane_crc(transfer.data(), 0), 0x0813);
    CHECK_EQ(sdc_cmd6_payload_lane_crc(transfer.data(), 1), 0x74AA);
    CHECK_EQ(sdc_cmd6_payload_lane_crc(transfer.data(), 2), 0xA451);
    CHECK_EQ(sdc_cmd6_payload_lane_crc(transfer.data(), 3), 0xC6DB);

    constexpr std::array<uint8_t, 8> trailer{
        0xCA, 0x62, 0x1E, 0x80, 0xAC, 0x2D, 0xA0, 0xBD};
    std::copy(trailer.begin(), trailer.end(), transfer.begin() + 64);
    CHECK(sdc_cmd6_software_crc_valid(transfer.data()));

    for (size_t bit = 0; bit < 8; ++bit) {
        auto corrupted = transfer;
        corrupted[0] ^= static_cast<uint8_t>(1U << bit);
        CHECK_FALSE(sdc_cmd6_software_crc_valid(corrupted.data()));
    }
    for (size_t bit = 0; bit < 64; ++bit) {
        auto corrupted = transfer;
        corrupted[64 + bit / 8] ^= static_cast<uint8_t>(1U << (bit % 8));
        CHECK_FALSE(sdc_cmd6_software_crc_valid(corrupted.data()));
    }
}

TEST_SUITE_END();
