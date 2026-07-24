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

#include "ui.hpp"
#include "ui_precision_rx.hpp"
#include "ui_navigation.hpp"
#include "external_app.hpp"

namespace ui::external_app::precision_rx {
void initialize_app(ui::NavigationView& nav) {
    nav.push<PrecisionRxView>();
}
}  // namespace ui::external_app::precision_rx

extern "C" {
__attribute__((section(".external_app.app_precision_rx.application_information"), used)) application_information_t _application_information_precision_rx = {
    /*.memory_location = */ (uint8_t*)0x00000000,
    /*.externalAppEntry = */ ui::external_app::precision_rx::initialize_app,
    /*.header_version = */ CURRENT_HEADER_VERSION,
    /*.build_fingerprint = */ {},
    /*.app_name = */ "Precision RX",
    /*.bitmap_data = */ {
        0x00, 0x00, 0xC0, 0x03, 0x30, 0x0C, 0x08, 0x10,
        0xE4, 0x27, 0x12, 0x48, 0x09, 0x90, 0x05, 0xA0,
        0x05, 0xA0, 0x09, 0x90, 0x12, 0x48, 0xE4, 0x27,
        0x08, 0x10, 0x30, 0x0C, 0xC0, 0x03, 0x00, 0x00},
    /*.icon_color = */ ui::Color::cyan().v,
    /*.menu_location = */ app_location_t::RX,
    /*.desired_menu_position = */ -1,
    /*.m4_app_tag = */ {'P', 'R', 'X', '1'},
    /*.m4_app_offset = */ 0x00000000,
};
}
