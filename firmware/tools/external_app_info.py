#!/usr/bin/env python3

#
# Copyright (C) 2024 Mark Thompson
# Modified for HackRF Edge in 2026 by HackRF Edge contributors.
#
# This file is part of PortaPack.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#

# external app address ranges below must match those in linker file "external.ld"
maximum_application_size = 32*1024
external_apps_address_start = 0xADB00000
external_apps_address_end = 0xAE0E0000

# P12 Precision RX keeps the legacy main-app window but links two bounded
# auxiliary sections far enough away to force absolute Thumb-1 veneers from
# the main image. Their fake spacing exactly matches their runtime spacing, so
# direct branches between the two auxiliary sections remain valid.
precision_rx_m4_panic_context_reserved_size = 112
precision_rx_aux0_fake_address = 0xCE0D0000
precision_rx_aux0_load_address = 0x100890D8
precision_rx_aux0_maximum_size = 2384
precision_rx_aux1_fake_address = 0xCE0D0988
precision_rx_aux1_load_address = 0x10089A60
precision_rx_aux1_maximum_size = 1440
precision_rx_segmented_maximum_file_size = 36*1024
