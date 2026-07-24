# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# Nonpromotable single-variable successor to the metadata-only reservation
# diagnostic. Preserve its allocation and timing probes while adding an
# erratum-aware SD CMD6 query/switch. The host clock remains at 25 MHz unless
# the card advertises High Speed and the returned switch status passes four
# software-verified data-line CRC16 checks.
include("${CMAKE_CURRENT_LIST_DIR}/hackrf-edge-sd-fast-reserve-diagnostic.cmake")

set(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC ON CACHE BOOL
    "Negotiate and instrument standards-compliant SD High Speed" FORCE)
