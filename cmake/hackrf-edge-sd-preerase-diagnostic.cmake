# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# Nonpromotable p7 A/B initializer.  Add one checked 8 KiB M0 debt buffer and
# standards-compliant ACMD23 pre-erase hints to the p6 8 KiB x 8 pipeline.
# The interrupted-file confidentiality caveat of metadata-only reservation
# still applies; this image is for sealed HIL evidence only.
include("${CMAKE_CURRENT_LIST_DIR}/hackrf-edge-sd-fast-reserve-diagnostic.cmake")

set(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC ON CACHE BOOL
    "Stage Precision RX writes and issue ACMD23 pre-erase hints" FORCE)
