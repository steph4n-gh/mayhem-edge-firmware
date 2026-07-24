# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# Nonpromotable A/B initializer.  Keep the SD timing probes enabled while
# replacing the confidentiality-safe foreground zero scrub with metadata-only
# allocation plus a bounded multi-fragment CLMT requirement.  Interrupted PART
# files can expose stale sectors, so this configuration is evidence-only.
include("${CMAKE_CURRENT_LIST_DIR}/hackrf-edge-sd-timing-diagnostic.cmake")

set(HACKRF_EDGE_SD_FAST_RESERVE_EXPERIMENT ON CACHE BOOL
    "Use metadata-only contiguous reservation for Precision RX" FORCE)
set(HACKRF_EDGE_SD_SAFE_DEFAULT_SPEED ON CACHE BOOL
    "Force the SD bus to standards-safe 25 MHz Default Speed" FORCE)
