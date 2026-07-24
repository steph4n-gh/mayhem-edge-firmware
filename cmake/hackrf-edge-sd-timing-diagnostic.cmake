# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# Nonpromotable diagnostic initializer.  This keeps the qualified experimental
# configuration while permitting the timing probe to use otherwise reserved
# aggregate padding.  The generated image must still fit the physical 1 MiB
# boundary and pass exact readback before use.
include("${CMAKE_CURRENT_LIST_DIR}/hackrf-edge-experimental.cmake")

set(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC ON CACHE BOOL
    "Instrument Precision RX SD write latency" FORCE)
set(MAYHEM_AGGREGATE_MIN_REMAINING_BYTES 64 CACHE STRING
    "Diagnostic-only minimum aggregate flash bytes that must remain" FORCE)
