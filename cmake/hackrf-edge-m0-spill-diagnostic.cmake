# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# Nonpromotable p9 initializer.  Retain p8's measured SD path and append three
# checked M0-owned 8 KiB buffers to the Precision RX cross-core descriptor
# pool.  The M4-local allocation remains exactly 64 KiB.
include("${CMAKE_CURRENT_LIST_DIR}/hackrf-edge-sd-preerase-diagnostic.cmake")

set(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC ON CACHE BOOL
    "Loan three M0 shared-SRAM buffers to Precision RX" FORCE)
