# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# Nonpromotable p11 initializer. Keep p10's allocations and borrow local
# capture block eight only while StreamInput is unbound, yielding a 16 KiB
# monitor ring without adding heap demand. Capture returns to p10's compact
# 8 KiB ring before the block is rebound.
include("${CMAKE_CURRENT_LIST_DIR}/hackrf-edge-hybrid-pool-diagnostic.cmake")

set(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC ON CACHE BOOL
    "Lease one unbound Precision RX capture block to the monitor DMA ring" FORCE)
