# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# Nonpromotable p10 initializer. Preserve p9's eleven-descriptor capture pool
# while moving one 8 KiB descriptor from M0 to M4. A Precision-RX-only 8 KiB
# SGPIO DMA ring funds the additional M4 descriptor, leaving total modeled M4
# demand unchanged and restoring the M0 allocation to the p8-proven 16 KiB.
include("${CMAKE_CURRENT_LIST_DIR}/hackrf-edge-m0-spill-diagnostic.cmake")

set(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC ON CACHE BOOL
    "Use the p10 nine-local/two-spill Precision RX pool and compact DMA ring" FORCE)
