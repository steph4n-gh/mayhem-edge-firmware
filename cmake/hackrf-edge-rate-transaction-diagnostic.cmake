# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# Nonpromotable p12 initializer. Keep p11's discontiguous monitor lease and
# add an overwrite-aware completion queue plus transactional Precision RX
# sampling-rate changes.
include("${CMAKE_CURRENT_LIST_DIR}/hackrf-edge-dma-lease-diagnostic.cmake")

set(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC ON CACHE BOOL
    "Use queued DMA completions and transactional Precision RX rate changes" FORCE)
set(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC ON CACHE BOOL
    "Load a bounded Precision RX M0 auxiliary segment from its p12 PPMA" FORCE)
