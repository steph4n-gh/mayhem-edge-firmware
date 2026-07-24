# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

# Cache initializer for the pinned HackRF Edge experimental aggregate build.
# Use with: cmake -C cmake/hackrf-edge-experimental.cmake -S . -B build ...

set(FLASH_MB_SIZE 1 CACHE STRING
    "Physical SPI flash capacity of the qualified standard HackRF One" FORCE)
set(FLASH_MB_LIMIT_SIZE 1 CACHE STRING
    "Maximum aggregate span for the qualified standard HackRF One" FORCE)
set(MAYHEM_AGGREGATE_SIZE_POLICY ON CACHE BOOL
    "Enforce aggregate firmware flash headroom" FORCE)
set(MAYHEM_AGGREGATE_MIN_REMAINING_BYTES 512 CACHE STRING
    "Minimum aggregate flash bytes that must remain" FORCE)
set(MAYHEM_AGGREGATE_WARNING_REMAINING_BYTES 16384 CACHE STRING
    "Emit a maintenance warning below this aggregate flash headroom" FORCE)
set(MAYHEM_LZ4_COMPRESSION_LEVEL 12 CACHE STRING
    "LZ4 compression level for embedded baseband chunks" FORCE)
set(MAYHEM_LZ4_NO_FRAME_CRC ON CACHE BOOL
    "Omit unused LZ4 frame content checksums from embedded chunks" FORCE)
set(HACKRF_EDGE_SD_TIMING_DIAGNOSTIC OFF CACHE BOOL
    "Instrument Precision RX SD write latency" FORCE)
set(HACKRF_EDGE_SD_PREERASE_DIAGNOSTIC OFF CACHE BOOL
    "Stage Precision RX writes and issue ACMD23 pre-erase hints" FORCE)
set(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC OFF CACHE BOOL
    "Loan three M0 shared-SRAM buffers to Precision RX" FORCE)
set(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC OFF CACHE BOOL
    "Use the p10 nine-local/two-spill Precision RX pool and compact DMA ring" FORCE)
set(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC OFF CACHE BOOL
    "Lease one unbound Precision RX capture block to the monitor DMA ring" FORCE)
set(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC OFF CACHE BOOL
    "Use queued DMA completions and transactional Precision RX rate changes" FORCE)
set(HACKRF_EDGE_PRECISION_RX_SEGMENTED_PPMA_DIAGNOSTIC OFF CACHE BOOL
    "Load a bounded Precision RX M0 auxiliary segment from its p12 PPMA" FORCE)
set(HACKRF_EDGE_SD_FAST_RESERVE_EXPERIMENT OFF CACHE BOOL
    "Use metadata-only contiguous reservation for Precision RX" FORCE)
set(HACKRF_EDGE_SD_CMD6_DIAGNOSTIC OFF CACHE BOOL
    "Negotiate and instrument standards-compliant SD High Speed" FORCE)
set(HACKRF_EDGE_SD_SAFE_DEFAULT_SPEED OFF CACHE BOOL
    "Force the SD bus to standards-safe 25 MHz Default Speed" FORCE)
set(HACKRF_EDGE_M4_EXTRA_FLAGS
    "-fipa-pta -fno-inline-functions-called-once -fno-ipa-sra -fno-partial-inlining"
    CACHE STRING "Additional size flags for the experimental HackRF M4 image" FORCE)
