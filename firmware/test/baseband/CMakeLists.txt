# Copyright (C) 2023 Bernd Herzog, Kyle Reed
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

project(baseband_test)

enable_language(C CXX ASM)

include(${CHIBIOS_PORTAPACK}/boards/PORTAPACK_BASEBAND/board.cmake)
include(${CHIBIOS_PORTAPACK}/os/hal/platforms/LPC43xx_M4/platform.cmake)
include(${CHIBIOS}/os/hal/hal.cmake)
include(${CHIBIOS_PORTAPACK}/os/ports/GCC/ARMCMx/LPC43xx_M4/port.cmake)
include(${CHIBIOS}/os/kernel/kernel.cmake)
include(${CHIBIOS}/test/test.cmake)

set(CMAKE_CXX_COMPILER g++)

add_executable(baseband_test EXCLUDE_FROM_ALL
	${PROJECT_SOURCE_DIR}/main.cpp
	${PROJECT_SOURCE_DIR}/dsp_fft_test.cpp
	${PROJECT_SOURCE_DIR}/precision_rx_capture_boundary_test.cpp
	${PROJECT_SOURCE_DIR}/precision_rx_dma_completion_queue_test.cpp
	${PROJECT_SOURCE_DIR}/precision_rx_dma_quiesce_test.cpp
	${PROJECT_SOURCE_DIR}/precision_rx_metrics_test.cpp
	${PROJECT_SOURCE_DIR}/precision_rx_rate_transaction_test.cpp
	${PROJECT_SOURCE_DIR}/stream_input_test.cpp
	${COMMON}/dsp_fft.cpp
	${BASEBAND}/precision_rx_metrics.cpp
	${BASEBAND}/stream_input.cpp
)

target_include_directories(baseband_test PRIVATE
	${DOCTESTINC}
	${COMMON}
	${PORTINC}
	${KERNINC}
	${TESTINC}
	${HALINC}
	${PLATFORMINC}
	${BOARDINC}
	${CHIBIOS}/os/various
	${BASEBAND}
)

target_compile_options(baseband_test PRIVATE
	-DLPC43XX
	-DLPC43XX_M4
	-D__NEWLIB__
	-DHACKRF_ONE
	-DTOOLCHAIN_GCC
	-DTOOLCHAIN_GCC_ARM
	-D_RANDOM_TCC=0
	-DVERSION_STRING=\"${VERSION}\"
	-DSTREAM_INPUT_HOST_TEST
	-DSTREAM_INPUT_BUFFER_COUNT_MAX_LOG2=4
)

if(HACKRF_EDGE_M0_SPILL_DIAGNOSTIC)
	target_compile_definitions(baseband_test PRIVATE
		HACKRF_EDGE_M0_SPILL_DIAGNOSTIC=1
	)
endif()
if(HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC)
	target_compile_definitions(baseband_test PRIVATE
		HACKRF_EDGE_PRECISION_RX_HYBRID_POOL_DIAGNOSTIC=1
	)
endif()
if(HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC)
	target_compile_definitions(baseband_test PRIVATE
		HACKRF_EDGE_PRECISION_RX_DMA_LEASE_DIAGNOSTIC=1
	)
endif()
if(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
	target_compile_definitions(baseband_test PRIVATE
		HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC=1
	)
endif()

add_test(NAME baseband_test
    COMMAND baseband_test
)

add_executable(baseband_stream_input_legacy_test EXCLUDE_FROM_ALL
	${PROJECT_SOURCE_DIR}/main.cpp
	${PROJECT_SOURCE_DIR}/stream_input_test.cpp
	${BASEBAND}/stream_input.cpp
)

target_include_directories(baseband_stream_input_legacy_test PRIVATE
	${DOCTESTINC}
	${COMMON}
	${PORTINC}
	${KERNINC}
	${TESTINC}
	${HALINC}
	${PLATFORMINC}
	${BOARDINC}
	${CHIBIOS}/os/various
	${BASEBAND}
)

target_compile_options(baseband_stream_input_legacy_test PRIVATE
	-DLPC43XX
	-DLPC43XX_M4
	-D__NEWLIB__
	-DHACKRF_ONE
	-DTOOLCHAIN_GCC
	-DTOOLCHAIN_GCC_ARM
	-D_RANDOM_TCC=0
	-DVERSION_STRING=\"${VERSION}\"
	-DSTREAM_INPUT_HOST_TEST
)

add_test(NAME baseband_stream_input_legacy_test
    COMMAND baseband_stream_input_legacy_test
)
