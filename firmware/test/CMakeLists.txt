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

project(tests)

set(DOCTESTINC ${PROJECT_SOURCE_DIR}/include)

enable_testing()
add_subdirectory(application)
add_subdirectory(baseband)

add_test(
    NAME spi_image_size_policy_test
    COMMAND ${CMAKE_COMMAND} -E env PYTHONDONTWRITEBYTECODE=1
        python3 -m unittest discover
        -s ${CMAKE_CURRENT_SOURCE_DIR}/../tools/tests
        -p test_spi_image_size_policy.py
)

add_test(
    NAME lz4_chunk_packaging_test
    COMMAND ${CMAKE_COMMAND} -E env PYTHONDONTWRITEBYTECODE=1
        python3 -m unittest discover
        -s ${CMAKE_CURRENT_SOURCE_DIR}/../tools/tests
        -p test_lz4_chunk_packaging.py
)

add_test(
    NAME external_app_fingerprint_test
    COMMAND ${CMAKE_COMMAND} -E env PYTHONDONTWRITEBYTECODE=1
        python3 -m unittest discover
        -s ${CMAKE_CURRENT_SOURCE_DIR}/../tools/tests
        -p test_external_app_fingerprint.py
)

add_test(
    NAME precision_rx_elf_verifier_test
    COMMAND ${CMAKE_COMMAND} -E env PYTHONDONTWRITEBYTECODE=1
        python3 -m unittest discover
        -s ${CMAKE_CURRENT_SOURCE_DIR}/../tools/tests
        -p test_precision_rx_elf_verifier.py
)

add_test(
    NAME precision_rx_application_elf_verifier_test
    COMMAND ${CMAKE_COMMAND} -E env PYTHONDONTWRITEBYTECODE=1
        python3 -m unittest discover
        -s ${CMAKE_CURRENT_SOURCE_DIR}/../tools/tests
        -p test_precision_rx_application_elf_verifier.py
)

add_custom_target(build_tests)
add_dependencies(
    build_tests
    application_test
    baseband_test
    baseband_stream_input_legacy_test
)
