#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

"""Linked-artifact regression checks for the Precision RX M0 application.

The p11 capture path loans 16 KiB of M0-owned SRAM to the M4 and writes each
returned descriptor directly to the SD writer.  Source tests cannot prove that
the optimized application retains the reviewed allocation geometry, publish
barriers, dequeue/write/recycle shape, exact consumer-release member, or
bounded, call-free journal recovery.  This verifier records diagnostic
instruction-shape evidence in the unstripped ``application.elf`` from every
reproducibility lane using the lane's GNU Arm ``nm`` and ``objdump`` tools.  It
is not a complete control-flow or register def-use proof; release identity is
established separately by the exact full-ELF SHA-256 pins in the frozen p11
contract.

The optimized build is allowed to inline ``CaptureThread::run()`` into
``CaptureThread::static_fn(void*)``.  Accordingly, readiness can be evidenced
either by a call to ``sdc_lld_capture_wait_ready`` or by its reviewed inlined
``sdc_lld_send_cmd_short_crc`` loop.  Missing or ambiguous evidence fails
closed and requires an explicit verifier review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

import verify_precision_rx_elf as core


VerificationError = core.VerificationError
Function = core.Function
Instruction = core.Instruction
Symbol = core.Symbol

EXPECTED_LOCAL_BUFFER_COUNT = 9
EXPECTED_SPILL_BUFFER_COUNT = 2
EXPECTED_SPILL_BYTES = 16 * 1024
EXPECTED_THREAD_STACK_BYTES = 1024
EXPECTED_CAPTURE_CONFIG_BYTES = 144
EXPECTED_CAPTURE_THREAD_BYTES = 216
EXPECTED_WRITE_SIZE = 8 * 1024
BASEBAND_OPEN_SUCCEEDED_OFFSET = 0x3A
MAX_CONSTRUCTOR_CODE_BYTES = 320
MAX_JOURNAL_RECOVERY_LOCAL_FRAME_BYTES = 256
M0_RAM_BASE = 0x20000000
M0_RAM_END = 0x20010000
MINIMUM_HEAP_SPAN_BYTES = 24 * 1024
MINIMUM_MODELED_HEAP_RESIDUAL_BYTES = 27 * 1024
EXPECTED_P12_RATE_TRANSACTION_PROTOCOL_VERSION = 3
EXPECTED_P12_ACK_CONFIGURED = 0xC0000001
EXPECTED_P12_ACK_PREPARED = 0xC0000002
EXPECTED_P12_ACK_COMMITTED = 0xC0000003
EXPECTED_P12_ACK_ABORTED = 0xC0000004
EXPECTED_P12_MESSAGE_ID = 115
EXPECTED_P12_COMMIT_CONTROL_WORD = 0x80000001
EXPECTED_P12_ABORT_CONTROL_WORD = 0x80000002
EXPECTED_P12_BOUNDED_WAIT_ITERATIONS = 500
EXPECTED_P12_M4_DMA_PAUSED_ARMED_STATE = 3
EXPECTED_P12_M0_FAULT_WATCHDOG_MS = 10
EXPECTED_P12_M4_DMA_FATAL_STATE = 5
EXPECTED_SHARED_MEMORY_BASE = 0x10088000
EXPECTED_BASEBAND_MESSAGE_OFFSET = 0x1000
EXPECTED_M4_DMA_RATE_STATE_OFFSET = 0x1A5F
CAPTURE_CONFIG_ABORT_REQUESTED_OFFSET = 0x39
CAPTURE_CONFIG_FINAL_REPORT_OFFSET = 0x3C
BUFFER_EXCHANGE_CONFIG_CAPTURE_OFFSET = 0x00
BUFFER_EXCHANGE_THREAD_OFFSET = 0x0C
BUFFER_EXCHANGE_DIRECTION_OFFSET = 0x10
BUFFER_EXCHANGE_CAPTURE_DIRECTION = 0
CHIBIOS_SUSPENDED_THREAD_STATE = 2

CONSTRUCTOR_PREFIX = "CaptureThread::CaptureThread("
DESTRUCTOR_NAME = "CaptureThread::~CaptureThread()"
STATIC_FN_NAME = "CaptureThread::static_fn(void*)"
STOP_CAPTURE_NAME = (
    "ui::external_app::precision_rx::PrecisionRxView::stop_capture()"
)
JOURNAL_RECOVERY_PREFIX = (
    "ui::external_app::precision_rx::PrecisionRxView::"
    "recover_snapshot_journal("
)
JOURNAL_RECOVERY_VENEER_NAME = (
    "___ZN2ui12external_app12precision_rx15PrecisionRxView24"
    "recover_snapshot_journalERK26PrecisionRxCaptureEvidence"
    "RKNS1_21SnapshotJournalBoundsE_veneer"
)


def _is_journal_recovery_call_target(name: str) -> bool:
    """Accept the function itself or its GNU-ld long-branch veneer."""

    return (
        name.startswith(JOURNAL_RECOVERY_PREFIX)
        or name == JOURNAL_RECOVERY_VENEER_NAME
    )


LOCAL_BUFFER_COUNT_SYMBOL = "hackrf_edge_precision_rx_app_local_buffer_count"
SPILL_BUFFER_COUNT_SYMBOL = "hackrf_edge_precision_rx_app_spill_buffer_count"
SPILL_BYTES_SYMBOL = "hackrf_edge_precision_rx_app_spill_bytes"
THREAD_STACK_BYTES_SYMBOL = "hackrf_edge_precision_rx_app_thread_stack_bytes"
CAPTURE_CONFIG_BYTES_SYMBOL = "hackrf_edge_precision_rx_app_capture_config_bytes"
CAPTURE_THREAD_BYTES_SYMBOL = "hackrf_edge_precision_rx_app_capture_thread_bytes"
DMA_ABORT_REQUIRES_RELEASE_SYMBOL = (
    "hackrf_edge_precision_rx_app_dma_abort_requires_consumer_release"
)
JOURNAL_FAIL_CLOSED_POLICY_SYMBOL = (
    "hackrf_edge_precision_rx_journal_fail_closed_recovery"
)
HEAP_BASE_SYMBOL = "__heap_base__"
HEAP_END_SYMBOL = "__heap_end__"
BUFFER_EXCHANGE_DESTRUCTOR_NAME = "BufferExchange::~BufferExchange()"
CONSUMER_RELEASE_HELPER_NAME = (
    "hackrf_edge_precision_rx_publish_dma_consumer_release"
)
SET_PRECISION_RX_PREFIX = "baseband::set_precision_rx("
SEND_MESSAGE_NAME = "baseband::send_message(Message const*)"
SEND_PRECISION_RX_BOUNDED_NAME = (
    "baseband::send_precision_rx_message_bounded(Message const*)"
)
RECEIVER_SET_BANDWIDTH_PREFIX = "ReceiverModel::set_baseband_bandwidth("
RECEIVER_SET_RATE_PREFIX = "ReceiverModel::set_sampling_rate("
RECEIVER_UPDATE_BANDWIDTH_NAME = "ReceiverModel::update_baseband_bandwidth()"
RECEIVER_UPDATE_RATE_NAME = "ReceiverModel::update_sampling_rate()"
RECEIVER_UPDATE_BANDWIDTH_VENEER_NAME = (
    "___ZN13ReceiverModel25update_baseband_bandwidthEv_veneer"
)
RECEIVER_UPDATE_RATE_VENEER_NAME = (
    "___ZN13ReceiverModel20update_sampling_rateEv_veneer"
)
RECEIVER_DISABLE_NAME = "ReceiverModel::disable()"
RECEIVER_DISABLE_VENEER_NAME = "___ZN13ReceiverModel7disableEv_veneer"
SHUTDOWN_PRECISION_RX_AFTER_FAULT_NAME = (
    "baseband::shutdown_precision_rx_after_rate_fault()"
)
PRECISION_RX_RATE_FATAL_NAME = "baseband::precision_rx_rate_fatal()"
PRECISION_RX_VIEW_CONSTRUCTOR_PREFIX = (
    "ui::external_app::precision_rx::PrecisionRxView::PrecisionRxView("
)
PRECISION_RX_VIEW_DESTRUCTOR_NAME = (
    "ui::external_app::precision_rx::PrecisionRxView::~PrecisionRxView()"
)
BASEBAND_SHUTDOWN_NAME = "baseband::shutdown()"
BASEBAND_SHUTDOWN_VENEER_NAME = "___ZN8baseband8shutdownEv_veneer"
RADIO_DISABLE_NAME = "radio::disable()"
RADIO_DISABLE_VENEER_NAME = "___ZN5radio7disableEv_veneer"
SET_ANTENNA_BIAS_NAME = "portapack::set_antenna_bias(bool)"
SET_ANTENNA_BIAS_VENEER_NAME = (
    "___ZN9portapack16set_antenna_biasEb_veneer"
)
RECEIVER_ENABLE_NAME = "ReceiverModel::enable()"
RECEIVER_ENABLE_VENEER_NAME = "___ZN13ReceiverModel6enableEv_veneer"
RECEIVER_MODEL_NAME = "portapack::receiver_model"
RECEIVER_MODEL_ENABLED_OFFSET = 40
DEBUG_PANIC_NAME = "chDbgPanic"


def _is_set_antenna_bias_target(name: str) -> bool:
    return name in {
        SET_ANTENNA_BIAS_NAME,
        SET_ANTENNA_BIAS_VENEER_NAME,
    }


def _is_receiver_enable_target(name: str) -> bool:
    return name in {
        RECEIVER_ENABLE_NAME,
        RECEIVER_ENABLE_VENEER_NAME,
    }


def _is_baseband_shutdown_target(name: str) -> bool:
    return name in {
        BASEBAND_SHUTDOWN_NAME,
        BASEBAND_SHUTDOWN_VENEER_NAME,
    }


def _is_receiver_bandwidth_write_target(name: str) -> bool:
    return (
        name.startswith(RECEIVER_SET_BANDWIDTH_PREFIX)
        or name == RECEIVER_UPDATE_BANDWIDTH_NAME
        or name == RECEIVER_UPDATE_BANDWIDTH_VENEER_NAME
    )


def _is_receiver_rate_write_target(name: str) -> bool:
    return (
        name.startswith(RECEIVER_SET_RATE_PREFIX)
        or name == RECEIVER_UPDATE_RATE_NAME
        or name == RECEIVER_UPDATE_RATE_VENEER_NAME
    )


def _is_receiver_disable_target(name: str) -> bool:
    return name in {
        RECEIVER_DISABLE_NAME,
        RECEIVER_DISABLE_VENEER_NAME,
    }


def _is_radio_disable_target(name: str) -> bool:
    return name in {
        RADIO_DISABLE_NAME,
        RADIO_DISABLE_VENEER_NAME,
    }

RATE_TRANSACTION_PROTOCOL_VERSION_SYMBOL = (
    "hackrf_edge_precision_rx_app_rate_transaction_protocol_version"
)
RATE_PREPARE_BEFORE_PHYSICAL_CHANGE_SYMBOL = (
    "hackrf_edge_precision_rx_app_rate_prepare_before_physical_change"
)
RATE_FILTER_BEFORE_CLOCK_SYMBOL = (
    "hackrf_edge_precision_rx_app_rate_filter_before_clock"
)
RATE_COMMIT_AFTER_PHYSICAL_CHANGE_SYMBOL = (
    "hackrf_edge_precision_rx_app_rate_commit_after_physical_change"
)
RATE_ROLLBACK_BEFORE_ABORT_SYMBOL = (
    "hackrf_edge_precision_rx_app_rate_rollback_before_abort"
)
RATE_FAIL_CLOSED_SYMBOL = "hackrf_edge_precision_rx_app_rate_fail_closed"
RATE_BOUNDED_WAIT_ITERATIONS_SYMBOL = (
    "hackrf_edge_precision_rx_app_rate_bounded_wait_iterations"
)
RATE_PERSISTENT_MESSAGE_SYMBOL = (
    "hackrf_edge_precision_rx_app_rate_persistent_message"
)
RATE_REJECTION_NO_PANIC_SYMBOL = (
    "hackrf_edge_precision_rx_app_rate_rejection_no_panic"
)
RATE_FAULT_SHUTDOWN_BOUNDED_SYMBOL = (
    "hackrf_edge_precision_rx_app_rate_fault_shutdown_bounded"
)
RATE_ROLLBACK_REQUIRES_PAUSED_ARMED_SYMBOL = (
    "hackrf_edge_precision_rx_app_rate_rollback_requires_paused_armed"
)
RATE_COMMIT_TIMEOUT_NO_ROLLBACK_SYMBOL = (
    "hackrf_edge_precision_rx_app_rate_commit_timeout_no_rollback"
)
M0_FAULT_WATCHDOG_MS_SYMBOL = (
    "hackrf_edge_precision_rx_m0_fault_watchdog_ms"
)
SHARED_MEMORY_SYMBOL = "shared_memory"
BUFFER_EXCHANGE_GET_NAME = "BufferExchange::get(FIFO<StreamBuffer*>*)"
SLEEP_TIMEOUT_NAME = "chSchGoSleepTimeoutS"
SLEEP_NAME = "chSchGoSleepS"
DEBUG_LOCK_NAME = "dbg_check_lock"
DEBUG_UNLOCK_NAME = "dbg_check_unlock"

P12_ABSOLUTE_METADATA = {
    RATE_TRANSACTION_PROTOCOL_VERSION_SYMBOL: (
        EXPECTED_P12_RATE_TRANSACTION_PROTOCOL_VERSION
    ),
    RATE_PREPARE_BEFORE_PHYSICAL_CHANGE_SYMBOL: 1,
    RATE_FILTER_BEFORE_CLOCK_SYMBOL: 1,
    RATE_COMMIT_AFTER_PHYSICAL_CHANGE_SYMBOL: 1,
    RATE_ROLLBACK_BEFORE_ABORT_SYMBOL: 1,
    RATE_FAIL_CLOSED_SYMBOL: 1,
    RATE_BOUNDED_WAIT_ITERATIONS_SYMBOL: (
        EXPECTED_P12_BOUNDED_WAIT_ITERATIONS
    ),
    RATE_PERSISTENT_MESSAGE_SYMBOL: 1,
    RATE_REJECTION_NO_PANIC_SYMBOL: 1,
    RATE_FAULT_SHUTDOWN_BOUNDED_SYMBOL: 1,
    RATE_ROLLBACK_REQUIRES_PAUSED_ARMED_SYMBOL: 1,
    RATE_COMMIT_TIMEOUT_NO_ROLLBACK_SYMBOL: 1,
    M0_FAULT_WATCHDOG_MS_SYMBOL: EXPECTED_P12_M0_FAULT_WATCHDOG_MS,
}


@dataclass(frozen=True)
class GateConfig:
    expected_local_buffer_count: int = EXPECTED_LOCAL_BUFFER_COUNT
    expected_spill_buffer_count: int = EXPECTED_SPILL_BUFFER_COUNT
    expected_spill_bytes: int = EXPECTED_SPILL_BYTES
    expected_thread_stack_bytes: int = EXPECTED_THREAD_STACK_BYTES
    expected_capture_config_bytes: int = EXPECTED_CAPTURE_CONFIG_BYTES
    expected_capture_thread_bytes: int = EXPECTED_CAPTURE_THREAD_BYTES
    maximum_constructor_code_bytes: int = MAX_CONSTRUCTOR_CODE_BYTES
    maximum_journal_recovery_local_frame_bytes: int = (
        MAX_JOURNAL_RECOVERY_LOCAL_FRAME_BYTES
    )
    m0_ram_base: int = M0_RAM_BASE
    m0_ram_end: int = M0_RAM_END
    minimum_heap_span_bytes: int = MINIMUM_HEAP_SPAN_BYTES
    minimum_modeled_heap_residual_bytes: int = (
        MINIMUM_MODELED_HEAP_RESIDUAL_BYTES
    )


_IMMEDIATE = r"#(0x[0-9a-fA-F]+|[0-9]+)\b"
_MOVE_IMMEDIATE = re.compile(
    rf"^(r(?:1[0-5]|[0-9])|sp|lr),\s*{_IMMEDIATE}"
)
_SHIFT_IMMEDIATE = re.compile(
    rf"^(r(?:1[0-5]|[0-9])|sp|lr),\s*"
    rf"(r(?:1[0-5]|[0-9])|sp|lr),\s*{_IMMEDIATE}"
)
_MOVE_REGISTER = re.compile(
    r"^(r(?:1[0-5]|[0-9])),\s*(r(?:1[0-5]|[0-9]))$"
)
_ADD_SELF_IMMEDIATE = re.compile(
    rf"^(r(?:1[0-5]|[0-9])),\s*{_IMMEDIATE}$"
)
_ADD_REGISTER_IMMEDIATE = re.compile(
    rf"^(r(?:1[0-5]|[0-9])),\s*"
    rf"(r(?:1[0-5]|[0-9])),\s*{_IMMEDIATE}$"
)
_SP_ADJUST_IMMEDIATE = re.compile(
    rf"^sp,\s*(?:sp,\s*)?{_IMMEDIATE}$"
)
_REGISTER_TOKEN = re.compile(r"\b(r(?:1[0-5]|[0-9])|pc)\b")
_CONDITIONAL_BRANCH = re.compile(
    r"^b(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)?$"
)
_UNSIZED_NM_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+)\s+([A-Za-z])\s+(.+?)\s*$"
)
_TEXT_DUMP_ADDRESS = re.compile(r"^[0-9a-fA-F]+$")
_TEXT_DUMP_BYTES = re.compile(r"^(?:[0-9a-fA-F]{2}){1,4}$")
_INDEXED_BYTE_LOAD = re.compile(
    r"^(r(?:1[0-5]|[0-9])),\s*"
    r"\[(r(?:1[0-5]|[0-9])),\s*(r(?:1[0-5]|[0-9]))\]$"
)


@dataclass(frozen=True)
class _SymbolicValue:
    kind: str
    value: int | None = None
    origins: tuple[Instruction, ...] = ()


@dataclass(frozen=True)
class _StoredWord:
    value: _SymbolicValue
    writer: Instruction


@dataclass(frozen=True)
class _SentMessage:
    call: Instruction
    pointer: _SymbolicValue
    pointer_writer: Instruction
    words: tuple[_StoredWord, _StoredWord]


@dataclass(frozen=True)
class _StackWrite:
    address: int
    size: int
    stored: _StoredWord


@dataclass(frozen=True)
class _StackRead:
    address: int
    size: int
    instruction: Instruction
    destination: str


@dataclass(frozen=True)
class _P12MessageTrace:
    sent: tuple[_SentMessage, ...]
    stack_writes: tuple[_StackWrite, ...]
    stack_reads: tuple[_StackRead, ...]


@dataclass(frozen=True)
class _M4RateStateCheck:
    base_writer: Instruction
    offset_writer: Instruction
    load: Instruction
    compare: Instruction
    nonfatal_branch: Instruction


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _unique_function(
    functions: Sequence[Function],
    description: str,
    predicate: Callable[[str], bool],
) -> Function:
    matches = [function for function in functions if predicate(function.name)]
    _require(
        len(matches) == 1,
        f"expected exactly one {description}; found {len(matches)}",
    )
    return matches[0]


def _unique_symbol_size(
    symbols: Sequence[Symbol],
    description: str,
    predicate: Callable[[str], bool],
) -> int:
    # C1/C2 and D1/D2 C++ aliases may produce duplicate nm rows at the same
    # address.  They are one linked implementation, not ambiguous evidence.
    matches = {
        (symbol.address, symbol.size)
        for symbol in symbols
        if predicate(symbol.name)
    }
    _require(
        len(matches) == 1,
        f"expected exactly one sized {description}; found {len(matches)}",
    )
    _, size = next(iter(matches))
    _require(size > 0, f"{description} has zero code size")
    return size


def _absolute_value(symbols: Sequence[Symbol], name: str) -> int:
    matches = [symbol for symbol in symbols if symbol.name == name]
    _require(len(matches) == 1, f"expected exactly one {name}; found {len(matches)}")
    symbol = matches[0]
    _require(symbol.kind.upper() == "A", f"{name} must be an absolute symbol")
    return symbol.address


def _unique_named_symbol(
    symbols: Sequence[Symbol],
    name: str,
) -> Symbol:
    matches = [symbol for symbol in symbols if symbol.name == name]
    _require(len(matches) == 1, f"expected exactly one {name}; found {len(matches)}")
    return matches[0]


def _p12_metadata(
    symbols: Sequence[Symbol],
) -> dict[str, int] | None:
    """Select p12 on any p12-only symbol and reject an incomplete symbol set."""

    symbol_names = {symbol.name for symbol in symbols}
    if not symbol_names.intersection(P12_ABSOLUTE_METADATA):
        return None

    metadata = {
        name: _absolute_value(symbols, name)
        for name in P12_ABSOLUTE_METADATA
    }
    for name, expected in P12_ABSOLUTE_METADATA.items():
        actual = metadata[name]
        _require(
            actual == expected,
            f"linked p12 metadata {name} is {actual}; expected {expected}",
        )
    return metadata


def _linked_value(nm_text: str, name: str) -> tuple[int, str]:
    """Read a linker symbol that GNU nm may emit without a size column."""

    matches: list[tuple[int, str]] = []
    for line in nm_text.splitlines():
        sized = core.NM_LINE.match(line)
        if sized and sized.group(4) == name:
            matches.append((int(sized.group(1), 16), sized.group(3)))
            continue
        unsized = _UNSIZED_NM_LINE.match(line)
        if unsized and unsized.group(3) == name:
            matches.append((int(unsized.group(1), 16), unsized.group(2)))
    _require(len(matches) == 1, f"expected exactly one {name}; found {len(matches)}")
    return matches[0]


def _calls(function: Function) -> list[Instruction]:
    return [
        instruction
        for instruction in function.instructions
        if instruction.mnemonic in {"bl", "blx"}
    ]


def _calls_matching(
    function: Function,
    predicate: Callable[[str], bool],
) -> list[Instruction]:
    return [
        instruction
        for instruction in _calls(function)
        if instruction.target is not None and predicate(instruction.target)
    ]


def _require_one_call(
    function: Function,
    description: str,
    predicate: Callable[[str], bool],
) -> Instruction:
    matches = _calls_matching(function, predicate)
    _require(
        len(matches) == 1,
        f"{function.name} must call {description} exactly once; found {len(matches)}",
    )
    return matches[0]


def _verify_direct_or_thumb_veneer_call(
    call: Instruction,
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
    direct_predicate: Callable[[str], bool],
    veneer_name: str,
    veneer_target_predicate: Callable[[str], bool],
    description: str,
) -> dict[str, object]:
    """Bind a call either directly or through one exact GNU-ld Thumb veneer."""

    branch_target = core._branch_target_address(call)
    _require(
        branch_target is not None,
        f"{description} call at 0x{call.address:x} has no linked address",
    )
    if call.target != veneer_name:
        direct = [
            symbol
            for symbol in symbols
            if symbol.name == call.target
            and direct_predicate(symbol.name)
            and symbol.kind.lower() == "t"
            and symbol.size > 0
        ]
        _require(
            len(direct) == 1 and direct[0].address == branch_target,
            f"{description} direct call does not resolve to one exact code symbol",
        )
        return {
            "shape": "direct",
            "call_address": call.address,
            "target_address": direct[0].address,
        }

    veneer_symbols = [
        symbol
        for symbol in symbols
        if symbol.name == veneer_name
        and symbol.address == branch_target
        and symbol.kind.lower() == "t"
        and symbol.size == 16
    ]
    veneer_functions = [
        function
        for function in functions
        if function.name == veneer_name and function.address == branch_target
    ]
    _require(
        len(veneer_symbols) == 1 and len(veneer_functions) == 1,
        f"{description} veneer must resolve to one exact 16-byte code symbol "
        "and function",
    )
    veneer = veneer_functions[0]
    instructions = veneer.instructions
    _require(
        len(instructions) == 6
        and [instruction.address for instruction in instructions]
        == [branch_target + offset for offset in (0, 2, 4, 6, 8, 10)]
        and [_clean_mnemonic(instruction) for instruction in instructions]
        == ["push", "ldr", "mov", "pop", "bx", "nop"]
        and core._operand_registers(instructions[0]) == ("r0",)
        and core._operand_registers(instructions[1]) == ("r0", "r15")
        and core._memory_location(instructions[1]) == ("r15", 8)
        and core._operand_registers(instructions[2]) == ("r12", "r0")
        and core._operand_registers(instructions[3]) == ("r0",)
        and core._operand_registers(instructions[4]) == ("r12",)
        and core._operand_registers(instructions[5]) == (),
        f"{description} veneer body differs from the exact reviewed "
        "push/ldr/mov/pop/bx/nop shape",
    )
    literal_address = core._pc_literal_target(instructions[1])
    _require(
        literal_address == branch_target + 12
        and literal_address in literal_words,
        f"{description} veneer lacks its exact +12 target literal",
    )
    target_symbols = [
        symbol
        for symbol in symbols
        if veneer_target_predicate(symbol.name)
        and symbol.kind.lower() == "t"
        and symbol.size > 0
    ]
    _require(
        len(target_symbols) == 1,
        f"{description} veneer ultimate target is not one exact code symbol",
    )
    literal = literal_words[literal_address]
    _require(
        literal & 1 == 1
        and (literal & ~1) == target_symbols[0].address,
        f"{description} veneer literal does not resolve with the Thumb bit "
        "to the expected ultimate target",
    )
    return {
        "shape": "gnu-ld-thumb-veneer",
        "call_address": call.address,
        "veneer_address": branch_target,
        "literal_address": literal_address,
        "target_address": target_symbols[0].address,
    }


def _is_control_flow_barrier(instruction: Instruction) -> bool:
    mnemonic = instruction.mnemonic.split(".", 1)[0]
    return (
        mnemonic in {"bl", "blx", "bx", "cbz", "cbnz"}
        or _CONDITIONAL_BRANCH.fullmatch(mnemonic) is not None
    )


def _writes_register(instruction: Instruction, register: str) -> bool:
    """Return whether an instruction can write ``register`` and fall through."""

    operands = instruction.operands.split(";", 1)[0].strip()
    mnemonic = instruction.mnemonic.lower().split(".", 1)[0]
    operand_registers = _REGISTER_TOKEN.findall(operands)

    # A pop/ldm containing pc terminates that path.  Other register-list loads
    # are implicit writes that a first-operand-only check would miss.
    if mnemonic.startswith("pop") or mnemonic.startswith("ldm"):
        if "pc" in operand_registers:
            return False
        return register in operand_registers

    # These instructions have two explicit destination registers.
    if mnemonic in {
        "ldrd",
        "ldrexd",
        "smlal",
        "smull",
        "umlal",
        "umull",
    }:
        return register in operand_registers[:2]

    if operands.split(",", 1)[0].strip() != register:
        return False
    return mnemonic not in {
        "b",
        "bl",
        "blx",
        "bx",
        "cbz",
        "cbnz",
        "cmp",
        "cmn",
        "dmb",
        "dsb",
        "isb",
        "str",
        "strb",
        "strd",
        "strh",
        "stm",
        "stmia",
        "teq",
        "tst",
    }


def _require_this_plus_call_argument(
    function: Function,
    call: Instruction,
    *,
    expected_offset: int,
    after: Instruction,
) -> tuple[Instruction, Instruction, Instruction, str]:
    """Prove a call's r0 argument is the entry ``this`` plus an offset.

    ``CaptureThread::static_fn`` receives its ``CaptureThread*`` context in
    r0.  The reviewed Thumb-1 shape saves it once in a callee-saved register,
    then materializes the release-helper argument after BufferExchange
    teardown.  Reject any other dataflow rather than inferring member identity
    from the presence of the helper call alone.
    """

    _require(
        function.name == STATIC_FN_NAME,
        "DMA consumer release must be published by CaptureThread::static_fn",
    )
    try:
        call_index = function.instructions.index(call)
    except ValueError as error:
        raise VerificationError(
            f"call is not part of disassembled function {function.name}"
        ) from error

    def last_writer(register: str, before_index: int) -> tuple[int, Instruction]:
        for index in range(before_index - 1, -1, -1):
            instruction = function.instructions[index]
            if _writes_register(instruction, register):
                return index, instruction
        raise VerificationError(
            f"cannot find writer of {register} before call to {call.target} "
            f"in {function.name}"
        )

    add_index, offset_add = last_writer("r0", call_index)
    add_operands = offset_add.operands.split(";", 1)[0].strip()
    add_mnemonic = offset_add.mnemonic.lower().split(".", 1)[0]
    offset = None
    source_register = "r0"
    self_add = _ADD_SELF_IMMEDIATE.fullmatch(add_operands)
    register_add = _ADD_REGISTER_IMMEDIATE.fullmatch(add_operands)
    if add_mnemonic in {"add", "adds"} and self_add:
        offset = int(self_add.group(2), 0)
    elif add_mnemonic in {"add", "adds"} and register_add:
        source_register = register_add.group(2)
        offset = int(register_add.group(3), 0)
    _require(
        offset is not None,
        f"{function.name} must form the DMA consumer-release argument with "
        "an immediate add to r0",
    )
    _require(
        offset == expected_offset,
        f"DMA consumer-release argument offset is {offset}; expected "
        f"{expected_offset}",
    )

    if source_register == "r0":
        move_index, base_move = last_writer("r0", add_index)
        move_operands = base_move.operands.split(";", 1)[0].strip()
        move = _MOVE_REGISTER.fullmatch(move_operands)
        _require(
            base_move.mnemonic.lower().split(".", 1)[0] in {"mov", "movs"}
            and move is not None,
            f"{function.name} must derive the DMA consumer-release argument "
            "from its saved this pointer",
        )
        source_register = move.group(2)
    else:
        move_index = add_index
        base_move = offset_add

    teardown_index = function.instructions.index(after)
    if move_index == add_index:
        contiguous_derivation = (
            add_index == teardown_index + 1 and call_index == add_index + 1
        )
    else:
        contiguous_derivation = (
            move_index == teardown_index + 1
            and add_index == move_index + 1
            and call_index == add_index + 1
        )
    _require(
        contiguous_derivation,
        "DMA consumer-release argument derivation must be contiguous after "
        "BufferExchange teardown",
    )

    _require(
        re.fullmatch(r"r(?:1[01]|[4-9])", source_register) is not None,
        "DMA consumer-release argument base must be held in a callee-saved "
        f"register; found {source_register}",
    )
    _require(
        base_move.address > after.address and offset_add.address > after.address,
        "DMA consumer-release argument must be formed after BufferExchange "
        "teardown",
    )

    base_writers = [
        instruction
        for instruction in function.instructions[:move_index]
        if _writes_register(instruction, source_register)
    ]
    _require(
        len(base_writers) == 1,
        f"{function.name} must save its entry this pointer exactly once in "
        f"{source_register}; found {len(base_writers)} writers",
    )
    this_init = base_writers[0]
    this_init_operands = this_init.operands.split(";", 1)[0].strip()
    this_init_move = _MOVE_REGISTER.fullmatch(this_init_operands)
    _require(
        this_init.mnemonic.lower().split(".", 1)[0] in {"mov", "movs"}
        and this_init_move is not None
        and this_init_move.group(1) == source_register
        and this_init_move.group(2) == "r0",
        f"{function.name} must initialize {source_register} from entry r0",
    )
    _require(
        not any(
            _writes_register(instruction, "r0")
            for instruction in function.instructions
            if instruction.address < this_init.address
        ),
        f"{function.name} modifies entry r0 before saving this",
    )
    _require(
        not any(
            instruction.address < this_init.address
            for instruction in _calls(function)
        ),
        f"{function.name} calls another function before saving this",
    )
    return this_init, base_move, offset_add, source_register


def _require_bounded_local_stack_frame(
    function: Function,
    maximum_bytes: int,
) -> int:
    """Prove a statically bounded, balanced local stack allocation."""

    allocated_bytes = 0
    released_bytes = 0
    for instruction in function.instructions:
        operands = instruction.operands.split(";", 1)[0].strip()
        if operands.split(",", 1)[0].strip() != "sp":
            continue
        mnemonic = instruction.mnemonic.lower().split(".", 1)[0]
        if mnemonic not in {"add", "adds", "sub", "subs"}:
            if _writes_register(instruction, "sp"):
                raise VerificationError(
                    f"{function.name} has unsupported dynamic stack write: "
                    f"{instruction.mnemonic} {instruction.operands}"
                )
            continue
        adjustment = _SP_ADJUST_IMMEDIATE.fullmatch(operands)
        _require(
            adjustment is not None,
            f"{function.name} has non-immediate stack adjustment: "
            f"{instruction.mnemonic} {instruction.operands}",
        )
        amount = int(adjustment.group(1), 0)
        if mnemonic in {"sub", "subs"}:
            allocated_bytes += amount
        else:
            released_bytes += amount

    _require(
        allocated_bytes <= maximum_bytes,
        f"{function.name} local stack frame is {allocated_bytes} bytes; "
        f"maximum is {maximum_bytes}",
    )
    _require(
        released_bytes == allocated_bytes,
        f"{function.name} local stack allocation/release is unbalanced: "
        f"{allocated_bytes}/{released_bytes} bytes",
    )
    return allocated_bytes


def _constant_argument_before_call(
    function: Function,
    call: Instruction,
    register: str,
) -> int:
    """Recover a fail-closed straight-line constant argument.

    GCC commonly materializes 16384 and 1024 on Cortex-M0 as ``movs r1,
    #128`` followed by ``lsls r1, r1, #7`` or ``#3``.  Walk backward from the
    call, recording same-register immediate shifts until reaching an immediate
    move.  A call, branch, non-self shift, or any unreviewed writer makes the
    value ambiguous and is rejected.
    """

    try:
        call_index = function.instructions.index(call)
    except ValueError as error:
        raise VerificationError(
            f"call is not part of disassembled function {function.name}"
        ) from error

    transformations: list[tuple[str, int]] = []
    for instruction in reversed(function.instructions[:call_index]):
        if _is_control_flow_barrier(instruction):
            raise VerificationError(
                f"cannot recover constant {register} before call to {call.target} "
                f"in {function.name}; crossed control flow at "
                f"{instruction.mnemonic} {instruction.operands}"
            )

        operands = instruction.operands.split(";", 1)[0].strip()
        destination = operands.split(",", 1)[0].strip()
        if destination != register:
            continue

        mnemonic = instruction.mnemonic.lower()
        move = _MOVE_IMMEDIATE.match(operands)
        if mnemonic in {"mov", "movs", "mov.w", "movw"} and move:
            value = int(move.group(2), 0)
            for operation, amount in reversed(transformations):
                if operation == "lsl":
                    value = (value << amount) & 0xFFFFFFFF
                else:
                    value = (value & 0xFFFFFFFF) >> amount
            return value

        shift = _SHIFT_IMMEDIATE.match(operands)
        if mnemonic in {"lsl", "lsls", "lsl.w", "lsr", "lsrs", "lsr.w"} and shift:
            source = shift.group(2)
            _require(
                source == register,
                f"cannot recover constant {register} before call to {call.target} "
                f"in {function.name}; shift source is {source}",
            )
            operation = "lsl" if mnemonic.startswith("lsl") else "lsr"
            transformations.append((operation, int(shift.group(3), 0)))
            continue

        raise VerificationError(
            f"cannot recover constant {register} before call to {call.target} "
            f"in {function.name}; last writer is {instruction.mnemonic} "
            f"{instruction.operands}"
        )

    raise VerificationError(
        f"cannot find constant {register} before call to {call.target} "
        f"in {function.name}"
    )


def _is_heap_alloc(name: str) -> bool:
    return "chHeapAlloc" in name


def _is_heap_free(name: str) -> bool:
    return "chHeapFree" in name


def _is_thread_create(name: str) -> bool:
    return "chThdCreateFromHeap" in name


def _is_ready_evidence(name: str) -> bool:
    return (
        "sdc_lld_capture_wait_ready" in name
        or "sdc_lld_send_cmd_short_crc" in name
    )


def _is_buffer_get(name: str) -> bool:
    return name.startswith("BufferExchange::get(")


def _is_stream_fifo_in_call(instruction: Instruction) -> bool:
    # The shared objdump parser deliberately extracts the first ``<...>``
    # target group.  A nested C++ template therefore truncates ``target`` at
    # ``FIFO<StreamBuffer*``.  The raw operands retain the full demangled name.
    return "<FIFO<StreamBuffer*>::in(" in instruction.operands


def _is_memcpy(name: str) -> bool:
    return "memcpy" in name.lower()


def _dmbs(function: Function) -> list[Instruction]:
    return [
        instruction
        for instruction in function.instructions
        if instruction.mnemonic.lower().startswith("dmb")
    ]


def _require_consumer_release_store(
    function: Function,
) -> tuple[Instruction, Instruction, Instruction, Instruction]:
    """Prove release ordering: DMB, store false, then DMB."""

    stores = [
        instruction
        for instruction in function.instructions
        if instruction.mnemonic.lower().split(".", 1)[0] == "strb"
    ]
    _require(
        len(stores) == 1,
        f"{function.name} must contain exactly one byte store; found {len(stores)}",
    )
    store = stores[0]
    store_operands = store.operands.split(";", 1)[0].strip()
    store_parts = store_operands.split(",", 1)
    _require(
        len(store_parts) == 2
        and re.fullmatch(
            r"\[r0(?:,\s*#(?:0x0|0))?\]!?",
            store_parts[1].strip(),
        )
        is not None,
        f"{function.name} byte store must target exactly [r0]",
    )
    source_register = store_parts[0].strip()
    _require(
        re.fullmatch(r"r(?:1[0-5]|[0-9])", source_register) is not None,
        f"{function.name} byte-store source is not a register: {source_register}",
    )

    source_writers = []
    for instruction in function.instructions:
        if instruction.address >= store.address:
            break
        operands = instruction.operands.split(";", 1)[0].strip()
        if operands.split(",", 1)[0].strip() == source_register:
            source_writers.append(instruction)
    _require(
        bool(source_writers),
        f"{function.name} does not initialize the byte-store source",
    )
    zero_move = source_writers[-1]
    move = _MOVE_IMMEDIATE.fullmatch(
        zero_move.operands.split(";", 1)[0].strip()
    )
    _require(
        zero_move.mnemonic.lower() in {"mov", "movs", "mov.w", "movw"}
        and move is not None
        and int(move.group(2), 0) == 0,
        f"{function.name} must initialize {source_register} to zero immediately "
        "before publishing consumer release",
    )

    dmbs_before_store = [
        instruction
        for instruction in _dmbs(function)
        if instruction.address < store.address
    ]
    _require(
        bool(dmbs_before_store),
        f"{function.name} must execute DMB before the release store",
    )
    dmbs_after_store = [
        instruction
        for instruction in _dmbs(function)
        if instruction.address > store.address
    ]
    _require(
        bool(dmbs_after_store),
        f"{function.name} must execute DMB after the release store",
    )
    return dmbs_before_store[-1], zero_move, store, dmbs_after_store[0]


def _parse_text_bytes(text: str) -> dict[int, int]:
    """Parse ``objdump -s`` section bytes without trusting its ASCII column."""

    contents: dict[int, int] = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or _TEXT_DUMP_ADDRESS.fullmatch(fields[0]) is None:
            continue
        address = int(fields[0], 16)
        offset = 0
        for field in fields[1:]:
            if (
                _TEXT_DUMP_BYTES.fullmatch(field) is None
                or len(field) % 2 != 0
            ):
                break
            encoded = bytes.fromhex(field)
            for value in encoded:
                contents[address + offset] = value
                offset += 1
    return contents


def _read_u32(
    contents: dict[int, int],
    address: int,
    *,
    description: str,
) -> int:
    missing = [offset for offset in range(4) if address + offset not in contents]
    _require(
        not missing,
            f"{description} is outside the supplied linked section byte image at "
        f"0x{address:08x}",
    )
    return sum(contents[address + offset] << (8 * offset) for offset in range(4))


def _with_origin(
    value: _SymbolicValue,
    instruction: Instruction,
) -> _SymbolicValue:
    origins = {
        origin.address: origin
        for origin in (*value.origins, instruction)
    }
    return _SymbolicValue(
        value.kind,
        value.value,
        tuple(origins[address] for address in sorted(origins)),
    )


def _unknown(instruction: Instruction) -> _SymbolicValue:
    return _SymbolicValue("unknown", origins=(instruction,))


def _last_dominating_register_writer(
    function: Function,
    register: str,
    *,
    before: Instruction,
) -> Instruction | None:
    """Return the last linked writer that dominates ``before``."""

    entry = min(instruction.address for instruction in function.instructions)
    dominators, reachable = core._dominators_from(
        function,
        entry,
        reject_thumb_it=False,
    )
    if before.address not in reachable:
        return None
    return next(
        (
            instruction
            for instruction in reversed(function.instructions)
            if instruction.address < before.address
            and instruction.address in dominators[before.address]
            and core._clobbers_register(instruction, register)
        ),
        None,
    )


def _constant_register_before(
    function: Function,
    register: str,
    *,
    before: Instruction,
    literal_words: dict[int, int],
    depth: int = 0,
) -> tuple[int, tuple[Instruction, ...]] | None:
    """Resolve a small linked constant/move chain feeding a call argument."""

    if depth > 8:
        return None
    writer = _last_dominating_register_writer(
        function,
        register,
        before=before,
    )
    if writer is None:
        return None
    literal_target = core._pc_literal_target(writer)
    if literal_target is not None and literal_target in literal_words:
        return literal_words[literal_target], (writer,)
    mnemonic = writer.mnemonic.lower().split(".", 1)[0]
    registers = core._operand_registers(writer)
    immediate = _immediate_operand(writer)
    location = core._memory_location(writer)
    if (
        mnemonic.startswith("ldr")
        and location is not None
        and location[0] == "r13"
    ):
        entry = min(
            instruction.address for instruction in function.instructions
        )
        dominators, reachable = core._dominators_from(
            function,
            entry,
            reject_thumb_it=False,
        )
        if writer.address in reachable:
            stack_store = next(
                (
                    instruction
                    for instruction in reversed(function.instructions)
                    if instruction.address < writer.address
                    and instruction.address in dominators[writer.address]
                    and instruction.mnemonic.startswith("str")
                    and core._memory_location(instruction) == location
                ),
                None,
            )
            if stack_store is not None:
                store_registers = core._operand_registers(stack_store)
                if store_registers:
                    source = _constant_register_before(
                        function,
                        store_registers[0],
                        before=stack_store,
                        literal_words=literal_words,
                        depth=depth + 1,
                    )
                    if source is not None:
                        return source[0], (*source[1], stack_store, writer)
    if mnemonic.startswith("mov"):
        if immediate is not None:
            return immediate, (writer,)
        if len(registers) >= 2:
            source = _constant_register_before(
                function,
                registers[1],
                before=writer,
                literal_words=literal_words,
                depth=depth + 1,
            )
            if source is not None:
                return source[0], (*source[1], writer)
    if mnemonic in {"add", "adds", "sub", "subs"} and immediate is not None:
        source_register = registers[1] if len(registers) >= 2 else register
        source = _constant_register_before(
            function,
            source_register,
            before=writer,
            literal_words=literal_words,
            depth=depth + 1,
        )
        if source is not None:
            delta = -immediate if mnemonic.startswith("sub") else immediate
            return (source[0] + delta) & 0xFFFFFFFF, (*source[1], writer)
    if mnemonic in {"lsl", "lsls"} and immediate is not None:
        source_register = registers[1] if len(registers) >= 2 else register
        source = _constant_register_before(
            function,
            source_register,
            before=writer,
            literal_words=literal_words,
            depth=depth + 1,
        )
        if source is not None:
            return (
                (source[0] << immediate) & 0xFFFFFFFF,
                (*source[1], writer),
            )
    return None


_INDEXED_MEMORY_OPERAND = re.compile(
    r"\[\s*(r(?:1[0-5]|[0-9])|sp|lr|pc)\s*,\s*"
    r"(r(?:1[0-5]|[0-9])|sp|lr|pc)"
    r"(?:\s*,\s*lsl\s*#(0x[0-9a-fA-F]+|[0-9]+))?\s*\]"
)


def _constant_memory_address(
    function: Function,
    instruction: Instruction,
    *,
    literal_words: dict[int, int],
) -> int | None:
    """Resolve the reviewed immediate or register-indexed memory address."""

    operands = instruction.operands.split(";", 1)[0]
    indexed = _INDEXED_MEMORY_OPERAND.search(operands)
    location = core._memory_location(instruction)
    if location is None:
        if indexed is None:
            return None
        base_register = core._canonical_register(indexed.group(1))
        immediate_offset = 0
    else:
        base_register, immediate_offset = location
    base = _constant_register_before(
        function,
        base_register,
        before=instruction,
        literal_words=literal_words,
    )
    if base is None:
        return None
    address = (base[0] + immediate_offset) & 0xFFFFFFFF
    if indexed is None:
        return address
    index_register = core._canonical_register(indexed.group(2))
    index = _constant_register_before(
        function,
        index_register,
        before=instruction,
        literal_words=literal_words,
    )
    if index is None:
        return None
    shift = int(indexed.group(3), 0) if indexed.group(3) else 0
    return (address + ((index[0] << shift) & 0xFFFFFFFF)) & 0xFFFFFFFF


def _register_value_before(
    function: Function,
    register: str,
    *,
    before: Instruction,
    literal_words: dict[int, int],
    depth: int = 0,
) -> tuple[str, int | None, tuple[Instruction, ...]] | None:
    """Resolve a constant or the entry sample-rate value through simple moves."""

    if depth > 8:
        return None
    writer = _last_dominating_register_writer(
        function,
        register,
        before=before,
    )
    if writer is None:
        return ("entry-r0", None, ()) if register == "r0" else None
    constant = _constant_register_before(
        function,
        register,
        before=before,
        literal_words=literal_words,
    )
    if constant is not None:
        return "constant", constant[0], constant[1]
    mnemonic = writer.mnemonic.lower().split(".", 1)[0]
    registers = core._operand_registers(writer)
    if mnemonic.startswith("mov") and len(registers) >= 2:
        source = _register_value_before(
            function,
            registers[1],
            before=writer,
            literal_words=literal_words,
            depth=depth + 1,
        )
        if source is not None:
            return source[0], source[1], (*source[2], writer)
    return None


def _add_symbolic(
    value: _SymbolicValue,
    amount: int,
    instruction: Instruction,
) -> _SymbolicValue:
    if value.kind not in {"constant", "stack"} or value.value is None:
        return _unknown(instruction)
    return _SymbolicValue(
        value.kind,
        (value.value + amount) & 0xFFFFFFFF,
        _with_origin(value, instruction).origins,
    )


def _clean_operands(instruction: Instruction) -> str:
    return instruction.operands.split(";", 1)[0].strip()


def _immediate_operand(instruction: Instruction) -> int | None:
    match = re.search(_IMMEDIATE, _clean_operands(instruction))
    return int(match.group(1), 0) if match else None


def _effective_symbolic_address(
    registers: dict[str, _SymbolicValue],
    instruction: Instruction,
) -> _SymbolicValue:
    location = core._memory_location(instruction)
    if location is None:
        return _unknown(instruction)
    base, offset = location
    return _add_symbolic(
        registers.get(base, _unknown(instruction)),
        offset,
        instruction,
    )


def _p12_sent_messages(
    function: Function,
    *,
    text_contents: dict[int, int],
    literal_words: dict[int, int],
) -> _P12MessageTrace:
    """Symbolically recover the three exact Message objects sent by M0.

    This intentionally models only the small reviewed Thumb subset emitted by
    ``baseband::set_precision_rx``.  Any unmodelled register write becomes
    unknown, so optimization drift fails closed rather than inheriting a stale
    value.
    """

    registers = {
        f"r{index}": _SymbolicValue("unknown")
        for index in range(16)
    }
    registers["r0"] = _SymbolicValue("entry-r0")
    registers["r13"] = _SymbolicValue("stack", 0)
    stack_words: dict[int, _StoredWord] = {}
    sent: list[_SentMessage] = []
    stack_writes: list[_StackWrite] = []
    stack_reads: list[_StackRead] = []

    for instruction in function.instructions:
        mnemonic = instruction.mnemonic.lower().split(".", 1)[0]
        operand_registers = core._operand_registers(instruction)

        if mnemonic in {"bl", "blx"}:
            if (
                instruction.target is not None
                and instruction.target.startswith(SEND_MESSAGE_NAME)
            ):
                pointer = registers["r0"]
                _require(
                    pointer.kind == "stack" and pointer.value is not None,
                    "p12 send_message r0 must point to a modeled stack Message",
                )
                first = stack_words.get(pointer.value)
                second = stack_words.get(pointer.value + 4)
                _require(
                    first is not None and second is not None,
                    "p12 send_message must receive a fully constructed "
                    "eight-byte stack Message",
                )
                _require(
                    pointer.origins,
                    "p12 send_message pointer has no linked materialization",
                )
                sent.append(
                    _SentMessage(
                        instruction,
                        pointer,
                        pointer.origins[-1],
                        (first, second),
                    )
                )
            for register in ("r0", "r1", "r2", "r3"):
                registers[register] = _unknown(instruction)
            continue

        if mnemonic == "push":
            registers["r13"] = _add_symbolic(
                registers["r13"],
                -4 * len(operand_registers),
                instruction,
            )
            continue
        if mnemonic == "pop":
            registers["r13"] = _add_symbolic(
                registers["r13"],
                4 * len(operand_registers),
                instruction,
            )
            for register in operand_registers:
                if register != "r13":
                    registers[register] = _unknown(instruction)
            continue

        if mnemonic.startswith("ldm"):
            _require(
                len(operand_registers) >= 2,
                f"unsupported load-multiple shape at 0x{instruction.address:x}",
            )
            base_register = operand_registers[0]
            base = registers[base_register]
            for index, destination in enumerate(operand_registers[1:]):
                address = (
                    (base.value + 4 * index) & 0xFFFFFFFF
                    if base.value is not None
                    else None
                )
                if base.kind == "constant" and address is not None:
                    value = _read_u32(
                        text_contents,
                        address,
                        description="p12 control-message source word",
                    )
                    registers[destination] = _SymbolicValue(
                        "constant",
                        value,
                        (instruction,),
                    )
                elif base.kind == "stack" and address is not None:
                    stored = stack_words.get(address)
                    stack_reads.append(
                        _StackRead(address, 4, instruction, destination)
                    )
                    registers[destination] = (
                        _with_origin(stored.value, instruction)
                        if stored is not None
                        else _unknown(instruction)
                    )
                else:
                    registers[destination] = _unknown(instruction)
            if "!" in _clean_operands(instruction):
                registers[base_register] = _add_symbolic(
                    base,
                    4 * (len(operand_registers) - 1),
                    instruction,
                )
            continue

        if mnemonic.startswith("stm"):
            _require(
                len(operand_registers) >= 2,
                f"unsupported store-multiple shape at 0x{instruction.address:x}",
            )
            base_register = operand_registers[0]
            base = registers[base_register]
            if base.kind == "stack" and base.value is not None:
                for index, source in enumerate(operand_registers[1:]):
                    address = base.value + 4 * index
                    stored = _StoredWord(
                        registers[source],
                        instruction,
                    )
                    stack_words[address] = stored
                    stack_writes.append(_StackWrite(address, 4, stored))
            if "!" in _clean_operands(instruction):
                registers[base_register] = _add_symbolic(
                    base,
                    4 * (len(operand_registers) - 1),
                    instruction,
                )
            continue

        if mnemonic.startswith("ldr"):
            destination = (
                operand_registers[0] if operand_registers else None
            )
            if destination is None:
                continue
            literal_target = core._pc_literal_target(instruction)
            if literal_target is not None:
                value = (
                    _read_u32(
                        text_contents,
                        literal_target,
                        description="p12 PC-relative literal",
                    )
                    if all(
                        literal_target + offset in text_contents
                        for offset in range(4)
                    )
                    else literal_words.get(literal_target)
                )
                registers[destination] = (
                    _SymbolicValue("constant", value, (instruction,))
                    if value is not None
                    else _unknown(instruction)
                )
                continue
            address = _effective_symbolic_address(registers, instruction)
            if address.kind == "stack" and address.value is not None:
                stored = stack_words.get(address.value)
                stack_reads.append(
                    _StackRead(
                        address.value,
                        1 if mnemonic == "ldrb"
                        else 2 if mnemonic == "ldrh"
                        else 4,
                        instruction,
                        destination,
                    )
                )
                registers[destination] = (
                    _with_origin(stored.value, instruction)
                    if stored is not None
                    else _unknown(instruction)
                )
            else:
                registers[destination] = _unknown(instruction)
            continue

        if mnemonic.startswith("str"):
            source = operand_registers[0] if operand_registers else None
            address = _effective_symbolic_address(registers, instruction)
            if (
                source is not None
                and address.kind == "stack"
                and address.value is not None
                and mnemonic in {"str", "strh", "strb"}
            ):
                size = 1 if mnemonic == "strb" else 2 if mnemonic == "strh" else 4
                stored = _StoredWord(
                    registers[source] if size == 4 else _unknown(instruction),
                    instruction,
                )
                if size == 4:
                    stack_words[address.value] = stored
                else:
                    write_end = address.value + size
                    for word_address in tuple(stack_words):
                        if (
                            address.value < word_address + 4
                            and word_address < write_end
                        ):
                            stack_words[word_address] = stored
                stack_writes.append(
                    _StackWrite(address.value, size, stored)
                )
            continue

        if mnemonic in {"mov", "movs", "movw"} and operand_registers:
            destination = operand_registers[0]
            immediate = _immediate_operand(instruction)
            if immediate is not None:
                registers[destination] = _SymbolicValue(
                    "constant",
                    immediate,
                    (instruction,),
                )
            elif len(operand_registers) >= 2:
                registers[destination] = _with_origin(
                    registers[operand_registers[1]],
                    instruction,
                )
            else:
                registers[destination] = _unknown(instruction)
            continue

        if mnemonic in {"add", "adds", "sub", "subs"} and operand_registers:
            destination = operand_registers[0]
            immediate = _immediate_operand(instruction)
            if immediate is None:
                registers[destination] = _unknown(instruction)
                continue
            source = (
                operand_registers[1]
                if len(operand_registers) >= 2
                else destination
            )
            amount = -immediate if mnemonic.startswith("sub") else immediate
            registers[destination] = _add_symbolic(
                registers[source],
                amount,
                instruction,
            )
            continue

        for destination in core._written_registers(instruction):
            registers[destination] = _unknown(instruction)

    return _P12MessageTrace(
        tuple(sent),
        tuple(stack_writes),
        tuple(stack_reads),
    )


def _p12_ack_read_from_payload(
    function: Function,
    *,
    stack_reads: Sequence[_StackRead],
    payload_address: int,
    after: Instruction,
    before: Instruction,
    name: str,
) -> _StackRead:
    """Require an acknowledgement load from the reusable payload word.

    The M4 mutates the second word of the stack Message while ``send_message``
    waits.  Require the linked M0 to reload that exact word and feed the value
    to a compare before any physical-side effect or rollback.
    """

    candidates = [
        read
        for read in stack_reads
        if read.address == payload_address
        and read.size == 4
        and after.address < read.instruction.address < before.address
    ]
    for read in candidates:
        for instruction in function.instructions:
            if instruction.address <= read.instruction.address:
                continue
            if instruction.address >= before.address:
                break
            if (
                instruction.mnemonic.lower().split(".", 1)[0] == "cmp"
                and read.destination in core._operand_registers(instruction)
            ):
                return read
            if read.destination in core._written_registers(instruction):
                break
    raise VerificationError(
        f"p12 {name} acknowledgement must be reloaded and compared from "
        "the reusable Message payload word"
    )


def _require_exact_p12_messages(
    function: Function,
    *,
    send_calls: Sequence[Instruction],
    target_clock: Instruction,
    rollback_filter: Instruction,
    text_contents: dict[int, int],
    literal_words: dict[int, int],
) -> dict[str, object]:
    trace = _p12_sent_messages(
        function,
        text_contents=text_contents,
        literal_words=literal_words,
    )
    sent = trace.sent
    _require(
        tuple(message.call for message in sent) == tuple(send_calls),
        "p12 symbolic send recovery does not match the three linked calls",
    )
    _require(
        len(sent) == 3,
        f"p12 reusable-message proof expected three sends; found {len(sent)}",
    )
    pointer_addresses = {
        message.pointer.value
        for message in sent
        if message.pointer.kind == "stack"
    }
    _require(
        len(pointer_addresses) == 1
        and all(message.pointer.kind == "stack" for message in sent),
        "p12 PREPARE, COMMIT, and ABORT must use the same stack Message",
    )
    message_pointer_address = next(iter(pointer_addresses))
    _require(
        message_pointer_address is not None,
        "p12 reusable stack Message has no modeled address",
    )
    message_id_address = message_pointer_address
    payload_address = message_pointer_address + 4

    id_writes = [
        write
        for write in trace.stack_writes
        if write.address < message_id_address + 4
        and message_id_address < write.address + write.size
    ]
    _require(
        len(id_writes) == 1,
        "p12 reusable Message ID word must have exactly one initialization "
        "and no rewrite",
    )
    id_initialization = id_writes[0].stored
    _require(
        id_initialization.value.kind == "constant"
        and id_initialization.value.value == EXPECTED_P12_MESSAGE_ID,
        f"p12 reusable Message ID initialization is not exactly "
        f"{EXPECTED_P12_MESSAGE_ID}",
    )
    _require(
        all(
            message.words[0].writer == id_initialization.writer
            and message.words[0].value == id_initialization.value
            for message in sent
        ),
        "p12 all sends must retain the single reusable Message ID "
        "initialization",
    )
    for message in sent:
        core._require_cfg_dominance(
            function,
            start=function.instructions[0],
            target=message.call,
            required=(
                (
                    "p12 reusable Message ID initialization",
                    id_initialization.writer,
                ),
            ),
        )

    expected_payloads = (
        ("entry-r0", None, "PREPARE"),
        ("constant", EXPECTED_P12_COMMIT_CONTROL_WORD, "COMMIT"),
        ("constant", EXPECTED_P12_ABORT_CONTROL_WORD, "ABORT"),
    )
    boundaries: tuple[Instruction | None, ...] = (
        None,
        target_clock,
        rollback_filter,
    )

    for message, (payload_kind, payload_value, name), boundary in zip(
        sent,
        expected_payloads,
        boundaries,
        strict=True,
    ):
        message_id, payload = message.words
        _require(
            message_id.value.kind == "constant"
            and message_id.value.value == EXPECTED_P12_MESSAGE_ID,
            f"p12 {name} message ID is not exactly "
            f"{EXPECTED_P12_MESSAGE_ID}",
        )
        _require(
            payload.value.kind == payload_kind
            and (
                payload_value is None
                or payload.value.value == payload_value
            ),
            (
                "p12 PREPARE payload is not the entry sample rate"
                if name == "PREPARE"
                else f"p12 {name} control word is not exactly "
                f"0x{payload_value:08x}"
            ),
        )

        evidence = {
            message.pointer_writer,
            message_id.writer,
            payload.writer,
            *message_id.value.origins,
            *payload.value.origins,
        }
        core._require_cfg_dominance(
            function,
            start=function.instructions[0],
            target=message.call,
            required=tuple(
                (
                    f"p12 {name} message def-use instruction "
                    f"0x{instruction.address:x}",
                    instruction,
                )
                for instruction in sorted(
                    evidence,
                    key=lambda item: item.address,
                )
            ),
        )
        if boundary is not None:
            _require(
                payload.writer.address > boundary.address,
                f"p12 {name} payload must be written after "
                f"0x{boundary.address:x}",
            )

    payload_writers = tuple(message.words[1].writer for message in sent)
    _require(
        len({writer.address for writer in payload_writers}) == 3,
        "p12 reusable Message must have distinct PREPARE, COMMIT, and ABORT "
        "payload writes",
    )
    prepare_ack_read = _p12_ack_read_from_payload(
        function,
        stack_reads=trace.stack_reads,
        payload_address=payload_address,
        after=sent[0].call,
        before=target_clock,
        name="PREPARE",
    )
    commit_ack_read = _p12_ack_read_from_payload(
        function,
        stack_reads=trace.stack_reads,
        payload_address=payload_address,
        after=sent[1].call,
        before=rollback_filter,
        name="COMMIT",
    )

    return {
        "message_id": EXPECTED_P12_MESSAGE_ID,
        "prepare_payload": "entry_sample_rate",
        "commit_control_word": EXPECTED_P12_COMMIT_CONTROL_WORD,
        "abort_control_word": EXPECTED_P12_ABORT_CONTROL_WORD,
        "message_def_use_cfg_dominated": True,
        "message_storage_reused": True,
        "message_id_initialized_once": True,
        "message_id_write_address": id_initialization.writer.address,
        "prepare_message_pointer_address": message_pointer_address,
        "commit_message_pointer_address": message_pointer_address,
        "abort_message_pointer_address": message_pointer_address,
        "prepare_payload_write_address": payload_writers[0].address,
        "commit_payload_write_address": payload_writers[1].address,
        "abort_payload_write_address": payload_writers[2].address,
        "prepare_ack_payload_read_address":
            prepare_ack_read.instruction.address,
        "commit_ack_payload_read_address":
            commit_ack_read.instruction.address,
    }


def _instruction_index(
    function: Function,
    instruction: Instruction,
) -> int:
    try:
        return function.instructions.index(instruction)
    except ValueError as error:
        raise VerificationError(
            f"instruction 0x{instruction.address:x} is not in {function.name}"
        ) from error


def _adjacent_instruction(
    function: Function,
    instruction: Instruction,
    offset: int = 1,
) -> Instruction:
    index = _instruction_index(function, instruction) + offset
    _require(
        0 <= index < len(function.instructions),
        f"{function.name} has no instruction {offset:+d} from "
        f"0x{instruction.address:x}",
    )
    return function.instructions[index]


def _clean_mnemonic(instruction: Instruction) -> str:
    return instruction.mnemonic.lower().split(".", 1)[0]


def _call_clobbers_register(
    instruction: Instruction,
    register: str,
) -> bool:
    return (
        _clean_mnemonic(instruction) in {"bl", "blx"}
        and register in {"r0", "r1", "r2", "r3", "r12", "r14"}
    )


def _last_register_writer(
    function: Function,
    before: Instruction,
    register: str,
) -> Instruction:
    before_index = _instruction_index(function, before)
    for instruction in reversed(function.instructions[:before_index]):
        if _call_clobbers_register(instruction, register) or _writes_register(
            instruction, register
        ):
            return instruction
    raise VerificationError(
        f"cannot find the linked writer of {register} before "
        f"0x{before.address:x} in {function.name}"
    )


def _literal_value(
    instruction: Instruction,
    *,
    text_contents: dict[int, int],
    literal_words: dict[int, int],
    description: str,
) -> int:
    target = core._pc_literal_target(instruction)
    _require(
        target is not None,
        f"{description} must be materialized by an exact PC-relative load",
    )
    if all(target + offset in text_contents for offset in range(4)):
        return _read_u32(text_contents, target, description=description)
    _require(
        target in literal_words,
        f"{description} literal 0x{target:08x} is absent from linked bytes",
    )
    return literal_words[target]


def _move_constant(
    instruction: Instruction,
) -> tuple[str, int] | None:
    if _clean_mnemonic(instruction) not in {"mov", "movs", "movw"}:
        return None
    match = _MOVE_IMMEDIATE.fullmatch(_clean_operands(instruction))
    if match is None:
        return None
    return match.group(1), int(match.group(2), 0)


def _compare_register_immediate(
    instruction: Instruction,
) -> tuple[str, int] | None:
    if _clean_mnemonic(instruction) != "cmp":
        return None
    operands = _clean_operands(instruction)
    match = re.fullmatch(
        rf"(r(?:1[0-5]|[0-9])),\s*{_IMMEDIATE}",
        operands,
    )
    if match is None:
        return None
    return match.group(1), int(match.group(2), 0)


def _require_no_register_clobber(
    function: Function,
    *,
    register: str,
    after: Instruction,
    before: Instruction,
    description: str,
) -> None:
    start = _instruction_index(function, after) + 1
    end = _instruction_index(function, before)
    clobbers = [
        instruction
        for instruction in function.instructions[start:end]
        if _call_clobbers_register(instruction, register)
        or _writes_register(instruction, register)
    ]
    _require(
        not clobbers,
        f"{description} is clobbered by "
        + ", ".join(f"0x{instruction.address:x}" for instruction in clobbers),
    )


def _branch_target(
    instruction: Instruction,
    *,
    description: str,
) -> int:
    target = core._branch_target_address(instruction)
    _require(
        target is not None,
        f"{description} at 0x{instruction.address:x} has no linked target",
    )
    return target


def _instruction_at(
    function: Function,
    address: int,
    *,
    description: str,
) -> Instruction:
    matches = [
        instruction
        for instruction in function.instructions
        if instruction.address == address
    ]
    _require(
        len(matches) == 1,
        f"{description} target 0x{address:x} is not one linked instruction",
    )
    return matches[0]


def _require_memory_operand(
    instruction: Instruction,
    *,
    base: str,
    offset: int,
    description: str,
) -> None:
    _require(
        core._memory_location(instruction) == (base, offset),
        f"{description} must address exactly [{base}, #{offset}]",
    )


def _p12_m4_rate_state_checks(
    function: Function,
    *,
    text_contents: dict[int, int],
    literal_words: dict[int, int],
) -> tuple[_M4RateStateCheck, _M4RateStateCheck]:
    candidates: list[_M4RateStateCheck] = []
    for load in function.instructions:
        if _clean_mnemonic(load) != "ldrb":
            continue
        match = _INDEXED_BYTE_LOAD.fullmatch(_clean_operands(load))
        if match is None:
            continue
        destination, base_register, offset_register = match.groups()
        base_writer = _last_register_writer(
            function, load, base_register
        )
        offset_writer = _last_register_writer(
            function, load, offset_register
        )
        if _clean_mnemonic(base_writer) != "ldr" or _clean_mnemonic(
            offset_writer
        ) != "ldr":
            continue
        try:
            base_value = _literal_value(
                base_writer,
                text_contents=text_contents,
                literal_words=literal_words,
                description="shared_memory base",
            )
            offset_value = _literal_value(
                offset_writer,
                text_contents=text_contents,
                literal_words=literal_words,
                description="m4_dma_rate_state offset",
            )
        except VerificationError:
            continue
        if (
            base_value != EXPECTED_SHARED_MEMORY_BASE
            or offset_value != EXPECTED_M4_DMA_RATE_STATE_OFFSET
        ):
            continue

        compare = _adjacent_instruction(function, load)
        compared = _compare_register_immediate(compare)
        _require(
            compared == (destination, EXPECTED_P12_M4_DMA_FATAL_STATE),
            "linked m4_dma_rate_state load must compare exactly against "
            f"fatal state {EXPECTED_P12_M4_DMA_FATAL_STATE}",
        )
        branch = _adjacent_instruction(function, compare)
        _require(
            _clean_mnemonic(branch) == "bne",
            "linked m4_dma_rate_state fatal check must use an exact BNE "
            "nonfatal branch",
        )
        _branch_target(
            branch,
            description="m4_dma_rate_state nonfatal branch",
        )
        _require_no_register_clobber(
            function,
            register=base_register,
            after=base_writer,
            before=load,
            description="shared_memory base",
        )
        _require_no_register_clobber(
            function,
            register=offset_register,
            after=offset_writer,
            before=load,
            description="m4_dma_rate_state offset",
        )
        candidates.append(
            _M4RateStateCheck(
                base_writer,
                offset_writer,
                load,
                compare,
                branch,
            )
        )

    _require(
        len(candidates) == 2,
        "BufferExchange::get must contain exactly two linked "
        "shared_memory.m4_dma_rate_state checks; found "
        f"{len(candidates)}",
    )
    ordered = sorted(candidates, key=lambda check: check.load.address)
    return ordered[0], ordered[1]


def _require_p12_buffer_exchange_watchdog(
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    *,
    text_contents: dict[int, int],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Bind the p12 M0 fatal-watchdog behavior in the optimized linked ELF."""

    watchdog_metadata_ms = _absolute_value(
        symbols, M0_FAULT_WATCHDOG_MS_SYMBOL
    )
    _require(
        watchdog_metadata_ms == EXPECTED_P12_M0_FAULT_WATCHDOG_MS,
        f"linked M0 fault watchdog metadata is {watchdog_metadata_ms}; "
        f"expected {EXPECTED_P12_M0_FAULT_WATCHDOG_MS}",
    )
    buffer_get = _unique_function(
        functions,
        BUFFER_EXCHANGE_GET_NAME,
        lambda name: name == BUFFER_EXCHANGE_GET_NAME,
    )
    buffer_get_size = _unique_symbol_size(
        symbols,
        BUFFER_EXCHANGE_GET_NAME,
        lambda name: name == BUFFER_EXCHANGE_GET_NAME,
    )
    _require(
        bool(buffer_get.instructions),
        f"{BUFFER_EXCHANGE_GET_NAME} has no linked instructions",
    )

    shared_memory = _unique_named_symbol(symbols, SHARED_MEMORY_SYMBOL)
    _require(
        shared_memory.size == 4,
        f"{SHARED_MEMORY_SYMBOL} must be one four-byte linked reference",
    )
    shared_memory_base = _read_u32(
        text_contents,
        shared_memory.address,
        description="shared_memory linked reference",
    )
    _require(
        shared_memory_base == EXPECTED_SHARED_MEMORY_BASE,
        "shared_memory linked reference does not bind the reviewed "
        f"0x{EXPECTED_SHARED_MEMORY_BASE:08x} transport base",
    )

    timed_calls = _calls_matching(
        buffer_get, lambda name: name == SLEEP_TIMEOUT_NAME
    )
    regular_sleep_calls = _calls_matching(
        buffer_get, lambda name: name == SLEEP_NAME
    )
    _require(
        len(timed_calls) == 1,
        f"{BUFFER_EXCHANGE_GET_NAME} must call {SLEEP_TIMEOUT_NAME} "
        f"exactly once; found {len(timed_calls)}",
    )
    _require(
        len(regular_sleep_calls) == 1,
        f"{BUFFER_EXCHANGE_GET_NAME} must retain exactly one non-precision "
        f"{SLEEP_NAME} call; found {len(regular_sleep_calls)}",
    )
    timed_call = timed_calls[0]
    regular_sleep_call = regular_sleep_calls[0]
    timeout_ms = _constant_argument_before_call(
        buffer_get, timed_call, "r1"
    )
    suspended_state = _constant_argument_before_call(
        buffer_get, timed_call, "r0"
    )
    _require(
        timeout_ms == EXPECTED_P12_M0_FAULT_WATCHDOG_MS,
        f"linked M0 fatal watchdog timeout is {timeout_ms} ms; expected "
        f"{EXPECTED_P12_M0_FAULT_WATCHDOG_MS}",
    )
    _require(
        suspended_state == CHIBIOS_SUSPENDED_THREAD_STATE,
        f"timed watchdog sleep state is {suspended_state}; expected "
        f"{CHIBIOS_SUSPENDED_THREAD_STATE}",
    )

    lock_instructions = [
        instruction
        for instruction in buffer_get.instructions
        if _clean_mnemonic(instruction) == "cpsid"
        and _clean_operands(instruction) == "i"
    ]
    _require(
        len(lock_instructions) == 1,
        "BufferExchange::get must contain one linked interrupt lock",
    )
    lock_instruction = lock_instructions[0]
    lock_calls = _calls_matching(
        buffer_get, lambda name: name == DEBUG_LOCK_NAME
    )
    unlock_calls = _calls_matching(
        buffer_get, lambda name: name == DEBUG_UNLOCK_NAME
    )
    _require(
        len(lock_calls) == 1 and len(unlock_calls) == 2,
        "BufferExchange::get must retain one debug lock and two reviewed "
        "debug unlock exits",
    )
    _require(
        lock_instruction.address < lock_calls[0].address < timed_call.address,
        "watchdog timed sleep must execute under the BufferExchange system lock",
    )

    entry_this_moves = []
    for instruction in buffer_get.instructions:
        if instruction.address >= lock_instruction.address:
            break
        if _clean_mnemonic(instruction) not in {"mov", "movs"}:
            continue
        registers = core._operand_registers(instruction)
        if (
            len(registers) >= 2
            and registers[1] == "r0"
            and re.fullmatch(r"r(?:1[01]|[4-9])", registers[0])
        ):
            entry_this_moves.append((instruction, registers[0]))
    _require(
        len(entry_this_moves) == 1,
        "BufferExchange::get must save entry this exactly once before locking",
    )
    this_init, this_register = entry_this_moves[0]
    this_writers = [
        instruction
        for instruction in buffer_get.instructions
        if instruction.address > this_init.address
        and _writes_register(instruction, this_register)
    ]
    _require(
        not this_writers,
        "BufferExchange::get saved this register is clobbered after entry",
    )

    state_checks = _p12_m4_rate_state_checks(
        buffer_get,
        text_contents=text_contents,
        literal_words=literal_words,
    )
    precheck, postcheck = state_checks
    _require(
        precheck.load.address < regular_sleep_call.address < timed_call.address
        < postcheck.load.address,
        "linked M4 fatal checks must bracket the precision watchdog sleep",
    )

    direction_loads = [
        instruction
        for instruction in buffer_get.instructions
        if instruction.address < precheck.load.address
        and _clean_mnemonic(instruction) == "ldrb"
        and core._memory_location(instruction)
        == (this_register, BUFFER_EXCHANGE_DIRECTION_OFFSET)
    ]
    _require(
        len(direction_loads) == 1,
        "precision watchdog gate must load BufferExchange::direction exactly once",
    )
    direction_load = direction_loads[0]
    direction_register = core._operand_registers(direction_load)[0]
    direction_compare = _adjacent_instruction(buffer_get, direction_load)
    _require(
        _compare_register_immediate(direction_compare)
        == (direction_register, BUFFER_EXCHANGE_CAPTURE_DIRECTION),
        "precision watchdog gate must compare direction exactly with CAPTURE",
    )
    direction_branch = _adjacent_instruction(buffer_get, direction_compare)
    _require(
        _clean_mnemonic(direction_branch) == "bne",
        "non-capture BufferExchange direction must bypass the precision gate",
    )
    _require_no_register_clobber(
        buffer_get,
        register=direction_register,
        after=direction_branch,
        before=precheck.nonfatal_branch,
        description="CAPTURE/null value on the pre-sleep fatal path",
    )

    config_loads = [
        instruction
        for instruction in buffer_get.instructions
        if direction_branch.address < instruction.address < precheck.load.address
        and _clean_mnemonic(instruction) == "ldr"
        and core._memory_location(instruction)
        == (this_register, BUFFER_EXCHANGE_CONFIG_CAPTURE_OFFSET)
    ]
    _require(
        len(config_loads) == 1,
        "precision watchdog gate must load config_capture exactly once",
    )
    config_load = config_loads[0]
    config_register = core._operand_registers(config_load)[0]
    config_compare = _adjacent_instruction(buffer_get, config_load)
    _require(
        _compare_register_immediate(config_compare) == (config_register, 0),
        "precision watchdog gate must reject null config_capture",
    )
    config_branch = _adjacent_instruction(buffer_get, config_compare)
    _require(
        _clean_mnemonic(config_branch) == "beq",
        "null config_capture must bypass the precision watchdog",
    )

    final_report_load = _adjacent_instruction(buffer_get, config_branch)
    _require(
        _clean_mnemonic(final_report_load) == "ldr",
        "precision watchdog gate must load precision_rx_final_report",
    )
    final_report_registers = core._operand_registers(final_report_load)
    _require(
        bool(final_report_registers)
        and final_report_registers[0] == config_register,
        "precision_rx_final_report gate must remain in the config register",
    )
    _require_memory_operand(
        final_report_load,
        base=config_register,
        offset=CAPTURE_CONFIG_FINAL_REPORT_OFFSET,
        description="precision_rx_final_report load",
    )
    final_report_compare = _adjacent_instruction(
        buffer_get, final_report_load
    )
    _require(
        _compare_register_immediate(final_report_compare)
        == (config_register, 0),
        "precision watchdog gate must reject null precision_rx_final_report",
    )
    final_report_branch = _adjacent_instruction(
        buffer_get, final_report_compare
    )
    _require(
        _clean_mnemonic(final_report_branch) == "beq",
        "null precision_rx_final_report must bypass the precision watchdog",
    )
    precheck_dmb = _adjacent_instruction(
        buffer_get, precheck.base_writer, -1
    )
    _require(
        _clean_mnemonic(precheck_dmb) == "dmb",
        "pre-sleep M4 fatal state must be sampled after a linked DMB",
    )
    core._require_cfg_dominance(
        buffer_get,
        start=buffer_get.instructions[0],
        target=precheck.nonfatal_branch,
        required=(
            ("capture direction load", direction_load),
            ("capture direction compare", direction_compare),
            ("capture direction gate", direction_branch),
            ("config_capture load", config_load),
            ("config_capture compare", config_compare),
            ("config_capture gate", config_branch),
            ("precision final-report load", final_report_load),
            ("precision final-report compare", final_report_compare),
            ("precision final-report gate", final_report_branch),
            ("pre-sleep M4 acquire DMB", precheck_dmb),
            ("pre-sleep shared base", precheck.base_writer),
            ("pre-sleep shared offset", precheck.offset_writer),
            ("pre-sleep M4 state load", precheck.load),
            ("pre-sleep M4 state compare", precheck.compare),
        ),
    )

    precision_flag_target = _branch_target(
        precheck.nonfatal_branch,
        description="pre-sleep M4 nonfatal branch",
    )
    precision_flag_one = _instruction_at(
        buffer_get,
        precision_flag_target,
        description="precision-capture flag",
    )
    precision_move = _move_constant(precision_flag_one)
    _require(
        precision_move is not None and precision_move[1] == 1,
        "pre-sleep nonfatal M4 check must materialize precision_capture=true",
    )
    precision_flag_register = precision_move[0]
    _require(
        precision_flag_register == config_register,
        "config/final-report null results and precision_capture flag must "
        "share one linked register",
    )
    precision_to_fifo = _adjacent_instruction(
        buffer_get, precision_flag_one
    )
    _require(
        _clean_mnemonic(precision_to_fifo) == "b",
        "precision_capture=true must join the reviewed FIFO path",
    )
    fifo_entry = _branch_target(
        precision_to_fifo,
        description="precision FIFO join",
    )

    nonprecision_target = _branch_target(
        direction_branch,
        description="non-precision direction branch",
    )
    nonprecision_zero = _instruction_at(
        buffer_get,
        nonprecision_target,
        description="non-precision flag",
    )
    _require(
        _move_constant(nonprecision_zero)
        == (precision_flag_register, 0),
        "non-precision path must materialize precision_capture=false",
    )
    _require(
        _adjacent_instruction(buffer_get, nonprecision_zero).address
        == fifo_entry,
        "precision and non-precision gates must join one FIFO path",
    )
    _require(
        _branch_target(
            config_branch,
            description="null config_capture branch",
        )
        == fifo_entry
        and _branch_target(
            final_report_branch,
            description="null precision_rx_final_report branch",
        )
        == fifo_entry,
        "only CAPTURE with config and final-report identity may set the "
        "precision watchdog flag",
    )
    watchdog_successors = core._control_flow_successors(buffer_get)
    precision_flag_predecessors = {
        source
        for source, targets in watchdog_successors.items()
        if precision_flag_one.address in targets
    }
    _require(
        precision_flag_predecessors == {precheck.nonfatal_branch.address},
        "only the pre-sleep nonfatal M4 check may set precision_capture=true",
    )

    timeout_writer = _last_register_writer(buffer_get, timed_call, "r1")
    timeout_move = _move_constant(timeout_writer)
    _require(
        timeout_move == ("r1", EXPECTED_P12_M0_FAULT_WATCHDOG_MS),
        "watchdog timeout register must be written exactly from the 10 ms "
        "linked constant",
    )
    zero_writer = _last_register_writer(
        buffer_get, timeout_writer, direction_register
    )
    _require(
        _move_constant(zero_writer) == (direction_register, 0),
        "precision timed-sleep path must materialize a stable null return",
    )
    timed_path_target = zero_writer.address
    timed_gate_branches = [
        instruction
        for instruction in buffer_get.instructions
        if instruction.address < zero_writer.address
        and core._is_conditional_branch(instruction)
        and core._branch_target_address(instruction) == timed_path_target
    ]
    _require(
        len(timed_gate_branches) == 1,
        "precision_capture flag must select exactly one timed-sleep path",
    )
    timed_gate_branch = timed_gate_branches[0]
    timed_gate_compare = _adjacent_instruction(
        buffer_get, timed_gate_branch, -1
    )
    _require(
        _clean_mnemonic(timed_gate_branch) == "bne"
        and _branch_target(
            timed_gate_branch,
            description="precision timed-sleep branch",
        )
        == timed_path_target,
        "precision_capture=true must be the sole branch into timed sleep",
    )
    _require(
        _compare_register_immediate(timed_gate_compare)
        == (precision_flag_register, 0),
        "timed sleep must be gated by the linked precision_capture flag",
    )
    timed_path_predecessors = {
        source
        for source, targets in watchdog_successors.items()
        if timed_path_target in targets
    }
    _require(
        timed_path_predecessors == {timed_gate_branch.address},
        "precision timed sleep must have exactly one linked entry edge",
    )
    _require_no_register_clobber(
        buffer_get,
        register=precision_flag_register,
        after=precision_flag_one,
        before=timed_gate_compare,
        description="precision_capture=true flag",
    )
    fifo_entry_instruction = _instruction_at(
        buffer_get,
        fifo_entry,
        description="precision FIFO join",
    )
    _require_no_register_clobber(
        buffer_get,
        register=precision_flag_register,
        after=fifo_entry_instruction,
        before=precision_flag_one,
        description="precision_capture flag through FIFO dequeue",
    )
    _require(
        timed_gate_branch.address < regular_sleep_call.address
        < timed_path_target < timed_call.address,
        "non-precision sleep must remain the fallthrough alternative to the "
        "precision timed watchdog",
    )

    post_clear = _adjacent_instruction(buffer_get, timed_call)
    _require(
        _clean_mnemonic(post_clear) == "str",
        "each timed wake must immediately clear BufferExchange::thread",
    )
    post_clear_registers = core._operand_registers(post_clear)
    _require(
        bool(post_clear_registers)
        and post_clear_registers[0] == direction_register,
        "timed-wake thread clear must store the linked zero register",
    )
    _require_memory_operand(
        post_clear,
        base=this_register,
        offset=BUFFER_EXCHANGE_THREAD_OFFSET,
        description="timed-wake thread clear",
    )
    post_clear_dmb = _adjacent_instruction(buffer_get, post_clear)
    _require(
        _clean_mnemonic(post_clear_dmb) == "dmb",
        "timed-wake thread clear must be followed by DMB before M4 state",
    )
    _require(
        _adjacent_instruction(buffer_get, post_clear_dmb)
        == postcheck.base_writer
        and _adjacent_instruction(buffer_get, postcheck.base_writer)
        == postcheck.offset_writer
        and _adjacent_instruction(buffer_get, postcheck.offset_writer)
        == postcheck.load,
        "every timed wake must flow directly from thread clear/DMB to the "
        "shared m4_dma_rate_state check",
    )
    _require_no_register_clobber(
        buffer_get,
        register=direction_register,
        after=zero_writer,
        before=post_clear,
        description="timed-watchdog null/thread-clear value",
    )
    core._require_cfg_dominance(
        buffer_get,
        start=buffer_get.instructions[0],
        target=postcheck.compare,
        required=(
            ("watchdog system lock", lock_instruction),
            ("precision timed sleep", timed_call),
            ("timed-wake thread clear", post_clear),
            ("timed-wake clear DMB", post_clear_dmb),
            ("post-wake shared base", postcheck.base_writer),
            ("post-wake shared offset", postcheck.offset_writer),
            ("post-wake M4 state load", postcheck.load),
        ),
    )
    watchdog_dominators, _ = core._dominators_from(
        buffer_get,
        buffer_get.instructions[0].address,
    )
    _require(
        lock_instruction.address in watchdog_dominators[timed_call.address]
        and not any(
            _clean_mnemonic(instruction) == "cpsie"
            and instruction.address in watchdog_dominators[timed_call.address]
            for instruction in buffer_get.instructions
        ),
        "precision timed sleep must be reached with the system lock held",
    )
    _require(
        not any(
            _clean_mnemonic(instruction) == "cpsie"
            for instruction in buffer_get.instructions[
                _instruction_index(buffer_get, timed_call)
                + 1:_instruction_index(buffer_get, postcheck.nonfatal_branch)
            ]
        ),
        "timed-wake thread clear and M4 fatal check must remain under lock",
    )

    def fatal_publication(
        check: _M4RateStateCheck,
        *,
        require_thread_clear: bool,
    ) -> tuple[Instruction, Instruction, Instruction]:
        one_move = _adjacent_instruction(
            buffer_get, check.nonfatal_branch
        )
        one = _move_constant(one_move)
        _require(
            one is not None and one[1] == 1,
            "M4 fatal fallthrough must materialize abort-request=true",
        )
        abort_source = one[0]
        config_reload = _adjacent_instruction(buffer_get, one_move)
        _require(
            _clean_mnemonic(config_reload) == "ldr",
            "M4 fatal fallthrough must reload config_capture",
        )
        config_reload_registers = core._operand_registers(config_reload)
        _require(
            bool(config_reload_registers),
            "M4 fatal config_capture reload has no destination",
        )
        abort_address_register = config_reload_registers[0]
        _require_memory_operand(
            config_reload,
            base=this_register,
            offset=BUFFER_EXCHANGE_CONFIG_CAPTURE_OFFSET,
            description="fatal config_capture reload",
        )
        abort_offset = _adjacent_instruction(buffer_get, config_reload)
        offset_match = _ADD_SELF_IMMEDIATE.fullmatch(
            _clean_operands(abort_offset)
        )
        _require(
            _clean_mnemonic(abort_offset) in {"add", "adds"}
            and offset_match is not None
            and offset_match.group(1) == abort_address_register
            and int(offset_match.group(2), 0)
            == CAPTURE_CONFIG_ABORT_REQUESTED_OFFSET,
            "M4 fatal path must derive exactly "
            "CaptureConfig::application_abort_requested",
        )
        abort_store = _adjacent_instruction(buffer_get, abort_offset)
        abort_store_registers = core._operand_registers(abort_store)
        _require(
            _clean_mnemonic(abort_store) == "strb"
            and bool(abort_store_registers)
            and abort_store_registers[0] == abort_source,
            "M4 fatal path must publish abort-request=true with one byte store",
        )
        _require_memory_operand(
            abort_store,
            base=abort_address_register,
            offset=0,
            description="fatal abort-request publication",
        )
        abort_dmb = _adjacent_instruction(buffer_get, abort_store)
        _require(
            _clean_mnemonic(abort_dmb) == "dmb",
            "M4 fatal abort-request publication must be followed by DMB",
        )
        tail = _adjacent_instruction(buffer_get, abort_dmb)
        if require_thread_clear:
            _require(
                _clean_mnemonic(tail) == "str",
                "pre-sleep fatal path must clear BufferExchange::thread",
            )
            tail_registers = core._operand_registers(tail)
            _require(
                bool(tail_registers)
                and tail_registers[0] == direction_register,
                "pre-sleep fatal thread clear must store CAPTURE/null",
            )
            _require_memory_operand(
                tail,
                base=this_register,
                offset=BUFFER_EXCHANGE_THREAD_OFFSET,
                description="pre-sleep fatal thread clear",
            )
            tail = _adjacent_instruction(buffer_get, tail)
        _require(
            _clean_mnemonic(tail) == "b",
            "M4 fatal path must branch directly to the fail-closed return",
        )
        core._require_cfg_dominance(
            buffer_get,
            start=one_move,
            target=tail,
            required=(
                ("fatal abort constant", one_move),
                ("fatal config reload", config_reload),
                ("fatal abort offset", abort_offset),
                ("fatal abort store", abort_store),
                ("fatal abort DMB", abort_dmb),
            ),
        )
        return abort_store, abort_dmb, tail

    pre_abort_store, pre_abort_dmb, pre_fatal_branch = fatal_publication(
        precheck,
        require_thread_clear=True,
    )
    post_abort_store, post_abort_dmb, post_fatal_branch = fatal_publication(
        postcheck,
        require_thread_clear=False,
    )
    fatal_return_target = _branch_target(
        post_fatal_branch,
        description="post-wake fatal return",
    )
    _require(
        _branch_target(
            pre_fatal_branch,
            description="pre-sleep fatal return",
        )
        == fatal_return_target,
        "both linked M4 fatal checks must share one fail-closed null return",
    )
    fatal_unlock = _instruction_at(
        buffer_get,
        fatal_return_target,
        description="M4 fatal unlock",
    )
    _require(
        _clean_mnemonic(fatal_unlock) in {"bl", "blx"}
        and fatal_unlock.target == DEBUG_UNLOCK_NAME,
        "M4 fatal path must unlock before returning null",
    )
    fatal_enable = _adjacent_instruction(buffer_get, fatal_unlock)
    _require(
        _clean_mnemonic(fatal_enable) == "cpsie"
        and _clean_operands(fatal_enable) == "i",
        "M4 fatal path must restore the system lock before return",
    )
    null_move = _adjacent_instruction(buffer_get, fatal_enable)
    null_move_registers = core._operand_registers(null_move)
    _require(
        _clean_mnemonic(null_move) in {"mov", "movs"}
        and len(null_move_registers) >= 2
        and null_move_registers[0] == "r0"
        and null_move_registers[1] == direction_register,
        "M4 fatal path must return the linked null register in r0",
    )
    null_return = _adjacent_instruction(buffer_get, null_move)
    _require(
        core._is_return_instruction(null_return),
        "M4 fatal null move must flow directly to the linked return",
    )
    _require_no_register_clobber(
        buffer_get,
        register=direction_register,
        after=zero_writer,
        before=post_fatal_branch,
        description="post-wake fatal null return",
    )

    post_nonfatal_target = _branch_target(
        postcheck.nonfatal_branch,
        description="post-wake nonfatal branch",
    )
    post_nonfatal_unlock = _instruction_at(
        buffer_get,
        post_nonfatal_target,
        description="post-wake nonfatal unlock",
    )
    _require(
        post_nonfatal_unlock.target == DEBUG_UNLOCK_NAME
        and post_nonfatal_target != fatal_return_target,
        "nonfatal post-wake check must unlock and continue rather than use the "
        "fatal null-return branch",
    )

    return {
        "function": buffer_get.name,
        "function_code_bytes": buffer_get_size,
        "watchdog_metadata_ms": watchdog_metadata_ms,
        "timed_sleep_call_address": timed_call.address,
        "timed_sleep_timeout_ms": timeout_ms,
        "precision_capture_identity": (
            "CAPTURE && config_capture && precision_rx_final_report"
        ),
        "precision_capture_gate_cfg_bound": True,
        "shared_memory_symbol_address": shared_memory.address,
        "shared_memory_base": shared_memory_base,
        "m4_dma_rate_state_offset": EXPECTED_M4_DMA_RATE_STATE_OFFSET,
        "m4_dma_fatal_state": EXPECTED_P12_M4_DMA_FATAL_STATE,
        "pre_sleep_state_check_address": precheck.load.address,
        "post_wake_state_check_address": postcheck.load.address,
        "post_wake_thread_clear_address": post_clear.address,
        "post_wake_thread_clear_under_lock": True,
        "pre_sleep_abort_store_address": pre_abort_store.address,
        "pre_sleep_abort_dmb_address": pre_abort_dmb.address,
        "post_wake_abort_store_address": post_abort_store.address,
        "post_wake_abort_dmb_address": post_abort_dmb.address,
        "application_abort_requested_offset": (
            CAPTURE_CONFIG_ABORT_REQUESTED_OFFSET
        ),
        "fatal_null_return_address": null_return.address,
        "abort_publication_and_null_return_cfg_bound": True,
    }


def _verify_p12_bounded_rate_send(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    """Prove that Precision RX uses a finite, non-panicking M0 send wait."""

    helper = _unique_function(
        functions,
        "bounded Precision RX message sender",
        lambda name: name == SEND_PRECISION_RX_BOUNDED_NAME,
    )
    helper_size = _unique_symbol_size(
        symbols,
        "bounded Precision RX message sender",
        lambda name: name == SEND_PRECISION_RX_BOUNDED_NAME,
    )
    _require(
        helper_size <= 192,
        f"{SEND_PRECISION_RX_BOUNDED_NAME} grew to {helper_size} bytes; "
        "maximum is 192",
    )
    calls = core._external_control_transfers(helper)
    _require(
        not any(
            call.target in {DEBUG_PANIC_NAME, SEND_MESSAGE_NAME}
            for call in calls
        ),
        "bounded Precision RX sender must not delegate to an unbounded/panicking "
        "message path",
    )
    sleep_calls = [
        call
        for call in calls
        if call.target is not None
        and (
            call.target.startswith("chThdSleep")
            or "sleep" in call.target.lower()
        )
    ]
    _require(
        len(sleep_calls) == 1,
        "bounded Precision RX sender must contain exactly one finite-wait "
        "sleep call",
    )

    backwards: list[tuple[Instruction, int]] = []
    for instruction in helper.instructions:
        if not core._is_branch(instruction):
            continue
        if instruction.mnemonic.lower().split(".", 1)[0] in {"bl", "blx"}:
            continue
        target = core._branch_target_address(instruction)
        if target is not None and target <= instruction.address:
            backwards.append((instruction, target))
    loop_edges = [
        (instruction, target)
        for instruction, target in backwards
        if target <= sleep_calls[0].address <= instruction.address
    ]
    _require(
        len(loop_edges) == 1,
        "bounded Precision RX sender must contain exactly one finite-wait "
        "loop back-edge",
    )
    loop_branch, loop_target = loop_edges[0]

    # A compiler can emit other address-backward branches to a shared return
    # suffix.  Prove those are not cycles: deleting the reviewed countdown
    # edge must leave the reachable helper CFG acyclic.
    successors = {
        address: set(targets)
        for address, targets in core._control_flow_successors(
            helper,
            reject_thumb_it=False,
        ).items()
    }
    _require(
        loop_target in successors[loop_branch.address],
        "bounded Precision RX sender loop edge is absent from its linked CFG",
    )
    successors[loop_branch.address].remove(loop_target)
    visiting: set[int] = set()
    visited: set[int] = set()

    def reject_additional_cycle(address: int) -> None:
        _require(
            address not in visiting,
            "bounded Precision RX sender contains an additional unreviewed "
            "control-flow cycle",
        )
        if address in visited:
            return
        visiting.add(address)
        for target in successors[address]:
            reject_additional_cycle(target)
        visiting.remove(address)
        visited.add(address)

    reject_additional_cycle(min(successors))
    loop_body = [
        instruction
        for instruction in helper.instructions
        if loop_target <= instruction.address <= loop_branch.address
    ]
    decrements = [
        instruction
        for instruction in loop_body
        if instruction.mnemonic.lower().split(".", 1)[0] in {"sub", "subs"}
        and core._has_immediate(instruction, 1)
    ]
    _require(
        len(decrements) == 1,
        "bounded Precision RX sender loop must decrement its remaining budget",
    )
    decrement = decrements[0]
    decrement_registers = core._operand_registers(decrement)
    _require(
        decrement_registers,
        "bounded Precision RX sender budget decrement has no destination "
        "register",
    )
    budget_register = decrement_registers[0]
    _require(
        loop_target <= sleep_calls[0].address <= loop_branch.address,
        "bounded Precision RX sender sleep must remain inside the decrementing "
        "loop",
    )
    loop_first = next(
        instruction
        for instruction in helper.instructions
        if instruction.address == loop_target
    )
    budget_materialization = _constant_register_before(
        helper,
        budget_register,
        before=loop_first,
        literal_words=literal_words,
    )
    _require(
        budget_materialization is not None
        and budget_materialization[0]
        == EXPECTED_P12_BOUNDED_WAIT_ITERATIONS + 1,
        "bounded Precision RX sender does not materialize the linked "
        "500-iteration wait budget in its compiler-normalized countdown",
    )

    instructions_by_address = {
        instruction.address: index
        for index, instruction in enumerate(helper.instructions)
    }
    decrement_index = instructions_by_address[decrement.address]
    sleep_index = instructions_by_address[sleep_calls[0].address]
    zero_exit_branches: list[Instruction] = []
    for index in range(decrement_index + 1, sleep_index):
        instruction = helper.instructions[index]
        target = core._branch_target_address(instruction)
        mnemonic = instruction.mnemonic.lower().split(".", 1)[0]
        if (
            target is None
            or target <= loop_branch.address
            or mnemonic not in {"beq", "cbz"}
        ):
            continue
        if mnemonic == "cbz":
            if budget_register in core._operand_registers(instruction):
                zero_exit_branches.append(instruction)
            continue
        condition_writer = helper.instructions[index - 1]
        condition_mnemonic = condition_writer.mnemonic.lower().split(".", 1)[0]
        if condition_writer.address == decrement.address:
            zero_exit_branches.append(instruction)
        elif (
            condition_mnemonic == "cmp"
            and budget_register in core._operand_registers(condition_writer)
            and core._has_immediate(condition_writer, 0)
        ):
            zero_exit_branches.append(instruction)
    _require(
        len(zero_exit_branches) == 1,
        "bounded Precision RX sender must exit on a zero countdown before "
        "sleeping or taking its loop back-edge",
    )

    barriers = [instruction for instruction in helper.instructions if core._dmb(instruction)]
    _require(
        len(barriers) >= 3
        and barriers[0].address < barriers[1].address < loop_target
        and barriers[-1].address > loop_branch.address,
        "bounded Precision RX sender must fence pointer publication and acquire "
        "the terminal slot state after its finite loop",
    )
    message_slot_address = (
        EXPECTED_SHARED_MEMORY_BASE + EXPECTED_BASEBAND_MESSAGE_OFFSET
    )
    message_slot_accesses = [
        instruction
        for instruction in helper.instructions
        if instruction.mnemonic.startswith(("ldr", "str"))
        and _constant_memory_address(
            helper,
            instruction,
            literal_words=literal_words,
        )
        == message_slot_address
    ]
    message_slot_loads = [
        instruction
        for instruction in message_slot_accesses
        if instruction.mnemonic.startswith("ldr")
    ]
    message_slot_stores = [
        instruction
        for instruction in message_slot_accesses
        if instruction.mnemonic.startswith("str")
    ]
    _require(
        len(message_slot_stores) == 1
        and barriers[0].address
        < message_slot_stores[0].address
        < barriers[1].address,
        "bounded Precision RX sender must publish exactly once to "
        "shared_memory.baseband_message between release barriers",
    )
    publication_store = message_slot_stores[0]
    publication_registers = core._operand_registers(publication_store)
    publication_value = (
        _register_value_before(
            helper,
            publication_registers[0],
            before=publication_store,
            literal_words=literal_words,
        )
        if publication_registers
        else None
    )
    _require(
        publication_value is not None
        and publication_value[:2] == ("entry-r0", None),
        "bounded Precision RX sender must publish its entry persistent-message "
        "pointer to shared_memory.baseband_message",
    )

    initial_slot_loads = [
        instruction
        for instruction in message_slot_loads
        if instruction.address < barriers[0].address
    ]
    loop_slot_loads = [
        instruction
        for instruction in message_slot_loads
        if loop_target <= instruction.address < decrement.address
    ]
    terminal_slot_loads = [
        instruction
        for instruction in message_slot_loads
        if instruction.address > barriers[-1].address
    ]
    _require(
        len(initial_slot_loads) == 1
        and len(loop_slot_loads) == 1
        and len(terminal_slot_loads) == 1
        and len(message_slot_loads) == 3,
        "bounded Precision RX sender must bind its initial, loop, and terminal "
        "samples to shared_memory.baseband_message",
    )

    def zero_test_branch(
        load: Instruction,
        *,
        before: int,
        zero_branch: bool,
    ) -> list[Instruction]:
        load_registers = core._operand_registers(load)
        if not load_registers:
            return []
        register = load_registers[0]
        candidates: list[Instruction] = []
        instructions_by_address_local = {
            instruction.address: index
            for index, instruction in enumerate(helper.instructions)
        }
        for instruction in helper.instructions:
            if not (
                load.address < instruction.address < before
                and core._is_conditional_branch(instruction)
            ):
                continue
            mnemonic = instruction.mnemonic.lower().split(".", 1)[0]
            if mnemonic in {"cbz", "cbnz"}:
                if (
                    register in core._operand_registers(instruction)
                    and (mnemonic == "cbz") == zero_branch
                ):
                    candidates.append(instruction)
                continue
            expected = "beq" if zero_branch else "bne"
            if mnemonic != expected:
                continue
            index = instructions_by_address_local[instruction.address]
            if index == 0:
                continue
            compare = helper.instructions[index - 1]
            if (
                compare.mnemonic.lower().split(".", 1)[0] == "cmp"
                and register in core._operand_registers(compare)
                and core._has_immediate(compare, 0)
            ):
                candidates.append(instruction)
        return candidates

    _require(
        len(
            zero_test_branch(
                initial_slot_loads[0],
                before=barriers[0].address,
                zero_branch=False,
            )
        )
        == 1,
        "bounded Precision RX sender must reject an occupied "
        "shared_memory.baseband_message slot before publication",
    )
    _require(
        len(
            zero_test_branch(
                loop_slot_loads[0],
                before=decrement.address,
                zero_branch=True,
            )
        )
        == 1,
        "bounded Precision RX sender loop must exit when "
        "shared_memory.baseband_message is cleared",
    )
    events = [
        instruction
        for instruction in helper.instructions
        if instruction.mnemonic.lower().split(".", 1)[0] == "sev"
    ]
    _require(
        len(events) == 1
        and barriers[1].address < events[0].address < loop_target,
        "bounded Precision RX sender must assert the M0-to-M4 event after "
        "publishing shared_memory.baseband_message and before waiting",
    )

    return {
        "function": helper.name,
        "linked_code_bytes": helper_size,
        "wait_iterations": EXPECTED_P12_BOUNDED_WAIT_ITERATIONS,
        "linked_counter_initial_value": (
            EXPECTED_P12_BOUNDED_WAIT_ITERATIONS + 1
        ),
        "single_decrementing_loop": True,
        "message_slot_address": message_slot_address,
        "message_slot_accesses_bound": True,
        "event_after_publication": True,
        "persistent_pointer_release_published": True,
        "terminal_slot_acquire_sampled": True,
        "panic_free": True,
    }


def _reachable_addresses(
    successors: dict[int, frozenset[int]],
    start: int,
    *,
    stop: frozenset[int] = frozenset(),
) -> frozenset[int]:
    reached: set[int] = set()
    pending = [start]
    while pending:
        address = pending.pop()
        if address in reached or address not in successors:
            continue
        reached.add(address)
        if address not in stop:
            pending.extend(successors[address] - reached)
    return frozenset(reached)


def _require_zero_failure_branch_after_call(
    function: Function,
    call: Instruction,
    *,
    literal_words: dict[int, int],
    description: str,
) -> Instruction:
    first = core._next_non_nop(function, call.address)
    mnemonic = first.mnemonic.lower().split(".", 1)[0]
    if (
        mnemonic == "cbz"
        and core._operand_registers(first)[:1] == ("r0",)
    ):
        return first
    _require(
        mnemonic == "cmp" and "r0" in core._operand_registers(first),
        f"{description} must immediately test its returned r0 value",
    )
    registers = core._operand_registers(first)
    zero_compared = core._has_immediate(first, 0)
    for register in registers:
        if register == "r0":
            continue
        value = _constant_register_before(
            function,
            register,
            before=first,
            literal_words=literal_words,
        )
        zero_compared = zero_compared or (
            value is not None and value[0] == 0
        )
    branch = core._next_non_nop(function, first.address)
    _require(
        zero_compared
        and branch.mnemonic.lower().split(".", 1)[0] == "beq",
        f"{description} must immediately branch to failure when returned "
        "r0 is zero",
    )
    return branch


def _verify_receiver_disable(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    function: Function,
    literal_words: dict[int, int],
    before: Instruction | None = None,
    description: str,
) -> dict[str, object]:
    """Bind ReceiverModel::disable or its reviewed linked inline expansion."""

    limit = before.address if before is not None else 1 << 64
    direct = [
        call
        for call in _calls_matching(
            function,
            _is_receiver_disable_target,
        )
        if call.address < limit
    ]
    if len(direct) == 1:
        linkage = _verify_direct_or_thumb_veneer_call(
            direct[0],
            symbols=symbols,
            functions=functions,
            literal_words=literal_words,
            direct_predicate=lambda name: name == RECEIVER_DISABLE_NAME,
            veneer_name=RECEIVER_DISABLE_VENEER_NAME,
            veneer_target_predicate=lambda name: name == RECEIVER_DISABLE_NAME,
            description=f"{description} ReceiverModel::disable",
        )
        return {
            "shape": linkage["shape"],
            "disable_address": direct[0].address,
            "receiver_model_enabled_clear_address": None,
            "radio_disable_call_address": None,
        }

    receiver_model = _unique_named_symbol(symbols, RECEIVER_MODEL_NAME)
    enabled_address = (
        receiver_model.address + RECEIVER_MODEL_ENABLED_OFFSET
    )
    enabled_clears: list[Instruction] = []
    for instruction in function.instructions:
        if (
            instruction.address >= limit
            or not instruction.mnemonic.startswith("strb")
            or _constant_memory_address(
                function,
                instruction,
                literal_words=literal_words,
            )
            != enabled_address
        ):
            continue
        registers = core._operand_registers(instruction)
        value = (
            _register_value_before(
                function,
                registers[0],
                before=instruction,
                literal_words=literal_words,
            )
            if registers
            else None
        )
        if value is not None and value[:2] == ("constant", 0):
            enabled_clears.append(instruction)
    radio_disable_calls = [
        call
        for call in _calls_matching(
            function,
            _is_radio_disable_target,
        )
        if call.address < limit
    ]
    for call in radio_disable_calls:
        _verify_direct_or_thumb_veneer_call(
            call,
            symbols=symbols,
            functions=functions,
            literal_words=literal_words,
            direct_predicate=lambda name: name == RADIO_DISABLE_NAME,
            veneer_name=RADIO_DISABLE_VENEER_NAME,
            veneer_target_predicate=lambda name: name == RADIO_DISABLE_NAME,
            description=f"{description} radio::disable",
        )
    _require(
        not direct
        and len(enabled_clears) == 1
        and len(radio_disable_calls) == 1
        and enabled_clears[0].address < radio_disable_calls[0].address,
        f"{description} must link ReceiverModel::disable before its mailbox "
        "operation (directly or as the exact enabled-clear/radio-disable "
        "inline expansion)",
    )
    return {
        "shape": "inlined",
        "disable_address": radio_disable_calls[0].address,
        "receiver_model_enabled_clear_address": enabled_clears[0].address,
        "radio_disable_call_address": radio_disable_calls[0].address,
    }


def _verify_p13_rate_fatal_helper(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> tuple[Function, dict[str, object]]:
    fatal = _unique_function(
        functions,
        "Precision RX fatal-rate helper",
        lambda name: name == PRECISION_RX_RATE_FATAL_NAME,
    )
    core._require_bounded_no_backward_branch(fatal)
    forbidden = _calls_matching(
        fatal,
        lambda name: (
            name
            in {
                DEBUG_PANIC_NAME,
                SEND_MESSAGE_NAME,
                SEND_PRECISION_RX_BOUNDED_NAME,
            }
            or _is_receiver_bandwidth_write_target(name)
            or _is_receiver_rate_write_target(name)
        ),
    )
    _require(
        not forbidden,
        "Precision RX fatal-rate helper must not panic, send, or restore the "
        "physical clock/filter",
    )

    latch_symbols = [
        symbol
        for symbol in symbols
        if symbol.name.endswith("precision_rx_rate_fault_latched")
    ]
    _require(
        len(latch_symbols) == 1
        and latch_symbols[0].size == 1
        and latch_symbols[0].kind.lower() in {"b", "d"},
        "Precision RX fatal-rate helper requires one persistent one-byte "
        "fault latch",
    )
    latch = latch_symbols[0]
    latch_stores: list[Instruction] = []
    for instruction in fatal.instructions:
        if (
            not instruction.mnemonic.startswith("strb")
            or _constant_memory_address(
                fatal,
                instruction,
                literal_words=literal_words,
            )
            != latch.address
        ):
            continue
        registers = core._operand_registers(instruction)
        value = (
            _register_value_before(
                fatal,
                registers[0],
                before=instruction,
                literal_words=literal_words,
            )
            if registers
            else None
        )
        if value is not None and value[:2] == ("constant", 1):
            latch_stores.append(instruction)
    _require(
        len(latch_stores) == 1,
        "Precision RX fatal-rate helper must set its persistent fault latch "
        "exactly once",
    )

    disable = _verify_receiver_disable(
        symbols=symbols,
        functions=functions,
        function=fatal,
        literal_words=literal_words,
        description="Precision RX fatal-rate helper",
    )
    _require(
        latch_stores[0].address < int(disable["disable_address"]),
        "Precision RX fatal-rate helper must latch Fatal before disabling RF",
    )
    fatal_returns = [
        instruction
        for instruction in fatal.instructions
        if instruction.address > int(disable["disable_address"])
        and instruction.mnemonic.lower().split(".", 1)[0].startswith("mov")
        and core._operand_registers(instruction)[:1] == ("r0",)
        and core._has_immediate(instruction, 3)
    ]
    _require(
        len(fatal_returns) == 1,
        "Precision RX fatal-rate helper must return the typed Fatal outcome",
    )
    return fatal, {
        "function": fatal.name,
        "fault_latch_address": latch.address,
        "fault_latch_store_address": latch_stores[0].address,
        "receiver_disable": disable,
        "typed_fatal_return": True,
        "bounded": True,
        "panic_free": True,
    }


def _verify_p13_fault_shutdown(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
    linked_contents: dict[int, int],
    rate_message: Symbol,
) -> dict[str, object]:
    shutdown = _unique_function(
        functions,
        "Precision RX fault shutdown",
        lambda name: name == SHUTDOWN_PRECISION_RX_AFTER_FAULT_NAME,
    )
    core._require_bounded_no_backward_branch(shutdown)
    forbidden = _calls_matching(
        shutdown,
        lambda name: name in {DEBUG_PANIC_NAME, SEND_MESSAGE_NAME},
    )
    _require(
        not forbidden,
        "Precision RX fault shutdown must not panic or use the unbounded "
        "generic sender",
    )
    send = _require_one_call(
        shutdown,
        "bounded Precision RX message sender",
        lambda name: name == SEND_PRECISION_RX_BOUNDED_NAME,
    )
    shutdown_symbols = [
        symbol
        for symbol in symbols
        if symbol.name.endswith("precision_rx_fault_shutdown_message")
    ]
    _require(
        len(shutdown_symbols) == 1
        and shutdown_symbols[0].size == 8
        and shutdown_symbols[0].kind.lower() == "d"
        and shutdown_symbols[0].address != rate_message.address,
        "Precision RX fault shutdown requires a distinct persistent eight-byte "
        "initialized ShutdownMessage",
    )
    shutdown_message = shutdown_symbols[0]
    shutdown_message_id = _read_u32(
        linked_contents,
        shutdown_message.address,
        description="persistent Precision RX fault ShutdownMessage ID",
    )
    shutdown_message_mode = _read_u32(
        linked_contents,
        shutdown_message.address + 4,
        description="persistent Precision RX fault ShutdownMessage mode",
    )
    _require(
        shutdown_message_id == 5 and shutdown_message_mode == 1,
        "persistent Precision RX fault ShutdownMessage must encode ID=5 and "
        "Mode::PrecisionRxFault=1",
    )
    send_pointer = _constant_register_before(
        shutdown,
        "r0",
        before=send,
        literal_words=literal_words,
    )
    _require(
        send_pointer is not None
        and send_pointer[0] == shutdown_message.address,
        "Precision RX fault shutdown bounded send must use its persistent "
        "ShutdownMessage",
    )
    disable = _verify_receiver_disable(
        symbols=symbols,
        functions=functions,
        function=shutdown,
        literal_words=literal_words,
        before=send,
        description="Precision RX fault shutdown",
    )
    _require(
        int(disable["disable_address"]) < send.address,
        "Precision RX fault shutdown must disable RF before its bounded "
        "mailbox attempt",
    )
    failure_branch = _require_zero_failure_branch_after_call(
        shutdown,
        send,
        literal_words=literal_words,
        description="Precision RX fault shutdown bounded send",
    )
    return {
        "function": shutdown.name,
        "persistent_shutdown_message_address": shutdown_message.address,
        "persistent_shutdown_message_bytes": shutdown_message.size,
        "persistent_shutdown_message_id": shutdown_message_id,
        "persistent_shutdown_message_mode": shutdown_message_mode,
        "distinct_from_rate_message": True,
        "receiver_disable": disable,
        "bounded_send_address": send.address,
        "bounded_send_failure_branch_address": failure_branch.address,
        "occupied_mailbox_never_overwritten": True,
        "bounded": True,
        "panic_free": True,
    }


def _verify_p15_view_shutdown_order(
    *,
    functions: Sequence[Function],
) -> dict[str, object]:
    """Prove normal teardown drains M4 before RF-off; faults remain RF-first."""

    view_candidates = [
        function
        for function in functions
        if function.name == PRECISION_RX_VIEW_DESTRUCTOR_NAME
        and _calls_matching(
            function,
            lambda name: name
            == SHUTDOWN_PRECISION_RX_AFTER_FAULT_NAME,
        )
    ]
    _require(
        len(view_candidates) == 1,
        "expected one PrecisionRxView destructor with the shutdown split",
    )
    view = view_candidates[0]
    fault_call = _require_one_call(
        view,
        "RF-first Precision RX fault shutdown",
        lambda name: name == SHUTDOWN_PRECISION_RX_AFTER_FAULT_NAME,
    )
    normal_shutdown_call = _require_one_call(
        view,
        "normal baseband shutdown",
        _is_baseband_shutdown_target,
    )
    normal_rf_disable_call = _require_one_call(
        view,
        "normal receiver disable",
        _is_receiver_disable_target,
    )
    split_branches = [
        instruction
        for instruction in view.instructions
        if instruction.address < fault_call.address
        and core._is_conditional_branch(instruction)
        and core._branch_target_address(instruction)
        == normal_shutdown_call.address
    ]
    _require(
        len(split_branches) == 1
        and core._next_non_nop(view, split_branches[0].address)
        == fault_call,
        "PrecisionRxView rate-fault split must send only the fault path to "
        "the persistent fault shutdown and only the normal path to shutdown",
    )
    split_branch = split_branches[0]
    view_successors = core._control_flow_successors(view)

    def view_reachable(start: int | None) -> frozenset[int]:
        reached: set[int] = set()
        pending = [start] if start is not None else []
        while pending:
            address = pending.pop()
            if address in reached or address not in view_successors:
                continue
            reached.add(address)
            pending.extend(view_successors[address] - reached)
        return frozenset(reached)

    fault_reachable = view_reachable(fault_call.address)
    normal_reachable = view_reachable(
        core._branch_target_address(split_branch)
    )
    _require(
        fault_call.address in fault_reachable
        and normal_shutdown_call.address not in fault_reachable
        and normal_rf_disable_call.address not in fault_reachable
        and normal_shutdown_call.address in normal_reachable
        and normal_rf_disable_call.address in normal_reachable
        and fault_call.address not in normal_reachable,
        "PrecisionRxView fault and normal teardown CFG successors must be "
        "disjoint: fault is persistent RF-first shutdown only; normal is "
        "baseband shutdown then ReceiverModel::disable only",
    )
    between_normal_calls = [
        instruction
        for instruction in view.instructions
        if normal_shutdown_call.address < instruction.address
        < normal_rf_disable_call.address
    ]
    _require(
        normal_shutdown_call.address < normal_rf_disable_call.address
        and not any(
            core._is_branch(instruction)
            or core._is_return_instruction(instruction)
            for instruction in between_normal_calls
        ),
        "normal PrecisionRxView teardown must complete baseband shutdown "
        "before ReceiverModel::disable",
    )

    shutdown = _unique_function(
        functions,
        BASEBAND_SHUTDOWN_NAME,
        lambda name: name == BASEBAND_SHUTDOWN_NAME,
    )
    send = _require_one_call(
        shutdown,
        "generic baseband message sender",
        lambda name: name.startswith("baseband::send_message("),
    )
    id_moves = [
        instruction
        for instruction in shutdown.instructions
        if instruction.address < send.address
        and instruction.mnemonic.startswith("mov")
        and core._instruction_immediates(instruction) == {5}
    ]
    mode_moves = [
        instruction
        for instruction in shutdown.instructions
        if instruction.address < send.address
        and instruction.mnemonic.startswith("mov")
        and core._instruction_immediates(instruction) == {0}
    ]
    id_stores = [
        instruction
        for instruction in shutdown.instructions
        if instruction.address < send.address
        and instruction.mnemonic.startswith("str")
        and core._memory_location(instruction) == ("r13", 0)
    ]
    mode_stores = [
        instruction
        for instruction in shutdown.instructions
        if instruction.address < send.address
        and instruction.mnemonic.startswith("str")
        and core._memory_location(instruction) == ("r13", 4)
    ]
    _require(
        len(id_moves) == len(mode_moves) == len(id_stores)
        == len(mode_stores) == 1
        and core._first_operand_register(id_stores[0])
        == core._first_operand_register(id_moves[0])
        and core._first_operand_register(mode_stores[0])
        == core._first_operand_register(mode_moves[0])
        and id_moves[0].address < id_stores[0].address < send.address
        and mode_moves[0].address < mode_stores[0].address < send.address,
        "normal baseband shutdown must construct linked Shutdown ID=5 and "
        "Mode::Normal=0 in its eight-byte stack message before send",
    )
    send_pointer_writer = core._last_register_writer(
        shutdown,
        "r0",
        before=send,
    )
    _require(
        send_pointer_writer is not None
        and send_pointer_writer.mnemonic.startswith("mov")
        and core._operand_registers(send_pointer_writer)[:2]
        == ("r0", "r13"),
        "normal baseband shutdown must pass the exact stack ShutdownMessage "
        "address in r0 to the generic sender",
    )
    return {
        "view_destructor": view.name,
        "fault_path_uses_persistent_fault_shutdown": True,
        "fault_and_normal_cfg_successors_disjoint": True,
        "normal_baseband_shutdown_precedes_receiver_disable": True,
        "normal_shutdown_message_id": 5,
        "normal_shutdown_message_mode": 0,
        "normal_shutdown_message_bytes": 8,
        "normal_shutdown_send_pointer_is_stack_message": True,
    }


def _verify_p13_antenna_bias_safety(
    *,
    symbols: Sequence[Symbol],
    functions: Sequence[Function],
    literal_words: dict[int, int],
) -> dict[str, object]:
    constructor = _unique_function(
        functions,
        "PrecisionRxView constructor",
        lambda name: name.startswith(PRECISION_RX_VIEW_CONSTRUCTOR_PREFIX),
    )
    bias_calls = _calls_matching(
        constructor,
        _is_set_antenna_bias_target,
    )
    enable_calls = _calls_matching(
        constructor,
        _is_receiver_enable_target,
    )
    _require(
        len(bias_calls) == 1 and len(enable_calls) == 1,
        "p13 PrecisionRxView constructor must link exactly one antenna-bias "
        "setter and one receiver enable",
    )
    bias_call = bias_calls[0]
    enable_call = enable_calls[0]
    _verify_direct_or_thumb_veneer_call(
        bias_call,
        symbols=symbols,
        functions=functions,
        literal_words=literal_words,
        direct_predicate=lambda name: name == SET_ANTENNA_BIAS_NAME,
        veneer_name=SET_ANTENNA_BIAS_VENEER_NAME,
        veneer_target_predicate=lambda name: name == SET_ANTENNA_BIAS_NAME,
        description="PrecisionRxView antenna-bias clear",
    )
    _verify_direct_or_thumb_veneer_call(
        enable_call,
        symbols=symbols,
        functions=functions,
        literal_words=literal_words,
        direct_predicate=lambda name: name == RECEIVER_ENABLE_NAME,
        veneer_name=RECEIVER_ENABLE_VENEER_NAME,
        veneer_target_predicate=lambda name: name == RECEIVER_ENABLE_NAME,
        description="PrecisionRxView receiver enable",
    )
    bias_value = _constant_register_before(
        constructor,
        "r0",
        before=bias_call,
        literal_words=literal_words,
    )
    _require(
        bias_value is not None and bias_value[0] == 0,
        "p13 PrecisionRxView constructor must pass exact false to "
        "portapack::set_antenna_bias",
    )
    dominators, reachable = core._dominators_from(
        constructor,
        min(instruction.address for instruction in constructor.instructions),
        reject_thumb_it=False,
    )
    _require(
        enable_call.address in reachable
        and bias_call.address in dominators[enable_call.address]
        and bias_call.address < enable_call.address,
        "p13 false antenna-bias call must dominate ReceiverModel::enable",
    )
    intervening_transfers = [
        instruction
        for instruction in constructor.instructions
        if bias_call.address < instruction.address < enable_call.address
        and (
            instruction.mnemonic in {"bl", "blx"}
            or core._is_conditional_branch(instruction)
        )
    ]
    _require(
        not intervening_transfers,
        "p13 false antenna-bias call and ReceiverModel::enable must remain "
        "adjacent in linked control flow",
    )
    return {
        "function": constructor.name,
        "set_false_call_address": bias_call.address,
        "receiver_enable_call_address": enable_call.address,
        "false_argument_value": 0,
        "false_bias_dominates_receiver_enable": True,
        "no_intervening_control_transfer": True,
        "linked_instruction_calibrated": True,
    }


def _verify_p13_commit_rollback_cfg(
    *,
    set_precision_rx: Function,
    literal_words: dict[int, int],
    message_symbol: Symbol,
    commit_send: Instruction,
    abort_send: Instruction,
    rollback_clock: Instruction,
    rollback_filter: Instruction,
    fatal_helper: Function,
) -> dict[str, object]:
    """Prove timeout/unknown/wrong-state paths cannot reach rollback."""

    successors = core._control_flow_successors(
        set_precision_rx,
        reject_thumb_it=False,
    )
    fatal_calls = _calls_matching(
        set_precision_rx,
        lambda name: name == fatal_helper.name,
    )
    _require(
        len(fatal_calls) == 1,
        "p13 set_precision_rx must converge every fatal outcome on exactly "
        "one linked fatal-rate helper call",
    )
    fatal_call = fatal_calls[0]

    def require_fail_closed(
        start: int,
        *,
        description: str,
    ) -> None:
        reached = _reachable_addresses(successors, start)
        _require(
            fatal_call.address in reached
            and rollback_clock.address not in reached
            and rollback_filter.address not in reached
            and abort_send.address not in reached,
            f"{description} must reach RF-disable Fatal without physical "
            "rollback or ABORT",
        )
        before_fatal = _reachable_addresses(
            successors,
            start,
            stop=frozenset({fatal_call.address}),
        )
        premature_sinks = [
            address
            for address in before_fatal
            if address != fatal_call.address and not successors[address]
        ]
        unreviewed_calls = [
            instruction
            for instruction in set_precision_rx.instructions
            if instruction.address in before_fatal
            and instruction.address != fatal_call.address
            and instruction.mnemonic in {"bl", "blx"}
        ]
        _require(
            not premature_sinks and not unreviewed_calls,
            f"{description} must call the fatal RF-disable helper immediately "
            "on every reachable outcome",
        )

    def require_rollback_gate(
        branch: Instruction,
        *,
        description: str,
    ) -> tuple[int, int]:
        branch_successors = successors[branch.address]
        rollback_successors = [
            start
            for start in branch_successors
            if rollback_clock.address
            in _reachable_addresses(successors, start)
        ]
        _require(
            len(branch_successors) == 2 and len(rollback_successors) == 1,
            f"{description} must have exactly one successor capable of "
            "physical rollback",
        )
        rollback_start = rollback_successors[0]
        failure_start = next(
            start for start in branch_successors if start != rollback_start
        )
        require_fail_closed(failure_start, description=description)
        return rollback_start, failure_start

    commit_completion_branch = _require_zero_failure_branch_after_call(
        set_precision_rx,
        commit_send,
        literal_words=literal_words,
        description="p13 bounded COMMIT",
    )

    payload_address = message_symbol.address + 4
    response_loads = [
        instruction
        for instruction in set_precision_rx.instructions
        if commit_completion_branch.address < instruction.address
        < rollback_clock.address
        and instruction.mnemonic.startswith("ldr")
        and _constant_memory_address(
            set_precision_rx,
            instruction,
            literal_words=literal_words,
        )
        == payload_address
    ]
    _require(
        len(response_loads) == 1,
        "p13 COMMIT completion must load exactly one response from the "
        "persistent message before classification",
    )
    response_load = response_loads[0]
    response_registers = core._operand_registers(response_load)
    _require(
        response_registers,
        "p13 COMMIT response load has no destination register",
    )
    response_register = response_registers[0]

    committed_compares = [
        instruction
        for instruction in set_precision_rx.instructions
        if response_load.address < instruction.address < rollback_clock.address
        and core._comparison_uses_constant(
            set_precision_rx,
            instruction,
            EXPECTED_P12_ACK_COMMITTED,
            literal_words=literal_words,
        )
    ]
    _require(
        len(committed_compares) == 1,
        "p13 COMMIT response must compare exactly once against ACK_COMMITTED",
    )
    committed_compare = committed_compares[0]
    committed_branch = core._next_non_nop(
        set_precision_rx,
        committed_compare.address,
    )
    _require(
        committed_branch.mnemonic.lower().split(".", 1)[0] == "beq",
        "p13 ACK_COMMITTED must branch to the RUN-state success check before "
        "rejection classification",
    )

    reject_adds: list[Instruction] = []
    for instruction in set_precision_rx.instructions:
        if not (
            committed_branch.address < instruction.address
            < rollback_clock.address
            and instruction.mnemonic.lower().split(".", 1)[0]
            in {"add", "adds"}
        ):
            continue
        registers = core._operand_registers(instruction)
        if (
            len(registers) < 2
            or registers[0] != response_register
            or registers[1] != response_register
        ):
            continue
        addend_register = registers[-1]
        addend = _constant_register_before(
            set_precision_rx,
            addend_register,
            before=instruction,
            literal_words=literal_words,
        )
        if addend is not None and addend[0] == 0x1FFFFFFF:
            reject_adds.append(instruction)
    _require(
        len(reject_adds) == 1,
        "p13 COMMIT rollback path must classify exactly the seven linked "
        "0xE0000001..0xE0000007 rejection words",
    )
    reject_add = reject_adds[0]
    reject_compare = core._next_non_nop(
        set_precision_rx,
        reject_add.address,
    )
    reject_branch = core._next_non_nop(
        set_precision_rx,
        reject_compare.address,
    )
    _require(
        reject_compare.mnemonic.lower().split(".", 1)[0] == "cmp"
        and response_register in core._operand_registers(reject_compare)
        and core._has_immediate(reject_compare, 6)
        and reject_branch.mnemonic.lower().split(".", 1)[0] == "bhi",
        "p13 COMMIT rollback path must reject every response outside the "
        "seven-value rejection schema",
    )

    rate_state_address = (
        EXPECTED_SHARED_MEMORY_BASE + EXPECTED_M4_DMA_RATE_STATE_OFFSET
    )
    paused_state_loads = [
        instruction
        for instruction in set_precision_rx.instructions
        if reject_branch.address < instruction.address < rollback_clock.address
        and instruction.mnemonic.startswith("ldrb")
        and _constant_memory_address(
            set_precision_rx,
            instruction,
            literal_words=literal_words,
        )
        == rate_state_address
    ]
    _require(
        len(paused_state_loads) == 1,
        "p13 rollback must sample shared_memory.m4_dma_rate_state exactly once "
        "after recognized COMMIT rejection",
    )
    paused_state_load = paused_state_loads[0]
    paused_register = core._operand_registers(paused_state_load)[0]
    paused_compares = [
        instruction
        for instruction in set_precision_rx.instructions
        if paused_state_load.address < instruction.address
        < rollback_clock.address
        and instruction.mnemonic.lower().split(".", 1)[0] == "cmp"
        and paused_register in core._operand_registers(instruction)
        and core._has_immediate(
            instruction,
            EXPECTED_P12_M4_DMA_PAUSED_ARMED_STATE,
        )
    ]
    _require(
        len(paused_compares) == 1
        and any(
            reject_branch.address < instruction.address
            < paused_state_load.address
            and core._dmb(instruction)
            for instruction in set_precision_rx.instructions
        ),
        "p13 rollback must acquire and compare the M4 state exactly against "
        "PausedArmed(3)",
    )
    paused_compare = paused_compares[0]
    paused_branch = core._next_non_nop(
        set_precision_rx,
        paused_compare.address,
    )
    _require(
        paused_branch.mnemonic.lower().split(".", 1)[0] == "bne",
        "p13 rollback must fail closed unless M4 state is PausedArmed(3)",
    )

    require_rollback_gate(
        commit_completion_branch,
        description="p13 COMMIT timeout path",
    )
    require_rollback_gate(
        reject_branch,
        description="p13 unknown COMMIT response path",
    )
    require_rollback_gate(
        paused_branch,
        description="p13 wrong PausedArmed state path",
    )
    dominators, reachable = core._dominators_from(
        set_precision_rx,
        min(instruction.address for instruction in set_precision_rx.instructions),
        reject_thumb_it=False,
    )
    _require(
        rollback_clock.address in reachable
        and {
            commit_completion_branch.address,
            response_load.address,
            committed_branch.address,
            reject_branch.address,
            paused_state_load.address,
            paused_branch.address,
        }.issubset(dominators[rollback_clock.address]),
        "p13 COMMIT completion, recognized rejection, and PausedArmed gates "
        "must dominate physical rollback",
    )

    # ACK_COMMITTED is not rollback-safe: it must reach a RUN(1) check whose
    # mismatch converges on the same RF-disable Fatal helper.
    committed_target = core._branch_target_address(committed_branch)
    _require(
        committed_target is not None,
        "p13 ACK_COMMITTED branch has no linked target",
    )
    committed_success_reached = _reachable_addresses(
        successors,
        committed_target,
    )
    committed_run_loads = [
        instruction
        for instruction in set_precision_rx.instructions
        if instruction.address in committed_success_reached
        and instruction.mnemonic.startswith("ldrb")
        and _constant_memory_address(
            set_precision_rx,
            instruction,
            literal_words=literal_words,
        )
        == rate_state_address
    ]
    committed_run_compares = [
        instruction
        for instruction in set_precision_rx.instructions
        if instruction.address in committed_success_reached
        and instruction.mnemonic.lower().split(".", 1)[0] == "cmp"
        and core._has_immediate(instruction, 1)
    ]
    _require(
        len(committed_run_loads) == 1
        and len(committed_run_compares) == 1,
        "p13 ACK_COMMITTED must acquire and require M4 RUN(1)",
    )
    committed_run_branch = core._next_non_nop(
        set_precision_rx,
        committed_run_compares[0].address,
    )
    _require(
        committed_run_branch.mnemonic.lower().split(".", 1)[0] == "bne",
        "p13 ACK_COMMITTED state mismatch must branch to Fatal",
    )
    committed_run_successors = successors[committed_run_branch.address]
    committed_run_failures = [
        start
        for start in committed_run_successors
        if fatal_call.address in _reachable_addresses(successors, start)
    ]
    _require(
        len(committed_run_successors) == 2
        and len(committed_run_failures) == 1,
        "p13 ACK_COMMITTED wrong-state path must converge on Fatal",
    )
    require_fail_closed(
        committed_run_failures[0],
        description="p13 ACK_COMMITTED wrong-state path",
    )

    abort_completion_branch = _require_zero_failure_branch_after_call(
        set_precision_rx,
        abort_send,
        literal_words=literal_words,
        description="p13 bounded ABORT",
    )
    aborted_compares = [
        instruction
        for instruction in set_precision_rx.instructions
        if instruction.address > abort_completion_branch.address
        and core._comparison_uses_constant(
            set_precision_rx,
            instruction,
            EXPECTED_P12_ACK_ABORTED,
            literal_words=literal_words,
        )
    ]
    _require(
        len(aborted_compares) == 1,
        "p13 completed ABORT must compare exactly once against ACK_ABORTED",
    )
    abort_completion_successors = successors[abort_completion_branch.address]
    abort_success_starts = [
        start
        for start in abort_completion_successors
        if aborted_compares[0].address
        in _reachable_addresses(successors, start)
    ]
    _require(
        len(abort_completion_successors) == 2
        and len(abort_success_starts) == 1,
        "p13 ABORT timeout must not reach ACK_ABORTED classification",
    )
    abort_timeout_failure = next(
        start
        for start in abort_completion_successors
        if start != abort_success_starts[0]
    )
    require_fail_closed(
        abort_timeout_failure,
        description="p13 ABORT timeout path",
    )
    aborted_branch = core._next_non_nop(
        set_precision_rx,
        aborted_compares[0].address,
    )
    _require(
        aborted_branch.mnemonic.lower().split(".", 1)[0] == "bne",
        "p13 non-ACK_ABORTED response must branch to Fatal",
    )
    aborted_successors = successors[aborted_branch.address]
    aborted_reachable = set().union(
        *(
            _reachable_addresses(successors, start)
            for start in aborted_successors
        )
    )
    aborted_run_load_candidates = [
        instruction
        for instruction in set_precision_rx.instructions
        if instruction.address in aborted_reachable
        and instruction.mnemonic.startswith("ldrb")
        and _constant_memory_address(
            set_precision_rx,
            instruction,
            literal_words=literal_words,
        )
        == rate_state_address
    ]
    _require(
        len(aborted_run_load_candidates) == 1,
        "p13 ACK_ABORTED must acquire M4 rate state before RolledBack",
    )
    aborted_run_load = aborted_run_load_candidates[0]
    aborted_success_starts = [
        start
        for start in aborted_successors
        if aborted_run_load.address
        in _reachable_addresses(successors, start)
    ]
    _require(
        len(aborted_successors) == 2 and len(aborted_success_starts) == 1,
        "p13 non-ACK_ABORTED response must converge on Fatal",
    )
    aborted_failure = next(
        start
        for start in aborted_successors
        if start != aborted_success_starts[0]
    )
    require_fail_closed(
        aborted_failure,
        description="p13 non-ACK_ABORTED path",
    )
    aborted_success_reached = _reachable_addresses(
        successors,
        aborted_success_starts[0],
    )
    aborted_run_loads = [
        instruction
        for instruction in set_precision_rx.instructions
        if instruction.address in aborted_success_reached
        and instruction.mnemonic.startswith("ldrb")
        and _constant_memory_address(
            set_precision_rx,
            instruction,
            literal_words=literal_words,
        )
        == rate_state_address
    ]
    _require(
        aborted_run_loads == [aborted_run_load],
        "p13 ACK_ABORTED must acquire M4 rate state before RolledBack",
    )
    aborted_run_register = core._operand_registers(aborted_run_loads[0])[0]
    aborted_run_compares = [
        instruction
        for instruction in set_precision_rx.instructions
        if instruction.address in aborted_success_reached
        and instruction.address > aborted_run_loads[0].address
        and instruction.mnemonic.lower().split(".", 1)[0] == "cmp"
        and aborted_run_register in core._operand_registers(instruction)
        and core._has_immediate(instruction, 1)
    ]
    _require(
        len(aborted_run_compares) == 1,
        "p13 ACK_ABORTED must require M4 RUN(1) before RolledBack",
    )
    aborted_run_branch = core._next_non_nop(
        set_precision_rx,
        aborted_run_compares[0].address,
    )
    aborted_run_successors = successors[aborted_run_branch.address]
    aborted_run_failures = [
        start
        for start in aborted_run_successors
        if fatal_call.address in _reachable_addresses(successors, start)
    ]
    _require(
        aborted_run_branch.mnemonic.lower().split(".", 1)[0] == "bne"
        and len(aborted_run_successors) == 2
        and len(aborted_run_failures) == 1,
        "p13 ACK_ABORTED wrong-state path must converge on Fatal",
    )
    require_fail_closed(
        aborted_run_failures[0],
        description="p13 ACK_ABORTED wrong-state path",
    )
    aborted_run_success_start = next(
        start
        for start in aborted_run_successors
        if start != aborted_run_failures[0]
    )
    rolled_back_results = [
        instruction
        for instruction in set_precision_rx.instructions
        if instruction.address
        in _reachable_addresses(successors, aborted_run_success_start)
        and instruction.mnemonic.lower().split(".", 1)[0].startswith("mov")
        and core._operand_registers(instruction)[:1] == ("r0",)
        and core._has_immediate(instruction, 2)
    ]
    _require(
        len(rolled_back_results) == 1,
        "p13 ACK_ABORTED RUN(1) path must return typed RolledBack",
    )

    return {
        "fatal_helper_call_address": fatal_call.address,
        "commit_completion_branch_address": commit_completion_branch.address,
        "commit_response_load_address": response_load.address,
        "commit_ack_branch_address": committed_branch.address,
        "recognized_rejection_add_address": reject_add.address,
        "recognized_rejection_branch_address": reject_branch.address,
        "paused_armed_state_load_address": paused_state_load.address,
        "paused_armed_compare_address": paused_compare.address,
        "paused_armed_branch_address": paused_branch.address,
        "rollback_only_after_completed_recognized_rejection": True,
        "rollback_requires_paused_armed": True,
        "commit_timeout_no_rollback": True,
        "unknown_response_no_rollback": True,
        "wrong_state_no_rollback": True,
        "ack_committed_wrong_state_fail_closed": True,
        "abort_timeout_fail_closed": True,
        "ack_aborted_wrong_state_fail_closed": True,
    }


def verify_outputs(
    nm_text: str,
    disassembly_text: str,
    *,
    elf_sha256: str,
    text_contents_text: str = "",
    nm_version: str = "fixture-nm",
    objdump_version: str = "fixture-objdump",
    config: GateConfig = GateConfig(),
) -> dict[str, object]:
    symbols = core.parse_nm(nm_text)
    functions = core.parse_disassembly(disassembly_text)
    literal_words = core.parse_literal_words(disassembly_text)
    text_contents = _parse_text_bytes(text_contents_text)
    p12_metadata = _p12_metadata(symbols)
    p12_profile = p12_metadata is not None
    if p12_profile:
        _require(
            bool(text_contents),
            "p12 linked verification requires objdump -s section bytes",
        )

    constructor = _unique_function(
        functions,
        "CaptureThread constructor",
        lambda name: name.startswith(CONSTRUCTOR_PREFIX),
    )
    destructor = _unique_function(
        functions,
        "CaptureThread destructor",
        lambda name: name == DESTRUCTOR_NAME,
    )
    static_fn = _unique_function(
        functions,
        STATIC_FN_NAME,
        lambda name: name == STATIC_FN_NAME,
    )

    constructor_size = _unique_symbol_size(
        symbols,
        "CaptureThread constructor",
        lambda name: name.startswith(CONSTRUCTOR_PREFIX),
    )
    _require(
        constructor_size <= config.maximum_constructor_code_bytes,
        f"CaptureThread constructor grew to {constructor_size} bytes; maximum is "
        f"{config.maximum_constructor_code_bytes}",
    )

    metadata = {
        "local_buffer_count": _absolute_value(symbols, LOCAL_BUFFER_COUNT_SYMBOL),
        "spill_buffer_count": _absolute_value(symbols, SPILL_BUFFER_COUNT_SYMBOL),
        "spill_bytes": _absolute_value(symbols, SPILL_BYTES_SYMBOL),
        "thread_stack_bytes": _absolute_value(symbols, THREAD_STACK_BYTES_SYMBOL),
        "capture_config_bytes": _absolute_value(symbols, CAPTURE_CONFIG_BYTES_SYMBOL),
        "capture_thread_bytes": _absolute_value(symbols, CAPTURE_THREAD_BYTES_SYMBOL),
        "dma_abort_requires_consumer_release": _absolute_value(
            symbols, DMA_ABORT_REQUIRES_RELEASE_SYMBOL
        ),
        "journal_fail_closed_policy_metadata": _absolute_value(
            symbols, JOURNAL_FAIL_CLOSED_POLICY_SYMBOL
        ),
    }
    expected_metadata = {
        "local_buffer_count": config.expected_local_buffer_count,
        "spill_buffer_count": config.expected_spill_buffer_count,
        "spill_bytes": config.expected_spill_bytes,
        "thread_stack_bytes": config.expected_thread_stack_bytes,
        "capture_config_bytes": config.expected_capture_config_bytes,
        "capture_thread_bytes": config.expected_capture_thread_bytes,
        "dma_abort_requires_consumer_release": 1,
        "journal_fail_closed_policy_metadata": 1,
    }
    for key, expected in expected_metadata.items():
        actual = metadata[key]
        _require(actual == expected, f"linked {key} is {actual}; expected {expected}")
    _require(
        metadata["spill_bytes"]
        == metadata["spill_buffer_count"] * EXPECTED_WRITE_SIZE,
        "linked spill bytes/count do not describe 8 KiB descriptors",
    )

    p12_linked_control: dict[str, object] | None = None
    p12_bounded_rate_send: dict[str, object] | None = None
    p12_m0_fault_watchdog: dict[str, object] | None = None
    p13_rate_fatal: dict[str, object] | None = None
    p13_fault_shutdown: dict[str, object] | None = None
    p15_view_shutdown: dict[str, object] | None = None
    p13_antenna_bias_safety: dict[str, object] | None = None
    if p12_profile:
        p12_bounded_rate_send = _verify_p12_bounded_rate_send(
            symbols=symbols,
            functions=functions,
            literal_words=literal_words,
        )
        p12_m0_fault_watchdog = _require_p12_buffer_exchange_watchdog(
            symbols,
            functions,
            text_contents=text_contents,
            literal_words=literal_words,
        )
        set_precision_rx = _unique_function(
            functions,
            "baseband::set_precision_rx",
            lambda name: name.startswith(SET_PRECISION_RX_PREFIX),
        )
        send_calls = sorted(
            _calls_matching(
                set_precision_rx,
                lambda name: name == SEND_PRECISION_RX_BOUNDED_NAME,
            ),
            key=lambda call: call.address,
        )
        bandwidth_calls = sorted(
            _calls_matching(
                set_precision_rx,
                _is_receiver_bandwidth_write_target,
            ),
            key=lambda call: call.address,
        )
        sampling_rate_calls = sorted(
            _calls_matching(
                set_precision_rx,
                _is_receiver_rate_write_target,
            ),
            key=lambda call: call.address,
        )
        forbidden_calls = _calls_matching(
            set_precision_rx,
            lambda name: name in {DEBUG_PANIC_NAME, SEND_MESSAGE_NAME},
        )
        _require(
            not forbidden_calls,
            "p12 set_precision_rx defined outcomes must not reach chDbgPanic "
            "or the unbounded generic sender",
        )
        core._require_bounded_no_backward_branch(set_precision_rx)

        transaction_literal_values: set[int] = set()
        for instruction in set_precision_rx.instructions:
            target = core._pc_literal_target(instruction)
            if target is not None and target in literal_words:
                transaction_literal_values.add(literal_words[target])
            transaction_literal_values.update(
                core._instruction_immediates(instruction)
            )
        _require(
            {
                EXPECTED_P12_ACK_CONFIGURED,
                EXPECTED_P12_ACK_PREPARED,
                EXPECTED_P12_ACK_COMMITTED,
                EXPECTED_P12_ACK_ABORTED,
            }.issubset(transaction_literal_values),
            "p12 set_precision_rx must link the exact CONFIGURED, PREPARED, "
            "COMMITTED, and ABORTED acknowledgement schema values",
        )
        _require(
            len(send_calls) == 3,
            "p12 set_precision_rx must link exactly three bounded PREPARE, "
            f"COMMIT, and ABORT sends; found {len(send_calls)}",
        )
        _require(
            len(bandwidth_calls) == 2 and len(sampling_rate_calls) == 2,
            "p12 set_precision_rx must link one target and one rollback write "
            "for both the filter and physical sample clock",
        )
        for call in bandwidth_calls:
            _verify_direct_or_thumb_veneer_call(
                call,
                symbols=symbols,
                functions=functions,
                literal_words=literal_words,
                direct_predicate=_is_receiver_bandwidth_write_target,
                veneer_name=RECEIVER_UPDATE_BANDWIDTH_VENEER_NAME,
                veneer_target_predicate=(
                    lambda name: name == RECEIVER_UPDATE_BANDWIDTH_NAME
                ),
                description="set_precision_rx bandwidth write",
            )
        for call in sampling_rate_calls:
            _verify_direct_or_thumb_veneer_call(
                call,
                symbols=symbols,
                functions=functions,
                literal_words=literal_words,
                direct_predicate=_is_receiver_rate_write_target,
                veneer_name=RECEIVER_UPDATE_RATE_VENEER_NAME,
                veneer_target_predicate=(
                    lambda name: name == RECEIVER_UPDATE_RATE_NAME
                ),
                description="set_precision_rx sample-rate write",
            )
        (
            prepare_send,
            commit_send,
            abort_send,
        ) = send_calls
        (
            target_filter,
            rollback_filter,
        ) = bandwidth_calls
        (
            target_clock,
            rollback_clock,
        ) = sampling_rate_calls
        _require(
            prepare_send.address < target_filter.address
            < target_clock.address < commit_send.address
            < rollback_clock.address < rollback_filter.address
            < abort_send.address,
            "p12 M0 ordering must be PREPARE -> target filter -> target clock -> "
            "COMMIT -> rollback clock -> rollback filter -> ABORT",
        )

        message_symbols = [
            symbol
            for symbol in symbols
            if symbol.name.endswith("precision_rx_rate_message")
        ]
        _require(
            len(message_symbols) == 1
            and message_symbols[0].size == 8
            and message_symbols[0].kind.lower() in {"b", "d"},
            "p12 rate transaction requires one persistent eight-byte "
            "precision_rx_rate_message object",
        )
        message_symbol = message_symbols[0]
        send_pointer_values = [
            _constant_register_before(
                set_precision_rx,
                "r0",
                before=call,
                literal_words=literal_words,
            )
            for call in send_calls
        ]
        _require(
            all(
                value is not None and value[0] == message_symbol.address
                for value in send_pointer_values
            ),
            "p12 PREPARE, COMMIT, and ABORT must all pass the persistent "
            "precision_rx_rate_message object",
        )

        payload_stores: list[
            tuple[Instruction, tuple[str, int | None, tuple[Instruction, ...]] | None]
        ] = []
        for instruction in set_precision_rx.instructions:
            if not instruction.mnemonic.startswith("str"):
                continue
            location = core._memory_location(instruction)
            registers = core._operand_registers(instruction)
            if location is None or not registers or location[1] != 4:
                continue
            base = _constant_register_before(
                set_precision_rx,
                location[0],
                before=instruction,
                literal_words=literal_words,
            )
            if base is None or base[0] != message_symbol.address:
                continue
            payload_stores.append(
                (
                    instruction,
                    _register_value_before(
                        set_precision_rx,
                        registers[0],
                        before=instruction,
                        literal_words=literal_words,
                    ),
                )
            )
        entry_payloads = [
            store
            for store, value in payload_stores
            if value is not None and value[:2] == ("entry-r0", None)
        ]
        commit_payloads = [
            store
            for store, value in payload_stores
            if value is not None
            and value[:2] == ("constant", EXPECTED_P12_COMMIT_CONTROL_WORD)
        ]
        abort_payloads = [
            store
            for store, value in payload_stores
            if value is not None
            and value[:2] == ("constant", EXPECTED_P12_ABORT_CONTROL_WORD)
        ]
        _require(
            len(entry_payloads) == len(commit_payloads) == len(abort_payloads) == 1
            and entry_payloads[0].address < prepare_send.address
            and target_clock.address < commit_payloads[0].address
            < commit_send.address
            and rollback_filter.address < abort_payloads[0].address
            < abort_send.address,
            "p12 persistent message payload must carry entry-rate PREPARE, "
            "exact COMMIT, and exact ABORT values at their bounded sends",
        )
        fatal_helper, p13_rate_fatal = _verify_p13_rate_fatal_helper(
            symbols=symbols,
            functions=functions,
            literal_words=literal_words,
        )
        p13_fault_shutdown = _verify_p13_fault_shutdown(
            symbols=symbols,
            functions=functions,
            literal_words=literal_words,
            linked_contents=text_contents,
            rate_message=message_symbol,
        )
        p15_view_shutdown = _verify_p15_view_shutdown_order(
            functions=functions,
        )
        p13_antenna_bias_safety = _verify_p13_antenna_bias_safety(
            symbols=symbols,
            functions=functions,
            literal_words=literal_words,
        )
        rollback_cfg = _verify_p13_commit_rollback_cfg(
            set_precision_rx=set_precision_rx,
            literal_words=literal_words,
            message_symbol=message_symbol,
            commit_send=commit_send,
            abort_send=abort_send,
            rollback_clock=rollback_clock,
            rollback_filter=rollback_filter,
            fatal_helper=fatal_helper,
        )

        prepare_completion_branch = (
            _require_zero_failure_branch_after_call(
                set_precision_rx,
                prepare_send,
                literal_words=literal_words,
                description="p13 bounded PREPARE",
            )
        )
        prepared_compares = [
            instruction
            for instruction in set_precision_rx.instructions
            if prepare_send.address < instruction.address
            < target_filter.address
            and core._comparison_uses_constant(
                set_precision_rx,
                instruction,
                EXPECTED_P12_ACK_PREPARED,
                literal_words=literal_words,
            )
        ]
        _require(
            len(prepared_compares) == 1,
            "p13 PREPARE response must compare exactly once against "
            "ACK_PREPARED before any RF-side effect",
        )
        prepared_branch = core._next_non_nop(
            set_precision_rx,
            prepared_compares[0].address,
        )
        prepare_dominators, prepare_reachable = core._dominators_from(
            set_precision_rx,
            min(
                instruction.address
                for instruction in set_precision_rx.instructions
            ),
            reject_thumb_it=False,
        )
        _require(
            prepared_branch.mnemonic.lower().split(".", 1)[0] == "beq"
            and target_filter.address in prepare_reachable
            and {
                prepare_completion_branch.address,
                prepared_compares[0].address,
                prepared_branch.address,
            }.issubset(prepare_dominators[target_filter.address]),
            "p13 PREPARE completion and ACK_PREPARED gates must dominate "
            "physical reconfiguration",
        )
        _require(
            any(
                prepare_send.address < instruction.address < target_filter.address
                and core._comparison_uses_constant(
                    set_precision_rx,
                    instruction,
                    EXPECTED_P12_ACK_PREPARED,
                    literal_words=literal_words,
                )
                for instruction in set_precision_rx.instructions
            )
            and any(
                commit_send.address < instruction.address < rollback_clock.address
                and core._comparison_uses_constant(
                    set_precision_rx,
                    instruction,
                    EXPECTED_P12_ACK_COMMITTED,
                    literal_words=literal_words,
                )
                for instruction in set_precision_rx.instructions
            )
            and any(
                instruction.address > abort_send.address
                and core._comparison_uses_constant(
                    set_precision_rx,
                    instruction,
                    EXPECTED_P12_ACK_ABORTED,
                    literal_words=literal_words,
                )
                for instruction in set_precision_rx.instructions
            ),
            "p12 M0 must compare PREPARED, COMMITTED, and ABORTED responses "
            "after their bounded sends",
        )
        _require(
            any(core._is_return_instruction(instruction) for instruction in set_precision_rx.instructions),
            "p12 set_precision_rx must return a typed bounded outcome",
        )
        p12_linked_control = {
            "function": set_precision_rx.name,
            "bounded_send_call_count": len(send_calls),
            "prepare_send_address": prepare_send.address,
            "target_filter_address": target_filter.address,
            "target_clock_address": target_clock.address,
            "commit_send_address": commit_send.address,
            "rollback_clock_address": rollback_clock.address,
            "rollback_filter_address": rollback_filter.address,
            "abort_send_address": abort_send.address,
            "prepare_rejection_returns_typed_result": True,
            "commit_failure_rolls_back_before_abort": True,
            "configured_and_prepared_ack_branches_dominate_rf_change": True,
            "committed_ack_branch_dominates_rollback": True,
            "aborted_acknowledgement_required": True,
            "defined_rejection_paths_panic_free": True,
            "defined_outcomes_control_flow_bounded": True,
            "acknowledgement_schema_values": sorted(
                value
                for value in transaction_literal_values
                if value
                in {
                    EXPECTED_P12_ACK_CONFIGURED,
                    EXPECTED_P12_ACK_PREPARED,
                    EXPECTED_P12_ACK_COMMITTED,
                    EXPECTED_P12_ACK_ABORTED,
                }
            ),
            "message_id": EXPECTED_P12_MESSAGE_ID,
            "prepare_payload": "entry_sample_rate",
            "commit_control_word": EXPECTED_P12_COMMIT_CONTROL_WORD,
            "abort_control_word": EXPECTED_P12_ABORT_CONTROL_WORD,
            "persistent_message_symbol": message_symbol.name,
            "persistent_message_address": message_symbol.address,
            "persistent_message_storage_reused": True,
            "persistent_payload_def_use_linked": True,
            **rollback_cfg,
        }

    heap_base, heap_base_kind = _linked_value(nm_text, HEAP_BASE_SYMBOL)
    heap_end, heap_end_kind = _linked_value(nm_text, HEAP_END_SYMBOL)
    _require(
        heap_base_kind.upper() in {"A", "B"},
        f"{HEAP_BASE_SYMBOL} has unexpected symbol kind {heap_base_kind}",
    )
    _require(
        heap_end_kind.upper() in {"A", "B"},
        f"{HEAP_END_SYMBOL} has unexpected symbol kind {heap_end_kind}",
    )
    _require(
        config.m0_ram_base <= heap_base < config.m0_ram_end,
        f"{HEAP_BASE_SYMBOL} 0x{heap_base:08x} is outside M0 SRAM",
    )
    _require(
        config.m0_ram_base < heap_end <= config.m0_ram_end,
        f"{HEAP_END_SYMBOL} 0x{heap_end:08x} is outside M0 SRAM",
    )
    _require(heap_base < heap_end, "linked application heap bounds are reversed")
    heap_span_bytes = heap_end - heap_base
    _require(
        heap_span_bytes >= config.minimum_heap_span_bytes,
        f"linked application heap span is {heap_span_bytes} bytes; minimum is "
        f"{config.minimum_heap_span_bytes}",
    )
    modeled_heap_residual_bytes = (
        heap_span_bytes
        - metadata["spill_bytes"]
        - metadata["thread_stack_bytes"]
    )
    _require(
        modeled_heap_residual_bytes >= 0,
        "linked heap cannot contain the spill allocation and worker stack",
    )
    _require(
        modeled_heap_residual_bytes
        >= config.minimum_modeled_heap_residual_bytes,
        f"modeled M0 heap residual is {modeled_heap_residual_bytes} bytes; "
        f"minimum is {config.minimum_modeled_heap_residual_bytes}",
    )

    heap_alloc = _require_one_call(constructor, "chHeapAlloc", _is_heap_alloc)
    allocated_bytes = _constant_argument_before_call(
        constructor, heap_alloc, "r1"
    )
    _require(
        allocated_bytes == config.expected_spill_bytes,
        f"CaptureThread spill allocation is {allocated_bytes} bytes; expected "
        f"{config.expected_spill_bytes}",
    )

    thread_create = _require_one_call(
        constructor, "chThdCreateFromHeap", _is_thread_create
    )
    thread_stack_bytes = _constant_argument_before_call(
        constructor, thread_create, "r1"
    )
    _require(
        thread_stack_bytes == config.expected_thread_stack_bytes,
        f"CaptureThread worker stack is {thread_stack_bytes} bytes; expected "
        f"{config.expected_thread_stack_bytes}",
    )

    constructor_dmbs = _dmbs(constructor)
    publish_dmbs = [
        instruction
        for instruction in constructor_dmbs
        if heap_alloc.address < instruction.address < thread_create.address
    ]
    _require(
        bool(publish_dmbs),
        "CaptureThread constructor must publish the spill loan with DMB between "
        "allocation and worker creation",
    )

    destructor_free = _require_one_call(
        destructor, "chHeapFree", _is_heap_free
    )

    memcpy_calls = _calls_matching(static_fn, _is_memcpy)
    _require(
        not memcpy_calls,
        f"{STATIC_FN_NAME} must not call memcpy; found: "
        + ", ".join(call.target or "<indirect>" for call in memcpy_calls),
    )

    static_dmbs = _dmbs(static_fn)
    _require(bool(static_dmbs), f"{STATIC_FN_NAME} must contain at least one DMB")

    ready_calls = _calls_matching(static_fn, _is_ready_evidence)
    _require(
        bool(ready_calls),
        f"{STATIC_FN_NAME} must call the SD ready helper or its inlined "
        "send_cmd_short_crc primitive",
    )
    get_call = _require_one_call(static_fn, "BufferExchange::get", _is_buffer_get)
    _require(
        min(call.address for call in ready_calls) < get_call.address,
        "SD readiness evidence must precede BufferExchange::get",
    )
    _require(
        min(instruction.address for instruction in static_dmbs)
        < min(call.address for call in ready_calls),
        "a DMB must precede the SD-ready/dequeue pipeline",
    )

    fifo_calls = [
        call for call in _calls(static_fn) if _is_stream_fifo_in_call(call)
    ]
    _require(
        bool(fifo_calls),
        f"{STATIC_FN_NAME} must recycle through FIFO<StreamBuffer*>::in",
    )
    indirect_after_get = [
        call
        for call in _calls(static_fn)
        if call.target is None and call.address > get_call.address
    ]
    _require(
        bool(indirect_after_get),
        f"{STATIC_FN_NAME} must contain an indirect writer call after dequeue",
    )
    writer_call = indirect_after_get[0]
    _require(
        any(call.address > writer_call.address for call in fifo_calls),
        "successful-path FIFO recycle evidence must follow the indirect writer call",
    )

    release_helper = _unique_function(
        functions,
        "DMA consumer-release helper",
        lambda name: name == CONSUMER_RELEASE_HELPER_NAME,
    )
    (
        release_pre_store_dmb,
        zero_move,
        release_store,
        release_post_store_dmb,
    ) = _require_consumer_release_store(release_helper)
    release_call_sites = [
        (function, call)
        for function in functions
        for call in _calls_matching(
            function, lambda name: name == CONSUMER_RELEASE_HELPER_NAME
        )
    ]
    _require(
        len(release_call_sites) == 1,
        "expected exactly one DMA consumer-release publication call; found "
        f"{len(release_call_sites)}",
    )
    release_owner, release_call = release_call_sites[0]
    teardown_calls = _calls_matching(
        release_owner, lambda name: name == BUFFER_EXCHANGE_DESTRUCTOR_NAME
    )
    teardown_before_release = [
        call for call in teardown_calls if call.address < release_call.address
    ]
    _require(
        len(teardown_calls) == 1 and len(teardown_before_release) == 1,
        f"{release_owner.name} must call BufferExchange teardown exactly once "
        "before publishing DMA consumer release",
    )
    teardown_call = teardown_before_release[0]
    intervening_control_flow = [
        instruction
        for instruction in release_owner.instructions
        if teardown_call.address < instruction.address < release_call.address
        and _is_control_flow_barrier(instruction)
    ]
    _require(
        not intervening_control_flow,
        "BufferExchange teardown and DMA consumer release must remain on one "
        "straight-line path",
    )
    (
        release_this_init,
        release_base_move,
        release_offset_add,
        release_base_register,
    ) = _require_this_plus_call_argument(
        release_owner,
        release_call,
        expected_offset=BASEBAND_OPEN_SUCCEEDED_OFFSET,
        after=teardown_call,
    )

    journal_recovery = _unique_function(
        functions,
        "Precision RX snapshot-journal recovery function",
        lambda name: name.startswith(JOURNAL_RECOVERY_PREFIX),
    )
    stop_capture = _unique_function(
        functions,
        "Precision RX stop_capture function",
        lambda name: name == STOP_CAPTURE_NAME,
    )
    journal_recovery_call = _require_one_call(
        stop_capture,
        "Precision RX snapshot-journal recovery",
        _is_journal_recovery_call_target,
    )
    _verify_direct_or_thumb_veneer_call(
        journal_recovery_call,
        symbols=symbols,
        functions=functions,
        literal_words=literal_words,
        direct_predicate=lambda name: name.startswith(JOURNAL_RECOVERY_PREFIX),
        veneer_name=JOURNAL_RECOVERY_VENEER_NAME,
        veneer_target_predicate=(
            lambda name: name.startswith(JOURNAL_RECOVERY_PREFIX)
        ),
        description="Precision RX snapshot-journal recovery",
    )
    journal_recovery_calls = _calls(journal_recovery)
    _require(
        not journal_recovery_calls,
        f"{journal_recovery.name} must remain call-free to exclude hidden "
        "bulk-copy and allocator helpers; found "
        f"{len(journal_recovery_calls)} call(s)",
    )
    journal_local_stack_frame_bytes = _require_bounded_local_stack_frame(
        journal_recovery,
        config.maximum_journal_recovery_local_frame_bytes,
    )

    return {
        "contract": (
            "precision-rx-application-linked-rate-transaction-v6"
            if p12_profile
            else "precision-rx-application-linked-dma-lease-v4"
        ),
        "profile": "p15-rate-transaction" if p12_profile else "p11-dma-lease",
        "elf_sha256": elf_sha256,
        "result": "PASS",
        "verification_scope": {
            "classification": "diagnostic-regression-shape",
            "complete_cfg_proof": False,
            "complete_def_use_proof": False,
            "release_authority": "frozen-full-elf-sha256",
            "limitation": (
                "Instruction-pattern checks are not a complete control-flow "
                "or register def-use proof."
            ),
        },
        "tool_versions": {
            "nm": nm_version,
            "objdump": objdump_version,
        },
        "allocation": {
            **metadata,
            "heap_base": heap_base,
            "heap_end": heap_end,
            "heap_span_bytes": heap_span_bytes,
            "minimum_heap_span_bytes": config.minimum_heap_span_bytes,
            "modeled_heap_residual_after_spill_and_stack_bytes": (
                modeled_heap_residual_bytes
            ),
            "minimum_modeled_heap_residual_bytes": (
                config.minimum_modeled_heap_residual_bytes
            ),
            "modeled_heap_residual_margin_bytes": (
                modeled_heap_residual_bytes
                - config.minimum_modeled_heap_residual_bytes
            ),
            "total_buffer_count": (
                metadata["local_buffer_count"] + metadata["spill_buffer_count"]
            ),
            "combined_capture_stream_bytes": (
                metadata["local_buffer_count"] * EXPECTED_WRITE_SIZE
                + metadata["spill_bytes"]
            ),
            "constructor_code_bytes": constructor_size,
            "maximum_constructor_code_bytes": config.maximum_constructor_code_bytes,
            "constructor_heap_alloc_call_count": 1,
            "constructor_thread_create_call_count": 1,
            "constructor_publish_dmb_count": len(publish_dmbs),
            "destructor_heap_free_call_address": destructor_free.address,
        },
        "pipeline": {
            "static_fn_name": STATIC_FN_NAME,
            "static_fn_dmb_count": len(static_dmbs),
            "memcpy_call_count": 0,
            "ready_evidence_targets": sorted(
                {call.target for call in ready_calls if call.target is not None}
            ),
            "ready_precedes_dequeue": True,
            "buffer_exchange_get_call_count": 1,
            "indirect_writer_call_address": writer_call.address,
            "stream_fifo_recycle_call_count": len(fifo_calls),
            "recycle_after_writer": True,
            "consumer_release_owner": release_owner.name,
            "buffer_exchange_teardown_call_address": teardown_call.address,
            "consumer_release_call_address": release_call.address,
            "consumer_release_zero_move_address": zero_move.address,
            "consumer_release_pre_store_dmb_address": (
                release_pre_store_dmb.address
            ),
            "consumer_release_store_address": release_store.address,
            "consumer_release_post_store_dmb_address": (
                release_post_store_dmb.address
            ),
            "consumer_release_after_buffer_exchange_teardown": True,
            "consumer_release_this_init_address": release_this_init.address,
            "consumer_release_argument_base_move_address": (
                release_base_move.address
            ),
            "consumer_release_argument_offset_add_address": (
                release_offset_add.address
            ),
            "consumer_release_argument_base_register": release_base_register,
            "consumer_release_argument_offset_bytes": (
                BASEBAND_OPEN_SUCCEEDED_OFFSET
            ),
            "consumer_release_argument_is_baseband_open_succeeded": True,
        },
        "journal_recovery": {
            "proof_scope": (
                "direct-stop-call/call-free/bounded-local-stack-frame"
            ),
            "fail_closed_policy_metadata": metadata[
                "journal_fail_closed_policy_metadata"
            ],
            "function_name": journal_recovery.name,
            "stop_capture_function_name": stop_capture.name,
            "stop_capture_direct_call_address": journal_recovery_call.address,
            "direct_call_count": 1,
            "internal_call_count": 0,
            "bulk_copy_call_count": 0,
            "allocator_call_count": 0,
            "local_stack_frame_bytes": journal_local_stack_frame_bytes,
            "maximum_local_stack_frame_bytes": (
                config.maximum_journal_recovery_local_frame_bytes
            ),
        },
        "rate_transaction": (
            {
                "protocol_version": p12_metadata[
                    RATE_TRANSACTION_PROTOCOL_VERSION_SYMBOL
                ],
                "prepare_before_physical_change": bool(
                    p12_metadata[RATE_PREPARE_BEFORE_PHYSICAL_CHANGE_SYMBOL]
                ),
                "filter_before_clock": bool(
                    p12_metadata[RATE_FILTER_BEFORE_CLOCK_SYMBOL]
                ),
                "commit_after_physical_change": bool(
                    p12_metadata[RATE_COMMIT_AFTER_PHYSICAL_CHANGE_SYMBOL]
                ),
                "rollback_before_abort": bool(
                    p12_metadata[RATE_ROLLBACK_BEFORE_ABORT_SYMBOL]
                ),
                "fail_closed": bool(
                    p12_metadata[RATE_FAIL_CLOSED_SYMBOL]
                ),
                "bounded_wait_iterations": p12_metadata[
                    RATE_BOUNDED_WAIT_ITERATIONS_SYMBOL
                ],
                "persistent_message": bool(
                    p12_metadata[RATE_PERSISTENT_MESSAGE_SYMBOL]
                ),
                "rejection_no_panic": bool(
                    p12_metadata[RATE_REJECTION_NO_PANIC_SYMBOL]
                ),
                "fault_shutdown_bounded": bool(
                    p12_metadata[RATE_FAULT_SHUTDOWN_BOUNDED_SYMBOL]
                ),
                "rollback_requires_paused_armed": bool(
                    p12_metadata[
                        RATE_ROLLBACK_REQUIRES_PAUSED_ARMED_SYMBOL
                    ]
                ),
                "commit_timeout_no_rollback": bool(
                    p12_metadata[RATE_COMMIT_TIMEOUT_NO_ROLLBACK_SYMBOL]
                ),
                "linked_control": p12_linked_control,
                "bounded_send": p12_bounded_rate_send,
                "fatal_helper": p13_rate_fatal,
                "fault_shutdown": p13_fault_shutdown,
                "view_shutdown": p15_view_shutdown,
                "antenna_bias_safety": p13_antenna_bias_safety,
                "m0_fault_watchdog": p12_m0_fault_watchdog,
                "post_build_instruction_calibration_required": [],
            }
            if p12_profile and p12_metadata is not None
            else None
        ),
    }


def verify_elf(
    elf: Path,
    *,
    nm_tool: str,
    objdump_tool: str,
    config: GateConfig = GateConfig(),
) -> dict[str, object]:
    _require(elf.is_file(), f"ELF does not exist or is not a regular file: {elf}")
    _require(elf.stat().st_size > 0, f"ELF is empty: {elf}")
    elf_sha256 = hashlib.sha256(elf.read_bytes()).hexdigest()
    nm_text = core._run_tool(
        [nm_tool, "-C", "-S", "--defined-only", str(elf)]
    )
    disassembly_text = core._run_tool([objdump_tool, "-drC", str(elf)])
    text_contents_text = core._run_tool(
        [objdump_tool, "-s", "-j", ".text", "-j", ".data", str(elf)]
    )
    return verify_outputs(
        nm_text,
        disassembly_text,
        elf_sha256=elf_sha256,
        text_contents_text=text_contents_text,
        nm_version=core._tool_version(nm_tool),
        objdump_version=core._tool_version(objdump_tool),
        config=config,
    )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path, help="unstripped application.elf")
    parser.add_argument("--nm", default="arm-none-eabi-nm", help="GNU Arm nm executable")
    parser.add_argument(
        "--objdump",
        default="arm-none-eabi-objdump",
        help="GNU Arm objdump executable",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        help="also write the deterministic JSON receipt to this path",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        report = verify_elf(
            args.elf,
            nm_tool=args.nm,
            objdump_tool=args.objdump,
        )
        encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.json_output:
            args.json_output.parent.mkdir(parents=True, exist_ok=True)
            args.json_output.write_text(encoded, encoding="utf-8")
        print("precision-rx-application-elf: PASS")
        print(encoded, end="")
        return 0
    except (OSError, ValueError, VerificationError) as error:
        print(f"precision-rx-application-elf: FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
