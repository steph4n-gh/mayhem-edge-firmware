#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path
import sys
import unittest


TOOLS_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIRECTORY))

import verify_precision_rx_elf as verifier  # noqa: E402


NM_FIXTURE = """
00000004 00000001 A hackrf_edge_stream_input_impl_buffer_count_log2
00000004 00000001 A hackrf_edge_precision_rx_mode_buffer_count_log2
00000009 00000001 A hackrf_edge_precision_rx_mode_local_buffer_count
00000002 00000001 A hackrf_edge_precision_rx_mode_spill_buffer_count
0000000b 00000001 A hackrf_edge_precision_rx_mode_total_buffer_count
00002000 00000004 A hackrf_edge_precision_rx_dma_buffer_bytes
00000800 00000004 A hackrf_edge_precision_rx_dma_transfer_bytes
00000004 00000001 A hackrf_edge_precision_rx_dma_transfer_count
00002000 00000004 A hackrf_edge_precision_rx_dma_loan_bytes
00004000 00000004 A hackrf_edge_precision_rx_dma_monitor_ring_bytes
00001000 00000004 A hackrf_edge_precision_rx_dma_monitor_transfer_bytes
00000800 00000004 A hackrf_edge_precision_rx_dma_monitor_transfer_samples
00002000 00000004 A hackrf_edge_precision_rx_dma_capture_ring_bytes
00000800 00000004 A hackrf_edge_precision_rx_dma_capture_transfer_bytes
00000400 00000004 A hackrf_edge_precision_rx_dma_capture_transfer_samples
00000002 00000001 A hackrf_edge_precision_rx_dma_monitor_owned_lli_count
00000002 00000001 A hackrf_edge_precision_rx_dma_monitor_loan_lli_count
00000008 00000001 A hackrf_edge_precision_rx_dma_loan_local_buffer_index
00000004 00000001 A hackrf_edge_precision_rx_dma_terminal_count_interrupt_count
001e8480 00000004 A hackrf_edge_precision_rx_dma_capture_rate_limit_hz
00000001 00000001 A hackrf_edge_precision_rx_dma_transition_discards_old_block
00000001 00000001 A hackrf_edge_precision_rx_dma_transition_resets_epoch
00000001 00000001 A hackrf_edge_precision_rx_dma_high_rate_bound_request_rejected
00000001 00000001 A hackrf_edge_precision_rx_dma_abort_force_unbind
00000001 00000001 A hackrf_edge_precision_rx_dma_abort_requires_consumer_release
00000000 00000001 A hackrf_edge_precision_rx_dma_scheduler_backlog_depth
00019000 00000004 A hackrf_edge_precision_rx_dma_service_deadline_ns_at_20m
0004b000 00000004 A hackrf_edge_precision_rx_dma_physical_retention_ns_at_20m
100016d0 00000040 b baseband::dma::lli_loop
00000100 00000080 T main
00000200 000000b0 T StreamInput::StreamInput(unsigned int, unsigned int)
00000300 0000014e T StreamInput::rebind(CaptureConfig*)
00000450 00000012 T StreamInput::acknowledge_open()
00000470 00000020 T StreamInput::seal()
00000490 00000020 T StreamInput::drained() const
00000500 000001e8 T PrecisionRxProcessor::service_capture_command()
00000700 00000190 T PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)
00000900 00000080 T BasebandThread::BasebandThread(unsigned long, BasebandProcessor*, baseband::Direction, bool, unsigned long)
00000a00 00000150 T BasebandThread::run()
00000c00 00000028 T precision_rx::MetricsAccumulator::begin_capture_interval()
00000d00 00000020 T operator new(unsigned int)
00000d20 00000020 T operator new[](unsigned int)
00000d40 00000020 T memset
00000d60 00000020 T memcpy
00000d80 00000020 T chHeapAlloc
00000e00 00000060 t baseband::dma::configure_lease_descriptors(bool)
00000e80 00000034 T baseband::dma::configure_precision_rx_lease(std::complex<signed char>*, std::complex<signed char>*)
00000f00 00000094 T baseband::dma::set_precision_rx_capture_geometry(bool)
00001000 0000004c T baseband::dma::enable_precision_rx()
00001080 00000078 T baseband::dma::wait_for_buffer()
00001100 0000001e T StreamInput::dma_loan_buffer()
00001140 0000001e T StreamInput::release_dma_loan()
00001180 0000001a T StreamInput::unbind_if_drained()
000011c0 00000028 T StreamInput::force_unbind_after_abort()
00001200 0000004c T BasebandThread::set_precision_rx_capture_geometry(bool)
00001280 00000022 T PrecisionRxProcessor::transition_dma_geometry(bool)
000012c0 00000010 T PrecisionRxProcessor::finish_capture_command()
00001300 00000020 T PrecisionRxProcessor::configure(unsigned long)
00001340 00000020 T baseband::SGPIO::configure(baseband::Direction)
"""


DISASSEMBLY_FIXTURE = """
00000100 <main>:
 100: f44f 7086  mov.w r0, #1072 ; 0x430
 104: f000 f800  bl  d00 <operator new(unsigned int)>
 108: 2209       movs r2, #9
 10a: f44f 5100  mov.w r1, #8192 ; 0x2000
 10e: f000 f800  bl  200 <StreamInput::StreamInput(unsigned int, unsigned int)>
 112: f000 f800  bl  1100 <StreamInput::dma_loan_buffer()>
 116: f000 f800  bl  900 <BasebandThread::BasebandThread(unsigned long, BasebandProcessor*, baseband::Direction, bool, unsigned long)>
 11a: 4770       bx lr

00000200 <StreamInput::StreamInput(unsigned int, unsigned int)>:
 200: 2220       movs r2, #32
 202: f000 f800  bl  d40 <memset>
 204: f44f 3090  mov.w r0, #73728 ; 0x12000
 206: f000 f800  bl  d20 <operator new[](unsigned int)>
 20a: f44f 3290  mov.w r2, #73728 ; 0x12000
 20e: f000 f800  bl  d40 <memset>
 212: 4770       bx lr

00000300 <StreamInput::rebind(CaptureConfig*)>:
 300: 2300       movs r3, #0
 302: 6003       str r3, [r0, #0]
 304: 4770       bx lr

00000450 <StreamInput::acknowledge_open()>:
 450: 2001       movs r0, #1
 452: 4770       bx lr

00000470 <StreamInput::seal()>:
 470: 2001       movs r0, #1
 472: 4770       bx lr

00000490 <StreamInput::drained() const>:
 490: 2001       movs r0, #1
 492: 4770       bx lr

00000500 <PrecisionRxProcessor::service_capture_command()>:
 500: f8d0 33ec  ldr.w r3, [r0, #1004]
 504: f3bf 8f5b  dmb ish
 506: f8d0 13f0  ldr.w r1, [r0, #1008]
 50a: b949       cbnz r1, 520 <PrecisionRxProcessor::service_capture_command()+0x20>
 50c: f000 f800  bl  1280 <PrecisionRxProcessor::transition_dma_geometry(bool)>
 510: 2800       cmp r0, #0
 512: d043       beq.n 59c <PrecisionRxProcessor::service_capture_command()+0x9c>
 514: e03e       b.n 594 <PrecisionRxProcessor::service_capture_command()+0x94>
 516: f8d0 2264  ldr.w r2, [r0, #612]
 518: 4b39       ldr r3, [pc, #228] ; (5a0 <PrecisionRxProcessor::service_capture_command()+0xa0>)
 51a: 429a       cmp r2, r3
 51c: d900       bls.n 520 <PrecisionRxProcessor::service_capture_command()+0x20>
 51e: e039       b.n 594 <PrecisionRxProcessor::service_capture_command()+0x94>
 520: 2101       movs r1, #1
 522: f000 f800  bl  1280 <PrecisionRxProcessor::transition_dma_geometry(bool)>
 526: f000 f800  bl  300 <StreamInput::rebind(CaptureConfig*)>
 52a: b928       cbnz r0, 538 <PrecisionRxProcessor::service_capture_command()+0x38>
 52c: f8c4 03f0  str.w r0, [r4, #1008]
 530: e034       b.n 59c <PrecisionRxProcessor::service_capture_command()+0x9c>
 538: 2248       movs r2, #72
 53a: f000 f800  bl  d60 <memcpy>
 53e: f000 f800  bl  c00 <precision_rx::MetricsAccumulator::begin_capture_interval()>
 542: f000 f800  bl  450 <StreamInput::acknowledge_open()>
 546: 2268       movs r2, #104
 548: f000 f800  bl  d40 <memset>
 54c: f000 f800  bl  470 <StreamInput::seal()>
 550: f000 f800  bl  490 <StreamInput::drained() const>
 554: f8d0 33e4  ldr.w r3, [r0, #996]
 558: b963       cbnz r3, 574 <PrecisionRxProcessor::service_capture_command()+0x74>
 55a: f8d0 13dc  ldr.w r1, [r0, #988]
 55e: b949       cbnz r1, 574 <PrecisionRxProcessor::service_capture_command()+0x74>
 560: f890 33d8  ldrb.w r3, [r0, #984]
 564: b133       cbz r3, 574 <PrecisionRxProcessor::service_capture_command()+0x74>
 566: f000 f800  bl  1280 <PrecisionRxProcessor::transition_dma_geometry(bool)>
 56a: b178       cbz r0, 59c <PrecisionRxProcessor::service_capture_command()+0x9c>
 56c: f000 f800  bl  12c0 <PrecisionRxProcessor::finish_capture_command()>
 570: e015       b.n 59e <PrecisionRxProcessor::service_capture_command()+0x9e>
 574: f000 f800  bl  1180 <StreamInput::unbind_if_drained()>
 578: f000 f800  bl  11c0 <StreamInput::force_unbind_after_abort()>
 57c: 2800       cmp r0, #0
 57e: d00d       beq.n 59c <PrecisionRxProcessor::service_capture_command()+0x9c>
 580: f8c4 13e4  str.w r1, [r4, #996]
 584: e7ef       b.n 566 <PrecisionRxProcessor::service_capture_command()+0x66>
 594: 4620       mov r0, r4
 596: f000 f800  bl  12c0 <PrecisionRxProcessor::finish_capture_command()>
 59a: e000       b.n 59e <PrecisionRxProcessor::service_capture_command()+0x9e>
 59c: bf00       nop
 59e: 4770       bx lr
 5a0: 001e8480   .word 0x001e8480

00000700 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)>:
 700: f8d0 326c  ldr.w r3, [r0, #620]
 704: b183       cbz r3, 72c <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x2c>
 706: 4a0e       ldr r2, [pc, #56] ; (740 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x40>)
 708: 4293       cmp r3, r2
 70a: d90b       bls.n 724 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x24>
 70c: f8d0 23dc  ldr.w r2, [r0, #988]
 710: b122       cbz r2, 71c <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x1c>
 712: f3bf 8f5b  dmb ish
 714: 2300       movs r3, #0
 716: f8c0 326c  str.w r3, [r0, #620]
 71a: e007       b.n 72c <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x2c>
 71c: f890 23d8  ldrb.w r2, [r0, #984]
 720: 2a00       cmp r2, #0
 722: d0f6       beq.n 712 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x12>
 724: 4619       mov r1, r3
 726: f000 f800  bl  1300 <PrecisionRxProcessor::configure(unsigned long)>
 72a: f000 f800  bl  500 <PrecisionRxProcessor::service_capture_command()>
 72e: 4770       bx lr
 740: 001e8480   .word 0x001e8480

00000900 <BasebandThread::BasebandThread(unsigned long, BasebandProcessor*, baseband::Direction, bool, unsigned long)>:
 900: 4770       bx lr

00000a00 <BasebandThread::run()>:
 a00: f44f 6000  mov.w r0, #8192 ; 0x2000
 a04: f000 f800  bl  d00 <operator new(unsigned int)>
 a08: f000 f800  bl  e80 <baseband::dma::configure_precision_rx_lease(std::complex<signed char>*, std::complex<signed char>*)>
 a0c: 2100       movs r1, #0
 a0e: f000 f800  bl  1340 <baseband::SGPIO::configure(baseband::Direction)>
 a12: f000 f800  bl  1000 <baseband::dma::enable_precision_rx()>
 a16: f000 f800  bl  1080 <baseband::dma::wait_for_buffer()>
 a1a: 4770       bx lr

00000c00 <precision_rx::MetricsAccumulator::begin_capture_interval()>:
 c00: 4770       bx lr

00000d00 <operator new(unsigned int)>:
 d00: f000 f800  bl  d80 <chHeapAlloc>
 d04: 4770       bx lr

00000d20 <operator new[](unsigned int)>:
 d20: f000 f800  bl  d80 <chHeapAlloc>
 d24: 4770       bx lr

00000d40 <memset>:
 d40: 4770       bx lr

00000d60 <memcpy>:
 d60: 4770       bx lr

00000d80 <chHeapAlloc>:
 d80: 4770       bx lr

00000e00 <baseband::dma::configure_lease_descriptors(bool)>:
 e00: 2800       cmp r0, #0
 e02: bf14       ite ne
 e04: f44f 6600  movne.w r6, #2048
 e08: f44f 5680  moveq.w r6, #4096
 e0c: 4c09       ldr r4, [pc, #36] ; (e34 <baseband::dma::configure_lease_descriptors(bool)+0x34>)
 e10: ea44 0496  orr.w r4, r4, r6, lsr #2
 e14: 2200       movs r2, #0
 e16: 2a02       cmp r2, #2
 e18: f8dc 1000  ldreq.w r1, [ip]
 e1c: eb03 1502  add.w r5, r3, r2, lsl #4
 e20: e9c3 7100  strd r7, r1, [r3]
 e24: e9c3 5402  strd r5, r4, [r3, #8]
 e28: 4431       add r1, r6
 e2a: 3201       adds r2, #1
 e2c: 2a04       cmp r2, #4
 e2e: d1f2       bne.n e16 <baseband::dma::configure_lease_descriptors(bool)+0x16>
 e30: 4770       bx lr
 e34: 8a480000   .word 0x8a480000

00000e80 <baseband::dma::configure_precision_rx_lease(std::complex<signed char>*, std::complex<signed char>*)>:
 e80: 6010       str r0, [r2, #0]
 e82: 6019       str r1, [r3, #0]
 e84: 2000       movs r0, #0
 e86: f000 f800  bl  e00 <baseband::dma::configure_lease_descriptors(bool)>
 e8a: 2001       movs r0, #1
 e8c: 4770       bx lr

00000f00 <baseband::dma::set_precision_rx_capture_geometry(bool)>:
 f00: f442 2280  orr.w r2, r2, #262144
 f04: f3bf 8f5f  dmb sy
 f08: f414 3400  ands.w r4, r4, #131072
 f0c: f421 2180  bic.w r1, r1, #262144
 f10: f3bf 8f5f  dmb sy
 f14: e01c       b.n f50 <baseband::dma::set_precision_rx_capture_geometry(bool)+0x50>
 f18: f023 0301  bic.w r3, r3, #1
 f1c: f3bf 8f5f  dmb sy
 f20: 60af       str r7, [r5, #8]
 f22: 612f       str r7, [r5, #16]
 f28: f000 f800  bl  e00 <baseband::dma::configure_lease_descriptors(bool)>
 f2c: f3bf 8f5f  dmb sy
 f30: 60af       str r7, [r5, #8]
 f32: 612f       str r7, [r5, #16]
 f34: 4770       bx lr
 f50: 4770       bx lr

00001000 <baseband::dma::enable_precision_rx()>:
 1000: e9d1 5401  ldrd r5, r4, [r1, #4]
 1004: 680e       ldr r6, [r1, #0]
 1006: 68c8       ldr r0, [r1, #12]
 1008: 6098       str r0, [r3, #8]
 100a: 6118       str r0, [r3, #16]
 100c: 6016       str r6, [r2, #0]
 100e: 6055       str r5, [r2, #4]
 1010: 6094       str r4, [r2, #8]
 1012: 60d0       str r0, [r2, #12]
 1014: f44f 4150  mov.w r1, #53248
 1018: 6111       str r1, [r2, #16]
 101a: f8d3 2110  ldr.w r2, [r3, #272]
 101e: f042 0201  orr.w r2, r2, #1
 1022: f8c3 2110  str.w r2, [r3, #272]
 1026: 4770       bx lr

00001080 <baseband::dma::wait_for_buffer()>:
 1080: 68c3       ldr r3, [r0, #12]
 1084: 6841       ldr r1, [r0, #4]
 1088: f641 72fe  movw r2, #8190
 108c: ea02 0243  and.w r2, r2, r3, lsl #1
 1090: 4770       bx lr

00001100 <StreamInput::dma_loan_buffer()>:
 1100: f8d0 3168  ldr.w r3, [r0, #360]
 1104: b943       cbnz r3, 111c <StreamInput::dma_loan_buffer()+0x1c>
 1106: f890 1164  ldrb.w r1, [r0, #356]
 110a: f8d0 216c  ldr.w r2, [r0, #364]
 110e: b121       cbz r1, 111c <StreamInput::dma_loan_buffer()+0x1c>
 1110: b11a       cbz r2, 111c <StreamInput::dma_loan_buffer()+0x1c>
 1112: f502 3380  add.w r3, r2, #65536
 1116: 4770       bx lr
 111c: 2000       movs r0, #0
 111e: 4770       bx lr

00001140 <StreamInput::release_dma_loan()>:
 1140: f8c0 3168  str.w r3, [r0, #360]
 1144: f8c0 3160  str.w r3, [r0, #352]
 1148: f880 3164  strb.w r3, [r0, #356]
 114c: f3bf 8f5f  dmb sy
 1150: 4770       bx lr

00001180 <StreamInput::unbind_if_drained()>:
 1180: f000 f800  bl  490 <StreamInput::drained() const>
 1184: b120       cbz r0, 1190 <StreamInput::unbind_if_drained()+0x10>
 1186: f3bf 8f5f  dmb sy
 118a: f000 f800  bl  1140 <StreamInput::release_dma_loan()>
 1190: 4770       bx lr

000011c0 <StreamInput::force_unbind_after_abort()>:
 11c0: f893 1039  ldrb.w r1, [r3, #57]
 11c4: b141       cbz r1, 11d8 <StreamInput::force_unbind_after_abort()+0x18>
 11c6: f893 303a  ldrb.w r3, [r3, #58]
 11ca: b923       cbnz r3, 11d8 <StreamInput::force_unbind_after_abort()+0x18>
 11cc: f3bf 8f5f  dmb sy
 11d0: f000 f800  bl  1140 <StreamInput::release_dma_loan()>
 11d8: 4770       bx lr

00001200 <BasebandThread::set_precision_rx_capture_geometry(bool)>:
 1200: f000 f800  bl  f00 <baseband::dma::set_precision_rx_capture_geometry(bool)>
 1204: b110       cbz r0, 120c <BasebandThread::set_precision_rx_capture_geometry(bool)+0xc>
 1206: f000 f800  bl  1000 <baseband::dma::enable_precision_rx()>
 120c: 4770       bx lr

00001280 <PrecisionRxProcessor::transition_dma_geometry(bool)>:
 1280: f000 f800  bl  1200 <BasebandThread::set_precision_rx_capture_geometry(bool)>
 1284: 4605       mov r5, r0
 1286: f000 f800  bl  1300 <PrecisionRxProcessor::configure(unsigned long)>
 128a: 4628       mov r0, r5
 128c: 4770       bx lr

000012c0 <PrecisionRxProcessor::finish_capture_command()>:
 12c0: f8c0 33f0  str.w r3, [r0, #1008]
 12c4: f3bf 8f5b  dmb ish
 12c8: f8c0 33ec  str.w r3, [r0, #1004]
 12cc: 4770       bx lr

00001300 <PrecisionRxProcessor::configure(unsigned long)>:
 1300: 4770       bx lr

00001340 <baseband::SGPIO::configure(baseband::Direction)>:
 1340: 4770       bx lr
"""


SECTION_FIXTURE = """
Sections:
Idx Name          Size      VMA       LMA       File off  Algn
  0 startup       00000114  00000000  00000000  00010000  2**4
                  CONTENTS, ALLOC, LOAD, DATA
  1 .text         0000478c  00000114  00000114  00010114  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, CODE
  2 .stacks       00001400  10000000  10000000  00030000  2**0
                  ALLOC
  3 .data         0000006c  10001400  000048a0  00021400  2**2
                  CONTENTS, ALLOC, LOAD, DATA
  4 .bss          00001420  1000146c  0000490c  0002146c  2**3
                  ALLOC
  5 .debug_info   00100000  00000000  00000000  0002146c  2**0
                  CONTENTS, READONLY, DEBUGGING
"""

P12_NM_FIXTURE = (
    NM_FIXTURE.replace(
        "00000000 00000001 A hackrf_edge_precision_rx_dma_scheduler_backlog_depth",
        "00000003 00000001 A hackrf_edge_precision_rx_dma_scheduler_backlog_depth",
        1,
    ).replace(
        "00019000 00000004 A hackrf_edge_precision_rx_dma_service_deadline_ns_at_20m",
        "00032000 00000004 A hackrf_edge_precision_rx_dma_service_deadline_ns_at_20m",
        1,
    )
    + """
00000003 00000001 A hackrf_edge_precision_rx_dma_completion_queue_depth
00019000 00000004 A hackrf_edge_precision_rx_dma_completion_period_ns_at_20m
00032000 00000004 A hackrf_edge_precision_rx_dma_oldest_claim_deadline_ns_at_20m
00000002 00000001 A hackrf_edge_precision_rx_dma_claim_guard_age
00000000 00000001 A hackrf_edge_precision_rx_dma_queue_drops_oldest
00000001 00000001 A hackrf_edge_precision_rx_dma_queue_spsc
00000001 00000001 A hackrf_edge_precision_rx_dma_queue_full_fail_closed
00000001 00000001 A hackrf_edge_precision_rx_dma_fast_irq_priority
0000001f 00000001 A hackrf_edge_precision_rx_dma_deferred_irq
00000003 00000001 A hackrf_edge_precision_rx_dma_deferred_irq_priority
00000001 00000001 A hackrf_edge_precision_rx_dma_fast_tc_w1c_first
00000001 00000001 A hackrf_edge_precision_rx_dma_fast_error_gate_first
00000001 00000001 A hackrf_edge_precision_rx_dma_unexpected_channel_fail_closed
00000001 00000001 A hackrf_edge_precision_rx_dma_worker_claim_irq_exclusion
00000001 00000001 A hackrf_edge_precision_rx_dma_software_descriptor_phase
00000001 00000001 A hackrf_edge_precision_rx_dma_gate_open_irq_exclusion
00000001 00000001 A hackrf_edge_precision_rx_dma_gate_open_requires_channel_enabled
00000001 00000001 A hackrf_edge_precision_rx_dma_rate_state_irq_exclusion
00000001 00000001 A hackrf_edge_precision_rx_dma_rate_state_scheduler_exclusion
00000001 00000001 A hackrf_edge_precision_rx_dma_claim_preserves_own_tc
00000001 00000001 A hackrf_edge_precision_rx_dma_rate_state_preserves_own_tc
00000001 00000001 A hackrf_edge_precision_rx_dma_exclusion_preserves_nvic_pending
00000001 00000001 A hackrf_edge_precision_rx_dma_shutdown_active_drain
00010000 00000004 A hackrf_edge_precision_rx_dma_shutdown_active_spin_limit
00000001 00000001 A hackrf_edge_precision_rx_dma_shutdown_timeout_halts
00002710 00000004 A hackrf_edge_precision_rx_dma_control_active_drain_timeout_us
001e8480 00000004 A hackrf_edge_precision_rx_dma_control_active_drain_ticks_at_200m
00000001 00000001 A hackrf_edge_precision_rx_dma_control_active_drain_uses_dwt
00000001 00000001 A hackrf_edge_precision_rx_dma_control_active_drain_counter_guard
00064000 00000004 A hackrf_edge_precision_rx_dma_control_slowest_descriptor_ticks_at_200m
00000020 00000001 A hackrf_edge_precision_rx_dma_lifetime_loss_counter_bits
00000001 00000001 A hackrf_edge_precision_rx_dma_lifetime_loss_saturating
00000002 00000001 A hackrf_edge_precision_rx_rate_transaction_protocol_version
00000001 00000001 A hackrf_edge_precision_rx_rate_prepare_gates_sgpio_before_dma_pause
00000001 00000001 A hackrf_edge_precision_rx_rate_prepare_ack_requires_pause_armed
00000001 00000001 A hackrf_edge_precision_rx_rate_commit_publishes_target_before_dma_resume
00000001 00000001 A hackrf_edge_precision_rx_rate_commit_ack_requires_first_new_rate_completion
00000001 00000001 A hackrf_edge_precision_rx_rate_fail_closed_on_prepare_failure
00000001 00000001 A hackrf_edge_precision_rx_rate_fail_closed_on_commit_failure
00001360 00000020 T PrecisionRxProcessor::PrecisionRxProcessor()
00001380 00000040 T PrecisionRxProcessor::on_message(Message const*)
000013c0 00000020 T PrecisionRxProcessor::request_rate_pause()
00001400 00000060 T PrecisionRxProcessor::resume_rate_change(unsigned long, unsigned long)
00001460 00000020 T PrecisionRxProcessor::service_rate_prepare()
00001480 00000040 T BasebandThread::prepare_precision_rx_rate_change()
000014c0 00000020 T BasebandThread::resume_precision_rx_rate_change()
00001500 00000008 T BasebandThread::precision_rx_rate_pause_armed() const
00001520 00000008 T baseband::dma::pause_precision_rx_rate_change()
00001540 00000008 T baseband::dma::resume_precision_rx_rate_change()
00002500 000000a8 t baseband::dma::halt_and_disable_precision_rx(bool&)
000015a0 00000010 t baseband::SGPIO::streaming_disable()
000015b0 00000010 t baseband::dma::open_precision_rx_sgpio_gate_locked()
000015c0 00000008 t baseband::dma::precision_rx_dma_faulted()
000015d0 00000054 t baseband::dma::fail_if_precision_rx_dma_error_pending_locked()
00001640 00000020 t baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)
00001680 00000040 t PrecisionRxProcessor::publish_running_if_dma_healthy(PrecisionRxProcessor::RateState)
000016c0 00000014 T PrecisionRxProcessor::process_complete_block(buffer_t<std::complex<signed char> > const&)
00001740 00000010 t baseband::dma::complete_precision_rx_dma_fault_locked()
00001c00 000000a0 t baseband::dma::claim_precision_rx_completion(baseband::dma::PrecisionRxDmaCompletion&)
00001cc0 0000002c t PrecisionRxProcessor::wait_while_rate_state(precision_rx::rate_transaction::State) const
00001d00 00000008 t PrecisionRxProcessor::rate_state() const
00001e00 00000060 T baseband::dma::quiesce_precision_rx_for_shutdown()
00001f00 00000030 T port_halt
00001f40 00000008 t BasebandThread::publish_precision_rx_worker_quiesced(bool)
00001900 00000048 T __late_init
00001980 00000014 T hackrf_edge_precision_rx_dma_deferred_interrupt
000019c0 00000008 T hackrf_edge_precision_rx_dma_fast_fault
000019d0 0000000c T hackrf_edge_precision_rx_dma_fast_terminal_count
00001b00 0000001c T VectorBC
00001b40 0000002c T Vector48
00002100 00000024 t precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)
00003000 00000020 T __ieee754_log10f
10001715 00000001 b baseband::dma::dma_fatal_latched
"""
)

P12_DISASSEMBLY_FIXTURE = DISASSEMBLY_FIXTURE.replace(
    (
        " 108: 2209       movs r2, #9\n"
        " 10a: f44f 5100  mov.w r1, #8192 ; 0x2000\n"
        " 10e: f000 f800  bl  200 "
        "<StreamInput::StreamInput(unsigned int, unsigned int)>\n"
        " 112: f000 f800  bl  1100 <StreamInput::dma_loan_buffer()>\n"
        " 116: f000 f800  bl  900 "
        "<BasebandThread::BasebandThread(unsigned long, BasebandProcessor*, "
        "baseband::Direction, bool, unsigned long)>"
    ),
    (
        " 108: f000 f800  bl  1360 "
        "<PrecisionRxProcessor::PrecisionRxProcessor()>"
    ),
    1,
).replace(
    "#1004]",
    "#1028]",
).replace(
    "#1008]",
    "#1032]",
).replace(
    "#996]",
    "#1020]",
).replace(
    "#988]",
    "#1012]",
).replace(
    "#984]",
    "#1008]",
).replace(
    " f00: f442 2280  orr.w r2, r2, #262144",
    (
        " f00: f000 f800  bl  2500 "
        "<baseband::dma::halt_and_disable_precision_rx(bool&)>\n"
        " f02: b128       cbz r0, f50 "
        "<baseband::dma::set_precision_rx_capture_geometry(bool)+0x50>\n"
        " f04: f442 2280  orr.w r2, r2, #262144"
    ),
    1,
).replace(
    (
        " 1080: 68c3       ldr r3, [r0, #12]\n"
        " 1084: 6841       ldr r1, [r0, #4]\n"
        " 1088: f641 72fe  movw r2, #8190\n"
        " 108c: ea02 0243  and.w r2, r2, r3, lsl #1\n"
        " 1090: 4770       bx lr"
    ),
    (
        " 1080: f000 f800  bl  1c00 "
        "<baseband::dma::claim_precision_rx_completion"
        "(baseband::dma::PrecisionRxDmaCompletion&)>\n"
        " 1084: f000 f800  bl  1580 "
        "<ThreadWait::sleep_locked(unsigned char volatile*)>\n"
        " 1088: f000 f800  bl  1c00 "
        "<baseband::dma::claim_precision_rx_completion"
        "(baseband::dma::PrecisionRxDmaCompletion&)>\n"
        " 108c: 6841       ldr r1, [r0, #4]\n"
        " 108e: 68c3       ldr r3, [r0, #12]\n"
        " 1090: f641 72fe  movw r2, #8190\n"
        " 1094: ea02 0243  and.w r2, r2, r3, lsl #1\n"
        " 1098: 4770       bx lr"
    ),
    1,
).replace(
    " 72e: 4770       bx lr",
    (
        " 72e: f000 f800  bl  1420 "
        "<PrecisionRxProcessor::service_rate_prepare()>\n"
        " 732: 4770       bx lr"
    ),
    1,
).replace(
    (
        " 1280: f000 f800  bl  1200 "
        "<BasebandThread::set_precision_rx_capture_geometry(bool)>\n"
        " 1284: 4605       mov r5, r0\n"
        " 1286: f000 f800  bl  1300 "
        "<PrecisionRxProcessor::configure(unsigned long)>\n"
        " 128a: 4628       mov r0, r5\n"
        " 128c: 4770       bx lr"
    ),
    (
        " 1280: f000 f800  bl  1200 "
        "<BasebandThread::set_precision_rx_capture_geometry(bool)>\n"
        " 1284: 4605       mov r5, r0\n"
        " 1286: b108       cbz r0, 128e "
        "<PrecisionRxProcessor::transition_dma_geometry(bool)+0xe>\n"
        " 1288: f000 f800  bl  1300 "
        "<PrecisionRxProcessor::configure(unsigned long)>\n"
        " 128c: 4628       mov r0, r5\n"
        " 128e: 4770       bx lr"
    ),
    1,
) + """
00001360 <PrecisionRxProcessor::PrecisionRxProcessor()>:
 1360: 2209       movs r2, #9
 1362: f44f 5100  mov.w r1, #8192 ; 0x2000
 1366: f000 f800  bl  200 <StreamInput::StreamInput(unsigned int, unsigned int)>
 136a: f000 f800  bl  1100 <StreamInput::dma_loan_buffer()>
 136e: f000 f800  bl  900 <BasebandThread::BasebandThread(unsigned long, BasebandProcessor*, baseband::Direction, bool, unsigned long)>
 1372: 4770       bx lr

00001380 <PrecisionRxProcessor::on_message(Message const*)>:
 1380: f000 f800  bl  13c0 <PrecisionRxProcessor::request_rate_pause()>
 1384: 684e       ldr r6, [r1, #4]
 1386: 4b0a       ldr r3, [pc, #40] ; (13b0 <PrecisionRxProcessor::on_message(Message const*)+0x30>)
 1388: 429e       cmp r6, r3
 138a: d001       beq.n 1390 <PrecisionRxProcessor::on_message(Message const*)+0x10>
 138c: 4770       bx lr
 1390: f890 3270  ldrb.w r3, [r0, #624]
 1394: 2b03       cmp r3, #3
 1396: d103       bne.n 13a0 <PrecisionRxProcessor::on_message(Message const*)+0x20>
 1398: f8d0 127c  ldr.w r1, [r0, #636]
 139a: 4a06       ldr r2, [pc, #24] ; (13b4 <PrecisionRxProcessor::on_message(Message const*)+0x34>)
 139c: e002       b.n 13a4 <PrecisionRxProcessor::on_message(Message const*)+0x24>
 13a0: 2000       movs r0, #0
 13a2: 4770       bx lr
 13a4: f000 f800  bl  1400 <PrecisionRxProcessor::resume_rate_change(unsigned long, unsigned long)>
 13a8: e000       b.n 13ac <PrecisionRxProcessor::on_message(Message const*)+0x2c>
 13ac: 6068       str r0, [r5, #4]
 13ae: 4770       bx lr
 13b0: 80000001   .word 0x80000001
 13b4: c0000003   .word 0xc0000003

000013c0 <PrecisionRxProcessor::request_rate_pause()>:
 13c0: f000 f800  bl  1500 <BasebandThread::precision_rx_rate_pause_armed() const>
 13c4: 4770       bx lr

00001400 <PrecisionRxProcessor::resume_rate_change(unsigned long, unsigned long)>:
 1400: 4617       mov r7, r2
 1402: f8c0 127c  str.w r1, [r0, #636]
 1406: f3bf 8f5f  dmb sy
 140a: f8c0 126c  str.w r1, [r0, #620]
 140e: f000 f800  bl  14c0 <BasebandThread::resume_precision_rx_rate_change()>
 1412: 2104       movs r1, #4
 1414: f000 f800  bl  1cc0 <PrecisionRxProcessor::wait_while_rate_state(precision_rx::rate_transaction::State) const>
 1418: b1b0       cbz r0, 1448 <PrecisionRxProcessor::resume_rate_change(unsigned long, unsigned long)+0x48>
 141a: f000 f800  bl  15c0 <baseband::dma::precision_rx_dma_faulted()>
 141e: 2800       cmp r0, #0
 1420: d112       bne.n 1448 <PrecisionRxProcessor::resume_rate_change(unsigned long, unsigned long)+0x48>
 1422: f894 3270  ldrb.w r3, [r4, #624]
 1426: 2b01       cmp r3, #1
 1428: d10e       bne.n 1448 <PrecisionRxProcessor::resume_rate_change(unsigned long, unsigned long)+0x48>
 142a: f8d4 3280  ldr.w r3, [r4, #640]
 142b: 4909       ldr r1, [pc, #36] ; (1450 <PrecisionRxProcessor::resume_rate_change(unsigned long, unsigned long)+0x50>)
 142c: f641 2238  movw r2, #6712 ; 0x1a38
 142e: 588a       ldr r2, [r1, r2]
 1430: 429a       cmp r2, r3
 1432: d10b       bne.n 144c <PrecisionRxProcessor::resume_rate_change(unsigned long, unsigned long)+0x4c>
 1434: 4638       mov r0, r7
 1436: 4770       bx lr
 1448: 2000       movs r0, #0
 144a: 4770       bx lr
 144c: 2000       movs r0, #0
 144e: 4770       bx lr
 1450: 10088000   .word 0x10088000

00001460 <PrecisionRxProcessor::service_rate_prepare()>:
 1460: f000 f800  bl  1480 <BasebandThread::prepare_precision_rx_rate_change()>
 1464: 4770       bx lr

00001480 <BasebandThread::prepare_precision_rx_rate_change()>:
 1480: f000 f800  bl  15a0 <baseband::SGPIO::streaming_disable()>
 1484: f000 f800  bl  1520 <baseband::dma::pause_precision_rx_rate_change()>
 1488: b930       cbnz r0, 1498 <BasebandThread::prepare_precision_rx_rate_change()+0x18>
 148a: 7813       ldrb r3, [r2, #0]
 148c: b933       cbnz r3, 149c <BasebandThread::prepare_precision_rx_rate_change()+0x1c>
 148e: f000 f800  bl  15b0 <baseband::dma::open_precision_rx_sgpio_gate_locked()>
 1492: 4770       bx lr
 1498: 4770       bx lr
 149c: 4770       bx lr

000014c0 <BasebandThread::resume_precision_rx_rate_change()>:
 14c0: f000 f800  bl  1540 <baseband::dma::resume_precision_rx_rate_change()>
 14c4: b130       cbz r0, 14d0 <BasebandThread::resume_precision_rx_rate_change()+0x10>
 14c6: f000 f800  bl  15b0 <baseband::dma::open_precision_rx_sgpio_gate_locked()>
 14ca: 4770       bx lr
 14d0: 4770       bx lr

00001500 <BasebandThread::precision_rx_rate_pause_armed() const>:
 1500: 2001       movs r0, #1
 1502: 4770       bx lr

00001520 <baseband::dma::pause_precision_rx_rate_change()>:
 1520: 2001       movs r0, #1
 1522: 4770       bx lr

00001540 <baseband::dma::resume_precision_rx_rate_change()>:
 1540: 2001       movs r0, #1
 1542: 4770       bx lr

00002500 <baseband::dma::halt_and_disable_precision_rx(bool&)>:
 2500: b538       push {r3, r4, r5, lr}
 2502: 4605       mov r5, r0
 2504: f000 f800  bl  15d0 <baseband::dma::fail_if_precision_rx_dma_error_pending_locked()>
 2508: b108       cbz r0, 250e <baseband::dma::halt_and_disable_precision_rx(bool&)+0xe>
 250a: 2000       movs r0, #0
 250c: bd38       pop {r3, r4, r5, pc}
 250e: 4b20       ldr r3, [pc, #128] ; (2590 <baseband::dma::halt_and_disable_precision_rx(bool&)+0x90>)
 2510: 68db       ldr r3, [r3, #12]
 2512: 01d8       lsls r0, r3, #7
 2514: d5f9       bpl.n 250a <baseband::dma::halt_and_disable_precision_rx(bool&)+0xa>
 2516: 4b1f       ldr r3, [pc, #124] ; (2594 <baseband::dma::halt_and_disable_precision_rx(bool&)+0x94>)
 2518: 681a       ldr r2, [r3, #0]
 251a: 07d1       lsls r1, r2, #31
 251c: d5f5       bpl.n 250a <baseband::dma::halt_and_disable_precision_rx(bool&)+0xa>
 251e: 4c1e       ldr r4, [pc, #120] ; (2598 <baseband::dma::halt_and_disable_precision_rx(bool&)+0x98>)
 2520: 6822       ldr r2, [r4, #0]
 2522: f442 2280  orr.w r2, r2, #262144
 2526: 6022       str r2, [r4, #0]
 2528: f3bf 8f5f  dmb sy
 252c: 491b       ldr r1, [pc, #108] ; (259c <baseband::dma::halt_and_disable_precision_rx(bool&)+0x9c>)
 252e: 6858       ldr r0, [r3, #4]
 2530: 6822       ldr r2, [r4, #0]
 2532: 0392       lsls r2, r2, #14
 2534: d503       bpl.n 253e <baseband::dma::halt_and_disable_precision_rx(bool&)+0x3e>
 2536: 685a       ldr r2, [r3, #4]
 2538: 1a12       subs r2, r2, r0
 253a: 428a       cmp r2, r1
 253c: d9f8       bls.n 2530 <baseband::dma::halt_and_disable_precision_rx(bool&)+0x30>
 253e: 6823       ldr r3, [r4, #0]
 2540: 039b       lsls r3, r3, #14
 2542: d50a       bpl.n 255a <baseband::dma::halt_and_disable_precision_rx(bool&)+0x5a>
 2544: f000 f800  bl  15d0 <baseband::dma::fail_if_precision_rx_dma_error_pending_locked()>
 2548: 2800       cmp r0, #0
 254a: d1de       bne.n 250a <baseband::dma::halt_and_disable_precision_rx(bool&)+0xa>
 254c: 6823       ldr r3, [r4, #0]
 254e: f423 2380  bic.w r3, r3, #262144
 2552: 6023       str r3, [r4, #0]
 2554: f3bf 8f5f  dmb sy
 2558: e7d8       b.n 250c <baseband::dma::halt_and_disable_precision_rx(bool&)+0xc>
 255a: f000 f800  bl  15d0 <baseband::dma::fail_if_precision_rx_dma_error_pending_locked()>
 255e: 2800       cmp r0, #0
 2560: d1d3       bne.n 250a <baseband::dma::halt_and_disable_precision_rx(bool&)+0xa>
 2562: 4c0f       ldr r4, [pc, #60] ; (25a0 <baseband::dma::halt_and_disable_precision_rx(bool&)+0xa0>)
 2564: 6863       ldr r3, [r4, #4]
 2566: f003 0301  and.w r3, r3, #1
 256a: 702b       strb r3, [r5, #0]
 256c: f8d4 3110  ldr.w r3, [r4, #272]
 2570: f023 0301  bic.w r3, r3, #1
 2574: f8c4 3110  str.w r3, [r4, #272]
 2578: 4b0a       ldr r3, [pc, #40] ; (25a4 <baseband::dma::halt_and_disable_precision_rx(bool&)+0xa4>)
 257a: 6018       str r0, [r3, #0]
 257c: f3bf 8f5f  dmb sy
 2580: f000 f800  bl  15d0 <baseband::dma::fail_if_precision_rx_dma_error_pending_locked()>
 2584: 2800       cmp r0, #0
 2586: d1c0       bne.n 250a <baseband::dma::halt_and_disable_precision_rx(bool&)+0xa>
 2588: 2001       movs r0, #1
 258a: 60a0       str r0, [r4, #8]
 258c: 6120       str r0, [r4, #16]
 258e: e7bd       b.n 250c <baseband::dma::halt_and_disable_precision_rx(bool&)+0xc>
 2590: e000edf0   .word 0xe000edf0
 2594: e0001000   .word 0xe0001000
 2598: 40002110   .word 0x40002110
 259c: 001e847f   .word 0x001e847f
 25a0: 40002000   .word 0x40002000
 25a4: 10001674   .word 0x10001674

000015a0 <baseband::SGPIO::streaming_disable()>:
 15a0: f443 6380  orr.w r3, r3, #1024
 15a4: 6003       str r3, [r0, #0]
 15a6: 4770       bx lr

000015b0 <baseband::dma::open_precision_rx_sgpio_gate_locked()>:
 15b0: f423 6380  bic.w r3, r3, #1024
 15b4: 6003       str r3, [r0, #0]
 15b6: 4770       bx lr

000015c0 <baseband::dma::precision_rx_dma_faulted()>:
 15c0: 7800       ldrb r0, [r0, #0]
 15c2: 4770       bx lr

000015d0 <baseband::dma::fail_if_precision_rx_dma_error_pending_locked()>:
 15d0: 6853       ldr r3, [r2, #4]
 15d2: 68d1       ldr r1, [r2, #12]
 15d4: 69d0       ldr r0, [r2, #28]
 15d6: d023       beq.n 1620 <baseband::dma::fail_if_precision_rx_dma_error_pending_locked()+0x50>
 15d8: f8c5 3080  str.w r3, [r5, #128]
 15dc: f3bf 8f5f  dmb sy
 15e0: f8c5 3180  str.w r3, [r5, #384]
 15e4: f3bf 8f5f  dmb sy
 15e8: 6857       ldr r7, [r2, #4]
 15ea: 68d6       ldr r6, [r2, #12]
 15ec: 69d4       ldr r4, [r2, #28]
 15ee: f000 f800  bl  1640 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>
 15f2: 6097       str r7, [r2, #8]
 15f4: 6116       str r6, [r2, #16]
 15f6: f8c5 3100  str.w r3, [r5, #256]
 15fa: f3bf 8f5f  dmb sy
 15fe: 602b       str r3, [r5, #0]
 1600: f000 f800  bl  1740 <baseband::dma::complete_precision_rx_dma_fault_locked()>
 1604: 2001       movs r0, #1
 1606: 4770       bx lr
 1620: 2000       movs r0, #0
 1622: 4770       bx lr

00001640 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>:
 1640: f8c2 3214  str.w r3, [r2, #532]
 1644: f023 0301  bic.w r3, r3, #1
 1648: f8c2 3110  str.w r3, [r2, #272]
 164c: 2305       movs r3, #5
 164e: 7013       strb r3, [r2, #0]
 1650: 2301       movs r3, #1
 1652: 6013       str r3, [r2, #0]
 1654: f3bf 8f5f  dmb sy
 1658: 4770       bx lr

00001680 <PrecisionRxProcessor::publish_running_if_dma_healthy(PrecisionRxProcessor::RateState)>:
 1680: b570       push {r4, r5, r6, lr}
 1682: 4607       mov r7, r0
 1684: 460e       mov r6, r1
 1686: f000 f800  bl  ef0 <dbg_check_lock>
 168a: 4b0a       ldr r3, [pc, #40] ; (16b4 <PrecisionRxProcessor::publish_running_if_dma_healthy(PrecisionRxProcessor::RateState)+0x34>)
 168c: 781c       ldrb r4, [r3, #0]
 168e: f897 5270  ldrb.w r5, [r7, #624]
 1692: b94c       cbnz r4, 16a8 <PrecisionRxProcessor::publish_running_if_dma_healthy(PrecisionRxProcessor::RateState)+0x28>
 1694: 42ae       cmp r6, r5
 1696: d00b       beq.n 16b0 <PrecisionRxProcessor::publish_running_if_dma_healthy(PrecisionRxProcessor::RateState)+0x30>
 1698: f000 f800  bl  f20 <dbg_check_unlock>
 169c: bd70       pop {r4, r5, r6, pc}
 16a8: 2305       movs r3, #5
 16aa: f3bf 8f5f  dmb sy
 16ac: f887 3270  strb.w r3, [r7, #624]
 16ae: e7f3       b.n 1698 <PrecisionRxProcessor::publish_running_if_dma_healthy(PrecisionRxProcessor::RateState)+0x18>
 16b0: 2301       movs r3, #1
 16b2: e7fa       b.n 16aa <PrecisionRxProcessor::publish_running_if_dma_healthy(PrecisionRxProcessor::RateState)+0x2a>
 16b4: 10001715   .word 0x10001715

000016c0 <PrecisionRxProcessor::process_complete_block(buffer_t<std::complex<signed char> > const&)>:
 16c0: b510       push {r4, lr}
 16c2: f000 f800  bl  1700 <precision_rx::MetricsAccumulator::observe_block(std::complex<signed char> const*, unsigned int)>
 16c6: b118       cbz r0, 16d0 <PrecisionRxProcessor::process_complete_block(buffer_t<std::complex<signed char> > const&)+0x10>
 16c8: f000 f800  bl  1720 <PrecisionRxProcessor::publish(precision_rx::MetricsSnapshot const&) const>
 16cc: 2001       movs r0, #1
 16ce: bd10       pop {r4, pc}
 16d0: 2000       movs r0, #0
 16d2: bd10       pop {r4, pc}

00001740 <baseband::dma::complete_precision_rx_dma_fault_locked()>:
 1740: f000 f800  bl  1800 <baseband::dma::record_unintentional_loss(unsigned long volatile&)>
 1744: f000 f800  bl  1810 <baseband::dma::reset_completion_queue_with_fast_irq_excluded()>
 1748: f000 f800  bl  1820 <baseband::dma::publish_queue_state()>
 174c: f000 b800  b.w 1830 <ThreadWait::wake_from_interrupt(int)>

00001900 <__late_init>:
 1900: b508       push {r3, lr}
 1902: f000 f800  bl  1a00 <halInit>
 1906: f000 f800  bl  1a10 <chSysInit>
 190a: 4b0f       ldr r3, [pc, #60] ; (1946 <__late_init+0x46>)
 190c: f04f 32ff  mov.w r2, #4294967295
 1910: f8c3 2f00  str.w r2, [r3, #3840]
 1914: f8c3 2f20  str.w r2, [r3, #3872]
 1918: f8c3 2f40  str.w r2, [r3, #3904]
 191c: f8c3 2f60  str.w r2, [r3, #3936]
 1920: f8c3 2f10  str.w r2, [r3, #3856]
 1924: f8c3 2f30  str.w r2, [r3, #3888]
 1928: f8c3 2f50  str.w r2, [r3, #3920]
 192c: f8c3 2f70  str.w r2, [r3, #3952]
 1930: f3bf 8f5f  dmb sy
 1934: 2160       movs r1, #96
 1936: 201f       movs r0, #31
 1938: f000 f800  bl  1a20 <nvicEnableVector>
 193c: e8bd 4008  ldmia.w sp!, {r3, lr}
 1940: 2120       movs r1, #32
 1942: 2002       movs r0, #2
 1944: f000 b800  b.w 1a20 <nvicEnableVector>
 1946: 40101000   .word 0x40101000

00001980 <hackrf_edge_precision_rx_dma_deferred_interrupt>:
 1980: 681c       ldr r4, [r3, #0]
 1982: b114       cbz r4, 198a <hackrf_edge_precision_rx_dma_deferred_interrupt+0xa>
 1984: f000 b800  b.w 1740 <baseband::dma::complete_precision_rx_dma_fault_locked()>
 198a: f000 f800  bl  1820 <baseband::dma::publish_queue_state()>
 198e: f000 b800  b.w 1830 <ThreadWait::wake_from_interrupt(int)>

000019c0 <hackrf_edge_precision_rx_dma_fast_fault>:
 19c0: 2100       movs r1, #0
 19c2: f000 b800  b.w 1640 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>
 19c6: 4770       bx lr

000019d0 <hackrf_edge_precision_rx_dma_fast_terminal_count>:
 19d0: 6013       str r3, [r2, #0]
 19d2: f3bf 8f5f  dmb sy
 19d6: f000 b800  b.w 1640 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>
 19da: 4770       bx lr

00001b00 <VectorBC>:
 1b00: f000 f800  bl  1c00 <dbg_check_enter_isr>
 1b04: f000 f800  bl  1c10 <dbg_check_lock_from_isr>
 1b08: f000 f800  bl  1980 <hackrf_edge_precision_rx_dma_deferred_interrupt>
 1b0c: f000 f800  bl  1c20 <dbg_check_unlock_from_isr>
 1b10: f000 f800  bl  1c30 <dbg_check_leave_isr>
 1b14: f000 b800  b.w 1c40 <_port_irq_epilogue>

00001b40 <Vector48>:
 1b40: 686e       ldr r6, [r5, #4]
 1b42: 68ec       ldr r4, [r5, #12]
 1b44: 69e9       ldr r1, [r5, #28]
 1b46: f000 f800  bl  19c0 <hackrf_edge_precision_rx_dma_fast_fault>
 1b4a: 60ae       str r6, [r5, #8]
 1b4c: f3bf 8f5f  dmb sy
 1b50: f000 f800  bl  19d0 <hackrf_edge_precision_rx_dma_fast_terminal_count>
 1b54: f000 f800  bl  19c0 <hackrf_edge_precision_rx_dma_fast_fault>
 1b58: f3bf 8f5f  dmb sy
 1b5c: 612c       str r4, [r5, #16]
 1b60: f3bf 8f5f  dmb sy
 1b64: f8c3 2100  str.w r2, [r3, #256]
 1b68: 4770       bx lr
"""

P12_DISASSEMBLY_FIXTURE = P12_DISASSEMBLY_FIXTURE.replace(
    """00000700 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)>:
 700: f8d0 326c  ldr.w r3, [r0, #620]
 704: b183       cbz r3, 72c <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x2c>
 706: 4a0e       ldr r2, [pc, #56] ; (740 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x40>)
 708: 4293       cmp r3, r2
 70a: d90b       bls.n 724 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x24>
 70c: f8d0 23dc  ldr.w r2, [r0, #1012]
 710: b122       cbz r2, 71c <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x1c>
 712: f3bf 8f5b  dmb ish
 714: 2300       movs r3, #0
 716: f8c0 326c  str.w r3, [r0, #620]
 71a: e007       b.n 72c <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x2c>
 71c: f890 23d8  ldrb.w r2, [r0, #1008]
 720: 2a00       cmp r2, #0
 722: d0f6       beq.n 712 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x12>
 724: 4619       mov r1, r3
 726: f000 f800  bl  1300 <PrecisionRxProcessor::configure(unsigned long)>
 72a: f000 f800  bl  500 <PrecisionRxProcessor::service_capture_command()>
 72e: f000 f800  bl  1420 <PrecisionRxProcessor::service_rate_prepare()>
 732: 4770       bx lr
 740: 001e8480   .word 0x001e8480""",
    """00000700 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)>:
 700: f8d0 326c  ldr.w r3, [r0, #620]
 704: b183       cbz r3, 750 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x50>
 706: 4a0e       ldr r2, [pc, #56] ; (740 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x40>)
 708: 4293       cmp r3, r2
 70a: d90b       bls.n 724 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x24>
 70c: f8d0 23dc  ldr.w r2, [r0, #1012]
 710: b122       cbz r2, 71c <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x1c>
 712: f3bf 8f5b  dmb ish
 714: 2300       movs r3, #0
 716: f8c0 326c  str.w r3, [r0, #620]
 71a: e019       b.n 750 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x50>
 71c: f890 23d8  ldrb.w r2, [r0, #1008]
 720: 2a00       cmp r2, #0
 722: d0f6       beq.n 712 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x12>
 724: 4619       mov r1, r3
 726: f000 f800  bl  1300 <PrecisionRxProcessor::configure(unsigned long)>
 72a: f3bf 8f5b  dmb ish
 72e: 2300       movs r3, #0
 730: f8c0 326c  str.w r3, [r0, #620]
 734: 2301       movs r3, #1
 736: e00b       b.n 750 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x50>
 740: 001e8480   .word 0x001e8480
 750: 9304       str r3, [sp, #16]
 752: f000 f800  bl  500 <PrecisionRxProcessor::service_capture_command()>
 756: f000 f800  bl  16c0 <PrecisionRxProcessor::process_complete_block(buffer_t<std::complex<signed char> > const&)>
 75a: b178       cbz r0, 77c <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x7c>
 75c: 9b04       ldr r3, [sp, #16]
 75e: 2b00       cmp r3, #0
 760: d102       bne.n 768 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x68>
 762: f000 f800  bl  1460 <PrecisionRxProcessor::service_rate_prepare()>
 766: 4770       bx lr
 768: f890 3270  ldrb.w r3, [r0, #624]
 76c: 2b04       cmp r3, #4
 76e: b2d9       uxtb r1, r3
 770: d1f7       bne.n 762 <PrecisionRxProcessor::execute(buffer_t<std::complex<signed char> > const&)+0x62>
 772: f000 f800  bl  1680 <PrecisionRxProcessor::publish_running_if_dma_healthy(PrecisionRxProcessor::RateState)>
 776: f000 f800  bl  1460 <PrecisionRxProcessor::service_rate_prepare()>
 77a: 4770       bx lr
 77c: 4770       bx lr""",
    1,
).replace(
    """00000a00 <BasebandThread::run()>:
 a00: f44f 6000  mov.w r0, #8192 ; 0x2000
 a04: f000 f800  bl  d00 <operator new(unsigned int)>
 a08: f000 f800  bl  e80 <baseband::dma::configure_precision_rx_lease(std::complex<signed char>*, std::complex<signed char>*)>
 a0c: 2100       movs r1, #0
 a0e: f000 f800  bl  1340 <baseband::SGPIO::configure(baseband::Direction)>
 a12: f000 f800  bl  1000 <baseband::dma::enable_precision_rx()>
 a16: f000 f800  bl  1080 <baseband::dma::wait_for_buffer()>
 a1a: 4770       bx lr""",
    """00000a00 <BasebandThread::run()>:
 a00: f44f 6000  mov.w r0, #8192 ; 0x2000
 a04: f000 f800  bl  d00 <operator new(unsigned int)>
 a08: f000 f800  bl  e80 <baseband::dma::configure_precision_rx_lease(std::complex<signed char>*, std::complex<signed char>*)>
 a0c: 2100       movs r1, #0
 a0e: f000 f800  bl  1340 <baseband::SGPIO::configure(baseband::Direction)>
 a12: f000 f800  bl  1000 <baseband::dma::enable_precision_rx()>
 a16: f000 f800  bl  1080 <baseband::dma::wait_for_buffer()>
 a1a: 4798       blx r3
 a1c: 4770       bx lr""",
    1,
).replace(
    """00001000 <baseband::dma::enable_precision_rx()>:
 1000: e9d1 5401  ldrd r5, r4, [r1, #4]
 1004: 680e       ldr r6, [r1, #0]
 1006: 68c8       ldr r0, [r1, #12]
 1008: 6098       str r0, [r3, #8]
 100a: 6118       str r0, [r3, #16]
 100c: 6016       str r6, [r2, #0]
 100e: 6055       str r5, [r2, #4]
 1010: 6094       str r4, [r2, #8]
 1012: 60d0       str r0, [r2, #12]
 1014: f44f 4150  mov.w r1, #53248
 1018: 6111       str r1, [r2, #16]
 101a: f8d3 2110  ldr.w r2, [r3, #272]
 101e: f042 0201  orr.w r2, r2, #1
 1022: f8c3 2110  str.w r2, [r3, #272]
 1026: 4770       bx lr""",
    """00001000 <baseband::dma::enable_precision_rx()>:
 1000: f000 f800  bl  15d0 <baseband::dma::fail_if_precision_rx_dma_error_pending_locked()>
 1004: b9a0       cbnz r0, 1030 <baseband::dma::enable_precision_rx()+0x30>
 1006: e9d1 5401  ldrd r5, r4, [r1, #4]
 100a: 680e       ldr r6, [r1, #0]
 100c: 68c8       ldr r0, [r1, #12]
 100e: 6098       str r0, [r3, #8]
 1010: 6118       str r0, [r3, #16]
 1012: 6016       str r6, [r2, #0]
 1014: 6055       str r5, [r2, #4]
 1016: 6094       str r4, [r2, #8]
 1018: 60d0       str r0, [r2, #12]
 101a: f44f 4150  mov.w r1, #53248
 101e: 6111       str r1, [r2, #16]
 1020: f8d3 2110  ldr.w r2, [r3, #272]
 1024: f042 0201  orr.w r2, r2, #1
 1028: f8c3 2110  str.w r2, [r3, #272]
 102c: 4770       bx lr
 1030: 4770       bx lr""",
    1,
)

P12_DISASSEMBLY_FIXTURE = P12_DISASSEMBLY_FIXTURE.replace(
    (
        " a1a: 4798       blx r3\n"
        " a1c: 4770       bx lr"
    ),
    (
        " a1a: 4798       blx r3\n"
        " a1c: f000 f800  bl  15a0 "
        "<baseband::SGPIO::streaming_disable()>\n"
        " a20: f000 f800  bl  1e00 "
        "<baseband::dma::quiesce_precision_rx_for_shutdown()>\n"
        " a24: 2800       cmp r0, #0\n"
        " a26: d103       bne.n a30 <BasebandThread::run()+0x30>\n"
        " a28: f000 f800  bl  1f00 <port_halt>\n"
        " a2c: 4770       bx lr\n"
        " a30: 2001       movs r0, #1\n"
        " a32: f000 f800  bl  1f40 "
        "<BasebandThread::publish_precision_rx_worker_quiesced(bool)>\n"
        " a36: 4770       bx lr"
    ),
    1,
)

P12_DISASSEMBLY_FIXTURE += """

00001c00 <baseband::dma::claim_precision_rx_completion(baseband::dma::PrecisionRxDmaCompletion&)>:
 1c00: f8c3 1080  str.w r1, [r3, #128]
 1c04: f3bf 8f5f  dmb sy
 1c10: 69ec       ldr r4, [r5, #28]
 1c12: 69a9       ldr r1, [r5, #24]
 1c14: 428c       cmp r4, r1
 1c16: d035       beq.n 1c84 <baseband::dma::claim_precision_rx_completion(baseband::dma::PrecisionRxDmaCompletion&)+0x84>
 1c18: f3bf 8f5f  dmb sy
 1c1c: e896 0003  ldmia.w r6, {r0, r1}
 1c20: e882 0003  stmia.w r2, {r0, r1}
 1c24: f3bf 8f5f  dmb sy
 1c28: 61ec       str r4, [r5, #28]
 1c2a: 6810       ldr r0, [r2, #0]
 1c2c: 2803       cmp r0, #3
 1c2e: 6853       ldr r3, [r2, #4]
 1c30: 683a       ldr r2, [r7, #0]
 1c32: 1ad2       subs r2, r2, r3
 1c34: 2101       movs r1, #1
 1c36: 428a       cmp r2, r1
 1c38: f000 f800  bl  1640 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>
 1c3c: 6865       ldr r5, [r4, #4]
 1c3e: 68e6       ldr r6, [r4, #12]
 1c40: 69e3       ldr r3, [r4, #28]
 1c42: ea45 0706  orr.w r7, r5, r6
 1c46: 433b       orrs r3, r7
 1c48: f023 0301  bic.w r3, r3, #1
 1c4c: f006 0601  and.w r6, r6, #1
 1c50: 4333       orrs r3, r6
 1c52: d105       bne.n 1c60 <baseband::dma::claim_precision_rx_completion(baseband::dma::PrecisionRxDmaCompletion&)+0x60>
 1c54: 2802       cmp r0, #2
 1c56: d10a       bne.n 1c6e <baseband::dma::claim_precision_rx_completion(baseband::dma::PrecisionRxDmaCompletion&)+0x6e>
 1c58: f005 0501  and.w r5, r5, #1
 1c5c: d007       beq.n 1c6e <baseband::dma::claim_precision_rx_completion(baseband::dma::PrecisionRxDmaCompletion&)+0x6e>
 1c60: f000 f800  bl  1640 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>
 1c64: 60a5       str r5, [r4, #8]
 1c66: 6126       str r6, [r4, #16]
 1c68: f8c3 2100  str.w r2, [r3, #256]
 1c6c: 2002       movs r0, #2
 1c6e: f3bf 8f5f  dmb sy
 1c72: 6019       str r1, [r3, #0]
 1c76: 4770       bx lr
 1c84: 2000       movs r0, #0
 1c86: e7f2       b.n 1c6e <baseband::dma::claim_precision_rx_completion(baseband::dma::PrecisionRxDmaCompletion&)+0x6e>

00001cc0 <PrecisionRxProcessor::wait_while_rate_state(precision_rx::rate_transaction::State) const>:
 1cc0: b570       push {r4, r5, r6, lr}
 1cc2: 460d       mov r5, r1
 1cc4: 68e7       ldr r7, [r4, #12]
 1cc6: f000 f800  bl  1d00 <PrecisionRxProcessor::rate_state() const>
 1cca: 42a8       cmp r0, r5
 1ccc: d108       bne.n 1ce0 <PrecisionRxProcessor::wait_while_rate_state(precision_rx::rate_transaction::State) const+0x20>
 1cce: 68e3       ldr r3, [r4, #12]
 1cd0: 1bdb       subs r3, r3, r7
 1cd2: 2b63       cmp r3, #99
 1cd4: d808       bhi.n 1ce8 <PrecisionRxProcessor::wait_while_rate_state(precision_rx::rate_transaction::State) const+0x28>
 1cd6: 2001       movs r0, #1
 1cd8: f000 f800  bl  1d10 <chThdSleep>
 1cdc: e7f3       b.n 1cc6 <PrecisionRxProcessor::wait_while_rate_state(precision_rx::rate_transaction::State) const+0x6>
 1ce0: 2001       movs r0, #1
 1ce2: f3bf 8f5f  dmb sy
 1ce6: bd70       pop {r4, r5, r6, pc}
 1ce8: 2000       movs r0, #0
 1cea: bd70       pop {r4, r5, r6, pc}

00001d00 <PrecisionRxProcessor::rate_state() const>:
 1d00: f890 0270  ldrb.w r0, [r0, #624]
 1d04: 4770       bx lr

00001e00 <baseband::dma::quiesce_precision_rx_for_shutdown()>:
 1e00: 4b13       ldr r3, [pc, #76] ; (1e50 <baseband::dma::quiesce_precision_rx_for_shutdown()+0x50>)
 1e02: 4a14       ldr r2, [pc, #80] ; (1e54 <baseband::dma::quiesce_precision_rx_for_shutdown()+0x54>)
 1e04: f8c3 2080  str.w r2, [r3, #128]
 1e08: f3bf 8f5f  dmb sy
 1e0c: 4b12       ldr r3, [pc, #72] ; (1e58 <baseband::dma::quiesce_precision_rx_for_shutdown()+0x58>)
 1e0e: 681a       ldr r2, [r3, #0]
 1e10: f442 2280  orr.w r2, r2, #262144
 1e14: 601a       str r2, [r3, #0]
 1e16: f3bf 8f5f  dmb sy
 1e1a: f44f 3080  mov.w r0, #65536
 1e1e: 681a       ldr r2, [r3, #0]
 1e20: 0392       lsls r2, r2, #14
 1e22: d502       bpl.n 1e2a <baseband::dma::quiesce_precision_rx_for_shutdown()+0x2a>
 1e24: 3801       subs r0, #1
 1e26: d1fa       bne.n 1e1e <baseband::dma::quiesce_precision_rx_for_shutdown()+0x1e>
 1e28: 4770       bx lr
 1e2a: 681a       ldr r2, [r3, #0]
 1e2c: f022 0201  bic.w r2, r2, #1
 1e30: 601a       str r2, [r3, #0]
 1e32: f3bf 8f5f  dmb sy
 1e36: 4b06       ldr r3, [pc, #24] ; (1e50 <baseband::dma::quiesce_precision_rx_for_shutdown()+0x50>)
 1e38: 4a06       ldr r2, [pc, #24] ; (1e54 <baseband::dma::quiesce_precision_rx_for_shutdown()+0x54>)
 1e3a: f8c3 2180  str.w r2, [r3, #384]
 1e3e: f3bf 8f5f  dmb sy
 1e42: 2001       movs r0, #1
 1e44: 4770       bx lr
 1e50: e000e100   .word 0xe000e100
 1e54: 80000004   .word 0x80000004
 1e58: 40002110   .word 0x40002110

00001f00 <port_halt>:
 1f00: 4770       bx lr

00001f40 <BasebandThread::publish_precision_rx_worker_quiesced(bool)>:
 1f40: 4770       bx lr

00002100 <precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)>:
 2100: eeb5 0ac0  vcmpe.f32 s0, #0.0
 2104: eef1 fa10  vmrs APSR_nzcv, fpscr
 2108: d906       bls.n 2118 <precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)+0x18>
 210a: b508       push {r3, lr}
 210c: ee20 0a20  vmul.f32 s0, s0, s1
 2110: f000 f800  bl  3000 <__ieee754_log10f>
 2114: bd08       pop {r3, pc}
 2118: 4801       ldr r0, [pc, #4] ; (2120 <precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)+0x20>)
 211a: 4770       bx lr
 2120: fffffb50   .word 0xfffffb50
"""


P12_GATE_OPEN_NM_FIXTURE = """
000023d0 00000010 t baseband::dma::end_precision_rx_rate_state_update()
00002478 00000002 t baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)
000025c8 00000004 t baseband::dma::begin_precision_rx_rate_state_update()
00002630 00000050 t baseband::dma::open_precision_rx_sgpio_gate_locked()
"""


P12_GATE_OPEN_DISASSEMBLY_FIXTURE = """
000023d0 <baseband::dma::end_precision_rx_rate_state_update()>:
 23d0: 4770       bx lr

00002478 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>:
 2478: 4770       bx lr

000025c8 <baseband::dma::begin_precision_rx_rate_state_update()>:
 25c8: 2001       movs r0, #1
 25ca: 4770       bx lr

00002630 <baseband::dma::open_precision_rx_sgpio_gate_locked()>:
 2630: b507       push {r0, r1, r2, lr}
 2632: f7ff ffc9  bl  25c8 <baseband::dma::begin_precision_rx_rate_state_update()>
 2636: b188       cbz r0, 265c <baseband::dma::open_precision_rx_sgpio_gate_locked()+0x2c>
 2638: 4b0e       ldr r3, [pc, #56] ; (2674 <baseband::dma::open_precision_rx_sgpio_gate_locked()+0x44>)
 263a: f8d3 0110  ldr.w r0, [r3, #272]
 263e: f010 0001  ands.w r0, r0, #1
 2642: d10e       bne.n 2662 <baseband::dma::open_precision_rx_sgpio_gate_locked()+0x32>
 2644: 4601       mov r1, r0
 2646: 9001       str r0, [sp, #4]
 2648: f7ff ff16  bl  2478 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>
 264c: 4b0a       ldr r3, [pc, #40] ; (2678 <baseband::dma::open_precision_rx_sgpio_gate_locked()+0x48>)
 264e: f04f 4200  mov.w r2, #2147483648
 2652: f8c3 2100  str.w r2, [r3, #256]
 2656: f7ff febb  bl  23d0 <baseband::dma::end_precision_rx_rate_state_update()>
 265a: 9801       ldr r0, [sp, #4]
 265c: b003       add sp, #12
 265e: f85d fb04  ldr.w pc, [sp], #4
 2662: 4a06       ldr r2, [pc, #24] ; (267c <baseband::dma::open_precision_rx_sgpio_gate_locked()+0x4c>)
 2664: 9001       str r0, [sp, #4]
 2666: f8d2 3214  ldr.w r3, [r2, #532]
 266a: f423 6380  bic.w r3, r3, #1024
 266e: f8c2 3214  str.w r3, [r2, #532]
 2672: e7f0       b.n 2656 <baseband::dma::open_precision_rx_sgpio_gate_locked()+0x26>
 2674: 40002000   .word 0x40002000
 2678: e000e100   .word 0xe000e100
 267c: 40101000   .word 0x40101000
"""


P12_RATE_STATE_IRQ_NM_FIXTURE = """
000023d0 00000010 t baseband::dma::end_precision_rx_rate_state_update()
00002478 00000002 t baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)
000025c8 00000068 t baseband::dma::begin_precision_rx_rate_state_update()
00002630 0000000a t baseband::dma::open_precision_rx_sgpio_gate_locked()
00002dec 0000000a t PrecisionRxProcessor::transition_rate_state(precision_rx::rate_transaction::Event)
100016d8 00000004 b baseband::dma::dma_fatal_latched
"""


P12_RATE_STATE_IRQ_DISASSEMBLY_FIXTURE = """
000023d0 <baseband::dma::end_precision_rx_rate_state_update()>:
 23d0: f3bf 8f5f  dmb sy
 23d4: 4b01       ldr r3, [pc, #4] ; (23dc <baseband::dma::end_precision_rx_rate_state_update()+0xc>)
 23d6: 2204       movs r2, #4
 23d8: 601a       str r2, [r3, #0]
 23da: 4770       bx lr
 23dc: e000e100   .word 0xe000e100

00002478 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>:
 2478: 4770       bx lr

000025c8 <baseband::dma::begin_precision_rx_rate_state_update()>:
 25c8: b5f8       push {r3, r4, r5, r6, r7, lr}
 25ca: 4b16       ldr r3, [pc, #88] ; (2624 <baseband::dma::begin_precision_rx_rate_state_update()+0x5c>)
 25cc: 2204       movs r2, #4
 25ce: f8c3 2080  str.w r2, [r3, #128]
 25d2: f3bf 8f5f  dmb sy
 25d6: 4c12       ldr r4, [pc, #72] ; (2628 <baseband::dma::begin_precision_rx_rate_state_update()+0x60>)
 25d8: 4a12       ldr r2, [pc, #72] ; (262c <baseband::dma::begin_precision_rx_rate_state_update()+0x64>)
 25da: 6865       ldr r5, [r4, #4]
 25dc: 68e7       ldr r7, [r4, #12]
 25de: 69e3       ldr r3, [r4, #28]
 25e0: 6812       ldr r2, [r2, #0]
 25e2: ea45 0607  orr.w r6, r5, r7
 25e6: 4333       orrs r3, r6
 25e8: f023 0301  bic.w r3, r3, #1
 25ec: f007 0701  and.w r7, r7, #1
 25f0: 433b       orrs r3, r7
 25f2: 4313       orrs r3, r2
 25f6: d013       beq.n 2620 <baseband::dma::begin_precision_rx_rate_state_update()+0x58>
 25fa: 2100       movs r1, #0
 25fc: f005 0001  and.w r0, r5, #1
 2600: f7ff ff3a  bl  2478 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>
 2604: b10e       cbz r6, 260a <baseband::dma::begin_precision_rx_rate_state_update()+0x42>
 2606: 60a5       str r5, [r4, #8]
 2608: 6127       str r7, [r4, #16]
 260a: 4b06       ldr r3, [pc, #24] ; (2624 <baseband::dma::begin_precision_rx_rate_state_update()+0x5c>)
 260c: f04f 4200  mov.w r2, #2147483648
 2610: f8c3 2100  str.w r2, [r3, #256]
 2614: f3bf 8f5f  dmb sy
 2618: 2204       movs r2, #4
 261a: 601a       str r2, [r3, #0]
 261c: 2000       movs r0, #0
 261e: bdf8       pop {r3, r4, r5, r6, r7, pc}
 2620: 2001       movs r0, #1
 2622: e7fc       b.n 261e <baseband::dma::begin_precision_rx_rate_state_update()+0x56>
 2624: e000e100   .word 0xe000e100
 2628: 40002000   .word 0x40002000
 262c: 100016d8   .word 0x100016d8

00002630 <baseband::dma::open_precision_rx_sgpio_gate_locked()>:
 2630: f7ff ffca  bl  25c8 <baseband::dma::begin_precision_rx_rate_state_update()>
 2634: f7ff fccc  bl  23d0 <baseband::dma::end_precision_rx_rate_state_update()>
 2638: 4770       bx lr

00002dec <PrecisionRxProcessor::transition_rate_state(precision_rx::rate_transaction::Event)>:
 2dec: f7ff fbea  bl  25c8 <baseband::dma::begin_precision_rx_rate_state_update()>
 2df0: f7ff faee  bl  23d0 <baseband::dma::end_precision_rx_rate_state_update()>
 2df4: 4770       bx lr
"""

P15_SHUTDOWN_MODE_DISASSEMBLY_FIXTURE = """
00000100 <main>:
 100: 6829       ldr r1, [r5, #0]
 102: 680b       ldr r3, [r1, #0]
 104: 2b05       cmp r3, #5
 106: d003       beq.n 110 <main+0x10>
 108: 4770       bx lr
 110: a802       add r0, sp, #8
 112: f000 f800  bl 200 <EventDispatcher::on_message_shutdown(ShutdownMessage const&)>
 116: 4770       bx lr

00000200 <EventDispatcher::on_message_shutdown(ShutdownMessage const&)>:
 200: 684b       ldr r3, [r1, #4]
 202: 2b01       cmp r3, #1
 204: b510       push {r4, lr}
 206: 4604       mov r4, r0
 208: d104       bne.n 214 <EventDispatcher::on_message_shutdown(ShutdownMessage const&)+0x14>
 20a: 6800       ldr r0, [r0, #0]
 20c: 6803       ldr r3, [r0, #0]
 20e: 68db       ldr r3, [r3, #12]
 210: 4798       blx r3
 212: bf00       nop
 214: 2300       movs r3, #0
 216: 7123       strb r3, [r4, #4]
 218: bd10       pop {r4, pc}

00000300 <BasebandThread::fail_close_precision_rx()>:
 300: 4a07       ldr r2, [pc, #28] ; (320 <BasebandThread::fail_close_precision_rx()+0x20>)
 302: f8d2 3214  ldr.w r3, [r2, #532]
 306: f443 6380  orr.w r3, r3, #1024
 30a: b510       push {r4, lr}
 30c: f8c2 3214  str.w r3, [r2, #532]
 310: f000 f800  bl 600 <dbg_check_lock>
 314: bd10       pop {r4, pc}
 320: 40101000   .word 0x40101000

00000400 <PrecisionRxProcessor::on_message(Message const*)>:
 400: 680b       ldr r3, [r1, #0]
 402: 2b05       cmp r3, #5
 404: d10c       bne.n 420 <PrecisionRxProcessor::on_message(Message const*)+0x20>
 406: 684b       ldr r3, [r1, #4]
 408: 2b01       cmp r3, #1
 40a: d109       bne.n 420 <PrecisionRxProcessor::on_message(Message const*)+0x20>
 40c: f200 4034  addw r0, r0, #1076
 410: f7ff ff76  bl 300 <BasebandThread::fail_close_precision_rx()>
 414: 4620       mov r0, r4
 416: 2108       movs r1, #8
 418: e8bd 4010  ldmia.w sp!, {r4, lr}
 41c: f000 b870  b.w 500 <PrecisionRxProcessor::transition_rate_state(precision_rx::rate_transaction::Event)>
 420: bd10       pop {r4, pc}

00000500 <PrecisionRxProcessor::transition_rate_state(precision_rx::rate_transaction::Event)>:
 500: 4770       bx lr

00000600 <dbg_check_lock>:
 600: 4770       bx lr
"""

P15_CHANNEL_DISABLED_DISASSEMBLY_FIXTURE = """
00000100 <baseband::dma::publish_precision_rx_quiesce_failure(precision_rx::dma_telemetry::QuiesceFailure)>:
 100: 4770       bx lr

00000120 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>:
 120: 4770       bx lr

00000200 <baseband::dma::pause_precision_rx_rate_change()>:
 200: 4a13       ldr r2, [pc, #76] ; (250 <baseband::dma::pause_precision_rx_rate_change()+0x50>)
 202: f8d2 4110  ldr.w r4, [r2, #272]
 206: f014 0401  ands.w r4, r4, #1
 20a: d119       bne.n 240 <baseband::dma::pause_precision_rx_rate_change()+0x40>
 20c: 2007       movs r0, #7
 20e: f7ff ff77  bl 100 <baseband::dma::publish_precision_rx_quiesce_failure(precision_rx::dma_telemetry::QuiesceFailure)>
 212: 4621       mov r1, r4
 214: 4620       mov r0, r4
 216: f7ff ff83  bl 120 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>
 21a: 4b0e       ldr r3, [pc, #56] ; (254 <baseband::dma::pause_precision_rx_rate_change()+0x54>)
 21c: f04f 4200  mov.w r2, #2147483648
 220: f8c3 2100  str.w r2, [r3, #256]
 224: f3bf 8f5f  dmb sy
 228: e006       b.n 238 <baseband::dma::pause_precision_rx_rate_change()+0x38>
 238: 4620       mov r0, r4
 23a: bd10       pop {r4, pc}
 240: 2401       movs r4, #1
 242: e7f9       b.n 238 <baseband::dma::pause_precision_rx_rate_change()+0x38>
 250: 40002000   .word 0x40002000
 254: e000e100   .word 0xe000e100

00000300 <baseband::dma::set_precision_rx_capture_geometry(bool)>:
 300: 4a13       ldr r2, [pc, #76] ; (350 <baseband::dma::set_precision_rx_capture_geometry(bool)+0x50>)
 302: f8d2 4110  ldr.w r4, [r2, #272]
 306: f014 0401  ands.w r4, r4, #1
 30a: d119       bne.n 340 <baseband::dma::set_precision_rx_capture_geometry(bool)+0x40>
 30c: 2007       movs r0, #7
 30e: f7ff fef7  bl 100 <baseband::dma::publish_precision_rx_quiesce_failure(precision_rx::dma_telemetry::QuiesceFailure)>
 312: 4621       mov r1, r4
 314: 4620       mov r0, r4
 316: f7ff ff03  bl 120 <baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>
 31a: 4b0e       ldr r3, [pc, #56] ; (354 <baseband::dma::set_precision_rx_capture_geometry(bool)+0x54>)
 31c: f04f 4200  mov.w r2, #2147483648
 320: f8c3 2100  str.w r2, [r3, #256]
 324: f3bf 8f5f  dmb sy
 328: e006       b.n 338 <baseband::dma::set_precision_rx_capture_geometry(bool)+0x38>
 338: 4620       mov r0, r4
 33a: bd10       pop {r4, pc}
 340: 2401       movs r4, #1
 342: e7f9       b.n 338 <baseband::dma::set_precision_rx_capture_geometry(bool)+0x38>
 350: 40002000   .word 0x40002000
 354: e000e100   .word 0xe000e100
"""

P15_SHUTDOWN_PREDICATE_NM_FIXTURE = """
10001000 00000001 b baseband::dma::dma_error_pending
10001004 00000004 b baseband::dma::dma_fatal_latched
"""

P15_SHUTDOWN_PREDICATE_DISASSEMBLY_FIXTURE = """
00000100 <baseband::dma::wake_precision_rx_worker_for_shutdown()>:
 100: f000 f800  bl 500 <dbg_check_lock>
 104: 4b06       ldr r3, [pc, #24] ; (120 <baseband::dma::wake_precision_rx_worker_for_shutdown()+0x20>)
 106: 2201       movs r2, #1
 108: 701a       strb r2, [r3, #0]
 10a: f3bf 8f5f  dmb sy
 10e: f000 f800  bl 520 <ThreadWait::wake_from_interrupt(int)>
 112: f000 f800  bl 540 <dbg_check_unlock>
 116: 4770       bx lr
 120: 10001000   .word 0x10001000

00000200 <baseband::dma::wait_for_buffer()>:
 200: 4a17       ldr r2, [pc, #92] ; (260 <baseband::dma::wait_for_buffer()+0x60>)
 202: 6812       ldr r2, [r2, #0]
 204: 4b17       ldr r3, [pc, #92] ; (264 <baseband::dma::wait_for_buffer()+0x64>)
 206: 781a       ldrb r2, [r3, #0]
 208: 461e       mov r6, r3
 20a: 2400       movs r4, #0
 20c: 701c       strb r4, [r3, #0]
 210: f000 f800  bl 560 <ThreadWait::sleep_locked()>
 214: 7833       ldrb r3, [r6, #0]
 216: 7034       strb r4, [r6, #0]
 218: 4770       bx lr
 260: 10001004   .word 0x10001004
 264: 10001000   .word 0x10001000

00000300 <BasebandThread::~BasebandThread()>:
 300: f000 f800  bl 580 <chThdTerminate>
 304: f7ff fefc  bl 100 <baseband::dma::wake_precision_rx_worker_for_shutdown()>
 308: f000 f800  bl 5a0 <chThdWait>
 30c: 4770       bx lr
"""


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise AssertionError(f"fixture token must occur once: {old!r}")
    return source.replace(old, new, 1)


class PrecisionRxElfVerifierTest(unittest.TestCase):
    def verify(
        self,
        disassembly=DISASSEMBLY_FIXTURE,
        sections=SECTION_FIXTURE,
        nm=NM_FIXTURE,
    ):
        return verifier.verify_outputs(
            nm,
            disassembly,
            sections,
            elf_sha256="0" * 64,
        )

    def verify_p12(
        self,
        nm=P12_NM_FIXTURE,
        disassembly=P12_DISASSEMBLY_FIXTURE,
    ):
        return verifier.verify_outputs(
            nm,
            disassembly,
            SECTION_FIXTURE,
            elf_sha256="0" * 64,
            _legacy_p14_test_contract=True,
        )

    def verify_p12_gate_open_helper(
        self,
        disassembly=P12_GATE_OPEN_DISASSEMBLY_FIXTURE,
    ):
        return verifier._verify_p12_gate_open_helper(
            symbols=verifier.parse_nm(P12_GATE_OPEN_NM_FIXTURE),
            functions=verifier.parse_disassembly(disassembly),
        )

    def verify_p12_rate_state_irq_exclusion(
        self,
        disassembly=P12_RATE_STATE_IRQ_DISASSEMBLY_FIXTURE,
    ):
        return verifier._verify_p12_rate_state_irq_exclusion(
            symbols=verifier.parse_nm(P12_RATE_STATE_IRQ_NM_FIXTURE),
            functions=verifier.parse_disassembly(disassembly),
            literal_words=verifier.parse_literal_words(disassembly),
        )

    def verify_p15_shutdown_mode_dispatch(
        self,
        disassembly=P15_SHUTDOWN_MODE_DISASSEMBLY_FIXTURE,
    ):
        return verifier._verify_p15_shutdown_mode_dispatch(
            functions=verifier.parse_disassembly(disassembly),
            literal_words=verifier.parse_literal_words(disassembly),
        )

    def verify_p15_channel_disabled(
        self,
        disassembly=P15_CHANNEL_DISABLED_DISASSEMBLY_FIXTURE,
    ):
        return verifier._verify_p15_channel_disabled_quiesce_failures(
            functions=verifier.parse_disassembly(disassembly),
            literal_words=verifier.parse_literal_words(disassembly),
        )

    def verify_p15_shutdown_predicate(
        self,
        nm=P15_SHUTDOWN_PREDICATE_NM_FIXTURE,
        disassembly=P15_SHUTDOWN_PREDICATE_DISASSEMBLY_FIXTURE,
    ):
        return verifier._verify_p15_shutdown_wake_predicate(
            symbols=verifier.parse_nm(nm),
            functions=verifier.parse_disassembly(disassembly),
            literal_words=verifier.parse_literal_words(disassembly),
        )

    def test_p15_shutdown_mode_dispatch_accepts_reviewed_chain(self):
        proof = self.verify_p15_shutdown_mode_dispatch()
        self.assertEqual(proof["shutdown_message_id"], 5)
        self.assertEqual(proof["precision_rx_fault_mode"], 1)
        self.assertEqual(proof["fatal_transition_event"], 8)
        self.assertTrue(proof["fault_mode_forwarded_to_processor"])
        self.assertTrue(proof["normal_mode_bypasses_processor_forward"])
        self.assertTrue(proof["fail_close_sgpio_host_disable_first"])

    def test_p15_shutdown_mode_dispatch_rejects_id_mode_and_path_mutations(
        self,
    ):
        mutations = (
            (
                " 104: 2b05       cmp r3, #5",
                " 104: 2b04       cmp r3, #4",
                "Shutdown ID=5",
            ),
            (
                " 202: 2b01       cmp r3, #1",
                " 202: 2b00       cmp r3, #0",
                "PrecisionRxFault=1",
            ),
            (
                " 208: d104       bne.n 214",
                " 208: d004       beq.n 214",
                "only dispatcher mode",
            ),
            (
                " 210: 4798       blx r3",
                " 210: bf00       nop",
                "indirect processor forward",
            ),
            (
                " 408: 2b01       cmp r3, #1",
                " 408: 2b02       cmp r3, #2",
                "PrecisionRxFault=1",
            ),
            (
                " 306: f443 6380  orr.w r3, r3, #1024",
                " 306: f443 6380  orr.w r3, r3, #512",
                "HOST_DISABLE",
            ),
            (
                " 416: 2108       movs r1, #8",
                " 416: 2107       movs r1, #7",
                "Fatal event=8",
            ),
        )
        for old, new, message in mutations:
            with self.subTest(mutation=old):
                disassembly = replace_once(
                    P15_SHUTDOWN_MODE_DISASSEMBLY_FIXTURE,
                    old,
                    new,
                )
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    message,
                ):
                    self.verify_p15_shutdown_mode_dispatch(disassembly)

    def test_p15_channel_disabled_accepts_both_control_callers(self):
        proof = self.verify_p15_channel_disabled()
        self.assertEqual(proof["reason"], 7)
        self.assertEqual(proof["reason_name"], "ChannelDisabled")
        self.assertEqual(len(proof["paths"]), 2)
        self.assertTrue(proof["rate_pause_bound"])
        self.assertTrue(proof["capture_geometry_bound"])
        self.assertTrue(proof["fatal_latch_and_deferred_pend_bound"])

    def test_p15_channel_disabled_rejects_reason_and_fault_mutations(self):
        mutations = (
            (
                " 20c: 2007       movs r0, #7",
                " 20c: 2006       movs r0, #6",
            ),
            (
                " 30c: 2007       movs r0, #7",
                " 30c: 2006       movs r0, #6",
            ),
            (
                " 216: f7ff ff83  bl 120 "
                "<baseband::dma::latch_precision_rx_dma_fault_fast"
                "(unsigned long, bool)>",
                " 216: bf00       nop",
            ),
            (
                " 220: f8c3 2100  str.w r2, [r3, #256]",
                " 220: f8c3 2080  str.w r2, [r3, #128]",
            ),
            (
                " 324: f3bf 8f5f  dmb sy",
                " 324: bf00       nop",
            ),
            (
                " 20a: d119       bne.n 240",
                " 20a: d019       beq.n 240",
            ),
        )
        for old, new in mutations:
            with self.subTest(mutation=old):
                disassembly = replace_once(
                    P15_CHANNEL_DISABLED_DISASSEMBLY_FIXTURE,
                    old,
                    new,
                )
                with self.assertRaises(verifier.VerificationError):
                    self.verify_p15_channel_disabled(disassembly)

    def test_p15_shutdown_predicate_accepts_durable_wake_and_waiter(self):
        proof = self.verify_p15_shutdown_predicate()
        self.assertEqual(proof["dma_error_pending_address"], "0x10001000")
        self.assertEqual(proof["dma_error_pending_bytes"], 1)
        self.assertEqual(proof["dma_fatal_latched_address"], "0x10001004")
        self.assertEqual(proof["dma_fatal_latched_bytes"], 4)
        self.assertTrue(proof["predicate_distinct_from_fatal_latch"])
        self.assertTrue(proof["waiter_consumes_before_sleep"])
        self.assertTrue(proof["waiter_consumes_after_wake"])
        self.assertTrue(proof["destructor_terminate_wake_wait_order"])

    def test_p15_shutdown_predicate_rejects_symbol_and_order_mutations(self):
        nm_mutations = (
            (
                "10001000 00000001 b baseband::dma::dma_error_pending",
                "10001000 00000004 b baseband::dma::dma_error_pending",
            ),
            (
                "10001004 00000004 b baseband::dma::dma_fatal_latched",
                "10001000 00000004 b baseband::dma::dma_fatal_latched",
            ),
        )
        for old, new in nm_mutations:
            with self.subTest(mutation=old):
                nm = replace_once(
                    P15_SHUTDOWN_PREDICATE_NM_FIXTURE,
                    old,
                    new,
                )
                with self.assertRaises(verifier.VerificationError):
                    self.verify_p15_shutdown_predicate(nm=nm)

        disassembly_mutations = (
            (
                " 108: 701a       strb r2, [r3, #0]",
                " 108: 705a       strb r2, [r3, #1]",
            ),
            (
                " 10a: f3bf 8f5f  dmb sy",
                " 10a: bf00       nop",
            ),
            (
                " 20c: 701c       strb r4, [r3, #0]",
                " 20c: bf00       nop",
            ),
            (
                " 216: 7034       strb r4, [r6, #0]",
                " 216: bf00       nop",
            ),
            (
                " 260: 10001004   .word 0x10001004\n"
                " 264: 10001000   .word 0x10001000",
                " 260: 10001000   .word 0x10001000\n"
                " 264: 10001004   .word 0x10001004",
            ),
            (
                " 300: f000 f800  bl 580 <chThdTerminate>\n"
                " 304: f7ff fefc  bl 100 "
                "<baseband::dma::wake_precision_rx_worker_for_shutdown()>",
                " 300: f7ff fefc  bl 100 "
                "<baseband::dma::wake_precision_rx_worker_for_shutdown()>\n"
                " 304: f000 f800  bl 580 <chThdTerminate>",
            ),
        )
        for old, new in disassembly_mutations:
            with self.subTest(mutation=old):
                disassembly = replace_once(
                    P15_SHUTDOWN_PREDICATE_DISASSEMBLY_FIXTURE,
                    old,
                    new,
                )
                with self.assertRaises(verifier.VerificationError):
                    self.verify_p15_shutdown_predicate(
                        disassembly=disassembly,
                    )

    def test_accepts_reviewed_open_path_and_records_resources(self):
        report = self.verify()
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["contract"], "precision-rx-linked-dma-lease-v5")
        self.assertEqual(
            report["verification_scope"]["classification"],
            "diagnostic-regression-shape",
        )
        self.assertFalse(report["verification_scope"]["complete_cfg_proof"])
        self.assertFalse(
            report["verification_scope"]["complete_def_use_proof"]
        )
        self.assertEqual(
            report["verification_scope"]["release_authority"],
            "frozen-full-elf-sha256",
        )
        self.assertEqual(report["open_path"]["rebind_internal_call_count"], 0)
        self.assertEqual(report["resources"]["processor_object_bytes"], 1072)
        self.assertEqual(report["resources"]["maximum_processor_object_bytes"], 1152)
        self.assertEqual(report["resources"]["capture_stream_bytes"], 73728)
        self.assertEqual(
            report["resources"]["supplemental_capture_stream_bytes"], 16384
        )
        self.assertEqual(
            report["resources"]["combined_capture_stream_bytes"], 90112
        )
        self.assertEqual(report["resources"]["baseband_dma_buffer_bytes"], 8192)
        self.assertEqual(report["open_path"]["stream_write_size"], 8192)
        self.assertEqual(report["open_path"]["stream_buffer_count"], 9)
        self.assertEqual(report["open_path"]["implementation_buffer_count_log2"], 4)
        self.assertEqual(report["open_path"]["mode_buffer_count_log2"], 4)
        self.assertEqual(report["open_path"]["mode_local_buffer_count"], 9)
        self.assertEqual(report["open_path"]["mode_spill_buffer_count"], 2)
        self.assertEqual(report["open_path"]["mode_total_buffer_count"], 11)
        self.assertEqual(report["open_path"]["dma_buffer_bytes"], 8192)
        self.assertEqual(report["open_path"]["dma_transfer_bytes"], 2048)
        self.assertEqual(report["open_path"]["dma_transfer_count"], 4)
        self.assertEqual(report["open_path"]["dma_lli_bytes"], 64)
        self.assertEqual(report["open_path"]["dma_loan_bytes"], 8192)
        self.assertEqual(report["open_path"]["dma_monitor_ring_bytes"], 16384)
        self.assertEqual(report["open_path"]["dma_monitor_transfer_bytes"], 4096)
        self.assertEqual(report["open_path"]["dma_monitor_transfer_samples"], 2048)
        self.assertEqual(report["open_path"]["dma_capture_ring_bytes"], 8192)
        self.assertEqual(report["open_path"]["dma_capture_transfer_bytes"], 2048)
        self.assertEqual(report["open_path"]["dma_capture_transfer_samples"], 1024)
        self.assertEqual(
            report["open_path"]["dma_terminal_count_interrupt_count"], 4
        )
        self.assertTrue(report["open_path"]["dma_transition_discards_old_block"])
        self.assertTrue(report["open_path"]["dma_transition_resets_epoch"])
        self.assertTrue(report["open_path"]["dma_abort_requires_consumer_release"])
        self.assertTrue(report["close_path"]["service_calls_seal"])
        self.assertTrue(report["close_path"]["service_calls_drained"])
        self.assertTrue(report["close_path"]["monitor_return_precedes_command_ack"])
        self.assertTrue(
            report["dma_lease_implementation"][
                "pl080_timeout_clears_halt_without_descriptor_rewrite"
            ]
        )
        self.assertEqual(
            report["dma_lease_implementation"]["scheduler_backlog_depth"], 0
        )
        self.assertEqual(
            report["dma_lease_implementation"]["service_deadline_ns_at_20m"],
            102400,
        )
        self.assertEqual(
            report["dma_lease_implementation"]["physical_retention_ns_at_20m"],
            307200,
        )
        self.assertGreaterEqual(
            report["resources"]["modeled_ram_headroom_bytes"],
            verifier.MINIMUM_MODELED_HEADROOM_BYTES,
        )

    def test_accepts_p12_queue_and_rate_transaction_contract(self):
        report = self.verify_p12()
        self.assertEqual(
            report["contract"],
            "precision-rx-linked-rate-transaction-v5",
        )
        self.assertEqual(report["profile"], "p14-dwt-rate-quiesce")
        self.assertEqual(
            report["dma_lease_implementation"]["scheduler_backlog_depth"],
            3,
        )
        self.assertEqual(
            report["dma_lease_implementation"]["service_deadline_ns_at_20m"],
            204800,
        )
        transaction = report["rate_transaction"]
        self.assertEqual(transaction["protocol_version"], 2)
        self.assertEqual(transaction["completion_queue_depth"], 3)
        self.assertEqual(transaction["completion_period_ns_at_20m"], 102400)
        self.assertEqual(
            transaction["oldest_claim_deadline_ns_at_20m"],
            204800,
        )
        self.assertEqual(transaction["claim_guard_age"], 2)
        self.assertFalse(transaction["queue_drops_oldest"])
        self.assertTrue(transaction["queue_spsc"])
        self.assertTrue(transaction["queue_full_fail_closed"])
        self.assertEqual(transaction["fast_irq_priority"], 1)
        self.assertEqual(transaction["deferred_irq"], 31)
        self.assertEqual(transaction["deferred_irq_priority"], 3)
        self.assertTrue(transaction["fast_tc_w1c_first"])
        self.assertTrue(transaction["fast_error_gate_first"])
        self.assertTrue(transaction["unexpected_channel_fail_closed"])
        self.assertTrue(transaction["worker_claim_irq_exclusion"])
        self.assertTrue(transaction["claim_preserves_own_tc"])
        self.assertTrue(transaction["rate_state_preserves_own_tc"])
        self.assertTrue(transaction["exclusion_preserves_nvic_pending"])
        self.assertTrue(transaction["shutdown_active_drain"])
        self.assertEqual(transaction["shutdown_active_spin_limit"], 65536)
        self.assertTrue(transaction["shutdown_timeout_halts"])
        self.assertEqual(transaction["control_active_drain_timeout_us"], 10000)
        self.assertEqual(
            transaction["control_active_drain_ticks_at_200m"],
            2000000,
        )
        self.assertTrue(transaction["control_active_drain_uses_dwt"])
        self.assertTrue(transaction["control_active_drain_counter_guard"])
        self.assertEqual(
            transaction["control_slowest_descriptor_ticks_at_200m"],
            409600,
        )
        self.assertEqual(transaction["lifetime_loss_counter_bits"], 32)
        self.assertTrue(transaction["lifetime_loss_saturating"])
        self.assertTrue(
            transaction["linked_control"]["prepare_wrapper_pre_gates_sgpio"]
        )
        self.assertFalse(
            transaction["linked_control"]["dma_halt_precedes_sgpio_gate"]
        )
        self.assertTrue(
            transaction["linked_control"]["dma_resume_precedes_sgpio_enable"]
        )
        self.assertTrue(
            transaction["linked_control"][
                "commit_ack_dominated_by_first_new_rate_completion"
            ]
        )
        self.assertTrue(
            transaction["completion_claim"][
                "exceptional_status_fail_closed"
            ]
        )
        self.assertTrue(
            transaction["completion_claim"]["sole_own_channel_tc_preserved"]
        )
        self.assertTrue(
            transaction["completion_claim"]["nvic_pending_preserved"]
        )
        self.assertTrue(
            transaction["shutdown_quiesce"][
                "worker_timeout_calls_port_halt"
            ]
        )
        control_drain = transaction["control_active_drain"]
        self.assertEqual(control_drain["demcr_address"], 0xE000EDFC)
        self.assertEqual(control_drain["dwt_ctrl_address"], 0xE0001000)
        self.assertEqual(control_drain["dwt_cyccnt_address"], 0xE0001004)
        self.assertEqual(
            control_drain["pl080_channel_config_address"],
            0x40002110,
        )
        self.assertEqual(control_drain["timeout_us"], 10000)
        self.assertEqual(control_drain["timeout_ticks"], 2000000)
        self.assertEqual(control_drain["loop_max_elapsed_ticks"], 1999999)
        self.assertEqual(
            control_drain["slowest_descriptor_ticks_at_200m"],
            409600,
        )
        self.assertTrue(control_drain["both_counter_guards_before_halt"])
        self.assertTrue(control_drain["cyccnt_sample_after_halt_dmb"])
        self.assertTrue(control_drain["unsigned_wrap_safe_elapsed"])
        self.assertTrue(control_drain["exact_deadline_boundary"])
        self.assertTrue(control_drain["final_active_recheck"])
        self.assertTrue(control_drain["timeout_h_only_rollback"])
        self.assertTrue(control_drain["timeout_bypasses_e_and_irq_clear"])
        self.assertTrue(control_drain["halt_set_config_rmw_def_use_bound"])
        self.assertTrue(
            control_drain["timeout_h_clear_config_rmw_def_use_bound"]
        )
        self.assertTrue(
            control_drain["success_e_clear_config_rmw_def_use_bound"]
        )
        self.assertTrue(
            control_drain["success_irq_clear_base_and_mask_bound"]
        )
        self.assertTrue(
            control_drain["all_pending_error_results_fail_closed"]
        )
        self.assertTrue(
            control_drain["config_and_dwt_base_registers_preserved"]
        )
        self.assertTrue(
            control_drain["exact_word_mmio_and_literal_access_shapes"]
        )
        self.assertTrue(control_drain["success_chain_cfg_dominated"])
        energy_log10 = transaction["energy_log10_safety"]
        self.assertEqual(
            energy_log10["function"],
            "precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)",
        )
        self.assertEqual(
            energy_log10["kernel_target"],
            "__ieee754_log10f",
        )
        self.assertTrue(
            energy_log10["non_positive_guard_dominates_kernel"]
        )
        self.assertTrue(energy_log10["wrapper_path_absent"])
        self.assertEqual(
            energy_log10["non_positive_fallback_dbfs_x10"],
            -1200,
        )
        self.assertTrue(energy_log10["bounded"])
        self.assertTrue(energy_log10["linked_instruction_calibrated"])
        self.assertEqual(
            len(transaction["post_build_instruction_calibration_required"]),
            0,
        )
        self.assertTrue(
            report["dma_lease_implementation"][
                "pending_error_fail_closed_proof"
            ]["enable_rejects_pending_error_before_register_writes"]
        )

    def test_p14_rejects_missing_demcr_trcena_guard(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2510: 68db       ldr r3, [r3, #12]",
            " 2510: 689b       ldr r3, [r3, #8]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "SCS_DEMCR.TRCENA",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_inverted_dwt_cyccntena_guard(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 251c: d5f5       bpl.n 250a "
                "<baseband::dma::halt_and_disable_precision_rx(bool&)+0xa>"
            ),
            (
                " 251c: d4f5       bmi.n 250a "
                "<baseband::dma::halt_and_disable_precision_rx(bool&)+0xa>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "DWT_CTRL.CYCCNTENA",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_inverted_pending_error_results(self):
        mutations = (
            (
                " 2508: b108       cbz r0, 250e ",
                " 2508: b108       cbnz r0, 250e ",
            ),
            (
                " 254a: d1de       bne.n 250a ",
                " 254a: d0de       beq.n 250a ",
            ),
            (
                " 2560: d1d3       bne.n 250a ",
                " 2560: d0d3       beq.n 250a ",
            ),
            (
                " 2586: d1c0       bne.n 250a ",
                " 2586: d0c0       beq.n 250a ",
            ),
        )
        for original, replacement in mutations:
            with self.subTest(instruction=original):
                disassembly = replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    original,
                    replacement,
                )
                with self.assertRaises(verifier.VerificationError):
                    self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_final_active_branch_bypassing_success_checks(self):
        original = (
            " 2542: d50a       bpl.n 255a "
            "<baseband::dma::halt_and_disable_precision_rx(bool&)+0x5a>"
        )
        for target, suffix in (("2562", "62"), ("256c", "6c"), ("2570", "70")):
            with self.subTest(target=target):
                disassembly = replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    original,
                    (
                        f" 2542: d50a       bpl.n {target} "
                        "<baseband::dma::halt_and_disable_precision_rx"
                        f"(bool&)+0x{suffix}>"
                    ),
                )
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    "first success pending-error check",
                ):
                    self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_cfg_bypass_around_final_success_error_check(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 257c: f3bf 8f5f  dmb sy",
            (
                " 257c: e004       b.n 2588 "
                "<baseband::dma::halt_and_disable_precision_rx(bool&)+0x88>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "final success pending-error call must dominate",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_narrow_address_and_timeout_literal_loads(self):
        mutations = (
            (
                " 250e: 4b20       ldr r3, [pc, #128]",
                " 250e: 4b20       ldrb r3, [pc, #128]",
            ),
            (
                " 2516: 4b1f       ldr r3, [pc, #124]",
                " 2516: 4b1f       ldrb r3, [pc, #124]",
            ),
            (
                " 251e: 4c1e       ldr r4, [pc, #120]",
                " 251e: 4c1e       ldrb r4, [pc, #120]",
            ),
            (
                " 252c: 491b       ldr r1, [pc, #108]",
                " 252c: 491b       ldrb r1, [pc, #108]",
            ),
            (
                " 2562: 4c0f       ldr r4, [pc, #60]",
                " 2562: 4c0f       ldrb r4, [pc, #60]",
            ),
        )
        for original, replacement in mutations:
            with self.subTest(instruction=original):
                disassembly = replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    original,
                    replacement,
                )
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    r"must link.*exact",
                ):
                    self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_writeback_or_postindexed_bound_loads(self):
        mutations = (
            (
                " 250e: 4b20       ldr r3, [pc, #128]",
                " 250e: 4b20       ldr r3, [pc, #128]!",
            ),
            (
                " 2510: 68db       ldr r3, [r3, #12]",
                " 2510: 68db       ldr r3, [r3], #12",
            ),
            (
                " 2520: 6822       ldr r2, [r4, #0]",
                " 2520: 6822       ldr r2, [r4, #0]!",
            ),
            (
                " 252e: 6858       ldr r0, [r3, #4]",
                " 252e: 6858       ldr r0, [r3, #4]!",
            ),
            (
                " 2530: 6822       ldr r2, [r4, #0]",
                " 2530: 6822       ldr r2, [r4], #0",
            ),
            (
                " 254c: 6823       ldr r3, [r4, #0]",
                " 254c: 6823       ldr r3, [r4, #0]!",
            ),
            (
                " 2564: 6863       ldr r3, [r4, #4]",
                " 2564: 6863       ldr r3, [r4], #4",
            ),
            (
                " 256c: f8d4 3110  ldr.w r3, [r4, #272]",
                " 256c: f8d4 3110  ldr.w r3, [r4, #272]!",
            ),
        )
        for original, replacement in mutations:
            with self.subTest(instruction=original):
                disassembly = replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    original,
                    replacement,
                )
                with self.assertRaises(verifier.VerificationError):
                    self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_writeback_or_postindexed_bound_stores(self):
        mutations = (
            (
                " 2526: 6022       str r2, [r4, #0]",
                " 2526: 6022       str r2, [r4, #0]!",
            ),
            (
                " 2552: 6023       str r3, [r4, #0]",
                " 2552: 6023       str r3, [r4], #0",
            ),
            (
                " 256a: 702b       strb r3, [r5, #0]",
                " 256a: 702b       strb r3, [r5, #0]!",
            ),
            (
                " 2574: f8c4 3110  str.w r3, [r4, #272]",
                " 2574: f8c4 3110  str.w r3, [r4], #272",
            ),
            (
                " 258a: 60a0       str r0, [r4, #8]",
                " 258a: 60a0       str r0, [r4, #8]!",
            ),
            (
                " 258c: 6120       str r0, [r4, #16]",
                " 258c: 6120       str r0, [r4], #16",
            ),
        )
        for original, replacement in mutations:
            with self.subTest(instruction=original):
                disassembly = replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    original,
                    replacement,
                )
                with self.assertRaises(verifier.VerificationError):
                    self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_narrow_demcr_and_dwt_control_loads(self):
        mutations = (
            (
                " 2510: 68db       ldr r3, [r3, #12]",
                " 2510: 68db       ldrb r3, [r3, #12]",
            ),
            (
                " 2518: 681a       ldr r2, [r3, #0]",
                " 2518: 681a       ldrb r2, [r3, #0]",
            ),
        )
        for original, replacement in mutations:
            with self.subTest(instruction=original):
                disassembly = replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    original,
                    replacement,
                )
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    "SCS_DEMCR.TRCENA and DWT_CTRL.CYCCNTENA",
                ):
                    self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_narrow_cyccnt_loads(self):
        mutations = (
            (
                " 252e: 6858       ldr r0, [r3, #4]",
                " 252e: 6858       ldrb r0, [r3, #4]",
            ),
            (
                " 2536: 685a       ldr r2, [r3, #4]",
                " 2536: 685a       ldrb r2, [r3, #4]",
            ),
        )
        for original, replacement in mutations:
            with self.subTest(instruction=original):
                disassembly = replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    original,
                    replacement,
                )
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    r"DWT_CYCCNT \(0xE0001004\)",
                ):
                    self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_narrow_active_loads(self):
        mutations = (
            (
                " 2530: 6822       ldr r2, [r4, #0]",
                " 2530: 6822       ldrb r2, [r4, #0]",
            ),
            (
                " 253e: 6823       ldr r3, [r4, #0]",
                " 253e: 6823       ldrb r3, [r4, #0]",
            ),
        )
        for original, replacement in mutations:
            with self.subTest(instruction=original):
                disassembly = replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    original,
                    replacement,
                )
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    "distinct loop and final PL080 ACTIVE samples",
                ):
                    self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_narrow_config_rmw_loads(self):
        mutations = (
            (
                " 2520: 6822       ldr r2, [r4, #0]",
                " 2520: 6822       ldrb r2, [r4, #0]",
                "HALT-set CONFIG RMW",
            ),
            (
                " 254c: 6823       ldr r3, [r4, #0]",
                " 254c: 6823       ldrb r3, [r4, #0]",
                "timeout H-clear CONFIG RMW",
            ),
            (
                " 256c: f8d4 3110  ldr.w r3, [r4, #272]",
                " 256c: f8d4 3110  ldrb.w r3, [r4, #272]",
                "success E-clear CONFIG RMW",
            ),
        )
        for original, replacement, message in mutations:
            with self.subTest(instruction=original):
                disassembly = replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    original,
                    replacement,
                )
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    message,
                ):
                    self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_narrow_config_rmw_stores(self):
        mutations = (
            (
                " 2526: 6022       str r2, [r4, #0]",
                " 2526: 6022       strb r2, [r4, #0]",
                "HALT-set CONFIG RMW",
            ),
            (
                " 2552: 6023       str r3, [r4, #0]",
                " 2552: 6023       strb r3, [r4, #0]",
                "timeout H-clear CONFIG RMW",
            ),
            (
                " 2574: f8c4 3110  str.w r3, [r4, #272]",
                " 2574: f8c4 3110  strb.w r3, [r4, #272]",
                "success E-clear CONFIG RMW",
            ),
        )
        for original, replacement, message in mutations:
            with self.subTest(instruction=original):
                disassembly = replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    original,
                    replacement,
                )
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    message,
                ):
                    self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_wrong_dwt_cyccnt_address(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2536: 685a       ldr r2, [r3, #4]",
            " 2536: 689a       ldr r2, [r3, #8]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            r"DWT_CYCCNT \(0xE0001004\)",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_loop_cyccnt_destination_aliasing_dwt_base(self):
        disassembly = replace_once(
            replace_once(
                replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    " 2536: 685a       ldr r2, [r3, #4]",
                    " 2536: 685b       ldr r3, [r3, #4]",
                ),
                " 2538: 1a12       subs r2, r2, r0",
                " 2538: 1a1b       subs r3, r3, r0",
            ),
            " 253a: 428a       cmp r2, r1",
            " 253a: 428b       cmp r3, r1",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must not alias the loop-carried DWT base register",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_off_by_one_deadline_literal(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 259c: 001e847f   .word 0x001e847f",
            " 259c: 001e8480   .word 0x001e8480",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "1,999,999-cycle boundary",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_signed_deadline_branch(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 253c: d9f8       bls.n 2530 "
                "<baseband::dma::halt_and_disable_precision_rx(bool&)+0x30>"
            ),
            (
                " 253c: ddf8       ble.n 2530 "
                "<baseband::dma::halt_and_disable_precision_rx(bool&)+0x30>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "wrap-safe unsigned",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_direct_deadline_arithmetic(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2538: 1a12       subs r2, r2, r0",
            " 2538: 1812       adds r2, r2, r0",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "not a signed or direct-deadline comparison",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_missing_final_active_recheck(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2540: 039b       lsls r3, r3, #14",
            " 2540: 035b       lsls r3, r3, #13",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "distinct loop and final PL080 ACTIVE samples",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_timeout_path_entering_e_clear(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 2558: e7d8       b.n 250c "
                "<baseband::dma::halt_and_disable_precision_rx(bool&)+0xc>"
            ),
            (
                " 2558: e00a       b.n 2570 "
                "<baseband::dma::halt_and_disable_precision_rx(bool&)+0x70>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "H-only rollback",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_halt_rmw_without_fresh_config_load(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2520: 6822       ldr r2, [r4, #0]",
            " 2520: 2200       movs r2, #0",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "HALT-set CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_timeout_rmw_without_fresh_config_load(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 254c: 6823       ldr r3, [r4, #0]",
            " 254c: 2300       movs r3, #0",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "timeout H-clear CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_success_rmw_without_fresh_config_load(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 256c: f8d4 3110  ldr.w r3, [r4, #272]",
            " 256c: 2300       movs r3, #0",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "success E-clear CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_halt_config_store_from_unrelated_register(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2526: 6022       str r2, [r4, #0]",
            " 2526: 6021       str r1, [r4, #0]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "HALT-set CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_timeout_config_store_from_unrelated_register(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2552: 6023       str r3, [r4, #0]",
            " 2552: 6022       str r2, [r4, #0]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "timeout H-clear CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_success_config_store_from_unrelated_register(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2574: f8c4 3110  str.w r3, [r4, #272]",
            " 2574: f8c4 2110  str.w r2, [r4, #272]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "success E-clear CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_halt_config_value_aliasing_base_register(self):
        disassembly = replace_once(
            replace_once(
                replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    " 2520: 6822       ldr r2, [r4, #0]",
                    " 2520: 6824       ldr r4, [r4, #0]",
                ),
                " 2522: f442 2280  orr.w r2, r2, #262144",
                " 2522: f444 2480  orr.w r4, r4, #262144",
            ),
            " 2526: 6022       str r2, [r4, #0]",
            " 2526: 6024       str r4, [r4, #0]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "HALT-set CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_timeout_config_value_aliasing_base_register(self):
        disassembly = replace_once(
            replace_once(
                replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    " 254c: 6823       ldr r3, [r4, #0]",
                    " 254c: 6824       ldr r4, [r4, #0]",
                ),
                " 254e: f423 2380  bic.w r3, r3, #262144",
                " 254e: f424 2480  bic.w r4, r4, #262144",
            ),
            " 2552: 6023       str r3, [r4, #0]",
            " 2552: 6024       str r4, [r4, #0]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "timeout H-clear CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_success_config_value_aliasing_base_register(self):
        disassembly = replace_once(
            replace_once(
                replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    " 256c: f8d4 3110  ldr.w r3, [r4, #272]",
                    " 256c: f8d4 4110  ldr.w r4, [r4, #272]",
                ),
                " 2570: f023 0301  bic.w r3, r3, #1",
                " 2570: f024 0401  bic.w r4, r4, #1",
            ),
            " 2574: f8c4 3110  str.w r3, [r4, #272]",
            " 2574: f8c4 4110  str.w r4, [r4, #272]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "success E-clear CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_success_irq_clears_at_wrong_base(self):
        disassembly = replace_once(
            replace_once(
                P12_DISASSEMBLY_FIXTURE,
                " 258a: 60a0       str r0, [r4, #8]",
                " 258a: 6098       str r0, [r3, #8]",
            ),
            " 258c: 6120       str r0, [r4, #16]",
            " 258c: 6118       str r0, [r3, #16]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "success IRQ retirement",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_success_irq_clears_with_wrong_channel_mask(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2588: 2001       movs r0, #1",
            " 2588: 2002       movs r0, #2",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "exact CH0 mask 1",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_success_irq_clears_from_unrelated_register(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 258c: 6120       str r0, [r4, #16]",
            " 258c: 6121       str r1, [r4, #16]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "same value register",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_narrow_success_irq_clear_stores(self):
        mutations = (
            (
                " 258a: 60a0       str r0, [r4, #8]",
                " 258a: 60a0       strb r0, [r4, #8]",
            ),
            (
                " 258c: 6120       str r0, [r4, #16]",
                " 258c: 6120       strb r0, [r4, #16]",
            ),
        )
        for original, replacement in mutations:
            with self.subTest(instruction=original):
                disassembly = replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    original,
                    replacement,
                )
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    "terminal-count and error IRQ clears",
                ):
                    self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_movt_shared_false_return(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 250a: 2000       movs r0, #0",
            " 250a: f2c0 0000  movt r0, #0",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "shared false return",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_movt_success_irq_channel_mask(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2588: 2001       movs r0, #1",
            " 2588: f2c0 0001  movt r0, #1",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "exact CH0 mask 1",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_halt_config_store_at_wrong_address(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2526: 6022       str r2, [r4, #0]",
            " 2526: 6062       str r2, [r4, #4]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "HALT-set CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_timeout_config_store_at_wrong_address(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2552: 6023       str r3, [r4, #0]",
            " 2552: 6063       str r3, [r4, #4]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "timeout H-clear CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_success_config_store_at_wrong_address(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2574: f8c4 3110  str.w r3, [r4, #272]",
            " 2574: f8c4 310c  str.w r3, [r4, #268]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "success E-clear CONFIG RMW",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_config_base_clobbered_by_timeout_literal(self):
        disassembly = replace_once(
            replace_once(
                P12_DISASSEMBLY_FIXTURE,
                (
                    " 252c: 491b       ldr r1, [pc, #108] ; "
                    "(259c <baseband::dma::halt_and_disable_precision_rx"
                    "(bool&)+0x9c>)"
                ),
                (
                    " 252c: 4c1b       ldr r4, [pc, #108] ; "
                    "(259c <baseband::dma::halt_and_disable_precision_rx"
                    "(bool&)+0x9c>)"
                ),
            ),
            " 253a: 428a       cmp r2, r1",
            " 253a: 42a2       cmp r2, r4",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "direct CH0 CONFIG base through ACTIVE drain",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_halt_rmw_clobbering_dwt_base(self):
        disassembly = replace_once(
            replace_once(
                replace_once(
                    P12_DISASSEMBLY_FIXTURE,
                    " 2520: 6822       ldr r2, [r4, #0]",
                    " 2520: 6823       ldr r3, [r4, #0]",
                ),
                " 2522: f442 2280  orr.w r2, r2, #262144",
                " 2522: f443 2380  orr.w r3, r3, #262144",
            ),
            " 2526: 6022       str r2, [r4, #0]",
            " 2526: 6023       str r3, [r4, #0]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "DWT register base",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p14_rejects_wrong_slowest_descriptor_cycle_proof(self):
        nm = replace_once(
            P12_NM_FIXTURE,
            (
                "00064000 00000004 A "
                "hackrf_edge_precision_rx_dma_control_slowest_descriptor_ticks_at_200m"
            ),
            (
                "00064001 00000004 A "
                "hackrf_edge_precision_rx_dma_control_slowest_descriptor_ticks_at_200m"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "linked p12 metadata",
        ):
            self.verify_p12(nm=nm)

    def test_p12_rejects_log10_kernel_without_non_positive_guard(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2100: eeb5 0ac0  vcmpe.f32 s0, #0.0",
            " 2100: eeb4 0a60  vcmp.f32 s0, s1",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "vcmpe.f32 s0, #0.0 non-positive guard",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_non_positive_path_reaching_log10_kernel(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 2108: d906       bls.n 2118 "
                "<precision_rx::(anonymous namespace)::"
                "energy_to_dbfs_x10(float)+0x18>"
            ),
            (
                " 2108: d902       bls.n 2110 "
                "<precision_rx::(anonymous namespace)::"
                "energy_to_dbfs_x10(float)+0x10>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "non-positive branch must bypass the direct log10 kernel call",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_log10_kernel_cfg_bypass_around_guard(self):
        original = """00002100 <precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)>:
 2100: eeb5 0ac0  vcmpe.f32 s0, #0.0
 2104: eef1 fa10  vmrs APSR_nzcv, fpscr
 2108: d906       bls.n 2118 <precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)+0x18>
 210a: b508       push {r3, lr}
 210c: ee20 0a20  vmul.f32 s0, s0, s1
 2110: f000 f800  bl  3000 <__ieee754_log10f>
 2114: bd08       pop {r3, pc}
 2118: 4801       ldr r0, [pc, #4] ; (2120 <precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)+0x20>)
 211a: 4770       bx lr
 2120: fffffb50   .word 0xfffffb50"""
        bypass = """00002100 <precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)>:
 2100: e004       b.n 210c <precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)+0xc>
 2102: eeb5 0ac0  vcmpe.f32 s0, #0.0
 2106: eef1 fa10  vmrs APSR_nzcv, fpscr
 210a: d907       bls.n 211c <precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)+0x1c>
 210c: b508       push {r3, lr}
 210e: ee20 0a20  vmul.f32 s0, s0, s1
 2112: f000 f800  bl  3000 <__ieee754_log10f>
 2116: bd08       pop {r3, pc}
 211c: 4800       ldr r0, [pc, #0] ; (2120 <precision_rx::(anonymous namespace)::energy_to_dbfs_x10(float)+0x20>)
 211e: 4770       bx lr
 2120: fffffb50   .word 0xfffffb50"""
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            original,
            bypass,
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "non-positive energy guard must dominate",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_log10_wrapper_call(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2110: f000 f800  bl  3000 <__ieee754_log10f>",
            " 2110: f000 f800  bl  3000 <log10f>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must not call a log10 wrapper",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_linked_log10_wrapper_definition(self):
        nm = P12_NM_FIXTURE + "\n00003040 00000020 T log10f\n"
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "linked log10 wrapper path must be absent",
        ):
            self.verify_p12(nm=nm)

    def test_p12_rejects_wrong_non_positive_dbfs_floor(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 2120: fffffb50   .word 0xfffffb50",
            " 2120: fffffb51   .word 0xfffffb51",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "return the linked -1200 dBFS-x10 floor",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_completion_claim_rejects_pending_retirement(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1c04: f3bf 8f5f  dmb sy",
            (
                " 1c04: f3bf 8f5f  dmb sy\n"
                " 1c08: f8c3 1180  str.w r1, [r3, #384]"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "preserve the DMA NVIC pending indication",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_completion_claim_rejects_own_tc_as_unconditional_fault(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1c4c: f006 0601  and.w r6, r6, #1",
            " 1c4c: ea46 0605  orr.w r6, r6, r5",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "isolate own-channel ERR",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_completion_claim_rejects_tc_fault_without_failed_claim_guard(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1c54: 2802       cmp r0, #2",
            " 1c54: 2801       cmp r0, #1",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "test whether an earlier queue/reuse check already failed",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_completion_claim_rejects_w1c_before_exception_latch(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 1c60: f000 f800  bl  1640 "
                "<baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>\n"
                " 1c64: 60a5       str r5, [r4, #8]"
            ),
            (
                " 1c60: 60a5       str r5, [r4, #8]\n"
                " 1c64: f000 f800  bl  1640 "
                "<baseband::dma::latch_precision_rx_dma_fault_fast(unsigned long, bool)>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "clear exceptional terminal-count status after latching",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_gate_open_helper_accepts_linked_mini_fixture(self):
        report = self.verify_p12_gate_open_helper()
        self.assertTrue(report["begin_failure_returns_closed"])
        self.assertTrue(report["disabled_channel_cannot_open_gate"])
        self.assertTrue(report["enabled_channel_opens_gate_under_exclusion"])
        self.assertTrue(report["result_preserved_across_exclusion_end"])

    def test_p12_gate_open_helper_rejects_begin_branch_inversion(self):
        disassembly = replace_once(
            P12_GATE_OPEN_DISASSEMBLY_FIXTURE,
            (
                " 2636: b188       cbz r0, 265c "
                "<baseband::dma::open_precision_rx_sgpio_gate_locked()+0x2c>"
            ),
            (
                " 2636: b988       cbnz r0, 265c "
                "<baseband::dma::open_precision_rx_sgpio_gate_locked()+0x2c>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "immediately reject a failed DMA exclusion begin",
        ):
            self.verify_p12_gate_open_helper(disassembly)

    def test_p12_gate_open_helper_rejects_enabled_branch_inversion(self):
        disassembly = replace_once(
            P12_GATE_OPEN_DISASSEMBLY_FIXTURE,
            (
                " 2642: d10e       bne.n 2662 "
                "<baseband::dma::open_precision_rx_sgpio_gate_locked()+0x32>"
            ),
            (
                " 2642: d00e       beq.n 2662 "
                "<baseband::dma::open_precision_rx_sgpio_gate_locked()+0x32>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "enter its open path only when CONFIG.E is set",
        ):
            self.verify_p12_gate_open_helper(disassembly)

    def test_p12_gate_open_helper_rejects_wrong_gate_bit(self):
        disassembly = replace_once(
            P12_GATE_OPEN_DISASSEMBLY_FIXTURE,
            " 266a: f423 6380  bic.w r3, r3, #1024",
            " 266a: f423 6380  bic.w r3, r3, #512",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "reviewed bit-10 read/clear/write",
        ):
            self.verify_p12_gate_open_helper(disassembly)

    def test_p12_gate_open_helper_rejects_healthy_path_skipping_end(self):
        disassembly = replace_once(
            P12_GATE_OPEN_DISASSEMBLY_FIXTURE,
            (
                " 2672: e7f0       b.n 2656 "
                "<baseband::dma::open_precision_rx_sgpio_gate_locked()+0x26>"
            ),
            (
                " 2672: e7f2       b.n 265a "
                "<baseband::dma::open_precision_rx_sgpio_gate_locked()+0x2a>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "CONFIG.E-set path must open SGPIO then end",
        ):
            self.verify_p12_gate_open_helper(disassembly)

    def test_p12_gate_open_helper_rejects_missing_deferred_pend(self):
        disassembly = replace_once(
            P12_GATE_OPEN_DISASSEMBLY_FIXTURE,
            " 2652: f8c3 2100  str.w r2, [r3, #256]",
            " 2652: f8c3 2104  str.w r2, [r3, #260]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "pend deferred completion",
        ):
            self.verify_p12_gate_open_helper(disassembly)

    def test_p12_gate_open_helper_rejects_pend_after_exclusion_end(self):
        disassembly = replace_once(
            P12_GATE_OPEN_DISASSEMBLY_FIXTURE,
            (
                " 2652: f8c3 2100  str.w r2, [r3, #256]\n"
                " 2656: f7ff febb  bl  23d0 "
                "<baseband::dma::end_precision_rx_rate_state_update()>"
            ),
            (
                " 2652: f7ff febb  bl  23d0 "
                "<baseband::dma::end_precision_rx_rate_state_update()>\n"
                " 2656: f8c3 2100  str.w r2, [r3, #256]"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "before ending IRQ exclusion",
        ):
            self.verify_p12_gate_open_helper(disassembly)

    def test_p12_rate_state_irq_exclusion_accepts_linked_mini_fixture(self):
        report = self.verify_p12_rate_state_irq_exclusion()
        self.assertTrue(report["priority1_mask_preserves_nvic_pending"])
        self.assertTrue(report["final_tc_err_enabled_fatal_sample"])
        self.assertTrue(report["sole_own_channel_tc_preserved"])
        self.assertTrue(report["healthy_sample_retains_exclusion"])
        self.assertTrue(report["end_dmb_precedes_reenable"])

    def test_p12_rate_state_irq_exclusion_rejects_missing_mask_dmb(self):
        disassembly = replace_once(
            P12_RATE_STATE_IRQ_DISASSEMBLY_FIXTURE,
            " 25d2: f3bf 8f5f  dmb sy",
            " 25d2: bf00       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "sample terminal-count status without retiring it",
        ):
            self.verify_p12_rate_state_irq_exclusion(disassembly)

    def test_p12_rate_state_irq_exclusion_rejects_pending_retirement(self):
        disassembly = replace_once(
            P12_RATE_STATE_IRQ_DISASSEMBLY_FIXTURE,
            " 25d2: f3bf 8f5f  dmb sy",
            (
                " 25d2: f3bf 8f5f  dmb sy\n"
                " 25d4: f8c3 2180  str.w r2, [r3, #384]"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "preserve the DMA NVIC pending indication",
        ):
            self.verify_p12_rate_state_irq_exclusion(disassembly)

    def test_p12_rate_state_irq_exclusion_rejects_own_tc_in_health_predicate(self):
        disassembly = replace_once(
            P12_RATE_STATE_IRQ_DISASSEMBLY_FIXTURE,
            " 25ec: f007 0701  and.w r7, r7, #1",
            " 25ec: ea47 0705  orr.w r7, r7, r5",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "remove sole own-channel TC",
        ):
            self.verify_p12_rate_state_irq_exclusion(disassembly)

    def test_p12_rate_state_irq_exclusion_rejects_missing_deferred_pend(self):
        disassembly = replace_once(
            P12_RATE_STATE_IRQ_DISASSEMBLY_FIXTURE,
            " 2610: f8c3 2100  str.w r2, [r3, #256]",
            " 2610: f8c3 2104  str.w r2, [r3, #260]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "software-pend deferred fault completion",
        ):
            self.verify_p12_rate_state_irq_exclusion(disassembly)

    def test_p12_rate_state_irq_exclusion_rejects_missing_reenable(self):
        disassembly = replace_once(
            P12_RATE_STATE_IRQ_DISASSEMBLY_FIXTURE,
            " 261a: 601a       str r2, [r3, #0]",
            " 261a: 605a       str r2, [r3, #4]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "re-enable the priority-1 DMA vector on failure",
        ):
            self.verify_p12_rate_state_irq_exclusion(disassembly)

    def test_p12_rate_state_irq_exclusion_rejects_reenable_before_dmb(self):
        disassembly = replace_once(
            P12_RATE_STATE_IRQ_DISASSEMBLY_FIXTURE,
            (
                " 2614: f3bf 8f5f  dmb sy\n"
                " 2618: 2204       movs r2, #4\n"
                " 261a: 601a       str r2, [r3, #0]"
            ),
            (
                " 2614: 2204       movs r2, #4\n"
                " 2618: 601a       str r2, [r3, #0]\n"
                " 261a: f3bf 8f5f  dmb sy"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "re-enable the priority-1 DMA vector on failure",
        ):
            self.verify_p12_rate_state_irq_exclusion(disassembly)

    def test_p12_rate_state_irq_exclusion_rejects_wrong_fatal_link(self):
        disassembly = replace_once(
            P12_RATE_STATE_IRQ_DISASSEMBLY_FIXTURE,
            " 262c: 100016d8   .word 0x100016d8",
            " 262c: 100016dc   .word 0x100016dc",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "not linked to dma_fatal_latched",
        ):
            self.verify_p12_rate_state_irq_exclusion(disassembly)

    def test_return_parser_accepts_postindexed_stack_pc_load(self):
        functions = verifier.parse_disassembly(
            """
00000100 <returner()>:
 100: f85d fb04  ldr.w pc, [sp], #4
"""
        )
        self.assertTrue(
            verifier._is_return_instruction(functions[0].instructions[0])
        )

    def test_p12_profile_rejects_each_wrong_transaction_metadata_value(self):
        for symbol, expected in verifier.P14_TEST_ABSOLUTE_METADATA.items():
            with self.subTest(symbol=symbol):
                old_line = next(
                    line
                    for line in P12_NM_FIXTURE.splitlines()
                    if line.endswith(f" {symbol}")
                )
                fields = old_line.split()
                fields[0] = f"{expected + 1:08x}"
                nm = replace_once(P12_NM_FIXTURE, old_line, " ".join(fields))
                with self.assertRaisesRegex(
                    verifier.VerificationError,
                    "linked p12 metadata",
                ):
                    self.verify_p12(nm=nm)

    def test_p12_rejects_wrong_shutdown_vector_mask(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1e54: 80000004   .word 0x80000004",
            " 1e54: 80000000   .word 0x80000000",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            r"exact NVIC, DMA\+deferred IRQ mask",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_reduced_shutdown_active_spin_bound(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1e1a: f44f 3080  mov.w r0, #65536",
            " 1e1a: f44f 3080  mov.w r0, #32768",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "initialize the bounded ACTIVE spin count",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_shutdown_loop_that_skips_active_resample(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 1e26: d1fa       bne.n 1e1e "
                "<baseband::dma::quiesce_precision_rx_for_shutdown()+0x1e>"
            ),
            (
                " 1e26: d1fa       bne.n 1e20 "
                "<baseband::dma::quiesce_precision_rx_for_shutdown()+0x20>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "return only to its linked CONFIG sample",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_shutdown_timeout_branch_inversion(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " a26: d103       bne.n a30 <BasebandThread::run()+0x30>",
            " a26: d003       beq.n a30 <BasebandThread::run()+0x30>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "fail-stop immediately on timeout",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_partial_p12_metadata_cannot_fall_back_to_p11(self):
        nm = replace_once(
            P12_NM_FIXTURE,
            (
                "00000002 00000001 A "
                "hackrf_edge_precision_rx_rate_transaction_protocol_version\n"
            ),
            "",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "rate_transaction_protocol_version; found 0",
        ):
            self.verify_p12(nm=nm)

    def test_p12_rejects_legacy_scheduler_values(self):
        nm = replace_once(
            P12_NM_FIXTURE,
            (
                "00000003 00000001 A "
                "hackrf_edge_precision_rx_dma_scheduler_backlog_depth"
            ),
            (
                "00000000 00000001 A "
                "hackrf_edge_precision_rx_dma_scheduler_backlog_depth"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "p12 scheduler contract",
        ):
            self.verify_p12(nm=nm)

    def test_p12_rejects_prepare_without_pause_armed_confirmation(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 13c0: f000 f800  bl  1500 "
                "<BasebandThread::precision_rx_rate_pause_armed() const>"
            ),
            " 13c0: bf00       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "on_message must reach a normal DMA-waiter armed check",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_sgpio_gate_after_dma_pause(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 15a0: f443 6380  orr.w r3, r3, #1024",
            " 15a0: f443 6380  orr.w r3, r3, #512",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "set the SGPIO gate bit",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_sgpio_enable_without_dma_resume(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 14c0: f000 f800  bl  1540 "
                "<baseband::dma::resume_precision_rx_rate_change()>"
            ),
            " 14c0: bf00       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "resume_precision_rx_rate_change.*exactly once",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_dma_resume_before_target_publication(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1402: f8c0 127c  str.w r1, [r0, #636]\n",
            "",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "publish the requested target rate",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_parser_preserves_nested_template_call_target(self):
        functions = verifier.parse_disassembly(
            """
00000100 <caller()>:
 100: f000 f800  bl  200 <FIFO<StreamBuffer*>::in(StreamBuffer* const&)>
 104: 4770       bx lr
"""
        )
        self.assertEqual(
            verifier._calls(functions[0])[0].target,
            "FIFO<StreamBuffer*>::in(StreamBuffer* const&)",
        )

    def test_p12_accepts_reviewed_fifo_rebind_helper(self):
        nm = (
            P12_NM_FIXTURE
            + "\n00001710 0000000a T "
            + "FIFO<StreamBuffer*>::in(StreamBuffer* const&)\n"
        )
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            """00000300 <StreamInput::rebind(CaptureConfig*)>:
 300: 2300       movs r3, #0
 302: 6003       str r3, [r0, #0]
 304: 4770       bx lr""",
            """00000300 <StreamInput::rebind(CaptureConfig*)>:
 300: f000 f800  bl  1710 <FIFO<StreamBuffer*>::in(StreamBuffer* const&)>
 304: 4770       bx lr

00001710 <FIFO<StreamBuffer*>::in(StreamBuffer* const&)>:
 1710: 6001       str r1, [r0, #0]
 1712: f3bf 8f5f  dmb sy
 1716: 6042       str r2, [r0, #4]
 1718: 4770       bx lr""",
        )
        report = self.verify_p12(nm=nm, disassembly=disassembly)
        helper = report["open_path"]["rebind_fifo_helper"]
        self.assertTrue(helper["call_free"])
        self.assertTrue(helper["bounded"])
        self.assertTrue(helper["publication_order_linked"])

    def test_p12_rejects_fifo_rebind_helper_without_publication_barrier(self):
        nm = (
            P12_NM_FIXTURE
            + "\n00001710 0000000a T "
            + "FIFO<StreamBuffer*>::in(StreamBuffer* const&)\n"
        )
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            """00000300 <StreamInput::rebind(CaptureConfig*)>:
 300: 2300       movs r3, #0
 302: 6003       str r3, [r0, #0]
 304: 4770       bx lr""",
            """00000300 <StreamInput::rebind(CaptureConfig*)>:
 300: f000 f800  bl  1710 <FIFO<StreamBuffer*>::in(StreamBuffer* const&)>
 304: 4770       bx lr

00001710 <FIFO<StreamBuffer*>::in(StreamBuffer* const&)>:
 1710: 6001       str r1, [r0, #0]
 1712: bf00       nop
 1716: 6042       str r2, [r0, #4]
 1718: 4770       bx lr""",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "exactly one publication DMB",
        ):
            self.verify_p12(nm=nm, disassembly=disassembly)

    def test_p12_rejects_unbounded_fifo_rebind_helper(self):
        nm = (
            P12_NM_FIXTURE
            + "\n00001710 0000000c T "
            + "FIFO<StreamBuffer*>::in(StreamBuffer* const&)\n"
        )
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            """00000300 <StreamInput::rebind(CaptureConfig*)>:
 300: 2300       movs r3, #0
 302: 6003       str r3, [r0, #0]
 304: 4770       bx lr""",
            """00000300 <StreamInput::rebind(CaptureConfig*)>:
 300: f000 f800  bl  1710 <FIFO<StreamBuffer*>::in(StreamBuffer* const&)>
 304: 4770       bx lr

00001710 <FIFO<StreamBuffer*>::in(StreamBuffer* const&)>:
 1710: 6001       str r1, [r0, #0]
 1712: f3bf 8f5f  dmb sy
 1716: e7fb       b.n 1710 <FIFO<StreamBuffer*>::in(StreamBuffer* const&)>
 1718: 6042       str r2, [r0, #4]
 171a: 4770       bx lr""",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "unbounded backward branch",
        ):
            self.verify_p12(nm=nm, disassembly=disassembly)

    def test_p12_accepts_lto_merged_allocator_alias(self):
        nm = replace_once(
            P12_NM_FIXTURE,
            "00000d20 00000020 T operator new[](unsigned int)",
            "00000d00 00000020 T operator new[](unsigned int)",
        )
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 206: f000 f800  bl  d20 <operator new[](unsigned int)>",
            " 206: f000 f800  bl  d00 <operator new(unsigned int)>",
        )
        disassembly = replace_once(
            disassembly,
            """00000d20 <operator new[](unsigned int)>:
 d20: f000 f800  bl  d80 <chHeapAlloc>
 d24: 4770       bx lr

""",
            "",
        )
        report = self.verify_p12(nm=nm, disassembly=disassembly)
        self.assertTrue(
            report["open_path"]["geometry_constructor_allocator_alias_merged"]
        )

    def test_p12_rejects_unproven_allocator_alias_address(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 206: f000 f800  bl  d20 <operator new[](unsigned int)>",
            " 206: f000 f800  bl  d00 <operator new(unsigned int)>",
        )
        disassembly = replace_once(
            disassembly,
            """00000d20 <operator new[](unsigned int)>:
 d20: f000 f800  bl  d80 <chHeapAlloc>
 d24: 4770       bx lr

""",
            "",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "operator new\\[\\].*found 0",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_accepts_bounded_explicit_geometry_initialization(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 20e: f000 f800  bl  d40 <memset>",
            (
                " 20e: f500 3388  add.w r3, r0, #73728\n"
                " 212: 2200       movs r2, #0\n"
                " 214: f800 2b01  strb.w r2, [r0], #1\n"
                " 218: 4298       cmp r0, r3\n"
                " 21a: d1fb       bne.n 214 "
                "<StreamInput::StreamInput(unsigned int, unsigned int)+0x14>"
            ),
        )
        report = self.verify_p12(disassembly=disassembly)
        self.assertEqual(
            report["open_path"]["geometry_constructor_value_initialization"],
            "bounded-explicit-byte-loop",
        )

    def test_p12_rejects_unbounded_explicit_geometry_initialization(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 20e: f000 f800  bl  d40 <memset>",
            (
                " 20e: f500 3388  add.w r3, r0, #73728\n"
                " 212: 2200       movs r2, #0\n"
                " 214: f800 2b01  strb.w r2, [r0], #1\n"
                " 218: 4298       cmp r0, r3\n"
                " 21a: d1fa       bne.n 212 "
                "<StreamInput::StreamInput(unsigned int, unsigned int)+0x12>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "bounded explicit value-initialization loop",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_wrong_committed_ack_literal(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 13b4: c0000003   .word 0xc0000003",
            " 13b4: c0000002   .word 0xc0000002",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "COMMITTED ACK literal",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_overwritten_committed_ack(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 142e: 588a       ldr r2, [r1, r2]",
            (
                " 142d: 4617       mov r7, r2\n"
                " 142e: 588a       ldr r2, [r1, r2]"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "preserved COMMITTED ACK register is overwritten",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_secondary_destination_overwriting_committed_ack(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1430: 429a       cmp r2, r3",
            (
                " 142f: e9d5 6700  ldrd r6, r7, [r5]\n"
                " 1430: 429a       cmp r2, r3"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "preserved COMMITTED ACK register is overwritten",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_lifetime_counter_self_compare(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 142e: 588a       ldr r2, [r1, r2]",
            " 142e: 461a       mov r2, r3",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "bind its current lifetime-loss operand",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_clobbered_dma_fault_result(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 141e: 2800       cmp r0, #0",
            (
                " 141d: 2000       movs r0, #0\n"
                " 141e: 2800       cmp r0, #0"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "fatal-DMA query result register r0 is overwritten",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_dma_fault_path_reaching_committed(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 1420: d112       bne.n 1448 "
                "<PrecisionRxProcessor::resume_rate_change(unsigned long, "
                "unsigned long)+0x48>"
            ),
            (
                " 1420: d108       bne.n 1434 "
                "<PrecisionRxProcessor::resume_rate_change(unsigned long, "
                "unsigned long)+0x34>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must bypass COMMITTED",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_missing_first_new_rate_marker(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 734: 2301       movs r3, #1",
            " 734: 2302       movs r3, #2",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "mark this as the first new-rate block",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_predicated_first_new_rate_marker(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 734: 2301       movs r3, #1\n"
                " 736: e00b       b.n 750 "
                "<PrecisionRxProcessor::execute"
                "(buffer_t<std::complex<signed char> > const&)+0x50>"
            ),
            (
                " 734: bf08       it eq\n"
                " 736: 2301       moveq r3, #1\n"
                " 738: e00a       b.n 750 "
                "<PrecisionRxProcessor::execute"
                "(buffer_t<std::complex<signed char> > const&)+0x50>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "unsupported Thumb IT predication",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_cfg_bypass_around_first_block_processing(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 752: f000 f800  bl  500 "
                "<PrecisionRxProcessor::service_capture_command()>"
            ),
            (
                " 752: e002       b.n 75a "
                "<PrecisionRxProcessor::execute"
                "(buffer_t<std::complex<signed char> > const&)+0x5a>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "complete first-new-rate block processing must dominate",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_inverted_complete_block_result_guard(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 75a: b178       cbz r0, 77c "
                "<PrecisionRxProcessor::execute"
                "(buffer_t<std::complex<signed char> > const&)+0x7c>"
            ),
            (
                " 75a: b978       cbnz r0, 77c "
                "<PrecisionRxProcessor::execute"
                "(buffer_t<std::complex<signed char> > const&)+0x7c>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must immediately branch on the returned r0 value",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_cfg_entry_bypass_into_run_publication(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 704: b183       cbz r3, 750 "
                "<PrecisionRxProcessor::execute"
                "(buffer_t<std::complex<signed char> > const&)+0x50>"
            ),
            (
                " 704: b183       cbz r3, 768 "
                "<PrecisionRxProcessor::execute"
                "(buffer_t<std::complex<signed char> > const&)+0x68>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "first-new-rate marker publication must dominate",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_running_publication_without_fatal_rejection(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 1692: b94c       cbnz r4, 16a8 "
                "<PrecisionRxProcessor::publish_running_if_dma_healthy"
                "(PrecisionRxProcessor::RateState)+0x28>"
            ),
            (
                " 1692: b14c       cbz r4, 16a8 "
                "<PrecisionRxProcessor::publish_running_if_dma_healthy"
                "(PrecisionRxProcessor::RateState)+0x28>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "reject a latched DMA fault",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_clobbered_fatal_latch_sample(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1692: b94c       cbnz r4, 16a8 ",
            (
                " 1690: 2400       movs r4, #0\n"
                " 1692: b94c       cbnz r4, 16a8 "
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "linked fatal DMA latch sample register r4 is overwritten",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_running_publication_with_unbound_fatal_base(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 168a: 4b0a       ldr r3, [pc, #40] ; "
                "(16b4 <PrecisionRxProcessor::publish_running_if_dma_healthy"
                "(PrecisionRxProcessor::RateState)+0x34>)"
            ),
            " 168a: 463b       mov r3, r7",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "not linked to dma_fatal_latched",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_processor_execute_before_dma_wait(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " a16: f000 f800  bl  1080 "
                "<baseband::dma::wait_for_buffer()>\n"
                " a1a: 4798       blx r3"
            ),
            (
                " a16: 4798       blx r3\n"
                " a1a: f000 f800  bl  1080 "
                "<baseband::dma::wait_for_buffer()>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "obtain a completed DMA buffer before invoking processor execute",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_missing_pending_error_sample(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 15ea: 68d6       ldr r6, [r2, #12]",
            " 15ea: 6896       ldr r6, [r2, #8]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "sample final DMA error status",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_clean_pending_error_path_that_clears_irq(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 15d6: d023       beq.n 1620 "
                "<baseband::dma::fail_if_precision_rx_dma_error_pending_locked"
                "()+0x50>"
            ),
            (
                " 15d6: d00c       beq.n 15f2 "
                "<baseband::dma::fail_if_precision_rx_dma_error_pending_locked"
                "()+0x22>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "return without clearing IRQ state",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_running_store_without_release_barrier(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 16aa: f3bf 8f5f  dmb sy",
            " 16aa: bf00       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "release-publish RUNNING",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_geometry_timeout_entering_configure(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " 1286: b108       cbz r0, 128e "
                "<PrecisionRxProcessor::transition_dma_geometry(bool)+0xe>"
            ),
            (
                " 1286: b100       cbz r0, 1288 "
                "<PrecisionRxProcessor::transition_dma_geometry(bool)+0x8>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "preserve the existing accounting epoch",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_accepts_reviewed_processor_ceiling_with_minimum_headroom(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 100: f44f 7086  mov.w r0, #1072 ; 0x430",
            " 100: f44f 7090  mov.w r0, #1152 ; 0x480",
        )
        report = self.verify(disassembly)
        self.assertEqual(report["resources"]["processor_object_bytes"], 1152)
        self.assertEqual(report["resources"]["modeled_ram_headroom_bytes"], 4340)
        self.assertGreaterEqual(
            report["resources"]["modeled_ram_headroom_bytes"],
            verifier.MINIMUM_MODELED_HEADROOM_BYTES,
        )

    def test_rejects_processor_larger_than_reviewed_ceiling(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 100: f44f 7086  mov.w r0, #1072 ; 0x430",
            " 100: f44f 7090  mov.w r0, #1153 ; 0x481",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "maximum is 1152"):
            self.verify(disassembly)

    def test_rejects_any_call_from_rebind(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 304: 4770       bx lr",
            " 304: f000 f800  bl  d40 <memset>\n 308: 4770       bx lr",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "call-free"):
            self.verify(disassembly)

    def test_rejects_allocator_on_service_path(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 59e: 4770       bx lr",
            " 59e: f000 f800  bl  d00 <operator new(unsigned int)>\n 5a2: 4770       bx lr",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "allocator"):
            self.verify(disassembly)

    def test_rejects_missing_open_acknowledgement(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 542: f000 f800  bl  450 <StreamInput::acknowledge_open()>\n",
            "",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "acknowledge_open.*once"):
            self.verify(disassembly)

    def test_rejects_missing_construction_time_dma_loan(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 112: f000 f800  bl  1100 <StreamInput::dma_loan_buffer()>\n",
            "",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "dma_loan_buffer.*once"):
            self.verify(disassembly)

    def test_rejects_initial_lease_not_wired_to_descriptor_builder(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " e86: f000 f800  bl  e00 <baseband::dma::configure_lease_descriptors(bool)>\n",
            "",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "descriptor.*once"):
            self.verify(disassembly)

    def test_rejects_geometry_switch_not_wired_to_descriptor_builder(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " f28: f000 f800  bl  e00 <baseband::dma::configure_lease_descriptors(bool)>\n",
            " f28: bf00       nop\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "descriptor.*once"):
            self.verify(disassembly)

    def test_rejects_descriptor_builder_without_loan_base_switch(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " e18: f8dc 1000  ldreq.w r1, [ip]\n",
            " e18: bf00       nop\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "loan-base switch"):
            self.verify(disassembly)

    def test_rejects_descriptor_control_without_terminal_count_bit(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " e34: 8a480000   .word 0x8a480000",
            " e34: 0a480000   .word 0x0a480000",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "terminal-count interrupt"):
            self.verify(disassembly)

    def test_rejects_descriptor_control_register_substitution(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " e24: e9c3 5402  strd r5, r4, [r3, #8]",
            " e24: e9c3 5002  strd r5, r0, [r3, #8]",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "must flow"):
            self.verify(disassembly)

    def test_rejects_geometry_switch_without_halt_before_active_poll(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " f00: f442 2280  orr.w r2, r2, #262144\n",
            " f00: f442 2280  orr.w r2, r2, #131072\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "set PL080 HALT"):
            self.verify(disassembly)

    def test_rejects_timeout_path_that_reaches_descriptor_rewrite(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " f14: e01c       b.n f50 <baseband::dma::set_precision_rx_capture_geometry(bool)+0x50>\n",
            " f14: e01c       b.n f20 <baseband::dma::set_precision_rx_capture_geometry(bool)+0x20>\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "timeout must bypass"):
            self.verify(disassembly)

    def test_rejects_fixed_enable_missing_control_register_write(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 1012: 60d0       str r0, [r2, #12]\n",
            "",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "write CONTROL"):
            self.verify(disassembly)

    def test_rejects_fixed_enable_channel_base_substitution(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 1012: 60d0       str r0, [r2, #12]",
            " 1012: 60f8       str r0, [r7, #12]",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "share one channel base"):
            self.verify(disassembly)

    def test_rejects_fixed_enable_lli_source_substitution(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 1010: 6094       str r4, [r2, #8]",
            " 1010: 6090       str r0, [r2, #8]",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "source-register substitution"):
            self.verify(disassembly)

    def test_rejects_baseband_run_without_initial_full_enable(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " a12: f000 f800  bl  1000 <baseband::dma::enable_precision_rx()>\n",
            "",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "enable_precision_rx.*once"):
            self.verify(disassembly)

    def test_rejects_wrapper_that_does_not_full_enable_rebuilt_ring(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 1206: f000 f800  bl  1000 <baseband::dma::enable_precision_rx()>\n",
            "",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "enable_precision_rx.*once"):
            self.verify(disassembly)

    def test_rejects_transition_that_can_skip_new_accounting_epoch(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 1284: 4605       mov r5, r0\n",
            " 1284: b110       cbz r0, 128a <PrecisionRxProcessor::transition_dma_geometry(bool)+0xa>\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "every geometry attempt"):
            self.verify(disassembly)

    def test_rejects_service_rate_guard_with_wrong_linked_limit(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 5a0: 001e8480   .word 0x001e8480",
            " 5a0: 003d0900   .word 0x003d0900",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "unsigned 2000000 Hz guard"):
            self.verify(disassembly)

    def test_rejects_execute_rate_guard_without_bound_config_test(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 70c: f8d0 23dc  ldr.w r2, [r0, #988]",
            " 70c: f8d0 23e0  ldr.w r2, [r0, #992]",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "config pointer"):
            self.verify(disassembly)

    def test_rejects_wait_path_reading_source_instead_of_rx_destination(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 1084: 6841       ldr r1, [r0, #4]\n",
            " 1084: 6801       ldr r1, [r0, #0]\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "DESTADDR"):
            self.verify(disassembly)

    def test_rejects_graceful_reclaim_without_acquire_barrier(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 1186: f3bf 8f5f  dmb sy\n",
            "",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "graceful DMA loan reclaim"):
            self.verify(disassembly)

    def test_rejects_abort_reclaim_observing_wrong_release_byte(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 11c6: f893 303a  ldrb.w r3, [r3, #58]\n",
            " 11c6: f893 303b  ldrb.w r3, [r3, #59]\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "consumer-release byte"):
            self.verify(disassembly)

    def test_rejects_command_ack_before_release_barrier(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 12c4: f3bf 8f5b  dmb ish\n 12c8: f8c0 33ec  str.w r3, [r0, #1004]",
            " 12c4: f8c0 33ec  str.w r3, [r0, #1004]\n 12c8: f3bf 8f5b  dmb ish",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "acknowledge command"):
            self.verify(disassembly)

    def test_rejects_missing_abort_unbind_service_path(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 578: f000 f800  bl  11c0 <StreamInput::force_unbind_after_abort()>\n",
            "",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "force_unbind.*once"):
            self.verify(disassembly)

    def test_rejects_close_ack_on_monitor_transition_failure(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 56a: b178       cbz r0, 59c <PrecisionRxProcessor::service_capture_command()+0x9c>\n",
            " 56a: b178       cbz r0, 56c <PrecisionRxProcessor::service_capture_command()+0x6c>\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "completion is not dominated"):
            self.verify(disassembly)

    def test_rejects_close_transition_branching_on_wrong_register(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 56a: b178       cbz r0, 59c <PrecisionRxProcessor::service_capture_command()+0x9c>",
            " 56a: b179       cbz r1, 59c <PrecisionRxProcessor::service_capture_command()+0x9c>",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "returned r0"):
            self.verify(disassembly)

    def test_rejects_unbind_branching_on_wrong_return_register(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 57c: 2800       cmp r0, #0",
            " 57c: 2900       cmp r1, #0",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "returned r0"):
            self.verify(disassembly)

    def test_rejects_close_retry_without_unbound_ownership_guard(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 560: f890 33d8  ldrb.w r3, [r0, #984]\n",
            " 560: f890 33d4  ldrb.w r3, [r0, #980]\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "StreamInput is sealed"):
            self.verify(disassembly)

    def test_rejects_successful_unbind_that_branches_to_ack(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 584: e7ef       b.n 566 <PrecisionRxProcessor::service_capture_command()+0x66>\n",
            " 584: e7ef       b.n 56c <PrecisionRxProcessor::service_capture_command()+0x6c>\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "re-enter the monitor transition"):
            self.verify(disassembly)

    def test_rejects_rebind_failure_that_acknowledges_instead_of_retrying(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 530: e034       b.n 59c <PrecisionRxProcessor::service_capture_command()+0x9c>\n",
            " 530: e034       b.n 596 <PrecisionRxProcessor::service_capture_command()+0x96>\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "rebind failure must leave OPEN pending"):
            self.verify(disassembly)

    def test_rejects_open_rollback_ack_before_monitor_success(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 514: e03e       b.n 594 <PrecisionRxProcessor::service_capture_command()+0x94>\n",
            " 514: e03e       b.n 59c <PrecisionRxProcessor::service_capture_command()+0x9c>\n",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "OPEN rollback may acknowledge"):
            self.verify(disassembly)

    def test_rejects_thread_construction_before_stream_storage(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 10e: f000 f800  bl  200 <StreamInput::StreamInput(unsigned int, unsigned int)>\n 112: f000 f800  bl  1100 <StreamInput::dma_loan_buffer()>\n 116: f000 f800  bl  900 <BasebandThread::BasebandThread(unsigned long, BasebandProcessor*, baseband::Direction, bool, unsigned long)>",
            " 10e: f000 f800  bl  900 <BasebandThread::BasebandThread(unsigned long, BasebandProcessor*, baseband::Direction, bool, unsigned long)>\n 112: f000 f800  bl  1100 <StreamInput::dma_loan_buffer()>\n 116: f000 f800  bl  200 <StreamInput::StreamInput(unsigned int, unsigned int)>",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "must precede"):
            self.verify(disassembly)

    def test_rejects_capture_sized_service_clear(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 546: 2268       movs r2, #104",
            " 546: f44f 3280  mov.w r2, #65536 ; 0x10000",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "65536 bytes"):
            self.verify(disassembly)

    def test_rejects_unreviewed_stream_geometry(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 108: 2209       movs r2, #9",
            " 108: 2204       movs r2, #4",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "buffer count"):
            self.verify(disassembly)

    def test_rejects_unreviewed_stream_write_size(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 10a: f44f 5100  mov.w r1, #8192 ; 0x2000",
            " 10a: f44f 4180  mov.w r1, #16384 ; 0x4000",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "write size"):
            self.verify(disassembly)

    def test_rejects_default_geometry_stream_input_implementation(self):
        nm = replace_once(
            NM_FIXTURE,
            "00000004 00000001 A hackrf_edge_stream_input_impl_buffer_count_log2",
            "00000003 00000001 A hackrf_edge_stream_input_impl_buffer_count_log2",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError, "implementation geometry is 2\\^3"
        ):
            verifier.verify_outputs(
                nm,
                DISASSEMBLY_FIXTURE,
                SECTION_FIXTURE,
                elf_sha256="0" * 64,
            )

    def test_rejects_default_geometry_precision_rx_mode(self):
        nm = replace_once(
            NM_FIXTURE,
            "00000004 00000001 A hackrf_edge_precision_rx_mode_buffer_count_log2",
            "00000003 00000001 A hackrf_edge_precision_rx_mode_buffer_count_log2",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError, "mode geometry is 2\\^3"
        ):
            verifier.verify_outputs(
                nm,
                DISASSEMBLY_FIXTURE,
                SECTION_FIXTURE,
                elf_sha256="0" * 64,
            )

    def test_rejects_wrong_precision_rx_local_buffer_count(self):
        nm = replace_once(
            NM_FIXTURE,
            "00000009 00000001 A hackrf_edge_precision_rx_mode_local_buffer_count",
            "00000008 00000001 A hackrf_edge_precision_rx_mode_local_buffer_count",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError, "local buffer count is 8"
        ):
            verifier.verify_outputs(
                nm,
                DISASSEMBLY_FIXTURE,
                SECTION_FIXTURE,
                elf_sha256="0" * 64,
            )

    def test_rejects_wrong_precision_rx_total_buffer_count(self):
        nm = replace_once(
            NM_FIXTURE,
            "0000000b 00000001 A hackrf_edge_precision_rx_mode_total_buffer_count",
            "0000000a 00000001 A hackrf_edge_precision_rx_mode_total_buffer_count",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError, "total buffer count is 10"
        ):
            verifier.verify_outputs(
                nm,
                DISASSEMBLY_FIXTURE,
                SECTION_FIXTURE,
                elf_sha256="0" * 64,
            )

    def test_rejects_wrong_precision_rx_spill_buffer_count(self):
        nm = replace_once(
            NM_FIXTURE,
            "00000002 00000001 A hackrf_edge_precision_rx_mode_spill_buffer_count",
            "00000003 00000001 A hackrf_edge_precision_rx_mode_spill_buffer_count",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError, "spill buffer count is 3"
        ):
            verifier.verify_outputs(
                nm,
                DISASSEMBLY_FIXTURE,
                SECTION_FIXTURE,
                elf_sha256="0" * 64,
            )

    def test_rejects_each_wrong_dma_geometry_value(self):
        cases = {
            "00002000 00000004 A hackrf_edge_precision_rx_dma_buffer_bytes":
                "00004000 00000004 A hackrf_edge_precision_rx_dma_buffer_bytes",
            "00000800 00000004 A hackrf_edge_precision_rx_dma_transfer_bytes":
                "00001000 00000004 A hackrf_edge_precision_rx_dma_transfer_bytes",
            "00000004 00000001 A hackrf_edge_precision_rx_dma_transfer_count":
                "00000002 00000001 A hackrf_edge_precision_rx_dma_transfer_count",
            "100016d0 00000040 b baseband::dma::lli_loop":
                "100016d0 00000020 b baseband::dma::lli_loop",
            "00002000 00000004 A hackrf_edge_precision_rx_dma_loan_bytes":
                "00001000 00000004 A hackrf_edge_precision_rx_dma_loan_bytes",
            "00004000 00000004 A hackrf_edge_precision_rx_dma_monitor_ring_bytes":
                "00002000 00000004 A hackrf_edge_precision_rx_dma_monitor_ring_bytes",
            "00001000 00000004 A hackrf_edge_precision_rx_dma_monitor_transfer_bytes":
                "00000800 00000004 A hackrf_edge_precision_rx_dma_monitor_transfer_bytes",
            "00000800 00000004 A hackrf_edge_precision_rx_dma_monitor_transfer_samples":
                "00000400 00000004 A hackrf_edge_precision_rx_dma_monitor_transfer_samples",
            "00002000 00000004 A hackrf_edge_precision_rx_dma_capture_ring_bytes":
                "00004000 00000004 A hackrf_edge_precision_rx_dma_capture_ring_bytes",
            "00000800 00000004 A hackrf_edge_precision_rx_dma_capture_transfer_bytes":
                "00001000 00000004 A hackrf_edge_precision_rx_dma_capture_transfer_bytes",
            "00000400 00000004 A hackrf_edge_precision_rx_dma_capture_transfer_samples":
                "00000800 00000004 A hackrf_edge_precision_rx_dma_capture_transfer_samples",
            "00000002 00000001 A hackrf_edge_precision_rx_dma_monitor_owned_lli_count":
                "00000001 00000001 A hackrf_edge_precision_rx_dma_monitor_owned_lli_count",
            "00000002 00000001 A hackrf_edge_precision_rx_dma_monitor_loan_lli_count":
                "00000003 00000001 A hackrf_edge_precision_rx_dma_monitor_loan_lli_count",
            "00000008 00000001 A hackrf_edge_precision_rx_dma_loan_local_buffer_index":
                "00000007 00000001 A hackrf_edge_precision_rx_dma_loan_local_buffer_index",
            "00000004 00000001 A hackrf_edge_precision_rx_dma_terminal_count_interrupt_count":
                "00000003 00000001 A hackrf_edge_precision_rx_dma_terminal_count_interrupt_count",
            "001e8480 00000004 A hackrf_edge_precision_rx_dma_capture_rate_limit_hz":
                "003d0900 00000004 A hackrf_edge_precision_rx_dma_capture_rate_limit_hz",
            "00000001 00000001 A hackrf_edge_precision_rx_dma_transition_discards_old_block":
                "00000000 00000001 A hackrf_edge_precision_rx_dma_transition_discards_old_block",
            "00000001 00000001 A hackrf_edge_precision_rx_dma_transition_resets_epoch":
                "00000000 00000001 A hackrf_edge_precision_rx_dma_transition_resets_epoch",
            "00000001 00000001 A hackrf_edge_precision_rx_dma_high_rate_bound_request_rejected":
                "00000000 00000001 A hackrf_edge_precision_rx_dma_high_rate_bound_request_rejected",
            "00000001 00000001 A hackrf_edge_precision_rx_dma_abort_force_unbind":
                "00000000 00000001 A hackrf_edge_precision_rx_dma_abort_force_unbind",
            "00000001 00000001 A hackrf_edge_precision_rx_dma_abort_requires_consumer_release":
                "00000000 00000001 A hackrf_edge_precision_rx_dma_abort_requires_consumer_release",
            "00000000 00000001 A hackrf_edge_precision_rx_dma_scheduler_backlog_depth":
                "00000001 00000001 A hackrf_edge_precision_rx_dma_scheduler_backlog_depth",
            "00019000 00000004 A hackrf_edge_precision_rx_dma_service_deadline_ns_at_20m":
                "00032000 00000004 A hackrf_edge_precision_rx_dma_service_deadline_ns_at_20m",
            "0004b000 00000004 A hackrf_edge_precision_rx_dma_physical_retention_ns_at_20m":
                "00019000 00000004 A hackrf_edge_precision_rx_dma_physical_retention_ns_at_20m",
        }
        for old, new in cases.items():
            with self.subTest(symbol=old.rsplit(" ", 1)[-1]):
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_outputs(
                        replace_once(NM_FIXTURE, old, new),
                        DISASSEMBLY_FIXTURE,
                        SECTION_FIXTURE,
                        elf_sha256="0" * 64,
                    )

    def test_rejects_missing_close_seal(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 54c: f000 f800  bl  470 <StreamInput::seal()>\n",
            "",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "seal.*exactly once"):
            self.verify(disassembly)

    def test_rejects_missing_close_drain(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 550: f000 f800  bl  490 <StreamInput::drained() const>\n",
            "",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "drained.*exactly once"):
            self.verify(disassembly)

    def test_rejects_insufficient_modeled_headroom(self):
        sections = replace_once(
            SECTION_FIXTURE,
            "  4 .bss          00001420",
            "  4 .bss          00001820",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "modeled RAM headroom"):
            self.verify(sections=sections)

    def test_rejects_new_unmodeled_allocator_caller(self):
        disassembly = DISASSEMBLY_FIXTURE + """
00000e00 <surprise_allocation()>:
 e00: 2020       movs r0, #32
 e02: f000 f800  bl  d00 <operator new(unsigned int)>
 e06: 4770       bx lr
"""
        with self.assertRaisesRegex(verifier.VerificationError, "unexpected operator new callers"):
            self.verify(disassembly)

    def test_rejects_direct_raw_heap_allocation(self):
        disassembly = DISASSEMBLY_FIXTURE + """
00000e00 <surprise_raw_allocation()>:
 e00: f000 f800  bl  d80 <chHeapAlloc>
 e04: 4770       bx lr
"""
        with self.assertRaisesRegex(verifier.VerificationError, "chHeapAlloc callers"):
            self.verify(disassembly)


if __name__ == "__main__":
    unittest.main()
