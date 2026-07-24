#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright 2026 HackRF Edge contributors
# SPDX-License-Identifier: GPL-2.0-or-later

from pathlib import Path
import sys
import unittest


TOOLS_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS_DIRECTORY))

import verify_precision_rx_application_elf as verifier  # noqa: E402


NM_FIXTURE = """
00000009 00000001 A hackrf_edge_precision_rx_app_local_buffer_count
00000002 00000001 A hackrf_edge_precision_rx_app_spill_buffer_count
00004000 00000004 A hackrf_edge_precision_rx_app_spill_bytes
00000400 00000004 A hackrf_edge_precision_rx_app_thread_stack_bytes
00000090 00000004 A hackrf_edge_precision_rx_app_capture_config_bytes
000000d8 00000004 A hackrf_edge_precision_rx_app_capture_thread_bytes
00000001 00000001 A hackrf_edge_precision_rx_app_dma_abort_requires_consumer_release
00000001 00000001 A hackrf_edge_precision_rx_journal_fail_closed_recovery
20004c10 B __heap_base__
20010000 A __heap_end__
00000100 0000011c T CaptureThread::CaptureThread(std::unique_ptr<stream::Writer>, unsigned int, unsigned int)
00000100 0000011c T CaptureThread::CaptureThread(std::unique_ptr<stream::Writer>, unsigned int, unsigned int)
00000300 00000040 T CaptureThread::~CaptureThread()
00000400 00000360 t CaptureThread::static_fn(void*)
00000900 0000000c T ui::external_app::precision_rx::PrecisionRxView::recover_snapshot_journal(PrecisionRxCaptureEvidence const&, ui::external_app::precision_rx::SnapshotJournalBounds const&)
"""


DISASSEMBLY_FIXTURE = """
00000100 <CaptureThread::CaptureThread(std::unique_ptr<stream::Writer>, unsigned int, unsigned int)>:
 100: 2180       movs r1, #128
 102: 01c9       lsls r1, r1, #7
 104: f000 f800  bl  900 <chHeapAlloc>
 108: f3bf 8f5f  dmb sy
 10c: 2180       movs r1, #128
 10e: 00c9       lsls r1, r1, #3
 110: f000 f800  bl  920 <chThdCreateFromHeap>
 114: f000 f800  bl  940 <chHeapFree>
 118: 4770       bx lr

00000300 <CaptureThread::~CaptureThread()>:
 300: f000 f800  bl  960 <CaptureThread::stop()>
 304: f000 f800  bl  940 <chHeapFree>
 308: 4770       bx lr

00000400 <CaptureThread::static_fn(void*)>:
 400: 0007       movs r7, r0
 402: f3bf 8f5f  dmb sy
 404: f000 f800  bl  a00 <baseband::send_message(Message const*)>
 408: f000 f800  bl  a20 <sdc_lld_send_cmd_short_crc>
 40c: f000 f800  bl  a40 <BufferExchange::get(FIFO<StreamBuffer*>*)>
 410: f000 f800  bl  a60 <memset>
 414: 4798       blx r3
 418: f000 f800  bl  a80 <FIFO<StreamBuffer*>::in(StreamBuffer* const&)>
 41c: f000 f800  bl  aa0 <BufferExchange::~BufferExchange()>
 420: 0038       movs r0, r7
 422: 303a       adds r0, #0x3a
 424: f000 f800  bl  ac0 <hackrf_edge_precision_rx_publish_dma_consumer_release>
 428: 4770       bx lr

00000800 <hackrf_edge_precision_rx_publish_dma_consumer_release>:
 800: f3bf 8f5f  dmb sy
 804: 2300       movs r3, #0
 806: 7003       strb r3, [r0, #0]
 808: f3bf 8f5f  dmb sy
 80c: 4770       bx lr

00000900 <ui::external_app::precision_rx::PrecisionRxView::recover_snapshot_journal(PrecisionRxCaptureEvidence const&, ui::external_app::precision_rx::SnapshotJournalBounds const&)>:
 900: b5f0       push {r4, r5, r6, r7, lr}
 902: b08d       sub sp, #0x34
 904: 2300       movs r3, #0
 906: 6003       str r3, [r0, #0]
 908: b00d       add sp, #0x34
 90a: bdf0       pop {r4, r5, r6, r7, pc}

00000a00 <ui::external_app::precision_rx::PrecisionRxView::stop_capture()>:
 a00: b510       push {r4, lr}
 a02: f000 f800  bl  900 <ui::external_app::precision_rx::PrecisionRxView::recover_snapshot_journal(PrecisionRxCaptureEvidence const&, ui::external_app::precision_rx::SnapshotJournalBounds const&)>
 a06: bd10       pop {r4, pc}
"""

P12_NM_FIXTURE = NM_FIXTURE + """
00000003 00000001 A hackrf_edge_precision_rx_app_rate_transaction_protocol_version
00000001 00000001 A hackrf_edge_precision_rx_app_rate_prepare_before_physical_change
00000001 00000001 A hackrf_edge_precision_rx_app_rate_filter_before_clock
00000001 00000001 A hackrf_edge_precision_rx_app_rate_commit_after_physical_change
00000001 00000001 A hackrf_edge_precision_rx_app_rate_rollback_before_abort
00000001 00000001 A hackrf_edge_precision_rx_app_rate_fail_closed
000001f4 00000004 A hackrf_edge_precision_rx_app_rate_bounded_wait_iterations
00000001 00000001 A hackrf_edge_precision_rx_app_rate_persistent_message
00000001 00000001 A hackrf_edge_precision_rx_app_rate_rejection_no_panic
00000001 00000001 A hackrf_edge_precision_rx_app_rate_fault_shutdown_bounded
00000001 00000001 A hackrf_edge_precision_rx_app_rate_rollback_requires_paused_armed
00000001 00000001 A hackrf_edge_precision_rx_app_rate_commit_timeout_no_rollback
0000000a 00000001 A hackrf_edge_precision_rx_m0_fault_watchdog_ms
00000b00 000000f0 T baseband::set_precision_rx(unsigned long)
00000c00 00000050 T baseband::send_precision_rx_message_bounded(Message const*)
00000c60 00000018 t baseband::precision_rx_rate_fatal()
00000c90 00000024 T baseband::shutdown_precision_rx_after_rate_fault()
00000c20 00000020 T ReceiverModel::update_baseband_bandwidth()
00000c40 00000020 T ReceiverModel::update_sampling_rate()
00000e00 000000e0 T BufferExchange::get(FIFO<StreamBuffer*>*)
00000f00 00000020 T radio::disable()
00001300 00000010 T ui::external_app::precision_rx::PrecisionRxView::PrecisionRxView(ui::NavigationView&)
00001400 00000010 t ___ZN9portapack16set_antenna_biasEb_veneer
00001420 00000010 t ___ZN13ReceiverModel6enableEv_veneer
00001600 00000020 T portapack::set_antenna_bias(bool)
00001620 00000020 T ReceiverModel::enable()
00001680 00000018 T baseband::shutdown()
000016a0 00000018 T ui::external_app::precision_rx::PrecisionRxView::~PrecisionRxView()
000016c0 00000002 T ReceiverModel::disable()
000016e0 00000002 t baseband::send_message(Message const*)
00002000 00000004 T shared_memory
20002000 00000038 D portapack::receiver_model
20003000 00000008 b baseband::(anonymous namespace)::precision_rx_rate_message
20003008 00000001 b baseband::(anonymous namespace)::precision_rx_rate_fault_latched
2000300c 00000008 d baseband::(anonymous namespace)::precision_rx_fault_shutdown_message
"""

P12_DISASSEMBLY_FIXTURE = DISASSEMBLY_FIXTURE + """
00000b00 <baseband::set_precision_rx(unsigned long)>:
 b00: b5f0       push {r4, r5, r6, r7, lr}
 b02: 4605       mov r5, r0
 b04: 4c2e       ldr r4, [pc, #184] ; (bc0 <baseband::set_precision_rx(unsigned long)+0xc0>)
 b06: 6065       str r5, [r4, #4]
 b08: 4620       mov r0, r4
 b0a: f000 f800  bl  c00 <baseband::send_precision_rx_message_bounded(Message const*)>
 b0e: b360       cbz r0, b9e <baseband::set_precision_rx(unsigned long)+0x9e>
 b10: 6863       ldr r3, [r4, #4]
 b12: 4a2c       ldr r2, [pc, #176] ; (bc4 <baseband::set_precision_rx(unsigned long)+0xc4>)
 b14: 4293       cmp r3, r2
 b16: d047       beq.n ba8 <baseband::set_precision_rx(unsigned long)+0xa8>
 b18: 4a2b       ldr r2, [pc, #172] ; (bc8 <baseband::set_precision_rx(unsigned long)+0xc8>)
 b1a: 4293       cmp r3, r2
 b1c: d000       beq.n b20 <baseband::set_precision_rx(unsigned long)+0x20>
 b1e: e03e       b.n b9e <baseband::set_precision_rx(unsigned long)+0x9e>
 b20: 4e2b       ldr r6, [pc, #172] ; (bdc <baseband::set_precision_rx(unsigned long)+0xdc>)
 b22: 4628       mov r0, r5
 b24: f000 f800  bl  d00 <ui::filter_bandwidth_for_sampling_rate(long)>
 b28: 4630       mov r0, r6
 b2a: f000 f800  bl  c20 <ReceiverModel::update_baseband_bandwidth()>
 b2e: 4630       mov r0, r6
 b30: f000 f800  bl  c40 <ReceiverModel::update_sampling_rate()>
 b34: 4b25       ldr r3, [pc, #148] ; (bcc <baseband::set_precision_rx(unsigned long)+0xcc>)
 b36: 6063       str r3, [r4, #4]
 b38: 4620       mov r0, r4
 b3a: f000 f800  bl  c00 <baseband::send_precision_rx_message_bounded(Message const*)>
 b3e: b170       cbz r0, b9e <baseband::set_precision_rx(unsigned long)+0x9e>
 b40: 6863       ldr r3, [r4, #4]
 b42: 4a23       ldr r2, [pc, #140] ; (bd0 <baseband::set_precision_rx(unsigned long)+0xd0>)
 b44: 4293       cmp r3, r2
 b46: d02f       beq.n ba8 <baseband::set_precision_rx(unsigned long)+0xa8>
 b48: 4a26       ldr r2, [pc, #152] ; (be0 <baseband::set_precision_rx(unsigned long)+0xe0>)
 b4a: 189b       adds r3, r3, r2
 b4c: 2b06       cmp r3, #6
 b4e: d826       bhi.n b9e <baseband::set_precision_rx(unsigned long)+0x9e>
 b50: f3bf 8f5f  dmb sy
 b54: 4f23       ldr r7, [pc, #140] ; (be4 <baseband::set_precision_rx(unsigned long)+0xe4>)
 b56: 4b24       ldr r3, [pc, #144] ; (be8 <baseband::set_precision_rx(unsigned long)+0xe8>)
 b58: 5cfa       ldrb r2, [r7, r3]
 b5a: 2a03       cmp r2, #3
 b5c: d11f       bne.n b9e <baseband::set_precision_rx(unsigned long)+0x9e>
 b5e: 4630       mov r0, r6
 b60: f000 f800  bl  c40 <ReceiverModel::update_sampling_rate()>
 b64: 4630       mov r0, r6
 b66: f000 f800  bl  c20 <ReceiverModel::update_baseband_bandwidth()>
 b6a: 4b1f       ldr r3, [pc, #124] ; (bd4 <baseband::set_precision_rx(unsigned long)+0xd4>)
 b6c: 6063       str r3, [r4, #4]
 b6e: 4620       mov r0, r4
 b70: f000 f800  bl  c00 <baseband::send_precision_rx_message_bounded(Message const*)>
 b74: b198       cbz r0, b9e <baseband::set_precision_rx(unsigned long)+0x9e>
 b76: 6863       ldr r3, [r4, #4]
 b78: 4a1c       ldr r2, [pc, #112] ; (bd8 <baseband::set_precision_rx(unsigned long)+0xd8>)
 b7a: 4293       cmp r3, r2
 b7c: d10f       bne.n b9e <baseband::set_precision_rx(unsigned long)+0x9e>
 b7e: f3bf 8f5f  dmb sy
 b82: 4b19       ldr r3, [pc, #100] ; (be8 <baseband::set_precision_rx(unsigned long)+0xe8>)
 b84: 5cfa       ldrb r2, [r7, r3]
 b86: 2a01       cmp r2, #1
 b88: d109       bne.n b9e <baseband::set_precision_rx(unsigned long)+0x9e>
 b8a: 2002       movs r0, #2
 b8c: e00a       b.n ba4 <baseband::set_precision_rx(unsigned long)+0xa4>
 b9e: f000 f800  bl  c60 <baseband::precision_rx_rate_fatal()>
 ba2: e000       b.n ba4 <baseband::set_precision_rx(unsigned long)+0xa4>
 ba4: bdf0       pop {r4, r5, r6, r7, pc}
 ba8: f3bf 8f5f  dmb sy
 bac: 4f0d       ldr r7, [pc, #52] ; (be4 <baseband::set_precision_rx(unsigned long)+0xe4>)
 bae: 4b0e       ldr r3, [pc, #56] ; (be8 <baseband::set_precision_rx(unsigned long)+0xe8>)
 bb0: 5cfa       ldrb r2, [r7, r3]
 bb2: 2a01       cmp r2, #1
 bb4: d1f3       bne.n b9e <baseband::set_precision_rx(unsigned long)+0x9e>
 bb6: 2000       movs r0, #0
 bb8: e7f4       b.n ba4 <baseband::set_precision_rx(unsigned long)+0xa4>
 bc0: 20003000   .word 0x20003000
 bc4: c0000001   .word 0xc0000001
 bc8: c0000002   .word 0xc0000002
 bcc: 80000001   .word 0x80000001
 bd0: c0000003   .word 0xc0000003
 bd4: 80000002   .word 0x80000002
 bd8: c0000004   .word 0xc0000004
 bdc: 20002000   .word 0x20002000
 be0: 1fffffff   .word 0x1fffffff
 be4: 10088000   .word 0x10088000
 be8: 00001a5f   .word 0x00001a5f

00000c00 <baseband::send_precision_rx_message_bounded(Message const*)>:
 c00: b510       push {r4, lr}
 c02: 4d12       ldr r5, [pc, #72] ; (c4c <baseband::send_precision_rx_message_bounded(Message const*)+0x4c>)
 c04: 682a       ldr r2, [r5, #0]
 c06: b99a       cbnz r2, c30 <baseband::send_precision_rx_message_bounded(Message const*)+0x30>
 c08: f3bf 8f5f  dmb sy
 c0c: 6028       str r0, [r5, #0]
 c0e: f3bf 8f5f  dmb sy
 c12: bf40       sev
 c14: 2400       movs r4, #501
 c18: 682a       ldr r2, [r5, #0]
 c1a: b142       cbz r2, c2e <baseband::send_precision_rx_message_bounded(Message const*)+0x2e>
 c1c: 3c01       subs r4, #1
 c1e: d006       beq.n c2e <baseband::send_precision_rx_message_bounded(Message const*)+0x2e>
 c20: 2001       movs r0, #1
 c22: f000 f800  bl  c80 <chThdSleep>
 c26: 2c00       cmp r4, #0
 c28: d1f6       bne.n c18 <baseband::send_precision_rx_message_bounded(Message const*)+0x18>
 c2a: bf00       nop
 c2c: bf00       nop
 c2e: f3bf 8f5f  dmb sy
 c30: 6828       ldr r0, [r5, #0]
 c32: b108       cbz r0, c38 <baseband::send_precision_rx_message_bounded(Message const*)+0x38>
 c34: 2000       movs r0, #0
 c36: bd10       pop {r4, pc}
 c38: 2001       movs r0, #1
 c3a: bd10       pop {r4, pc}
 c4c: 10089000   .word 0x10089000
 c50: 40050000   .word 0x40050000

00000c60 <baseband::precision_rx_rate_fatal()>:
 c60: b510       push {r4, lr}
 c62: 2201       movs r2, #1
 c64: 4b05       ldr r3, [pc, #20] ; (c7c <baseband::precision_rx_rate_fatal()+0x1c>)
 c66: 701a       strb r2, [r3, #0]
 c68: 2200       movs r2, #0
 c6a: 4b05       ldr r3, [pc, #20] ; (c80 <baseband::precision_rx_rate_fatal()+0x20>)
 c6c: 3328       adds r3, #40
 c6e: 701a       strb r2, [r3, #0]
 c70: f000 f800  bl  f00 <radio::disable()>
 c74: 2003       movs r0, #3
 c76: bd10       pop {r4, pc}
 c7c: 20003008   .word 0x20003008
 c80: 20002000   .word 0x20002000

00000c90 <baseband::shutdown_precision_rx_after_rate_fault()>:
 c90: b510       push {r4, lr}
 c92: 2400       movs r4, #0
 c94: 4b0e       ldr r3, [pc, #56] ; (cd0 <baseband::shutdown_precision_rx_after_rate_fault()+0x40>)
 c96: 3328       adds r3, #40
 c98: 701c       strb r4, [r3, #0]
 c9a: f000 f800  bl  f00 <radio::disable()>
 c9e: 480d       ldr r0, [pc, #52] ; (cd4 <baseband::shutdown_precision_rx_after_rate_fault()+0x44>)
 ca0: f000 f800  bl  c00 <baseband::send_precision_rx_message_bounded(Message const*)>
 ca4: 42a0       cmp r0, r4
 ca6: d003       beq.n cb0 <baseband::shutdown_precision_rx_after_rate_fault()+0x20>
 ca8: 2001       movs r0, #1
 caa: bd10       pop {r4, pc}
 cb0: 2000       movs r0, #0
 cb2: bd10       pop {r4, pc}
 cd0: 20002000   .word 0x20002000
 cd4: 2000300c   .word 0x2000300c

00000e00 <BufferExchange::get(FIFO<StreamBuffer*>*)>:
 e00: b5f8       push {r3, r4, r5, r6, r7, lr}
 e02: 0005       movs r5, r0
 e04: 000f       movs r7, r1
 e06: b672       cpsid i
 e08: f000 f800  bl  1100 <dbg_check_lock>
 e0c: 7c2c       ldrb r4, [r5, #16]
 e0e: 2c00       cmp r4, #0
 e10: d114       bne.n e3c <BufferExchange::get(FIFO<StreamBuffer*>*)+0x3c>
 e12: 682e       ldr r6, [r5, #0]
 e14: 2e00       cmp r6, #0
 e16: d012       beq.n e3e <BufferExchange::get(FIFO<StreamBuffer*>*)+0x3e>
 e18: 6bf6       ldr r6, [r6, #60]
 e1a: 2e00       cmp r6, #0
 e1c: d00f       beq.n e3e <BufferExchange::get(FIFO<StreamBuffer*>*)+0x3e>
 e1e: f3bf 8f5f  dmb sy
 e22: 4a2c       ldr r2, [pc, #176] ; (ed4 <BufferExchange::get(FIFO<StreamBuffer*>*)+0xd4>)
 e24: 4b2c       ldr r3, [pc, #176] ; (ed8 <BufferExchange::get(FIFO<StreamBuffer*>*)+0xd8>)
 e26: 5cd3       ldrb r3, [r2, r3]
 e28: 2b05       cmp r3, #5
 e2a: d121       bne.n e70 <BufferExchange::get(FIFO<StreamBuffer*>*)+0x70>
 e2c: 2201       movs r2, #1
 e2e: 682b       ldr r3, [r5, #0]
 e30: 3339       adds r3, #57
 e32: 701a       strb r2, [r3, #0]
 e34: f3bf 8f5f  dmb sy
 e38: 60ec       str r4, [r5, #12]
 e3a: e014       b.n e66 <BufferExchange::get(FIFO<StreamBuffer*>*)+0x66>
 e3c: 2600       movs r6, #0
 e3e: 68ba       ldr r2, [r7, #8]
 e40: 68fb       ldr r3, [r7, #12]
 e42: 429a       cmp r2, r3
 e44: d016       beq.n e74 <BufferExchange::get(FIFO<StreamBuffer*>*)+0x74>
 e46: 687a       ldr r2, [r7, #4]
 e48: 68fb       ldr r3, [r7, #12]
 e4a: 3a01       subs r2, #1
 e4c: 4013       ands r3, r2
 e4e: 683a       ldr r2, [r7, #0]
 e50: 009b       lsls r3, r3, #2
 e52: 589c       ldr r4, [r3, r2]
 e54: f3bf 8f5f  dmb sy
 e58: 68fb       ldr r3, [r7, #12]
 e5a: 3301       adds r3, #1
 e5c: 60fb       str r3, [r7, #12]
 e5e: 2c00       cmp r4, #0
 e60: d008       beq.n e74 <BufferExchange::get(FIFO<StreamBuffer*>*)+0x74>
 e62: 2300       movs r3, #0
 e64: 60eb       str r3, [r5, #12]
 e66: f000 f800  bl  1120 <dbg_check_unlock>
 e6a: b662       cpsie i
 e6c: 0020       movs r0, r4
 e6e: bdf8       pop {r3, r4, r5, r6, r7, pc}
 e70: 2601       movs r6, #1
 e72: e7e4       b.n e3e <BufferExchange::get(FIFO<StreamBuffer*>*)+0x3e>
 e74: 7c2c       ldrb r4, [r5, #16]
 e76: 2c00       cmp r4, #0
 e78: d10b       bne.n e92 <BufferExchange::get(FIFO<StreamBuffer*>*)+0x92>
 e7a: 682b       ldr r3, [r5, #0]
 e7c: 2b00       cmp r3, #0
 e7e: d008       beq.n e92 <BufferExchange::get(FIFO<StreamBuffer*>*)+0x92>
 e80: 001a       movs r2, r3
 e82: 3239       adds r2, #57
 e84: 7812       ldrb r2, [r2, #0]
 e86: 2a00       cmp r2, #0
 e88: d003       beq.n e92 <BufferExchange::get(FIFO<StreamBuffer*>*)+0x92>
 e8a: 3338       adds r3, #56
 e8c: 781b       ldrb r3, [r3, #0]
 e8e: 2b00       cmp r3, #0
 e90: d1d2       bne.n e38 <BufferExchange::get(FIFO<StreamBuffer*>*)+0x38>
 e92: 4b12       ldr r3, [pc, #72] ; (edc <BufferExchange::get(FIFO<StreamBuffer*>*)+0xdc>)
 e94: 699b       ldr r3, [r3, #24]
 e96: 60eb       str r3, [r5, #12]
 e98: 2e00       cmp r6, #0
 e9a: d107       bne.n eac <BufferExchange::get(FIFO<StreamBuffer*>*)+0xac>
 e9c: 2002       movs r0, #2
 e9e: f000 f800  bl  1140 <chSchGoSleepS>
 ea2: 60ee       str r6, [r5, #12]
 ea4: f000 f800  bl  1120 <dbg_check_unlock>
 ea8: b662       cpsie i
 eaa: e7ac       b.n e06 <BufferExchange::get(FIFO<StreamBuffer*>*)+0x6>
 eac: 2400       movs r4, #0
 eae: 210a       movs r1, #10
 eb0: 2002       movs r0, #2
 eb2: f000 f800  bl  1160 <chSchGoSleepTimeoutS>
 eb6: 60ec       str r4, [r5, #12]
 eb8: f3bf 8f5f  dmb sy
 ebc: 4a05       ldr r2, [pc, #20] ; (ed4 <BufferExchange::get(FIFO<StreamBuffer*>*)+0xd4>)
 ebe: 4b06       ldr r3, [pc, #24] ; (ed8 <BufferExchange::get(FIFO<StreamBuffer*>*)+0xd8>)
 ec0: 5cd3       ldrb r3, [r2, r3]
 ec2: 2b05       cmp r3, #5
 ec4: d1ee       bne.n ea4 <BufferExchange::get(FIFO<StreamBuffer*>*)+0xa4>
 ec6: 2201       movs r2, #1
 ec8: 682b       ldr r3, [r5, #0]
 eca: 3339       adds r3, #57
 ecc: 701a       strb r2, [r3, #0]
 ece: f3bf 8f5f  dmb sy
 ed2: e7c8       b.n e66 <BufferExchange::get(FIFO<StreamBuffer*>*)+0x66>
 ed4: 10088000   .word 0x10088000
 ed8: 00001a5f   .word 0x00001a5f
 edc: 20001f6c   .word 0x20001f6c

00001300 <ui::external_app::precision_rx::PrecisionRxView::PrecisionRxView(ui::NavigationView&)>:
 1300: b510       push {r4, lr}
 1302: 2000       movs r0, #0
 1304: f000 f800  bl  1400 <___ZN9portapack16set_antenna_biasEb_veneer>
 1308: 4810       ldr r0, [pc, #64] ; (134c <ui::external_app::precision_rx::PrecisionRxView::PrecisionRxView(ui::NavigationView&)+0x4c>)
 130a: f000 f800  bl  1420 <___ZN13ReceiverModel6enableEv_veneer>
 130e: bd10       pop {r4, pc}
 134c: 20002000   .word 0x20002000

00001400 <___ZN9portapack16set_antenna_biasEb_veneer>:
 1400: b401       push {r0}
 1402: 4802       ldr r0, [pc, #8] ; (140c <___ZN9portapack16set_antenna_biasEb_veneer+0xc>)
 1404: 4684       mov ip, r0
 1406: bc01       pop {r0}
 1408: 4760       bx ip
 140a: bf00       nop
 140c: 00001601   .word 0x00001601

00001420 <___ZN13ReceiverModel6enableEv_veneer>:
 1420: b401       push {r0}
 1422: 4802       ldr r0, [pc, #8] ; (142c <___ZN13ReceiverModel6enableEv_veneer+0xc>)
 1424: 4684       mov ip, r0
 1426: bc01       pop {r0}
 1428: 4760       bx ip
 142a: bf00       nop
 142c: 00001621   .word 0x00001621

00001680 <baseband::shutdown()>:
 1680: b503       push {r0, r1, lr}
 1682: 2400       movs r4, #0
 1684: 2305       movs r3, #5
 1686: 4668       mov r0, sp
 1688: 9300       str r3, [sp, #0]
 168a: 9401       str r4, [sp, #4]
 168c: f000 f828  bl 16e0 <baseband::send_message(Message const*)>
 1690: bd03       pop {r0, r1, pc}

000016a0 <ui::external_app::precision_rx::PrecisionRxView::~PrecisionRxView()>:
 16a0: b510       push {r4, lr}
 16a2: 7843       ldrb r3, [r0, #1]
 16a4: 2b00       cmp r3, #0
 16a6: d002       beq.n 16ae <ui::external_app::precision_rx::PrecisionRxView::~PrecisionRxView()+0xe>
 16a8: f7ff fafa  bl c90 <baseband::shutdown_precision_rx_after_rate_fault()>
 16ac: e003       b.n 16b6 <ui::external_app::precision_rx::PrecisionRxView::~PrecisionRxView()+0x16>
 16ae: f7ff ffe7  bl 1680 <baseband::shutdown()>
 16b2: f000 f805  bl 16c0 <ReceiverModel::disable()>
 16b6: bd10       pop {r4, pc}

000016c0 <ReceiverModel::disable()>:
 16c0: 4770       bx lr

000016e0 <baseband::send_message(Message const*)>:
 16e0: 4770       bx lr
"""

P12_TEXT_CONTENTS_FIXTURE = """
Contents of section .text:
 00b90 010000c0 020000c0 030000c0 01000080
 00ba0 02000080 00200000
 00ed0 0000c8e7 00800810 5f1a0000 6c1f0020
 02000 00800810
 2000300c 05000000 01000000
"""


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise AssertionError(f"fixture token must occur once: {old!r}")
    return source.replace(old, new, 1)


def thumb_veneer_fixture(
    address: int,
    name: str,
    ultimate_address: int,
) -> tuple[str, str]:
    nm = f"{address:08x} 00000010 t {name}\n"
    disassembly = f"""
{address:08x} <{name}>:
 {address:04x}: b401       push {{r0}}
 {address + 2:04x}: 4802       ldr r0, [pc, #8] ; ({address + 12:x} <{name}+0xc>)
 {address + 4:04x}: 4684       mov ip, r0
 {address + 6:04x}: bc01       pop {{r0}}
 {address + 8:04x}: 4760       bx ip
 {address + 10:04x}: bf00       nop
 {address + 12:04x}: {ultimate_address | 1:08x}   .word 0x{ultimate_address | 1:08x}
"""
    return nm, disassembly


def segmented_rate_veneer_fixture() -> tuple[str, str]:
    bandwidth_name = verifier.RECEIVER_UPDATE_BANDWIDTH_VENEER_NAME
    rate_name = verifier.RECEIVER_UPDATE_RATE_VENEER_NAME
    radio_name = verifier.RADIO_DISABLE_VENEER_NAME
    disassembly = P12_DISASSEMBLY_FIXTURE.replace(
        "bl  c20 <ReceiverModel::update_baseband_bandwidth()>",
        f"bl  3000 <{bandwidth_name}>",
    ).replace(
        "bl  c40 <ReceiverModel::update_sampling_rate()>",
        f"bl  3020 <{rate_name}>",
    ).replace(
        "bl  f00 <radio::disable()>",
        f"bl  3040 <{radio_name}>",
    )
    nm = P12_NM_FIXTURE
    for address, name, target in (
        (0x3000, bandwidth_name, 0x0C20),
        (0x3020, rate_name, 0x0C40),
        (0x3040, radio_name, 0x0F00),
    ):
        veneer_nm, veneer_disassembly = thumb_veneer_fixture(
            address,
            name,
            target,
        )
        nm += veneer_nm
        disassembly += veneer_disassembly
    return nm, disassembly


class PrecisionRxApplicationElfVerifierTest(unittest.TestCase):
    def verify(self, nm=NM_FIXTURE, disassembly=DISASSEMBLY_FIXTURE):
        return verifier.verify_outputs(
            nm,
            disassembly,
            elf_sha256="0" * 64,
        )

    def verify_p12(
        self,
        nm=P12_NM_FIXTURE,
        disassembly=P12_DISASSEMBLY_FIXTURE,
        text_contents=P12_TEXT_CONTENTS_FIXTURE,
    ):
        return verifier.verify_outputs(
            nm,
            disassembly,
            elf_sha256="0" * 64,
            text_contents_text=text_contents,
        )

    def test_accepts_reviewed_lto_shape_and_records_contract(self):
        report = self.verify()
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(
            report["contract"],
            "precision-rx-application-linked-dma-lease-v4",
        )
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
        self.assertEqual(report["allocation"]["spill_bytes"], 16384)
        self.assertEqual(report["allocation"]["thread_stack_bytes"], 1024)
        self.assertEqual(report["allocation"]["capture_config_bytes"], 144)
        self.assertEqual(report["allocation"]["capture_thread_bytes"], 216)
        self.assertEqual(report["allocation"]["total_buffer_count"], 11)
        self.assertEqual(report["allocation"]["heap_span_bytes"], 46064)
        self.assertEqual(
            report["allocation"][
                "modeled_heap_residual_after_spill_and_stack_bytes"
            ],
            28656,
        )
        self.assertEqual(
            report["allocation"]["minimum_modeled_heap_residual_bytes"],
            27648,
        )
        self.assertEqual(
            report["allocation"]["modeled_heap_residual_margin_bytes"],
            1008,
        )
        self.assertEqual(
            report["allocation"]["combined_capture_stream_bytes"], 90112
        )
        self.assertTrue(report["pipeline"]["ready_precedes_dequeue"])
        self.assertEqual(report["pipeline"]["memcpy_call_count"], 0)
        self.assertTrue(report["pipeline"]["recycle_after_writer"])
        self.assertTrue(
            report["pipeline"][
                "consumer_release_after_buffer_exchange_teardown"
            ]
        )
        self.assertEqual(
            report["allocation"]["dma_abort_requires_consumer_release"], 1
        )
        self.assertEqual(
            report["allocation"]["journal_fail_closed_policy_metadata"], 1
        )
        self.assertEqual(
            report["pipeline"]["consumer_release_argument_offset_bytes"],
            0x3A,
        )
        self.assertTrue(
            report["pipeline"][
                "consumer_release_argument_is_baseband_open_succeeded"
            ]
        )
        self.assertEqual(
            report["journal_recovery"]["local_stack_frame_bytes"], 52
        )
        self.assertEqual(
            report["journal_recovery"]["maximum_local_stack_frame_bytes"],
            256,
        )
        self.assertEqual(report["journal_recovery"]["internal_call_count"], 0)

    def test_accepts_p12_prepare_commit_rollback_contract(self):
        report = self.verify_p12()
        self.assertEqual(
            report["contract"],
            "precision-rx-application-linked-rate-transaction-v6",
        )
        self.assertEqual(report["profile"], "p15-rate-transaction")
        transaction = report["rate_transaction"]
        self.assertEqual(transaction["protocol_version"], 3)
        self.assertEqual(transaction["bounded_wait_iterations"], 500)
        self.assertTrue(transaction["persistent_message"])
        self.assertTrue(transaction["rejection_no_panic"])
        self.assertTrue(transaction["fault_shutdown_bounded"])
        self.assertTrue(transaction["rollback_requires_paused_armed"])
        self.assertTrue(transaction["commit_timeout_no_rollback"])
        self.assertTrue(transaction["prepare_before_physical_change"])
        self.assertTrue(transaction["filter_before_clock"])
        self.assertTrue(transaction["commit_after_physical_change"])
        self.assertTrue(transaction["rollback_before_abort"])
        self.assertTrue(transaction["fail_closed"])
        self.assertEqual(
            transaction["linked_control"]["bounded_send_call_count"],
            3,
        )
        self.assertTrue(
            transaction["linked_control"][
                "commit_failure_rolls_back_before_abort"
            ]
        )
        self.assertEqual(
            transaction["linked_control"]["message_id"],
            115,
        )
        self.assertEqual(
            transaction["linked_control"]["prepare_payload"],
            "entry_sample_rate",
        )
        self.assertEqual(
            transaction["linked_control"]["commit_control_word"],
            0x80000001,
        )
        self.assertEqual(
            transaction["linked_control"]["abort_control_word"],
            0x80000002,
        )
        self.assertTrue(
            transaction["linked_control"]["persistent_message_storage_reused"]
        )
        self.assertTrue(
            transaction["linked_control"]["persistent_payload_def_use_linked"]
        )
        self.assertTrue(
            transaction["linked_control"]["defined_rejection_paths_panic_free"]
        )
        self.assertTrue(
            transaction["linked_control"]["defined_outcomes_control_flow_bounded"]
        )
        self.assertTrue(
            transaction["linked_control"][
                "rollback_only_after_completed_recognized_rejection"
            ]
        )
        self.assertTrue(
            transaction["linked_control"]["rollback_requires_paused_armed"]
        )
        self.assertTrue(
            transaction["linked_control"]["commit_timeout_no_rollback"]
        )
        self.assertTrue(
            transaction["linked_control"]["unknown_response_no_rollback"]
        )
        self.assertTrue(
            transaction["linked_control"]["wrong_state_no_rollback"]
        )
        self.assertTrue(
            transaction["linked_control"][
                "ack_committed_wrong_state_fail_closed"
            ]
        )
        self.assertTrue(
            transaction["linked_control"]["abort_timeout_fail_closed"]
        )
        self.assertTrue(
            transaction["linked_control"][
                "ack_aborted_wrong_state_fail_closed"
            ]
        )
        self.assertEqual(
            transaction["linked_control"]["persistent_message_address"],
            0x20003000,
        )
        bounded = transaction["bounded_send"]
        self.assertEqual(bounded["wait_iterations"], 500)
        self.assertEqual(bounded["linked_counter_initial_value"], 501)
        self.assertTrue(bounded["single_decrementing_loop"])
        self.assertEqual(bounded["message_slot_address"], 0x10089000)
        self.assertTrue(bounded["message_slot_accesses_bound"])
        self.assertTrue(bounded["event_after_publication"])
        self.assertTrue(bounded["persistent_pointer_release_published"])
        self.assertTrue(bounded["terminal_slot_acquire_sampled"])
        self.assertTrue(bounded["panic_free"])
        fatal = transaction["fatal_helper"]
        self.assertTrue(fatal["bounded"])
        self.assertTrue(fatal["typed_fatal_return"])
        self.assertEqual(fatal["fault_latch_address"], 0x20003008)
        self.assertEqual(
            fatal["receiver_disable"]["shape"],
            "inlined",
        )
        shutdown = transaction["fault_shutdown"]
        self.assertTrue(shutdown["bounded"])
        self.assertTrue(shutdown["distinct_from_rate_message"])
        self.assertTrue(shutdown["occupied_mailbox_never_overwritten"])
        self.assertEqual(
            shutdown["persistent_shutdown_message_address"],
            0x2000300C,
        )
        self.assertEqual(shutdown["persistent_shutdown_message_bytes"], 8)
        self.assertEqual(shutdown["persistent_shutdown_message_id"], 5)
        self.assertEqual(shutdown["persistent_shutdown_message_mode"], 1)
        view_shutdown = transaction["view_shutdown"]
        self.assertTrue(
            view_shutdown["fault_and_normal_cfg_successors_disjoint"]
        )
        self.assertTrue(
            view_shutdown[
                "normal_baseband_shutdown_precedes_receiver_disable"
            ]
        )
        self.assertTrue(
            view_shutdown[
                "normal_shutdown_send_pointer_is_stack_message"
            ]
        )
        self.assertEqual(view_shutdown["normal_shutdown_message_id"], 5)
        self.assertEqual(view_shutdown["normal_shutdown_message_mode"], 0)
        self.assertEqual(view_shutdown["normal_shutdown_message_bytes"], 8)
        antenna_bias = transaction["antenna_bias_safety"]
        self.assertEqual(antenna_bias["false_argument_value"], 0)
        self.assertTrue(
            antenna_bias["false_bias_dominates_receiver_enable"]
        )
        self.assertTrue(antenna_bias["no_intervening_control_transfer"])
        self.assertTrue(antenna_bias["linked_instruction_calibrated"])
        self.assertEqual(
            len(transaction["post_build_instruction_calibration_required"]),
            0,
        )
        watchdog = transaction["m0_fault_watchdog"]
        self.assertEqual(watchdog["watchdog_metadata_ms"], 10)
        self.assertEqual(watchdog["timed_sleep_timeout_ms"], 10)
        self.assertTrue(watchdog["precision_capture_gate_cfg_bound"])
        self.assertEqual(watchdog["shared_memory_base"], 0x10088000)
        self.assertEqual(watchdog["m4_dma_rate_state_offset"], 0x1A5F)
        self.assertEqual(watchdog["m4_dma_fatal_state"], 5)
        self.assertTrue(watchdog["post_wake_thread_clear_under_lock"])
        self.assertEqual(
            watchdog["application_abort_requested_offset"],
            0x39,
        )
        self.assertTrue(
            watchdog["abort_publication_and_null_return_cfg_bound"]
        )

    def test_p12_rejects_duplicate_linked_buffer_exchange_get(self):
        duplicate = """
00001200 <BufferExchange::get(FIFO<StreamBuffer*>*)>:
 1200: 4770       bx lr
"""
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "expected exactly one BufferExchange::get",
        ):
            self.verify_p12(
                disassembly=P12_DISASSEMBLY_FIXTURE + duplicate
            )

    def test_p12_rejects_wrong_watchdog_timeout_materialization(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " eae: 210a       movs r1, #10",
            " eae: 2109       movs r1, #9",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "fatal watchdog timeout is 9 ms; expected 10",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_timed_sleep_not_selected_by_precision_gate(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " e9a: d107       bne.n eac "
                "<BufferExchange::get(FIFO<StreamBuffer*>*)+0xac>"
            ),
            (
                " e9a: e007       b.n eac "
                "<BufferExchange::get(FIFO<StreamBuffer*>*)+0xac>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "precision_capture flag must select exactly one timed-sleep path",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_extra_entry_edge_into_timed_sleep(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " e74: 7c2c       ldrb r4, [r5, #16]",
            (
                " e74: 7c2c       ldrb r4, [r5, #16]\n"
                " e75: d019       beq.n eac "
                "<BufferExchange::get(FIFO<StreamBuffer*>*)+0xac>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "precision_capture flag must select exactly one timed-sleep path",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_non_precision_final_report_identity(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " e18: 6bf6       ldr r6, [r6, #60]",
            " e18: 6bb6       ldr r6, [r6, #56]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "precision_rx_final_report load must address exactly",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_pre_sleep_null_value_clobber(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " e1e: f3bf 8f5f  dmb sy",
            (
                " e1d: 2401       movs r4, #1\n"
                " e1e: f3bf 8f5f  dmb sy"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "CAPTURE/null value on the pre-sleep fatal path is clobbered",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_cfg_bypass_around_precision_identity_gate(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " e0c: 7c2c       ldrb r4, [r5, #16]",
            (
                " e0b: d00d       beq.n e2a "
                "<BufferExchange::get(FIFO<StreamBuffer*>*)+0x2a>\n"
                " e0c: 7c2c       ldrb r4, [r5, #16]"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "capture direction load must dominate",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_pre_sleep_state_sample_without_dmb(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " e1e: f3bf 8f5f  dmb sy",
            " e1e: 46c0       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "pre-sleep M4 fatal state must be sampled after a linked DMB",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_precision_flag_clobber_before_timed_gate(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " e74: 7c2c       ldrb r4, [r5, #16]",
            (
                " e74: 7c2c       ldrb r4, [r5, #16]\n"
                " e75: 2600       movs r6, #0"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "precision_capture=true flag is clobbered",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_wrong_shared_m4_rate_state_offset(self):
        text_contents = replace_once(
            P12_TEXT_CONTENTS_FIXTURE,
            "00800810 5f1a0000 6c1f0020",
            "00800810 601a0000 6c1f0020",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "exactly two linked shared_memory.m4_dma_rate_state checks",
        ):
            self.verify_p12(text_contents=text_contents)

    def test_p12_rejects_shared_memory_reference_to_wrong_base(self):
        text_contents = replace_once(
            P12_TEXT_CONTENTS_FIXTURE,
            " 02000 00800810",
            " 02000 01800810",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "does not bind the reviewed 0x10088000 transport base",
        ):
            self.verify_p12(text_contents=text_contents)

    def test_p12_rejects_post_wake_state_other_than_fatal_five(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " ec2: 2b05       cmp r3, #5",
            " ec2: 2b04       cmp r3, #4",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "compare exactly against fatal state 5",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_post_wake_thread_clear_wrong_member(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " eb6: 60ec       str r4, [r5, #12]",
            " eb6: 60ac       str r4, [r5, #8]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "timed-wake thread clear must address exactly",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_unlock_that_dominates_timed_sleep(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " e98: 2e00       cmp r6, #0",
            (
                " e97: b662       cpsie i\n"
                " e98: 2e00       cmp r6, #0"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "timed sleep must be reached with the system lock held",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_cfg_bypass_around_each_timed_wake_check(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " eac: 2400       movs r4, #0",
            (
                " eac: 2400       movs r4, #0\n"
                " ead: d005       beq.n ebc "
                "<BufferExchange::get(FIFO<StreamBuffer*>*)+0xbc>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "precision timed sleep must dominate",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_null_value_clobbered_as_second_destination(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " eae: 210a       movs r1, #10",
            (
                " eae: 210a       movs r1, #10\n"
                " eaf: e9d0 6400  ldrd r6, r4, [r0]"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "null/thread-clear value is clobbered",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_abort_publication_wrong_member(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " eca: 3339       adds r3, #57",
            " eca: 333a       adds r3, #58",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "derive exactly CaptureConfig::application_abort_requested",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_abort_publication_not_true(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " ec6: 2201       movs r2, #1",
            " ec6: 2200       movs r2, #0",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "materialize abort-request=true",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_abort_publication_without_dmb(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " ece: f3bf 8f5f  dmb sy",
            " ece: 46c0       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "abort-request publication must be followed by DMB",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_fatal_path_non_null_return(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " e6c: 0020       movs r0, r4",
            " e6c: 0030       movs r0, r6",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "return the linked null register in r0",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_profile_rejects_each_wrong_transaction_metadata_value(self):
        for symbol, expected in verifier.P12_ABSOLUTE_METADATA.items():
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

    def test_partial_p12_metadata_cannot_fall_back_to_p11(self):
        nm = replace_once(
            P12_NM_FIXTURE,
            (
                "00000003 00000001 A "
                "hackrf_edge_precision_rx_app_rate_transaction_protocol_version\n"
            ),
            "",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "app_rate_transaction_protocol_version; found 0",
        ):
            self.verify_p12(nm=nm)

    def test_p12_rejects_clock_before_filter(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " b2a: f000 f800  bl  c20 "
                "<ReceiverModel::update_baseband_bandwidth()>\n"
                " b2e: 4630       mov r0, r6\n"
                " b30: f000 f800  bl  c40 "
                "<ReceiverModel::update_sampling_rate()>"
            ),
            (
                " b2a: f000 f800  bl  c40 "
                "<ReceiverModel::update_sampling_rate()>\n"
                " b2e: 4630       mov r0, r6\n"
                " b30: f000 f800  bl  c20 "
                "<ReceiverModel::update_baseband_bandwidth()>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "PREPARE -> target filter -> target clock",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_accepts_exact_segmented_receiver_write_veneers(self):
        nm, disassembly = segmented_rate_veneer_fixture()
        report = self.verify_p12(nm=nm, disassembly=disassembly)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(
            report["contract"],
            "precision-rx-application-linked-rate-transaction-v6",
        )

    def test_p13_rejects_segmented_veneer_without_exact_symbol(self):
        nm, disassembly = segmented_rate_veneer_fixture()
        nm = replace_once(
            nm,
            (
                "00003000 00000010 t "
                f"{verifier.RECEIVER_UPDATE_BANDWIDTH_VENEER_NAME}\n"
            ),
            "",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "one exact 16-byte code symbol",
        ):
            self.verify_p12(nm=nm, disassembly=disassembly)

    def test_p13_rejects_segmented_veneer_with_malformed_body(self):
        nm, disassembly = segmented_rate_veneer_fixture()
        disassembly = replace_once(
            disassembly,
            " 3000: b401       push {r0}",
            " 3000: 4770       bx lr",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "veneer body differs",
        ):
            self.verify_p12(nm=nm, disassembly=disassembly)

    def test_p13_rejects_segmented_veneer_with_wrong_literal(self):
        nm, disassembly = segmented_rate_veneer_fixture()
        disassembly = replace_once(
            disassembly,
            " 300c: 00000c21   .word 0x00000c21",
            " 300c: 00000c41   .word 0x00000c41",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "expected ultimate target",
        ):
            self.verify_p12(nm=nm, disassembly=disassembly)

    def test_p13_rejects_segmented_veneer_without_thumb_bit(self):
        nm, disassembly = segmented_rate_veneer_fixture()
        disassembly = replace_once(
            disassembly,
            " 300c: 00000c21   .word 0x00000c21",
            " 300c: 00000c20   .word 0x00000c20",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "Thumb bit",
        ):
            self.verify_p12(nm=nm, disassembly=disassembly)

    def test_p13_rejects_segmented_veneer_call_address_name_mismatch(self):
        nm, disassembly = segmented_rate_veneer_fixture()
        disassembly = replace_once(
            disassembly,
            (
                " b2a: f000 f800  bl  3000 "
                f"<{verifier.RECEIVER_UPDATE_BANDWIDTH_VENEER_NAME}>"
            ),
            (
                " b2a: f000 f800  bl  3060 "
                f"<{verifier.RECEIVER_UPDATE_BANDWIDTH_VENEER_NAME}>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "one exact 16-byte code symbol",
        ):
            self.verify_p12(nm=nm, disassembly=disassembly)

    def test_p13_rejects_segmented_veneer_wrong_ultimate_symbol(self):
        nm, disassembly = segmented_rate_veneer_fixture()
        nm = replace_once(
            nm,
            (
                "00000c20 00000020 T "
                "ReceiverModel::update_baseband_bandwidth()"
            ),
            (
                "00000c24 00000020 T "
                "ReceiverModel::update_baseband_bandwidth()"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "expected ultimate target",
        ):
            self.verify_p12(nm=nm, disassembly=disassembly)

    def test_p13_rejects_malformed_antenna_bias_veneer(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1408: 4760       bx ip",
            " 1408: 4770       bx lr",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "antenna-bias clear veneer body differs",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_receiver_enable_veneer_wrong_target(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 142c: 00001621   .word 0x00001621",
            " 142c: 00001601   .word 0x00001601",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "receiver enable veneer literal",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_lookalike_receiver_write_veneer(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            (
                " b30: f000 f800  bl  c40 "
                "<ReceiverModel::update_sampling_rate()>"
            ),
            (
                " b30: f000 f800  bl  c40 "
                "<___ZN13ReceiverModel20update_sampling_rateEv_"
                "veneer_lookalike>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "one target and one rollback write",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_lookalike_radio_disable_veneer(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " c70: f000 f800  bl  f00 <radio::disable()>",
            (
                " c70: f000 f800  bl  f00 "
                "<___ZN5radio7disableEv_veneer_lookalike>"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must link ReceiverModel::disable",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_abort_before_physical_rollback(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " b70: f000 f800  bl  c00 "
            "<baseband::send_precision_rx_message_bounded(Message const*)>",
            " b62: f000 f800  bl  c00 "
            "<baseband::send_precision_rx_message_bounded(Message const*)>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "rollback clock -> rollback filter -> ABORT",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_bounded_sender_without_terminal_acquire(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " c2e: f3bf 8f5f  dmb sy",
            " c2e: bf00       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "terminal slot state",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_bounded_sender_without_budget_decrement(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " c1c: 3c01       subs r4, #1",
            " c1c: 46c0       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "decrement its remaining budget",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_bounded_sender_without_zero_countdown_exit(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " c1e: d006       beq.n c2e "
            "<baseband::send_precision_rx_message_bounded(Message const*)+0x2e>",
            " c1e: bf00       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "exit on a zero countdown",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_bounded_sender_with_wrong_normalized_budget(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " c14: 2400       movs r4, #501",
            " c14: 2400       movs r4, #502",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "compiler-normalized countdown",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_bounded_sender_delegating_to_generic_sender(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " c22: f000 f800  bl  c80 <chThdSleep>",
            " c22: f000 f800  bl  c80 <baseband::send_message(Message const*)>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must not delegate",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_commit_timeout_path_reaching_rollback(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " b3e: b170       cbz r0, b9e "
            "<baseband::set_precision_rx(unsigned long)+0x9e>",
            " b3e: b170       cbz r0, b5e "
            "<baseband::set_precision_rx(unsigned long)+0x5e>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "COMMIT timeout path",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_unknown_commit_response_path_reaching_rollback(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " b4e: d826       bhi.n b9e "
            "<baseband::set_precision_rx(unsigned long)+0x9e>",
            " b4e: d806       bhi.n b5e "
            "<baseband::set_precision_rx(unsigned long)+0x5e>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "unknown COMMIT response path",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_wrong_paused_armed_state_path_reaching_rollback(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " b5c: d11f       bne.n b9e "
            "<baseband::set_precision_rx(unsigned long)+0x9e>",
            " b5c: d100       bne.n b5e "
            "<baseband::set_precision_rx(unsigned long)+0x5e>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "wrong PausedArmed state path",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_abort_timeout_path_reaching_ack_classification(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " b74: b198       cbz r0, b9e "
            "<baseband::set_precision_rx(unsigned long)+0x9e>",
            " b74: b100       cbz r0, b76 "
            "<baseband::set_precision_rx(unsigned long)+0x76>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "ABORT timeout",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_ack_aborted_wrong_state_returning_rolled_back(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " b88: d109       bne.n b9e "
            "<baseband::set_precision_rx(unsigned long)+0x9e>",
            " b88: d100       bne.n b8a "
            "<baseband::set_precision_rx(unsigned long)+0x8a>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "ACK_ABORTED wrong-state",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_rollback_state_other_than_paused_armed_three(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " b5a: 2a03       cmp r2, #3",
            " b5a: 2a01       cmp r2, #1",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "PausedArmed\\(3\\)",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_fault_shutdown_stack_or_transient_message(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " cd4: 2000300c   .word 0x2000300c",
            " cd4: 20000010   .word 0x20000010",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must use its persistent ShutdownMessage",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p15_rejects_fault_shutdown_message_wrong_size(self):
        nm = replace_once(
            P12_NM_FIXTURE,
            "2000300c 00000008 d "
            "baseband::(anonymous namespace)::"
            "precision_rx_fault_shutdown_message",
            "2000300c 00000004 d "
            "baseband::(anonymous namespace)::"
            "precision_rx_fault_shutdown_message",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "distinct persistent eight-byte initialized ShutdownMessage",
        ):
            self.verify_p12(nm=nm)

    def test_p15_rejects_fault_shutdown_message_uninitialized_kind(self):
        nm = replace_once(
            P12_NM_FIXTURE,
            "2000300c 00000008 d "
            "baseband::(anonymous namespace)::"
            "precision_rx_fault_shutdown_message",
            "2000300c 00000008 b "
            "baseband::(anonymous namespace)::"
            "precision_rx_fault_shutdown_message",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "distinct persistent eight-byte initialized ShutdownMessage",
        ):
            self.verify_p12(nm=nm)

    def test_p15_rejects_fault_shutdown_message_wrong_id_bytes(self):
        contents = replace_once(
            P12_TEXT_CONTENTS_FIXTURE,
            " 2000300c 05000000 01000000",
            " 2000300c 06000000 01000000",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must encode ID=5",
        ):
            self.verify_p12(text_contents=contents)

    def test_p15_rejects_fault_shutdown_message_wrong_mode_bytes(self):
        contents = replace_once(
            P12_TEXT_CONTENTS_FIXTURE,
            " 2000300c 05000000 01000000",
            " 2000300c 05000000 02000000",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "Mode::PrecisionRxFault=1",
        ):
            self.verify_p12(text_contents=contents)

    def test_p15_rejects_normal_shutdown_wrong_id(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1684: 2305       movs r3, #5",
            " 1684: 2304       movs r3, #4",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "Shutdown ID=5",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p15_rejects_normal_shutdown_wrong_mode(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1682: 2400       movs r4, #0",
            " 1682: 2401       movs r4, #1",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "Mode::Normal=0",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p15_rejects_normal_shutdown_send_pointer_not_stack(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1686: 4668       mov r0, sp",
            " 1686: 4620       mov r0, r4",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "exact stack ShutdownMessage address",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p15_rejects_normal_rf_disable_before_baseband_shutdown(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 16ae: f7ff ffe7  bl 1680 <baseband::shutdown()>\n"
            " 16b2: f000 f805  bl 16c0 <ReceiverModel::disable()>",
            " 16ae: f000 f805  bl 16c0 <ReceiverModel::disable()>\n"
            " 16b2: f7ff ffe7  bl 1680 <baseband::shutdown()>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "rate-fault split|complete baseband shutdown before "
            "ReceiverModel::disable",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p15_rejects_fault_path_reaching_normal_teardown(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 16ac: e003       b.n 16b6 "
            "<ui::external_app::precision_rx::PrecisionRxView::"
            "~PrecisionRxView()+0x16>",
            " 16ac: e000       b.n 16ae "
            "<ui::external_app::precision_rx::PrecisionRxView::"
            "~PrecisionRxView()+0xe>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "CFG successors must be disjoint",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p15_rejects_rate_fault_split_targeting_fault_path(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 16a6: d002       beq.n 16ae "
            "<ui::external_app::precision_rx::PrecisionRxView::"
            "~PrecisionRxView()+0xe>",
            " 16a6: d0ff       beq.n 16a8 "
            "<ui::external_app::precision_rx::PrecisionRxView::"
            "~PrecisionRxView()+0x8>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "rate-fault split",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_fault_shutdown_without_rf_disable(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " c9a: f000 f800  bl  f00 <radio::disable()>",
            " c9a: bf00       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must link ReceiverModel::disable",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_fault_helper_without_persistent_latch(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " c66: 701a       strb r2, [r3, #0]",
            " c66: bf00       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "set its persistent fault latch",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_true_antenna_bias_before_receiver_enable(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1302: 2000       movs r0, #0",
            " 1302: 2001       movs r0, #1",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "pass exact false",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_receiver_enable_path_bypassing_false_bias(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1300: b510       push {r4, lr}",
            " 1300: b111       cbz r1, 1308 "
            "<ui::external_app::precision_rx::PrecisionRxView::"
            "PrecisionRxView(ui::NavigationView&)+0x8>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must dominate ReceiverModel::enable",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_control_transfer_between_bias_and_enable(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " 1308: 4810       ldr r0, [pc, #64] ; "
            "(134c <ui::external_app::precision_rx::PrecisionRxView::"
            "PrecisionRxView(ui::NavigationView&)+0x4c>)",
            " 1308: f000 f800  bl  1440 <unreviewed_side_effect()>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "adjacent in linked control flow",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_bounded_sender_wrong_mailbox_member(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " c4c: 10089000   .word 0x10089000",
            " c4c: 10089004   .word 0x10089004",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "shared_memory.baseband_message",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_bounded_sender_without_event_after_publication(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " c12: bf40       sev",
            " c12: bf00       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "assert the M0-to-M4 event",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p13_rejects_bounded_sender_that_overwrites_occupied_mailbox(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " c06: b99a       cbnz r2, c30 "
            "<baseband::send_precision_rx_message_bounded(Message const*)+0x30>",
            " c06: bf00       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "reject an occupied",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_panic_on_defined_set_rate_path(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " b9e: f000 f800  bl  c60 <baseband::precision_rx_rate_fatal()>",
            " b9e: f000 f800  bl  c80 <chDbgPanic>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must not reach chDbgPanic",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_requires_linked_text_byte_image(self):
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "requires objdump -s section bytes",
        ):
            self.verify_p12(text_contents="")

    def test_p12_rejects_wrong_commit_control_word(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " bcc: 80000001   .word 0x80000001",
            " bcc: 80000003   .word 0x80000003",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "exact COMMIT",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_wrong_abort_control_word(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " bd4: 80000002   .word 0x80000002",
            " bd4: 80000003   .word 0x80000003",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "exact ABORT",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_prepare_payload_not_entry_rate(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " b06: 6065       str r5, [r4, #4]",
            " b06: 6066       str r6, [r4, #4]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "entry-rate PREPARE",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_send_pointer_to_wrong_persistent_object(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " b38: 4620       mov r0, r4",
            " b38: 4630       mov r0, r6",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must all pass the persistent",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_missing_commit_payload_writer(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " b36: 6063       str r3, [r4, #4]",
            " b36: 46c0       nop",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "exact COMMIT",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_missing_aborted_acknowledgement(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " bd8: c0000004   .word 0xc0000004",
            " bd8: c0000003   .word 0xc0000003",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "ABORTED acknowledgement",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_unbounded_set_rate_cycle(self):
        disassembly = replace_once(
            P12_DISASSEMBLY_FIXTURE,
            " ba2: e000       b.n ba4 <baseband::set_precision_rx(unsigned long)+0xa4>",
            " ba2: e7fc       b.n b9e <baseband::set_precision_rx(unsigned long)+0x9e>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "unbounded control-flow cycle",
        ):
            self.verify_p12(disassembly=disassembly)

    def test_p12_rejects_nonpersistent_message_symbol(self):
        nm = replace_once(
            P12_NM_FIXTURE,
            (
                "20003000 00000008 b "
                "baseband::(anonymous namespace)::precision_rx_rate_message"
            ),
            (
                "20003000 00000004 b "
                "baseband::(anonymous namespace)::precision_rx_rate_message"
            ),
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "persistent eight-byte",
        ):
            self.verify_p12(nm=nm)

    def test_accepts_direct_wait_ready_helper(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            "<sdc_lld_send_cmd_short_crc>",
            "<sdc_lld_capture_wait_ready(SDCDriver*)>",
        )
        report = self.verify(disassembly=disassembly)
        self.assertIn(
            "sdc_lld_capture_wait_ready(SDCDriver*)",
            report["pipeline"]["ready_evidence_targets"],
        )

    def test_rejects_each_wrong_absolute_metadata_value(self):
        cases = {
            "00000009 00000001 A hackrf_edge_precision_rx_app_local_buffer_count":
                "00000008 00000001 A hackrf_edge_precision_rx_app_local_buffer_count",
            "00000002 00000001 A hackrf_edge_precision_rx_app_spill_buffer_count":
                "00000003 00000001 A hackrf_edge_precision_rx_app_spill_buffer_count",
            "00004000 00000004 A hackrf_edge_precision_rx_app_spill_bytes":
                "00006000 00000004 A hackrf_edge_precision_rx_app_spill_bytes",
            "00000400 00000004 A hackrf_edge_precision_rx_app_thread_stack_bytes":
                "00000800 00000004 A hackrf_edge_precision_rx_app_thread_stack_bytes",
            "00000090 00000004 A hackrf_edge_precision_rx_app_capture_config_bytes":
                "0000008c 00000004 A hackrf_edge_precision_rx_app_capture_config_bytes",
            "000000d8 00000004 A hackrf_edge_precision_rx_app_capture_thread_bytes":
                "000000dc 00000004 A hackrf_edge_precision_rx_app_capture_thread_bytes",
            "00000001 00000001 A hackrf_edge_precision_rx_app_dma_abort_requires_consumer_release":
                "00000000 00000001 A hackrf_edge_precision_rx_app_dma_abort_requires_consumer_release",
            "00000001 00000001 A hackrf_edge_precision_rx_journal_fail_closed_recovery":
                "00000000 00000001 A hackrf_edge_precision_rx_journal_fail_closed_recovery",
        }
        for old, new in cases.items():
            with self.subTest(symbol=old.rsplit(" ", 1)[-1]):
                with self.assertRaises(verifier.VerificationError):
                    self.verify(nm=replace_once(NM_FIXTURE, old, new))

    def test_rejects_non_absolute_metadata(self):
        nm = replace_once(
            NM_FIXTURE,
            "00004000 00000004 A hackrf_edge_precision_rx_app_spill_bytes",
            "00004000 00000004 D hackrf_edge_precision_rx_app_spill_bytes",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "must be an absolute"):
            self.verify(nm=nm)

    def test_rejects_heap_bound_outside_m0_sram(self):
        nm = replace_once(
            NM_FIXTURE,
            "20010000 A __heap_end__",
            "20010004 A __heap_end__",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "outside M0 SRAM"):
            self.verify(nm=nm)

    def test_rejects_heap_smaller_than_reviewed_minimum(self):
        nm = replace_once(
            NM_FIXTURE,
            "20004c10 B __heap_base__",
            "2000b000 B __heap_base__",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "minimum is 24576"):
            self.verify(nm=nm)

    def test_accepts_exact_minimum_modeled_heap_residual(self):
        nm = replace_once(
            NM_FIXTURE,
            "20004c10 B __heap_base__",
            "20005000 B __heap_base__",
        )
        report = self.verify(nm=nm)
        self.assertEqual(
            report["allocation"][
                "modeled_heap_residual_after_spill_and_stack_bytes"
            ],
            27648,
        )
        self.assertEqual(
            report["allocation"]["modeled_heap_residual_margin_bytes"],
            0,
        )

    def test_rejects_modeled_heap_residual_one_byte_below_minimum(self):
        nm = replace_once(
            NM_FIXTURE,
            "20004c10 B __heap_base__",
            "20005001 B __heap_base__",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "modeled M0 heap residual is 27647 bytes; minimum is 27648",
        ):
            self.verify(nm=nm)

    def test_rejects_constructor_larger_than_reviewed_ceiling(self):
        nm = NM_FIXTURE.replace("0000011c T CaptureThread::CaptureThread", "00000141 T CaptureThread::CaptureThread")
        with self.assertRaisesRegex(verifier.VerificationError, "maximum is 320"):
            self.verify(nm=nm)

    def test_rejects_duplicate_spill_allocation(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 108: f3bf 8f5f  dmb sy",
            " 106: f000 f800  bl  900 <chHeapAlloc>\n 108: f3bf 8f5f  dmb sy",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "exactly once; found 2"):
            self.verify(disassembly=disassembly)

    def test_rejects_wrong_shifted_spill_allocation(self):
        disassembly = replace_once(DISASSEMBLY_FIXTURE, "#7\n 104:", "#6\n 104:")
        with self.assertRaisesRegex(verifier.VerificationError, "8192 bytes"):
            self.verify(disassembly=disassembly)

    def test_rejects_unknown_argument_writer(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 102: 01c9       lsls r1, r1, #7",
            " 102: 3101       adds r1, #1",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "last writer is adds"):
            self.verify(disassembly=disassembly)

    def test_rejects_wrong_shifted_thread_stack(self):
        disassembly = replace_once(DISASSEMBLY_FIXTURE, "#3\n 110:", "#4\n 110:")
        with self.assertRaisesRegex(verifier.VerificationError, "2048 bytes"):
            self.verify(disassembly=disassembly)

    def test_rejects_missing_publish_dmb(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 108: f3bf 8f5f  dmb sy\n",
            "",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "publish the spill loan"):
            self.verify(disassembly=disassembly)

    def test_rejects_missing_destructor_free(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 304: f000 f800  bl  940 <chHeapFree>",
            " 304: 46c0       nop",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "chHeapFree exactly once"):
            self.verify(disassembly=disassembly)

    def test_rejects_static_fn_memcpy_but_allows_memset(self):
        disassembly = replace_once(DISASSEMBLY_FIXTURE, "<memset>", "<memcpy>")
        with self.assertRaisesRegex(verifier.VerificationError, "must not call memcpy"):
            self.verify(disassembly=disassembly)

    def test_rejects_missing_static_fn_dmb(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 402: f3bf 8f5f  dmb sy",
            " 402: 46c0       nop",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "at least one DMB"):
            self.verify(disassembly=disassembly)

    def test_rejects_ready_call_after_dequeue(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 408: f000 f800  bl  a20 <sdc_lld_send_cmd_short_crc>\n 40c: f000 f800  bl  a40 <BufferExchange::get(FIFO<StreamBuffer*>*)>",
            " 408: f000 f800  bl  a40 <BufferExchange::get(FIFO<StreamBuffer*>*)>\n 40c: f000 f800  bl  a20 <sdc_lld_send_cmd_short_crc>",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "must precede"):
            self.verify(disassembly=disassembly)

    def test_rejects_missing_ready_evidence(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            "<sdc_lld_send_cmd_short_crc>",
            "<unrelated_sd_call>",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "SD ready helper"):
            self.verify(disassembly=disassembly)

    def test_rejects_missing_buffer_exchange_get(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            "<BufferExchange::get(FIFO<StreamBuffer*>*)>",
            "<BufferExchange::get_prefill(FIFO<StreamBuffer*>*)>",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "BufferExchange::get exactly once"):
            self.verify(disassembly=disassembly)

    def test_rejects_missing_indirect_writer_after_dequeue(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 414: 4798       blx r3",
            " 414: f000 f800  bl  aa0 <direct_call>",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "indirect writer call"):
            self.verify(disassembly=disassembly)

    def test_rejects_missing_recycle_after_writer(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 418: f000 f800  bl  a80 <FIFO<StreamBuffer*>::in(StreamBuffer* const&)>",
            " 418: f000 f800  bl  a80 <unrelated_fifo_call>",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "must recycle through"):
            self.verify(disassembly=disassembly)

    def test_rejects_consumer_release_before_buffer_exchange_teardown(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 41c: f000 f800  bl  aa0 <BufferExchange::~BufferExchange()>\n"
            " 420: 0038       movs r0, r7\n"
            " 422: 303a       adds r0, #0x3a\n"
            " 424: f000 f800  bl  ac0 <hackrf_edge_precision_rx_publish_dma_consumer_release>",
            " 41c: f000 f800  bl  ac0 <hackrf_edge_precision_rx_publish_dma_consumer_release>\n"
            " 420: 0038       movs r0, r7\n"
            " 422: 303a       adds r0, #0x3a\n"
            " 424: f000 f800  bl  aa0 <BufferExchange::~BufferExchange()>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError, "before publishing DMA consumer release"
        ):
            self.verify(disassembly=disassembly)

    def test_rejects_nonzero_consumer_release_store(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 804: 2300       movs r3, #0",
            " 804: 2301       movs r3, #1",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "initialize r3 to zero"):
            self.verify(disassembly=disassembly)

    def test_rejects_consumer_release_without_post_store_dmb(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 808: f3bf 8f5f  dmb sy",
            " 808: 46c0       nop",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "DMB after"):
            self.verify(disassembly=disassembly)

    def test_rejects_consumer_release_without_pre_store_dmb(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 800: f3bf 8f5f  dmb sy",
            " 800: 46c0       nop",
        )
        with self.assertRaisesRegex(verifier.VerificationError, "DMB before"):
            self.verify(disassembly=disassembly)

    def test_rejects_metadata_preserving_wrong_release_member_offset(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 422: 303a       adds r0, #0x3a",
            " 422: 303b       adds r0, #0x3b",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "argument offset is 59; expected 58",
        ):
            self.verify(disassembly=disassembly)

    def test_rejects_release_argument_not_derived_from_entry_this(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 400: 0007       movs r7, r0",
            " 400: 000f       movs r7, r1",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must initialize r7 from entry r0",
        ):
            self.verify(disassembly=disassembly)

    def test_rejects_release_argument_clobbered_after_offset_add(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 424: f000 f800  bl  ac0 <hackrf_edge_precision_rx_publish_dma_consumer_release>",
            " 423: bc01       pop {r0}\n"
            " 424: f000 f800  bl  ac0 <hackrf_edge_precision_rx_publish_dma_consumer_release>",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "immediate add to r0",
        ):
            self.verify(disassembly=disassembly)

    def test_rejects_saved_this_clobbered_as_second_load_destination(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 402: f3bf 8f5f  dmb sy",
            " 402: f3bf 8f5f  dmb sy\n"
            " 403: e9d1 6700  ldrd r6, r7, [r1]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "save its entry this pointer exactly once",
        ):
            self.verify(disassembly=disassembly)

    def test_rejects_release_helper_store_beyond_argument(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 806: 7003       strb r3, [r0, #0]",
            " 806: 7043       strb r3, [r0, #1]",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "byte store must target exactly",
        ):
            self.verify(disassembly=disassembly)

    def test_rejects_missing_stop_to_journal_recovery_call(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            "<ui::external_app::precision_rx::PrecisionRxView::recover_snapshot_journal(PrecisionRxCaptureEvidence const&, ui::external_app::precision_rx::SnapshotJournalBounds const&)>\n a06:",
            "<unrelated_journal_function>\n a06:",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "snapshot-journal recovery exactly once; found 0",
        ):
            self.verify(disassembly=disassembly)

    def test_accepts_segmented_stop_to_journal_recovery_veneer(self):
        veneer_address = 0x1700
        veneer_name = verifier.JOURNAL_RECOVERY_VENEER_NAME
        veneer_nm, veneer_disassembly = thumb_veneer_fixture(
            veneer_address,
            veneer_name,
            0x0900,
        )
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            (
                " a02: f000 f800  bl  900 "
                "<ui::external_app::precision_rx::PrecisionRxView::"
                "recover_snapshot_journal(PrecisionRxCaptureEvidence const&, "
                "ui::external_app::precision_rx::SnapshotJournalBounds const&)>"
            ),
            f" a02: f000 f800  bl  1700 <{veneer_name}>",
        )
        report = self.verify(
            nm=NM_FIXTURE + veneer_nm,
            disassembly=disassembly + veneer_disassembly,
        )
        self.assertEqual(report["journal_recovery"]["direct_call_count"], 1)

    def test_rejects_journal_recovery_bulk_copy_call(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 908: b00d       add sp, #0x34",
            " 907: f000 f800  bl  b00 <memcpy>\n"
            " 908: b00d       add sp, #0x34",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "must remain call-free",
        ):
            self.verify(disassembly=disassembly)

    def test_rejects_journal_recovery_1664_byte_local_copy(self):
        disassembly = replace_once(
            DISASSEMBLY_FIXTURE,
            " 902: b08d       sub sp, #0x34",
            " 902: b08d       sub sp, #0x680",
        )
        disassembly = replace_once(
            disassembly,
            " 908: b00d       add sp, #0x34",
            " 908: b00d       add sp, #0x680",
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "local stack frame is 1664 bytes; maximum is 256",
        ):
            self.verify(disassembly=disassembly)


if __name__ == "__main__":
    unittest.main()
