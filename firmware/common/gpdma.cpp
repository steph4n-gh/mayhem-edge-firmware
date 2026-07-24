/*
 * Copyright (C) 2014 Jared Boone, ShareBrained Technology, Inc.
 *
 * This file is part of PortaPack.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#include "gpdma.hpp"

#include <array>

namespace lpc43xx {
namespace gpdma {

namespace {

struct ChannelHandlers {
    TCHandler tc;
    ErrHandler err;

    constexpr ChannelHandlers()
        : tc(nullptr),
          err(nullptr) {
    }
};

}  // namespace

static std::array<ChannelHandlers, channels.size()> handlers_table{{}};

namespace channel {

void Channel::set_handlers(const TCHandler tc_handler, const ErrHandler err_handler) const {
    handlers_table[number].tc = tc_handler;
    handlers_table[number].err = err_handler;
}

void Channel::configure(
    const LLI& first_lli,
    const uint32_t config) const {
    disable();
    clear_interrupts();

    LPC_GPDMA_Channel_Type* const channel = &LPC_GPDMA->CH[number];
    channel->SRCADDR = first_lli.srcaddr;
    channel->DESTADDR = first_lli.destaddr;
    channel->LLI = first_lli.lli;
    channel->CONTROL = first_lli.control;
    channel->CONFIG = config;
}

} /* namespace channel */

extern "C" {

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
/*
 * Implemented by the P12 Precision RX DMA path. The fast pair performs only
 * MMIO, fixed-ring publication, and scalar telemetry; the deferred routine is
 * the sole bridge into ChibiOS.
 */
void hackrf_edge_precision_rx_dma_fast_terminal_count(void);
void hackrf_edge_precision_rx_dma_fast_fault(uint32_t pending_terminal_count);
void hackrf_edge_precision_rx_dma_deferred_interrupt(void);

CH_FAST_IRQ_HANDLER(DMA_IRQHandler) {
    constexpr uint32_t precision_rx_channel_mask = 1U;
    const uint32_t tc_stat = LPC_GPDMA->INTTCSTAT;
    const uint32_t err_stat = LPC_GPDMA->INTERRSTAT;
    const uint32_t enabled_channels = LPC_GPDMA->ENBLDCHNS;
    const bool unexpected_channel =
        ((tc_stat | err_stat | enabled_channels) &
         ~precision_rx_channel_mask) != 0U;
    const bool fault =
        unexpected_channel ||
        (err_stat & precision_rx_channel_mask) != 0U;

    /*
     * ERR is W1C only after the product fault gate has closed. TC is W1C
     * before normal bookkeeping so a later completion can re-pend this
     * priority-1 vector instead of merging into the current sticky bit.
     */
    if (fault) {
        hackrf_edge_precision_rx_dma_fast_fault(
            (tc_stat & precision_rx_channel_mask) != 0U ? 1U : 0U);
    }
    if (tc_stat != 0U) {
        LPC_GPDMA->INTTCCLR = tc_stat;
        __DMB();
        if (!fault &&
            (tc_stat & precision_rx_channel_mask) != 0U) {
            hackrf_edge_precision_rx_dma_fast_terminal_count();
        }
    }
    if (err_stat != 0U) {
        if (!fault) {
            hackrf_edge_precision_rx_dma_fast_fault(0U);
        }
        __DMB();
        LPC_GPDMA->INTERRCLR = err_stat;
    }

    if (fault || (tc_stat | err_stat) != 0U) {
        __DMB();
        NVIC_ISPR(SGPIO_IRQn >> 5U) =
            1U << (SGPIO_IRQn & 0x1fU);
    }
}

CH_IRQ_HANDLER(SGPIO_IRQHandler) {
    CH_IRQ_PROLOGUE();
    chSysLockFromIsr();
    hackrf_edge_precision_rx_dma_deferred_interrupt();
    chSysUnlockFromIsr();
    CH_IRQ_EPILOGUE();
}
#else
CH_IRQ_HANDLER(DMA_IRQHandler) {
    CH_IRQ_PROLOGUE();

    chSysLockFromIsr();

    const auto tc_stat = LPC_GPDMA->INTTCSTAT;
    /* TODO: Service the higher channel numbers first, they're higher priority
     * right?!?
     */
    for (size_t i = 0; i < handlers_table.size(); i++) {
        if ((tc_stat >> i) & 1) {
            if (handlers_table[i].tc) {
                handlers_table[i].tc();
            }
        }
    }
    LPC_GPDMA->INTTCCLR = tc_stat;

    /* Test for *any* error first, before looping, since errors should be
     * exceptional and we should spend as little time on them in the common
     * case.
     */
    const auto err_stat = LPC_GPDMA->INTERRSTAT;
    if (err_stat) {
        for (size_t i = 0; i < handlers_table.size(); i++) {
            if ((err_stat >> i) & 1) {
                if (handlers_table[i].err) {
                    handlers_table[i].err();
                }
            }
        }
        LPC_GPDMA->INTERRCLR = err_stat;
    }

    chSysUnlockFromIsr();

    CH_IRQ_EPILOGUE();
}
#endif
}

} /* namespace gpdma */
} /* namespace lpc43xx */
