/*
 * Copyright (C) 2016 Jared Boone, ShareBrained Technology, Inc.
 * Copyright (C) 2016 Furrtek
 * Modified for HackRF Edge in 2026 by HackRF Edge contributors.
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

#include "baseband_api.hpp"
#include <cstring>

#include "audio.hpp"
#include "tonesets.hpp"
#include "dsp_iir_config.hpp"

#include "portapack_shared_memory.hpp"
#include "portapack_persistent_memory.hpp"

#include "core_control.hpp"

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
#include "portapack.hpp"
#include "ui_spectrum.hpp"
#endif

/* Set true to enable additional checks to ensure
 * M4 and M0 are synchronized before passing messages. */
static constexpr bool enforce_core_sync = true;

/* Set true to enable check for baseband messages getting stuck.
 * This implies the baseband thread is not dequeuing and has probably stalled.
 * NB: This check adds a small amout of overhead to the message sending code
 * and may impact application perf if it is sending a lot of messages. */
static constexpr bool check_for_message_hang = true;

using namespace portapack;

#if defined(__arm__) && \
    defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
/*
 * Linked p12 M0 policy evidence. The application verifier also inspects the
 * optimized call ordering; these absolutes make profile detection and the
 * reviewed fail-closed contract explicit.
 */
__asm__(
    ".global hackrf_edge_precision_rx_app_rate_transaction_protocol_version\n"
    ".type hackrf_edge_precision_rx_app_rate_transaction_protocol_version, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_transaction_protocol_version, 3\n"
    ".size hackrf_edge_precision_rx_app_rate_transaction_protocol_version, 1\n"
    ".global hackrf_edge_precision_rx_app_rate_prepare_before_physical_change\n"
    ".type hackrf_edge_precision_rx_app_rate_prepare_before_physical_change, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_prepare_before_physical_change, 1\n"
    ".size hackrf_edge_precision_rx_app_rate_prepare_before_physical_change, 1\n"
    ".global hackrf_edge_precision_rx_app_rate_filter_before_clock\n"
    ".type hackrf_edge_precision_rx_app_rate_filter_before_clock, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_filter_before_clock, 1\n"
    ".size hackrf_edge_precision_rx_app_rate_filter_before_clock, 1\n"
    ".global hackrf_edge_precision_rx_app_rate_commit_after_physical_change\n"
    ".type hackrf_edge_precision_rx_app_rate_commit_after_physical_change, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_commit_after_physical_change, 1\n"
    ".size hackrf_edge_precision_rx_app_rate_commit_after_physical_change, 1\n"
    ".global hackrf_edge_precision_rx_app_rate_rollback_before_abort\n"
    ".type hackrf_edge_precision_rx_app_rate_rollback_before_abort, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_rollback_before_abort, 1\n"
    ".size hackrf_edge_precision_rx_app_rate_rollback_before_abort, 1\n"
    ".global hackrf_edge_precision_rx_app_rate_fail_closed\n"
    ".type hackrf_edge_precision_rx_app_rate_fail_closed, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_fail_closed, 1\n"
    ".size hackrf_edge_precision_rx_app_rate_fail_closed, 1\n"
    ".global hackrf_edge_precision_rx_app_rate_bounded_wait_iterations\n"
    ".type hackrf_edge_precision_rx_app_rate_bounded_wait_iterations, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_bounded_wait_iterations, 500\n"
    ".size hackrf_edge_precision_rx_app_rate_bounded_wait_iterations, 4\n"
    ".global hackrf_edge_precision_rx_app_rate_persistent_message\n"
    ".type hackrf_edge_precision_rx_app_rate_persistent_message, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_persistent_message, 1\n"
    ".size hackrf_edge_precision_rx_app_rate_persistent_message, 1\n"
    ".global hackrf_edge_precision_rx_app_rate_rejection_no_panic\n"
    ".type hackrf_edge_precision_rx_app_rate_rejection_no_panic, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_rejection_no_panic, 1\n"
    ".size hackrf_edge_precision_rx_app_rate_rejection_no_panic, 1\n"
    ".global hackrf_edge_precision_rx_app_rate_fault_shutdown_bounded\n"
    ".type hackrf_edge_precision_rx_app_rate_fault_shutdown_bounded, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_fault_shutdown_bounded, 1\n"
    ".size hackrf_edge_precision_rx_app_rate_fault_shutdown_bounded, 1\n"
    ".global hackrf_edge_precision_rx_app_rate_rollback_requires_paused_armed\n"
    ".type hackrf_edge_precision_rx_app_rate_rollback_requires_paused_armed, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_rollback_requires_paused_armed, 1\n"
    ".size hackrf_edge_precision_rx_app_rate_rollback_requires_paused_armed, 1\n"
    ".global hackrf_edge_precision_rx_app_rate_commit_timeout_no_rollback\n"
    ".type hackrf_edge_precision_rx_app_rate_commit_timeout_no_rollback, %object\n"
    ".set hackrf_edge_precision_rx_app_rate_commit_timeout_no_rollback, 1\n"
    ".size hackrf_edge_precision_rx_app_rate_commit_timeout_no_rollback, 1\n");
#endif

namespace baseband {

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
/*
 * This transaction machinery is used only by the Precision RX external app.
 * Keep its code in that app's load image instead of consuming the last bytes
 * of the fixed 1 MiB aggregate SPI image. Persistent mailbox objects remain
 * in M0 RAM so a delayed M4 can never observe an expired stack object.
 */
#define HACKRF_EDGE_PRECISION_RX_EXTERNAL_TEXT \
    __attribute__((section(".text.ui.external_app.precision_rx.rate_transaction")))

namespace {

constexpr uint32_t precision_rx_rate_message_wait_iterations = 500U;
constexpr uint8_t precision_rx_rate_state_running = 1U;
constexpr uint8_t precision_rx_rate_state_paused_armed = 3U;
PrecisionRxConfigMessage precision_rx_rate_message{};
ShutdownMessage precision_rx_fault_shutdown_message{
    ShutdownMessage::Mode::PrecisionRxFault};
bool precision_rx_rate_fault_latched{false};

}  // namespace

HACKRF_EDGE_PRECISION_RX_EXTERNAL_TEXT
__attribute__((noinline, noclone, used, externally_visible, optimize("Os", "no-if-conversion", "no-if-conversion2"))) bool send_precision_rx_message_bounded(const Message* const message) {
    /*
     * Callers provide persistent storage. A timeout therefore cannot publish
     * a pointer to an expired stack frame if the M4 is delayed or faulted.
     */
    if (shared_memory.baseband_message != nullptr) {
        return false;
    }

    __DMB();
    shared_memory.baseband_message = message;
    __DMB();
    creg::m0apptxevent::assert_event();

    uint32_t remaining = precision_rx_rate_message_wait_iterations;
    while (shared_memory.baseband_message != nullptr && remaining != 0U) {
        --remaining;
        chThdSleepMilliseconds(1);
    }
    __DMB();
    return shared_memory.baseband_message == nullptr;
}

HACKRF_EDGE_PRECISION_RX_EXTERNAL_TEXT
static bool precision_rx_rate_state_is(const uint8_t expected) {
    __DMB();
    return shared_memory.m4_dma_rate_state == expected;
}

HACKRF_EDGE_PRECISION_RX_EXTERNAL_TEXT
static PrecisionRxRateResult precision_rx_rate_fatal() {
    precision_rx_rate_fault_latched = true;
    receiver_model.disable();
    return PrecisionRxRateResult::Fatal;
}
#endif

static void send_message(const Message* const message) {
    // If message is only sent by this function via one thread, no need to check if
    // another message is present before setting new message.
    shared_memory.baseband_message = message;
    creg::m0apptxevent::assert_event();

    if constexpr (check_for_message_hang) {
#ifdef PRALINE
        /* Timeout: ~3 seconds at typical clock speeds */
        auto count = 200'000'000u;
#else
        auto count = UINT32_MAX;
#endif
        while (shared_memory.baseband_message && --count)
            /* spin */;

        if (count == 0)
#ifdef PRALINE
            chDbgPanic("BB Msg Timeout");
#else
            chDbgPanic("Baseband Send Fail");
#endif
    } else {
        while (shared_memory.baseband_message)
            /* spin */;
    }
}

void AMConfig::apply() const {
    const AMConfigureMessage message{
        taps_6k0_decim_0,             // common FIR filter taps pre-decim_0 to all 6 x AM mod types.(AM-9K, AM-6K, USB, LSB, CW, AMFM-WFAX)
        decim_1,                      // var decim_1 FIR taps filter , variable values , to handle two spectrum decim factor 1 and 2 (zoom) and more APT LPF filtered .
        decim_2,                      // var decim_2 FIR taps filter , variable values, depending selected  AM mod(AM  9k / 6k and all rest AM modes)
        channel,                      // var channel FIR taps filter , variable values, depending selected  AM mode, each one different  (DSB-9K, DSB-6K, USB-3K, LSB-3K,CW,AMFM-WFAX)
        modulation,                   // var parameter . enum class Modulation : int32_t {DSB = 0, SSB = 1, SSB_FM = 2}
        audio_12k_iir_filter_config,  // var parameter , 300 Hz hpf all except Wefax (1.500Hz lpf)
        spectrum_decimation_factor};  // var parameter , waterfall no zoom : 1 ,for zoom x 2 : 2
    send_message(&message);
    audio::set_rate(audio::Rate::Hz_12000);
}

void NBFMConfig::apply(const uint8_t squelch_level) const {
    const NBFMConfigureMessage message{
        decim_0,
        decim_1,
        channel,
        2,
        deviation,
        audio_24k_hpf_300hz_config,
        audio_24k_deemph_300_6_config,
        squelch_level};
    send_message(&message);
    audio::set_rate(audio::Rate::Hz_24000);
}

void WFMConfig::apply() const {
    const WFMConfigureMessage message{
        decim_0,             // 	Dynamic array 24 taps : taps_200k_decim_0 , 	taps_180k_wfm_decim_0, taps_80k_wfm_decim_0
        decim_1,             // 	Dynamic array 16 taps : taps_200k_decim_1 or 	taps_180k_wfm_decim_1, taps_80k_wfm_decim_1
        taps_64_lp_156_198,  // Fixed channel audio filter 15khz
        75000,
        audio_48k_hpf_30hz_config,
        audio_48k_deemph_2122_6_config};
    send_message(&message);
    audio::set_rate(audio::Rate::Hz_48000);
}

void WFMAMConfig::apply() const {
    const WFMAMConfigureMessage message{
        decim_0,         // 	Fixed 24 taps array : taps_16k0_decim_0
        decim_1,         // Dynamic  32 taps array : taps_80k_wfmam_decim_1, 38k_wfmam
        taps_64_lp_bpf,  // Dynamic 64 taps array , to filter modulated DSB AM 2k4 carrier before demod. AM .(LPF / BPF)
        17000,           // NOAA satellite tx , FM deviation = +-17Khz.
        apt_audio_12k_notch_2k4_config,
        apt_audio_12k_lpf_2000hz_config};
    send_message(&message);
    audio::set_rate(audio::Rate::Hz_12000);
}

void set_tone(const uint32_t index, const uint32_t delta, const uint32_t duration) {
    shared_memory.bb_data.tones_data.tone_defs[index].delta = delta;
    shared_memory.bb_data.tones_data.tone_defs[index].duration = duration;
}

void set_tones_config(const uint32_t bw, const uint32_t pre_silence, const uint16_t tone_count, const bool dual_tone, const bool audio_out) {
    const TonesConfigureMessage message{
        bw,
        pre_silence,
        tone_count,
        dual_tone,
        audio_out};
    send_message(&message);
}

void kill_tone() {
    const TonesConfigureMessage message{
        0,
        0,
        0,
        false,
        false};
    send_message(&message);
}

void set_sstv_data(const uint8_t vis_code, const uint32_t pixel_duration) {
    const SSTVConfigureMessage message{
        vis_code,
        pixel_duration};
    send_message(&message);
}

void set_sstvrx_data(const uint8_t code) {
    const SSTVRXConfigureMessage message{
        code};
    send_message(&message);
}

void set_sstvrx_phase_slant(const int16_t phase, const int16_t slant) {
    const SSTVRXPhaseSlantMessage message{
        phase,
        slant};
    send_message(&message);
}

void set_afsk(const uint32_t baudrate, const uint32_t word_length, const uint32_t trigger_value, const bool trigger_word) {
    const AFSKRxConfigureMessage message{
        baudrate,
        word_length,
        trigger_value,
        trigger_word};
    send_message(&message);
}

void set_aprs(const uint32_t baudrate) {
    const APRSRxConfigureMessage message{
        baudrate};
    send_message(&message);
}

void set_btlerx(uint8_t channel_number) {
    const BTLERxConfigureMessage message{
        channel_number};
    send_message(&message);
}

void set_btletx(uint8_t channel_number, char* macAddress, char* advertisementData, uint8_t pduType) {
    const BTLETxConfigureMessage message{
        channel_number,
        macAddress,
        advertisementData,
        pduType};
    send_message(&message);
}

void set_nrf(const uint32_t baudrate, const uint32_t word_length, const uint32_t trigger_value, const bool trigger_word) {
    const NRFRxConfigureMessage message{
        baudrate,
        word_length,
        trigger_value,
        trigger_word};
    send_message(&message);
}

void set_fsk(const uint8_t samplesPerSymbol, const uint32_t syncWord, const uint8_t syncWordLength, const uint32_t preamble, const uint8_t preambleLength, uint16_t numDataBytes) {
    const FSKRxConfigureMessage message{
        samplesPerSymbol,
        syncWord,
        syncWordLength,
        preamble,
        preambleLength,
        numDataBytes};

    send_message(&message);
}

void set_afsk_data(const uint32_t afsk_samples_per_bit, const uint32_t afsk_phase_inc_mark, const uint32_t afsk_phase_inc_space, const uint8_t afsk_repeat, const uint32_t afsk_bw, const uint8_t symbol_count) {
    const AFSKTxConfigureMessage message{
        afsk_samples_per_bit,
        afsk_phase_inc_mark,
        afsk_phase_inc_space,
        afsk_repeat,
        afsk_bw,
        symbol_count};
    send_message(&message);
}

void kill_afsk() {
    const AFSKTxConfigureMessage message{
        0,
        0,
        0,
        0,
        0,
        false};
    send_message(&message);
}

void set_audiotx_config(
    const uint32_t divider,
    const float deviation_hz,
    const float audio_gain,
    uint8_t audio_shift_bits_s16,
    uint8_t bits_per_sample,
    const uint32_t tone_key_delta,
    const bool am_enabled,
    const bool dsb_enabled,
    const bool usb_enabled,
    const bool lsb_enabled) {
    const AudioTXConfigMessage message{
        divider,
        deviation_hz,
        audio_gain,
        audio_shift_bits_s16,
        bits_per_sample,
        tone_key_delta,
        (float)persistent_memory::tone_mix() / 100.0f,
        am_enabled,
        dsb_enabled,
        usb_enabled,
        lsb_enabled};
    send_message(&message);
}

void set_fifo_data(const int8_t* data) {
    const FIFODataMessage message{
        data};
    send_message(&message);
}

void set_pitch_rssi(int32_t avg, bool enabled) {
    const PitchRSSIConfigureMessage message{
        enabled,
        avg};
    send_message(&message);
}

void set_ook_data(const uint32_t stream_length, const uint32_t samples_per_bit, const uint8_t repeat, const uint32_t pause_symbols, const uint8_t de_bruijn_length) {
    const OOKConfigureMessage message{
        stream_length,
        samples_per_bit,
        repeat,
        pause_symbols,
        de_bruijn_length};
    send_message(&message);
}

void kill_ook() {
    const OOKConfigureMessage message{
        0,
        0,
        0,
        0,
        0};
    send_message(&message);
}

void set_fsk_data(const uint32_t stream_length, const uint32_t samples_per_bit, const uint32_t shift, const uint32_t progress_notice) {
    const FSKConfigureMessage message{
        stream_length,
        samples_per_bit,
        shift,
        progress_notice};
    send_message(&message);
}

void set_pocsag(int8_t baud_config) {
    const POCSAGConfigureMessage message{baud_config};
    send_message(&message);
}

void set_adsb() {
    const ADSBConfigureMessage message{};
    send_message(&message);
}

void set_jammer(const bool run, const jammer::JammerType type, const uint32_t speed) {
    const JammerConfigureMessage message{
        run,
        type,
        speed};
    send_message(&message);
}

void set_rds_data(const uint16_t message_length) {
    const RDSConfigureMessage message{
        message_length};
    send_message(&message);
}

void set_spectrum(
    const size_t sampling_rate,
    const size_t trigger) {
    const WidebandSpectrumConfigMessage message{
        sampling_rate, trigger};
    send_message(&message);
}

void set_time_sink(
    const size_t sampling_rate,
    const size_t trigger) {
    const TimeSinkConfigMessage message{
        sampling_rate, trigger};
    send_message(&message);
}

void set_wefax_config(uint8_t lpm = 120, uint8_t ioc = 0) {
    const WeFaxRxConfigureMessage message{lpm, ioc};
    send_message(&message);
}

void set_noaaapt_config() {
    const NoaaAptRxConfigureMessage message{};
    send_message(&message);
}

void set_vor_config(bool enabled) {
    const VorRxConfigureMessage message{enabled};
    send_message(&message);
}

void set_vor_tx_config(uint16_t radial_deg, bool ident_enabled, const std::string& ident, bool enabled) {
    const VorTxConfigureMessage message{radial_deg, ident_enabled, ident.c_str(), enabled};
    send_message(&message);
}

void set_flex_config() {
    const FlexConfigureMessage message{};
    send_message(&message);
}

void set_siggen_tone(const uint32_t tone) {
    const SigGenToneMessage message{
        TONES_F2D(tone, TONES_SAMPLERATE)};
    send_message(&message);
}

void set_siggen_config(const uint32_t bw, const uint32_t shape, const uint32_t duration) {
    const SigGenConfigMessage message{
        bw, shape, duration * TONES_SAMPLERATE};
    send_message(&message);
}

void set_spectrum_painter_config(const uint16_t width, const uint16_t height, bool update, int32_t bw) {
    SpectrumPainterBufferConfigureRequestMessage message{width, height, update, bw};
    send_message(&message);
}

void set_subghzd_config(uint8_t modulation = 0, uint32_t sampling_rate = 0) {
    const SubGhzFPRxConfigureMessage message{modulation, sampling_rate};
    send_message(&message);
}

void set_moreserx_config(uint8_t mode) {
    const MorseRXConfigureMessage message{mode};
    send_message(&message);
}

void set_tonedetect_config(uint8_t squelch, uint32_t ctcss_freq_x10) {
    const ToneDetectConfigureMessage message{squelch, ctcss_freq_x10};
    send_message(&message);
}

void set_morsetx_config(uint8_t mode, uint32_t tone, float fm_delta) {
    const MorseTXConfigureMessage message{mode, tone, fm_delta};
    send_message(&message);
}

void set_morsetx_key(bool key_down) {
    const MorseTXkeyMessage message{key_down};
    send_message(&message);
}

void set_bitstream_config(uint32_t deviation, uint8_t mode) {
    const StreamTXConfigurationMessage message{deviation, mode};
    send_message(&message);
}

void set_rtty_config(uint16_t baud, uint16_t shift, uint8_t* payload, uint16_t payload_length) {
    RTTYDataMessage message{baud, shift};
    if (payload && payload_length > 0) {
        message.data_len = payload_length > message.max_len ? message.max_len : payload_length;
        for (size_t i = 0; i < message.data_len; ++i) {
            message.data[i] = payload[i];
        }
    }
    send_message(&message);
}

void set_rtty_config(RTTYDataMessage& message) {
    send_message(&message);
}

void set_epirb_tx_config(EPIRBTXDataMessage& message) {
    send_message(&message);
}

void set_epirb_rx_config(EPIRBRXConfig& message) {
    send_message(&message);
}

void set_p25tx_data(const uint8_t* dibits, uint16_t frame_length) {
    const size_t max_len = sizeof(shared_memory.bb_data.data);
    if (frame_length > max_len) frame_length = max_len;
    memcpy(shared_memory.bb_data.data, dibits, frame_length);
    P25TxConfigureMessage msg{};
    msg.frame_length = frame_length;
    send_message(&msg);
}

void set_hunter_config(uint32_t threshold, uint32_t hangtime_ms, bool start) {
    HunterConfigMessage message{};
    message.energy_threshold = threshold;
    message.hangtime_ms = hangtime_ms;
    message.start = start;
    send_message(&message);
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
HACKRF_EDGE_PRECISION_RX_EXTERNAL_TEXT
PrecisionRxRateResult set_precision_rx(uint32_t input_sample_rate_hz) {
    using Result = PrecisionRxRateResult;

    if (precision_rx_rate_fault_latched) {
        return precision_rx_rate_fatal();
    }

    /*
     * Keep the invariant message ID in persistent storage; only its mutable
     * request/ack word changes across PREPARE, COMMIT, and ABORT.
     */
    precision_rx_rate_message.input_sample_rate_hz = input_sample_rate_hz;
    if (!send_precision_rx_message_bounded(&precision_rx_rate_message)) {
        return precision_rx_rate_fatal();
    }

    const uint32_t prepare_response =
        precision_rx_rate_message.input_sample_rate_hz;
    if (prepare_response ==
        precision_rx::rate_control::ack_configured) {
        if (precision_rx_rate_state_is(precision_rx_rate_state_running)) {
            return Result::Applied;
        }
        return precision_rx_rate_fatal();
    }
    if (prepare_response !=
        precision_rx::rate_control::ack_prepared) {
        /*
         * Some PREPARE reject words can describe either a restored old stream
         * or an M4 that already failed closed. Only RUN is recoverable.
         */
        if (is_precision_rx_rate_rejection(prepare_response) &&
            precision_rx_rate_state_is(precision_rx_rate_state_running)) {
            return Result::Rejected;
        }
        return precision_rx_rate_fatal();
    }

    const uint32_t previous_sample_rate = receiver_model.sampling_rate();
    const uint32_t previous_filter_bandwidth =
        receiver_model.baseband_bandwidth();
    receiver_model.set_baseband_bandwidth(
        ui::filter_bandwidth_for_sampling_rate(input_sample_rate_hz));
    receiver_model.set_sampling_rate(input_sample_rate_hz);

    precision_rx_rate_message.input_sample_rate_hz =
        precision_rx::rate_control::request_commit;
    const bool commit_completed =
        send_precision_rx_message_bounded(&precision_rx_rate_message);
    if (!commit_completed) {
        return precision_rx_rate_fatal();
    }

    const uint32_t commit_response =
        precision_rx_rate_message.input_sample_rate_hz;
    if (commit_response ==
        precision_rx::rate_control::ack_committed) {
        if (precision_rx_rate_state_is(precision_rx_rate_state_running)) {
            return Result::Applied;
        }
        return precision_rx_rate_fatal();
    }

    /*
     * A completed, recognized rejection is rollback-safe only while M4 proves
     * that the DMA ring is paused and armed. A timeout may leave the persistent
     * COMMIT owned by M4, so it must never reach these physical writes.
     */
    if (!is_precision_rx_rate_rejection(commit_response) ||
        !precision_rx_rate_state_is(precision_rx_rate_state_paused_armed)) {
        return precision_rx_rate_fatal();
    }

    /* Restore the old physical clock before asking M4 to resume the old ring. */
    receiver_model.set_sampling_rate(previous_sample_rate);
    receiver_model.set_baseband_bandwidth(previous_filter_bandwidth);

    precision_rx_rate_message.input_sample_rate_hz =
        precision_rx::rate_control::request_abort;
    if (!send_precision_rx_message_bounded(&precision_rx_rate_message)) {
        return precision_rx_rate_fatal();
    }

    if (precision_rx_rate_message.input_sample_rate_hz !=
            precision_rx::rate_control::ack_aborted ||
        !precision_rx_rate_state_is(precision_rx_rate_state_running)) {
        return precision_rx_rate_fatal();
    }
    return Result::RolledBack;
}
#else
void set_precision_rx(uint32_t input_sample_rate_hz) {
    const PrecisionRxConfigMessage message{input_sample_rate_hz};
    send_message(&message);
}
#endif

static bool baseband_image_running = false;

bool is_image_running() {
    return baseband_image_running;
}

void run_image(const spi_flash::image_tag_t image_tag) {
    if (baseband_image_running) {
        chDbgPanic("BBRunning");
    }

    creg::m4txevent::clear();
    shared_memory.clear_baseband_ready();

    m4_init(image_tag, memory::map::m4_code, false);
    baseband_image_running = true;

    creg::m4txevent::enable();

    if constexpr (enforce_core_sync) {
        // Wait up to 3 seconds for baseband to start handling events.
        auto count = 3'000u;
        while (!shared_memory.baseband_ready && --count)
            chThdSleepMilliseconds(1);

        if (count == 0)
            chDbgPanic("Baseband Sync Fail");
    }
}

void run_prepared_image(const uint32_t m4_code) {
    if (baseband_image_running) {
        chDbgPanic("BBRunning");
    }

    creg::m4txevent::clear();
    shared_memory.clear_baseband_ready();

    m4_init_prepared(m4_code, false);
    baseband_image_running = true;

    creg::m4txevent::enable();

    if constexpr (enforce_core_sync) {
        // Wait up to 3 seconds for baseband to start handling events.
        auto count = 3'000u;
        while (!shared_memory.baseband_ready && --count)
            chThdSleepMilliseconds(1);

        if (count == 0)
            chDbgPanic("Baseband Sync Fail");
    }
}

void shutdown() {
    if (!baseband_image_running) {
        return;
    }

    creg::m4txevent::disable();

    ShutdownMessage message;
    send_message(&message);

    shared_memory.application_queue.reset();
    // Allow time for the shutdown message to be processed and for the baseband
    // core to stop before starting another image. Otherwise, the M4 may still be
    // running and cause a crash when the next image is started.
#ifdef PRALINE
    chThdSleepMilliseconds(20);
#endif
    baseband_image_running = false;
}

#if defined(HACKRF_EDGE_PRECISION_RX_RATE_TRANSACTION_DIAGNOSTIC)
HACKRF_EDGE_PRECISION_RX_EXTERNAL_TEXT
bool shutdown_precision_rx_after_rate_fault() {
    /*
     * RF is made safe even when a wedged M4 still owns the message slot.
     * Never overwrite that slot: every potentially outstanding object is
     * persistent, and a later destructor call may retry this bounded stop.
     */
    receiver_model.disable();
    if (!baseband_image_running) {
        return true;
    }

    creg::m4txevent::disable();
    if (!send_precision_rx_message_bounded(
            &precision_rx_fault_shutdown_message)) {
        return false;
    }

    shared_memory.application_queue.reset();
    baseband_image_running = false;
    return true;
}
#undef HACKRF_EDGE_PRECISION_RX_EXTERNAL_TEXT
#endif

void spectrum_streaming_start() {
    SpectrumStreamingConfigMessage message{
        SpectrumStreamingConfigMessage::Mode::Running};
    send_message(&message);
}

void spectrum_streaming_stop() {
    SpectrumStreamingConfigMessage message{
        SpectrumStreamingConfigMessage::Mode::Stopped};
    send_message(&message);
}

void set_sample_rate(uint32_t sample_rate, OversampleRate oversample_rate) {
    SampleRateConfigMessage message{sample_rate, oversample_rate};
    send_message(&message);
}

void capture_start(CaptureConfig* const config) {
    CaptureConfigMessage message{config};
    send_message(&message);
}

void capture_stop(bool flush) {
    CaptureConfigMessage message{nullptr, flush};
    send_message(&message);
}

void replay_start(ReplayConfig* const config) {
    ReplayConfigMessage message{config};
    send_message(&message);
}

void replay_stop() {
    ReplayConfigMessage message{nullptr};
    send_message(&message);
}

void request_beep(RequestSignalMessage::Signal beep_type) {
    RequestSignalMessage message{beep_type};
    send_message(&message);
}

void request_roger_beep() {
    request_beep(RequestSignalMessage::Signal::RogerBeepRequest);
}

void request_rssi_beep() {
    request_beep(RequestSignalMessage::Signal::RSSIBeepRequest);
}

void request_beep_stop() {
    request_beep(RequestSignalMessage::Signal::BeepStopRequest);
}

void request_audio_beep(uint32_t freq, uint32_t sample_rate, uint32_t duration_ms) {
    AudioBeepMessage message{freq, sample_rate, duration_ms};
    send_message(&message);
}

} /* namespace baseband */
