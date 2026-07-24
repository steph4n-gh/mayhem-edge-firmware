# Precision RX

Precision RX is the standalone PortaPack half of the experimental HackRF Edge
receiver work. It keeps the radio's raw C8 acquisition path intact while an
isolated M4 image produces bounded-cost signal-health and continuity evidence.

## Operation

- Select the center frequency, RF amplifier, LNA/VGA gains, and sample rate.
- Rates from 1 through 20 MS/s are available for live health telemetry.
- Raw SD capture is deliberately limited to 1 or 2 MS/s. Press **CAPTURE** to
  create a uniquely named `CAPTURES/PRX_YYYYMMDDTHHMMSS_NN.C8` file and press
  **STOP** to close it cleanly.
- The app writes a same-stem `.PRX` v1 sidecar after the C8 file has been
  synchronized. It separates known M4 DMA loss, SD FIFO loss, and file-write
  loss and includes CRC32C-protected full-capture aggregates plus the last 16
  delivered metric records.

The gain indication is advisory only. `REDUCE`, `HOLD`, and `INCREASE` never
change hardware gain automatically.

## Measurement boundary

Metrics select at most one million complex samples per second, preserving raw
input ticks while bounding work on the LPC4320. At rates above 1 MS/s the
carrier estimate is explicitly modulo the selected analysis rate and clipping
is sampled, not exhaustive. The UI labels that condition `MOD`; it labels the
MAX2837 low-bandwidth analog-filter limitation `ANALOG-RISK` at 1 MS/s.

The device-relative input clock is not UTC and is not oscillator-calibrated.
Precision RX does not claim extra ADC bits, additional RF sensitivity,
alias-free undersampling, seamless retuning, or loss-free SD capture.

## Verification

The `precision_rx_metrics_test` cases cover ticks, loss, carrier/DC behavior,
analysis work bounds, robust level, gain dwell, forced capture tails, exact
evidence intervals, and uint32 sequence wrap. The normal Mayhem `ppfw` target
also enforces the 32 KiB external-app and baseband image limits.

This code is part of the Mayhem GPL-2.0-or-later firmware. The separate PRX v1
wire-layout reference and host decoder may be distributed under their stated
permissive licenses.
