//! Host-testable USB Audio Class output descriptor and PCM helpers.
//!
//! This parses the common single-configuration UAC1/UAC2 layout. It does not
//! touch controller registers; packet scheduling is host-testable.

use crate::usb::xhci::trb::Trb;

const CONFIG: u8 = 2;
const INTERFACE: u8 = 4;
const ENDPOINT: u8 = 5;
const CS_INTERFACE: u8 = 0x24;
const CS_ENDPOINT: u8 = 0x25;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AudioVersion {
    Uac1,
    Uac2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AudioStream {
    pub version: AudioVersion,
    pub control_interface: u8,
    pub interface: u8,
    pub alternate: u8,
    pub endpoint_address: u8,
    pub max_packet: u16,
    pub interval: u8,
    pub channels: u8,
    pub subframe_bytes: u8,
    pub bit_resolution: u8,
    pub clock_source: Option<u8>,
    /// Zero means continuous; otherwise the discrete rates advertised.
    pub sample_rates: [u32; 8],
    pub sample_rate_count: u8,
}

fn le24(b: &[u8]) -> u32 {
    u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16)
}

/// Select the best output stream for 48 kHz, 16-bit stereo, preferring exact
/// channel/bit matches and then the smallest packet size.
pub fn select_output(bytes: &[u8]) -> Option<AudioStream> {
    if bytes.len() < 9 || bytes[0] < 9 || bytes[1] != CONFIG {
        return None;
    }
    let total = usize::from(u16::from_le_bytes([bytes[2], bytes[3]])).min(bytes.len());
    let mut version = None;
    let mut control = None;
    let mut iface: Option<(u8, u8, bool)> = None;
    let mut fmt: Option<(u8, u8, u8, [u32; 8], u8)> = None;
    let mut clock = None;
    let mut candidates: [Option<AudioStream>; 16] = [None; 16];
    let mut n = 0;
    let mut at = 0;
    while at + 2 <= total {
        let len = usize::from(bytes[at]);
        if len < 2 || at + len > total {
            return None;
        }
        let d = &bytes[at..at + len];
        match d[1] {
            INTERFACE if len >= 9 => {
                iface = Some((d[2], d[3], d[5] == 1 && d[6] == 2));
                fmt = None;
                if d[5] == 1 && d[6] == 1 {
                    control = Some(d[2]);
                }
            }
            CS_INTERFACE if len >= 3 => match d[2] {
                1 if iface.map(|x| x.2).unwrap_or(false) => {
                    // UAC2 AS_GENERAL carries bNrChannels at offset 10. UAC1
                    // AS_GENERAL has none (offset 4 is bDelay); UAC1 channels
                    // come from FORMAT_TYPE_I below.
                    if version == Some(AudioVersion::Uac2) && d.len() >= 11 {
                        let channels = d[10];
                        if let Some((_, sub, bits, rates, count)) = fmt {
                            fmt = Some((channels, sub, bits, rates, count));
                        } else {
                            fmt = Some((channels, 0, 0, [0; 8], 0));
                        }
                    }
                }
                1 if d.len() >= 8 && iface.map(|x| !x.2).unwrap_or(false) => {
                    let bcd = u16::from_le_bytes([d[3], d[4]]);
                    version = Some(if bcd >= 0x0200 {
                        AudioVersion::Uac2
                    } else {
                        AudioVersion::Uac1
                    });
                    if version == Some(AudioVersion::Uac2) && d.len() >= 8 {
                        clock = Some(d[7]);
                    }
                }
                // FORMAT_TYPE_I. UAC1: bNrChannels[4], bSubframeSize[5],
                // bBitResolution[6], bSamFreqType[7] (so at least 8 bytes).
                // UAC2: bSubslotSize[4], bBitResolution[5] (at least 6 bytes).
                2 if iface.map(|x| x.2).unwrap_or(false)
                    && d.len()
                        >= if version == Some(AudioVersion::Uac2) {
                            6
                        } else {
                            8
                        } =>
                {
                    let (channels, sub, bits) = if version == Some(AudioVersion::Uac2) {
                        (fmt.map(|x| x.0).unwrap_or(0), d[4], d[5])
                    } else {
                        (d[4], d[5], d[6])
                    };
                    let mut rates = [0; 8];
                    let mut count = 0;
                    if version == Some(AudioVersion::Uac1) && d.len() >= 8 {
                        let nr = usize::from(d[7]);
                        if nr == 0 {
                            count = 0;
                        } else if d.len() >= 8 + nr * 3 {
                            count = nr.min(8) as u8;
                            for i in 0..usize::from(count) {
                                rates[i] = le24(&d[8 + i * 3..]);
                            }
                        }
                    } else if version == Some(AudioVersion::Uac2) {
                        // UAC2 clock rates are queried from the clock entity.
                        // This slice selects the common 48 kHz default.
                        rates[0] = 48_000;
                        count = 1;
                    }
                    fmt = Some((channels, sub, bits, rates, count));
                }
                0x0a if d.len() >= 4 && version == Some(AudioVersion::Uac2) => clock = Some(d[3]),
                _ => {}
            },
            ENDPOINT if len >= 7 => {
                if let (
                    Some((number, alt, true)),
                    Some((ch, sub, bits, rates, count)),
                    Some(v),
                    Some(ci),
                ) = (iface, fmt, version, control)
                {
                    let attr = d[3] & 3;
                    if alt != 0 && d[2] & 0x80 == 0 && attr == 1 && n < candidates.len() {
                        let mut rs = rates;
                        let rc = count;
                        // UAC2 rates belong to the clock entity, not FORMAT_TYPE.
                        if v == AudioVersion::Uac2 && rc == 1 {
                            rs[0] = 48_000;
                        }
                        candidates[n] = Some(AudioStream {
                            version: v,
                            control_interface: ci,
                            interface: number,
                            alternate: alt,
                            endpoint_address: d[2],
                            max_packet: u16::from_le_bytes([d[4], d[5]]) & 0x7ff,
                            interval: d[6],
                            channels: ch,
                            subframe_bytes: sub,
                            bit_resolution: bits,
                            clock_source: clock,
                            sample_rates: rs,
                            sample_rate_count: rc,
                        });
                        n += 1;
                    }
                }
            }
            CS_ENDPOINT if len >= 8 => {}
            _ => {}
        }
        at += len;
    }
    candidates[..n]
        .iter()
        .flatten()
        .copied()
        .filter(|s| {
            s.channels >= 2
                && s.subframe_bytes >= 2
                && s.bit_resolution >= 16
                && (s.sample_rate_count == 0
                    || s.sample_rates[..usize::from(s.sample_rate_count)].contains(&48_000))
        })
        .min_by_key(|s| (s.channels != 2, s.bit_resolution != 16, s.max_packet))
}

/// Exact endpoint service interval in microseconds. Full speed uses 1 ms;
/// high speed bInterval encodes 2^(n-1) microframes of 125 us.
pub fn service_interval_us(high_speed: bool, interval: u8) -> Option<u32> {
    if interval == 0 {
        return None;
    }
    if high_speed {
        (interval <= 16).then(|| 125u32 << (interval - 1))
    } else {
        Some(1000)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcmFramer {
    rate: u32,
    channels: u8,
    sample_bytes: u8,
    interval_us: u32,
    remainder: u64,
}
impl PcmFramer {
    pub fn new(rate: u32, channels: u8, sample_bytes: u8, interval_us: u32) -> Option<Self> {
        (rate > 0 && channels > 0 && sample_bytes > 0 && interval_us > 0).then_some(Self {
            rate,
            channels,
            sample_bytes,
            interval_us,
            remainder: 0,
        })
    }
    /// Returns packet byte count, carrying fractional frames between packets.
    pub fn next_packet_bytes(&mut self) -> usize {
        let numerator = u64::from(self.rate) * u64::from(self.interval_us) + self.remainder;
        let frames = numerator / 1_000_000;
        self.remainder = numerator % 1_000_000;
        frames as usize * usize::from(self.channels) * usize::from(self.sample_bytes)
    }
    /// Fill one packet from interleaved PCM, wrapping the caller's ring cursor.
    pub fn fill_i16(&mut self, ring: &[i16], cursor: &mut usize, out: &mut [i16]) -> usize {
        let bytes = self.next_packet_bytes();
        let samples = (bytes / 2).min(out.len());
        if ring.is_empty() {
            out[..samples].fill(0);
            return samples;
        }
        for dst in &mut out[..samples] {
            *dst = ring[*cursor % ring.len()];
            *cursor = (*cursor + 1) % ring.len();
        }
        samples
    }
}

/// Prepare `packets.len()` service intervals ahead of `controller_frame`.
/// Each PCM output chunk has `packet_stride_samples` samples; its DMA address
/// is supplied in the matching entry. Frame IDs wrap at the xHCI 11-bit field.
pub struct AudioBatch<'a> {
    pub controller_frame: u16,
    pub lead_frames: u16,
    pub packets: &'a [(u64, u16)],
    pub pcm_ring: &'a [i16],
    pub cursor: &'a mut usize,
    pub pcm: &'a mut [i16],
    pub packet_stride_samples: usize,
    pub trbs: &'a mut [Trb],
}

pub fn schedule_isoch_ahead(framer: &mut PcmFramer, batch: &mut AudioBatch<'_>) -> usize {
    let AudioBatch {
        controller_frame,
        lead_frames,
        packets,
        pcm_ring,
        cursor,
        pcm,
        packet_stride_samples,
        trbs,
    } = batch;
    let count = packets
        .len()
        .min(trbs.len())
        .min(pcm.len() / (*packet_stride_samples).max(1));
    for i in 0..count {
        let start = i * *packet_stride_samples;
        let out = &mut pcm[start..start + *packet_stride_samples];
        let samples = framer.fill_i16(pcm_ring, cursor, out);
        let bytes = (samples * 2).min(usize::from(packets[i].1));
        trbs[i] = Trb::isoch(
            packets[i].0,
            bytes as u32,
            controller_frame
                .wrapping_add(*lead_frames)
                .wrapping_add(i as u16)
                & 0x7ff,
            false,
            i + 1 == count,
        );
    }
    count
}

/// Deterministic 16-bit sine approximation using a parabolic fixed-point wave.
#[derive(Clone, Copy, Debug, Default)]
pub struct TestTone {
    phase: u32,
    step: u32,
}
impl TestTone {
    pub fn new(frequency_hz: u32, sample_rate: u32) -> Option<Self> {
        (sample_rate > 0 && frequency_hz < sample_rate / 2).then_some(Self {
            phase: 0,
            step: ((u64::from(frequency_hz) << 32) / u64::from(sample_rate)) as u32,
        })
    }
    pub fn next_sample(&mut self) -> i16 {
        self.phase = self.phase.wrapping_add(self.step);
        let x = (self.phase >> 16) as i32;
        let tri = if x < 32768 { x } else { 65535 - x };
        let y = (4i64 * i64::from(tri) * i64::from(32767 - tri) * 2 / 32767) as i32 - 32767;
        y.clamp(-32767, 32767) as i16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Real UAC1 shape: AC, AS alt zero, stereo Type I PCM 16-bit/48 kHz, OUT.
    const UAC1: &[u8] = &[
        9, 2, 73, 0, 2, 1, 0, 0x80, 50, 9, 4, 0, 0, 0, 1, 1, 0, 0, 9, 0x24, 1, 0, 1, 0x26, 0, 1, 1,
        9, 4, 1, 0, 0, 1, 2, 0, 0, 9, 4, 1, 1, 1, 1, 2, 0, 0, 7, 0x24, 1, 1, 2, 3, 0, 11, 0x24, 2,
        1, 2, 2, 16, 1, 0x80, 0xbb, 0, 9, 5, 1, 1, 192, 0, 1, 0, 0,
    ];
    // UAC2 clock source and Type I 16-bit stereo format, one 48 kHz clock.
    const UAC2: &[u8] = &[
        9, 2, 85, 0, 2, 1, 0, 0x80, 50, 9, 4, 0, 0, 0, 1, 1, 0, 0, 9, 0x24, 1, 0, 2, 9, 0, 1, 1, 8,
        0x24, 0x0a, 3, 7, 0, 0, 0, 9, 4, 1, 0, 0, 1, 2, 0, 0, 9, 4, 1, 1, 1, 1, 2, 0, 0, 16, 0x24,
        1, 1, 0, 1, 1, 0, 0, 0, 2, 3, 0, 0, 0, 0, 6, 0x24, 2, 1, 2, 16, 9, 5, 1, 1, 192, 0, 1, 0,
        0,
    ];
    #[test]
    fn parses_uac1_and_uac2() {
        let a = select_output(UAC1).unwrap();
        assert_eq!(
            (
                a.version,
                a.interface,
                a.alternate,
                a.channels,
                a.bit_resolution
            ),
            (AudioVersion::Uac1, 1, 1, 2, 16)
        );
        let b = select_output(UAC2).unwrap();
        assert_eq!(b.version, AudioVersion::Uac2);
        assert_eq!(b.clock_source, Some(3));
    }
    #[test]
    fn fractional_44100_packet_pattern_totals_one_second() {
        let mut f = PcmFramer::new(44100, 1, 2, 1000).unwrap();
        let mut frames = 0;
        let mut saw44 = false;
        let mut saw45 = false;
        for _ in 0..1000 {
            let n = f.next_packet_bytes() / 2;
            frames += n;
            saw44 |= n == 44;
            saw45 |= n == 45;
        }
        assert_eq!(frames, 44100);
        assert!(saw44 && saw45);
    }

    #[test]
    fn stereo_44100_scheduler_emits_one_second_of_pcm_bytes() {
        let mut framer = PcmFramer::new(44_100, 2, 2, 1000).unwrap();
        let mut cursor = 0;
        let source = [7i16; 256];
        let mut output = [0i16; 90];
        let mut total = 0;
        for _ in 0..1000 {
            let n = framer.fill_i16(&source, &mut cursor, &mut output);
            total += n * 2;
        }
        assert_eq!(total, 176_400);
    }

    #[test]
    fn isoch_schedule_stays_ahead_and_wraps_frame_id() {
        let mut framer = PcmFramer::new(48_000, 2, 2, 1000).unwrap();
        let packets = [(0x1000, 192), (0x2000, 192)];
        let mut pcm = [0i16; 192];
        let mut trbs = [Trb::default(); 2];
        let mut cursor = 0;
        let mut batch = AudioBatch {
            controller_frame: 2046,
            lead_frames: 2,
            packets: &packets,
            pcm_ring: &[],
            cursor: &mut cursor,
            pcm: &mut pcm,
            packet_stride_samples: 96,
            trbs: &mut trbs,
        };
        let n = schedule_isoch_ahead(&mut framer, &mut batch);
        assert_eq!(n, 2);
        assert_eq!((trbs[0].0[3] >> 20) & 0x7ff, 0);
        assert_eq!((trbs[1].0[3] >> 20) & 0x7ff, 1);
        assert_eq!(trbs[0].0[2], 192);
        assert_eq!(trbs[1].0[2], 192);
    }
    #[test]
    fn ring_wraps_and_tone_is_bounded() {
        let mut f = PcmFramer::new(48000, 2, 2, 1000).unwrap();
        let ring = [1, 2, 3, 4, 5];
        let mut cursor = 3;
        let mut out = [0; 192];
        assert_eq!(f.fill_i16(&ring, &mut cursor, &mut out), 96);
        assert_eq!(&out[..4], &[4, 5, 1, 2]);
        assert_eq!(cursor, 4);
        let mut tone = TestTone::new(440, 48000).unwrap();
        for _ in 0..1000 {
            let x = tone.next_sample();
            assert!((-32767..=32767).contains(&x));
        }
    }
    #[test]
    fn uac1_channels_come_from_format_type_not_as_general_delay() {
        // Review regression: UAC1 AS_GENERAL offset 4 is bDelay. In the UAC1
        // vector bDelay happened to equal the channel count (2); set it to 7.
        let mut v = UAC1.to_vec();
        let at = v
            .windows(7)
            .position(|w| w == [7, 0x24, 1, 1, 2, 3, 0])
            .expect("AS_GENERAL present");
        v[at + 4] = 7;
        assert_eq!(select_output(&v).unwrap().channels, 2);
    }

    #[test]
    fn short_uac1_format_descriptor_does_not_panic() {
        // FORMAT_TYPE_I with bLength 7 (< 8 required for UAC1): rejected, no panic.
        let mut v = UAC1.to_vec();
        let at = v
            .windows(3)
            .position(|w| w == [11, 0x24, 2])
            .expect("FORMAT_TYPE_I present");
        v[at] = 7;
        let _ = select_output(&v);
    }
}
