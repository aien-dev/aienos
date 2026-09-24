//! HID boot-protocol keyboard reports.
//!
//! Pure parsing: an 8-byte boot-protocol report in, key events out. No MMIO
//! and no allocation, so the whole behaviour is host-tested. The decoder is
//! make-only (key releases are ignored), and a fixed-capacity sink keeps the
//! decoded text when the caller wants it as one string.

/// Modifier bit positions in byte 0 of a boot-protocol report.
pub mod modifier {
    pub const LEFT_CTRL: u8 = 1 << 0;
    pub const LEFT_SHIFT: u8 = 1 << 1;
    pub const LEFT_ALT: u8 = 1 << 2;
    pub const RIGHT_CTRL: u8 = 1 << 4;
    pub const RIGHT_SHIFT: u8 = 1 << 5;
    pub const RIGHT_ALT: u8 = 1 << 6;
    pub const ANY_SHIFT: u8 = LEFT_SHIFT | RIGHT_SHIFT;
}

pub use modifier::{LEFT_ALT, LEFT_CTRL, LEFT_SHIFT, RIGHT_ALT, RIGHT_CTRL, RIGHT_SHIFT};

/// One decoded key press. Releases never produce an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyEvent {
    /// A printable character, already shifted.
    Char(char),
    Enter,
    Backspace,
    Tab,
    Escape,
    /// Cursor keys arrive as ANSI escape sequences on the early console.
    Up,
    Down,
    Left,
    Right,
}

/// Length of a HID boot-protocol keyboard report.
pub const BOOT_REPORT_LEN: usize = 8;
const MAX_KEYS: usize = 6;

/// Unshifted and shifted characters per usage ID, starting at usage 0x04:
/// letters first, then digits, each pair unshifted then shifted.
#[rustfmt::skip]
const KEYMAP: &[u8] = b"aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrRsStTuUvVwWxXyYzZ\
    1!2@3#4$5%6^7&8*9(0)";

/// Usage 0x2c (space) and the punctuation row: usages 0x2c..=0x38, each pair
/// unshifted then shifted. Usage 0x32 (non-US `#`/`~`) sits between `\` and `;`.
#[rustfmt::skip]
const PUNCT: &[u8] = b"  -_=+[{]}\\|#~;:'\"`~,<.>/?";

const USAGE_ENTER: u8 = 0x28;
const USAGE_ESCAPE: u8 = 0x29;
const USAGE_BACKSPACE: u8 = 0x2a;
const USAGE_TAB: u8 = 0x2b;
const USAGE_CAPS_LOCK: u8 = 0x39;
const USAGE_F1: u8 = 0x3a;
const USAGE_F12: u8 = 0x45;
const USAGE_RIGHT_ARROW: u8 = 0x4f;
const USAGE_LEFT_ARROW: u8 = 0x50;
const USAGE_DOWN_ARROW: u8 = 0x51;
const USAGE_UP_ARROW: u8 = 0x52;

fn decode_usage(usage: u8, shift: bool) -> Option<KeyEvent> {
    let c = match usage {
        0x04..=0x27 => KEYMAP[usize::from(usage - 0x04) * 2 + usize::from(shift)],
        USAGE_ENTER => return Some(KeyEvent::Enter),
        USAGE_ESCAPE => return Some(KeyEvent::Escape),
        USAGE_BACKSPACE => return Some(KeyEvent::Backspace),
        USAGE_TAB => return Some(KeyEvent::Tab),
        0x2c..=0x38 => PUNCT[usize::from(usage - 0x2c) * 2 + usize::from(shift)],
        // Caps Lock and the function row are not echoed.
        USAGE_CAPS_LOCK | USAGE_F1..=USAGE_F12 => return None,
        USAGE_RIGHT_ARROW => return Some(KeyEvent::Right),
        USAGE_LEFT_ARROW => return Some(KeyEvent::Left),
        USAGE_DOWN_ARROW => return Some(KeyEvent::Down),
        USAGE_UP_ARROW => return Some(KeyEvent::Up),
        _ => return None,
    };
    Some(KeyEvent::Char(char::from(c)))
}

/// Stateless-format decoder: a key press is emitted once, on the first report
/// containing it, and releases are ignored, so a key held across polls does
/// not auto-repeat.
pub struct BootKeyboardDecoder {
    previous: [u8; MAX_KEYS],
}

impl Default for BootKeyboardDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl BootKeyboardDecoder {
    pub const fn new() -> Self {
        Self {
            previous: [0; MAX_KEYS],
        }
    }

    /// Handle one 8-byte boot-protocol report, calling `emit` for every key
    /// that is newly pressed relative to the previous report. Reports with a
    /// rollover error (all usages 0x01) or a wrong length are ignored.
    pub fn handle_report(&mut self, report: &[u8], mut emit: impl FnMut(KeyEvent)) {
        if report.len() != BOOT_REPORT_LEN {
            return;
        }
        let usages: [u8; MAX_KEYS] = report[2..8].try_into().unwrap_or([0; MAX_KEYS]);
        if usages[0] == 0x01 {
            // Phantom state during rollover: ignore this report entirely and
            // do not treat it as a release.
            return;
        }
        let shift = report[0] & modifier::ANY_SHIFT != 0;
        for usage in usages {
            if usage == 0 || self.previous.contains(&usage) {
                continue;
            }
            if let Some(event) = decode_usage(usage, shift) {
                emit(event);
            }
        }
        self.previous = usages;
    }
}

/// Fixed-capacity text collector for decoded keystrokes, heap-free.
pub struct TextSink<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Default for TextSink<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> TextSink<N> {
    pub const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }

    pub fn as_str(&self) -> &str {
        // Only ASCII is ever pushed.
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn push(&mut self, byte: u8) {
        if self.len < N {
            self.bytes[self.len] = byte;
            self.len += 1;
        }
    }

    /// Record one event; cursor keys become their ANSI escape sequences.
    pub fn record(&mut self, event: KeyEvent) {
        match event {
            KeyEvent::Char(c) => self.push(c as u8),
            KeyEvent::Enter => self.push(b'\n'),
            KeyEvent::Backspace => self.push(0x08),
            KeyEvent::Tab => self.push(b'\t'),
            KeyEvent::Escape => self.push(0x1b),
            KeyEvent::Up => [0x1b, b'[', b'A'].iter().for_each(|b| self.push(*b)),
            KeyEvent::Down => [0x1b, b'[', b'B'].iter().for_each(|b| self.push(*b)),
            KeyEvent::Right => [0x1b, b'[', b'C'].iter().for_each(|b| self.push(*b)),
            KeyEvent::Left => [0x1b, b'[', b'D'].iter().for_each(|b| self.push(*b)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(modifiers: u8, usages: [u8; MAX_KEYS]) -> [u8; BOOT_REPORT_LEN] {
        let mut r = [0u8; BOOT_REPORT_LEN];
        r[0] = modifiers;
        r[2..8].copy_from_slice(&usages);
        r
    }

    fn decode(
        decoder: &mut BootKeyboardDecoder,
        report: &[u8; BOOT_REPORT_LEN],
    ) -> TextSink<16> {
        let mut sink = TextSink::new();
        decoder.handle_report(report, |e| sink.record(e));
        sink
    }

    #[test]
    fn letter_make_and_release_produces_one_character() {
        let mut d = BootKeyboardDecoder::new();
        assert_eq!(decode(&mut d, &report(0, [0x04, 0, 0, 0, 0, 0])).as_str(), "a");
        assert_eq!(decode(&mut d, &report(0, [0; 6])).as_str(), "");
        // Held keys do not repeat: same usage in consecutive reports is quiet.
        assert_eq!(decode(&mut d, &report(0, [0x04, 0, 0, 0, 0, 0])).as_str(), "a");
        assert_eq!(decode(&mut d, &report(0, [0x04, 0, 0, 0, 0, 0])).as_str(), "");
    }

    #[test]
    fn shift_and_digits_use_the_shifted_column() {
        let mut d = BootKeyboardDecoder::new();
        assert_eq!(
            decode(&mut d, &report(LEFT_SHIFT, [0x04, 0x1e, 0, 0, 0, 0])).as_str(),
            "A!"
        );
        // Right shift works the same.
        let mut d = BootKeyboardDecoder::new();
        assert_eq!(
            decode(&mut d, &report(RIGHT_SHIFT, [0x27, 0x28, 0, 0, 0, 0])).as_str(),
            ")\n"
        );
    }

    #[test]
    fn punctuation_and_space_decode() {
        let mut d = BootKeyboardDecoder::new();
        assert_eq!(
            decode(&mut d, &report(0, [0x2c, 0x2d, 0x36, 0x37, 0x38, 0])).as_str(),
            " -,./"
        );
        let mut d = BootKeyboardDecoder::new();
        assert_eq!(
            decode(&mut d, &report(LEFT_SHIFT, [0x2f, 0x30, 0x31, 0x33, 0x34, 0x35]))
                .as_str(),
            "{}|:\"~"
        );
        let mut d = BootKeyboardDecoder::new();
        assert_eq!(
            decode(&mut d, &report(LEFT_SHIFT, [0x2d, 0x2e, 0x32, 0x36, 0x37, 0x38]))
                .as_str(),
            "_+~<>?"
        );
    }

    #[test]
    fn control_keys_and_arrows() {
        let mut d = BootKeyboardDecoder::new();
        let mut sink = TextSink::<32>::new();
        d.handle_report(&report(0, [0x2a, 0x2b, 0x29, 0, 0, 0]), |e| sink.record(e));
        d.handle_report(&report(0, [0; 6]), |e| sink.record(e));
        d.handle_report(&report(0, [USAGE_UP_ARROW, 0, 0, 0, 0, 0]), |e| {
            sink.record(e)
        });
        assert_eq!(sink.as_str(), "\x08\t\x1b\x1b[A");
    }

    #[test]
    fn rollover_error_and_wrong_length_are_ignored() {
        let mut d = BootKeyboardDecoder::new();
        let phantom = report(0, [0x01, 0x01, 0x01, 0x01, 0x01, 0x01]);
        assert_eq!(decode(&mut d, &phantom).as_str(), "");
        // A rollover report does not count as a release.
        d.handle_report(&report(0, [0x04, 0, 0, 0, 0, 0]), |_| {});
        let mut sink = TextSink::<8>::new();
        d.handle_report(&phantom, |e| sink.record(e));
        d.handle_report(&report(0, [0x04, 0, 0, 0, 0, 0]), |e| sink.record(e));
        assert!(sink.is_empty());
        // Wrong length never decodes.
        d.handle_report(&[0u8; 4], |_| panic!("no event"));
    }

    #[test]
    fn unmapped_usages_are_dropped() {
        let mut d = BootKeyboardDecoder::new();
        assert_eq!(
            decode(&mut d, &report(0, [USAGE_CAPS_LOCK, 0, 0, 0, 0, 0])).as_str(),
            ""
        );
        assert_eq!(
            decode(&mut d, &report(0, [USAGE_F1, USAGE_F12, 0, 0, 0, 0])).as_str(),
            ""
        );
    }

    #[test]
    fn sink_truncates_instead_of_overflowing() {
        let mut sink = TextSink::<4>::new();
        for c in "hello".chars() {
            sink.record(KeyEvent::Char(c));
        }
        assert_eq!(sink.as_str(), "hell");
    }
}
