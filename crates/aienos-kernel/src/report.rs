//! Fixed-capacity text buffer for boot reports, usable without a heap.
//!
//! The same report text is sent to every output (screen, firmware variable,
//! serial), so all of them carry identical evidence.

use core::fmt;

pub struct ReportBuf<const N: usize> {
    bytes: [u8; N],
    len: usize,
    truncated: bool,
}

impl<const N: usize> Default for ReportBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ReportBuf<N> {
    pub const fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
            truncated: false,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn as_str(&self) -> &str {
        // Only whole UTF-8 characters are ever appended.
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    /// True if some text did not fit.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

impl<const N: usize> fmt::Write for ReportBuf<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            let mut tmp = [0u8; 4];
            let encoded = c.encode_utf8(&mut tmp).as_bytes();
            if self.len + encoded.len() > N {
                self.truncated = true;
                return Ok(());
            }
            self.bytes[self.len..self.len + encoded.len()].copy_from_slice(encoded);
            self.len += encoded.len();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    #[test]
    fn formats_and_truncates_on_character_boundaries() {
        let mut r = ReportBuf::<8>::new();
        write!(r, "ab{}", 12).unwrap();
        assert_eq!(r.as_str(), "ab12");
        write!(r, "é€xyz").unwrap();
        assert!(r.truncated());
        assert_eq!(r.as_str(), "ab12é");
        assert!(r.as_bytes().len() <= 8);
    }
}
