//! Early boot screen: text drawn straight into the firmware-provided
//! framebuffer (UEFI GOP) after boot services exit. No GPU driver is involved;
//! the firmware has already set the display mode.

pub mod font;

use core::fmt;
use core::ptr::write_volatile;
use font::{lit, GLYPH_HEIGHT, GLYPH_WIDTH};

/// Byte order of a 32-bit framebuffer pixel, as reported by GOP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelOrder {
    /// Bytes are red, green, blue, reserved.
    Rgb,
    /// Bytes are blue, green, red, reserved.
    Bgr,
}

/// Framebuffer geometry recorded before firmware exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FramebufferInfo {
    pub base: u64,
    pub size_bytes: u64,
    pub width: usize,
    pub height: usize,
    /// Pixels per scanline (may exceed `width`).
    pub stride: usize,
    pub order: PixelOrder,
}

impl FramebufferInfo {
    /// Rejects geometry that would write outside the reported buffer.
    pub fn validated(self) -> Option<Self> {
        let needed = (self.stride as u64)
            .checked_mul(self.height as u64)?
            .checked_mul(4)?;
        (self.width > 0
            && self.height > 0
            && self.stride >= self.width
            && needed <= self.size_bytes)
            .then_some(self)
    }
}

const CELL_W: usize = GLYPH_WIDTH + 1;
const CELL_H: usize = GLYPH_HEIGHT + 3;
/// Columns the text grid aims for; the scale grows until 80 cells fill the width.
const TARGET_COLUMNS: usize = 80;
const MARGIN_CELLS: usize = 1;

pub const BACKGROUND: (u8, u8, u8) = (0x10, 0x14, 0x1c);
pub const FOREGROUND: (u8, u8, u8) = (0xe8, 0xec, 0xf2);
pub const ACCENT: (u8, u8, u8) = (0x5c, 0xd6, 0x8a);

/// Text console over a linear 32-bit framebuffer.
pub struct Screen {
    base: *mut u32,
    info: FramebufferInfo,
    scale: usize,
    col: usize,
    row: usize,
    color: (u8, u8, u8),
}

impl Screen {
    /// # Safety
    /// `info` must describe memory that is mapped, writable and not used by
    /// anything else for the lifetime of the screen.
    pub unsafe fn new(info: FramebufferInfo) -> Option<Self> {
        let info = info.validated()?;
        Some(Self {
            base: info.base as usize as *mut u32,
            info,
            scale: (info.width / (TARGET_COLUMNS * CELL_W)).max(1),
            col: MARGIN_CELLS,
            row: MARGIN_CELLS,
            color: FOREGROUND,
        })
    }

    fn pixel(&self, (r, g, b): (u8, u8, u8)) -> u32 {
        match self.info.order {
            PixelOrder::Bgr => u32::from(r) << 16 | u32::from(g) << 8 | u32::from(b),
            PixelOrder::Rgb => u32::from(b) << 16 | u32::from(g) << 8 | u32::from(r),
        }
    }

    fn fill(&mut self, x0: usize, y0: usize, w: usize, h: usize, color: (u8, u8, u8)) {
        let value = self.pixel(color);
        for y in y0..(y0 + h).min(self.info.height) {
            for x in x0..(x0 + w).min(self.info.width) {
                // SAFETY: x < width <= stride and y < height, so the offset is
                // inside the buffer checked by `FramebufferInfo::validated`.
                unsafe { write_volatile(self.base.add(y * self.info.stride + x), value) };
            }
        }
    }

    pub fn clear(&mut self) {
        let (w, h) = (self.info.width, self.info.height);
        self.fill(0, 0, w, h, BACKGROUND);
        self.col = MARGIN_CELLS;
        self.row = MARGIN_CELLS;
    }

    pub fn set_color(&mut self, color: (u8, u8, u8)) {
        self.color = color;
    }

    pub fn columns(&self) -> usize {
        self.info.width / (CELL_W * self.scale)
    }

    pub fn rows(&self) -> usize {
        self.info.height / (CELL_H * self.scale)
    }

    fn newline(&mut self) {
        self.col = MARGIN_CELLS;
        self.row += 1;
    }

    pub fn put_char(&mut self, c: char) {
        if c == '\n' {
            self.newline();
            return;
        }
        if self.col + MARGIN_CELLS >= self.columns() {
            self.newline();
        }
        if self.row + MARGIN_CELLS >= self.rows() {
            return; // Screen full: drop rather than scroll over earlier lines.
        }
        let s = self.scale;
        let (x0, y0) = (self.col * CELL_W * s, self.row * CELL_H * s);
        let color = self.color;
        for gy in 0..GLYPH_HEIGHT {
            for gx in 0..GLYPH_WIDTH {
                if lit(c, gx, gy) {
                    self.fill(x0 + gx * s, y0 + gy * s, s, s, color);
                }
            }
        }
        self.col += 1;
    }

    /// Paint a blank line at the current row (used for in-place countdowns).
    pub fn clear_row(&mut self) {
        let s = self.scale;
        let y = self.row * CELL_H * s;
        let w = self.info.width;
        self.fill(0, y, w, CELL_H * s, BACKGROUND);
        self.col = MARGIN_CELLS;
    }
}

impl fmt::Write for Screen {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        s.chars().for_each(|c| self.put_char(c));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    fn screen(buf: &mut std::vec::Vec<u32>, width: usize, height: usize, stride: usize) -> Screen {
        let info = FramebufferInfo {
            base: buf.as_mut_ptr() as u64,
            size_bytes: (buf.len() * 4) as u64,
            width,
            height,
            stride,
            order: PixelOrder::Bgr,
        };
        unsafe { Screen::new(info) }.unwrap()
    }

    #[test]
    fn rejects_geometry_larger_than_the_buffer() {
        let info = FramebufferInfo {
            base: 0x1000,
            size_bytes: 100 * 100 * 4,
            width: 100,
            height: 101,
            stride: 100,
            order: PixelOrder::Rgb,
        };
        assert!(info.validated().is_none());
        assert!(FramebufferInfo {
            height: 100,
            ..info
        }
        .validated()
        .is_some());
        assert!(FramebufferInfo {
            stride: 99,
            height: 10,
            ..info
        }
        .validated()
        .is_none());
    }

    #[test]
    fn draws_glyph_pixels_and_respects_stride_padding() {
        // 480 px wide gives scale 1; stride 500 leaves 20 px of padding per line.
        let (w, h, stride) = (480, 120, 500);
        let mut buf = std::vec![0u32; stride * h];
        let mut s = screen(&mut buf, w, h, stride);
        s.clear();
        write!(s, "L").unwrap();
        let fg =
            u32::from(FOREGROUND.0) << 16 | u32::from(FOREGROUND.1) << 8 | u32::from(FOREGROUND.2);
        let (x0, y0) = (MARGIN_CELLS * CELL_W, MARGIN_CELLS * CELL_H);
        let at = |x: usize, y: usize| buf[(y0 + y) * stride + x0 + x];
        // The L glyph: left column lit, bottom row lit, top-right dark.
        assert_eq!(at(0, 0), fg);
        assert_eq!(at(4, 6), fg);
        assert_ne!(at(4, 0), fg);
        // Padding beyond `width` is never touched.
        assert!((0..h).all(|y| buf[y * stride + w..(y + 1) * stride]
            .iter()
            .all(|p| *p == 0)));
    }

    #[test]
    fn scales_up_on_wide_screens_and_drops_text_past_the_last_row() {
        let (w, h) = (1920, 40);
        let mut buf = std::vec![0u32; w * h];
        let mut s = screen(&mut buf, w, h, w);
        assert_eq!(s.columns(), 80);
        assert_eq!(s.rows(), 1);
        s.clear();
        write!(s, "HELLO").unwrap(); // Row 1 is past the last row at this height.
        let bg =
            u32::from(BACKGROUND.0) << 16 | u32::from(BACKGROUND.1) << 8 | u32::from(BACKGROUND.2);
        assert!(buf.iter().all(|p| *p == bg));
    }
}
