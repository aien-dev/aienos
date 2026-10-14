//! Binary hypervectors (default 8192 bits = 128 u64 words).
//!
//! - Item vectors are generated on the fly from a seeded hash of each symbol (splitmix64);
//!   no random table is stored.
//! - Binding is XOR; order inside a feature is kept by rotating the i-th symbol's vector
//!   by (len - 1 - i) words (a fixed permutation).
//! - Bundling is a weighted majority: an integer counter per bit gets +w for a 1 and -w for
//!   a 0; the sign gives the bit, and a fixed seeded tie-break vector settles zeros.
//! - Similarity is 1 - 2 * Hamming / D, in [-1, 1].

use crate::features::Feat;

/// Global seed of all item vectors (frozen with the artifact).
pub const SEED: u64 = 0x414c_4c45_4e52_4546; // "ALLENREF"

/// splitmix64 step.
#[inline]
pub fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Fill `out` with the item vector of (family, value).
pub fn item(fam: u64, val: u64, out: &mut [u64]) {
    let mut s = SEED ^ fam.wrapping_mul(0xD6E8_FEB8_6659_FD93) ^ val;
    // decorrelate nearby seeds
    splitmix(&mut s);
    for o in out.iter_mut() {
        *o = splitmix(&mut s);
    }
}

/// XOR-accumulate the bound vector of `f` into `acc`; `tmp` is scratch of the same length.
pub fn bind_into(f: &Feat, acc: &mut [u64], tmp: &mut [u64]) {
    let w = acc.len();
    for a in acc.iter_mut() {
        *a = 0;
    }
    let len = f.len as usize;
    for j in 0..len {
        let (fam, val) = f.syms[j].family();
        item(fam, val, tmp);
        let rot = (len - 1 - j) % w;
        for x in 0..w {
            acc[(x + rot) % w] ^= tmp[x];
        }
    }
}

/// Encode a feature list into `out` (binary). `cnt` (64 * words), `acc` and `tmp` are scratch.
pub fn encode(feats: &[Feat], out: &mut [u64], cnt: &mut [i32], acc: &mut [u64], tmp: &mut [u64]) {
    let w = out.len();
    for c in cnt.iter_mut() {
        *c = 0;
    }
    for f in feats {
        bind_into(f, acc, tmp);
        let wt = f.w as i32;
        for x in 0..w {
            let v = acc[x];
            let base = x * 64;
            for b in 0..64 {
                // +wt for a 1 bit, -wt for a 0 bit
                let bit = ((v >> b) & 1) as i32;
                cnt[base + b] += (2 * bit - 1) * wt;
            }
        }
    }
    item(7, 0, tmp); // tie-break vector
    for x in 0..w {
        let mut o = 0u64;
        for b in 0..64 {
            let c = cnt[x * 64 + b];
            let bit = if c > 0 {
                1
            } else if c < 0 {
                0
            } else {
                (tmp[x] >> b) & 1
            };
            o |= bit << b;
        }
        out[x] = o;
    }
}

/// Hamming distance.
#[inline]
pub fn hamming(a: &[u64], b: &[u64]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

/// Similarity in [-1, 1].
#[inline]
pub fn sim(a: &[u64], b: &[u64]) -> f32 {
    let d = (a.len() * 64) as f32;
    1.0 - 2.0 * hamming(a, b) as f32 / d
}

/// Square root without libm (Newton iterations; enough for thresholds and normalisation).
pub fn sqrtf(x: f32) -> f32 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut y = f32::from_bits((x.to_bits() >> 1) + 0x1fbd_1df5);
    for _ in 0..4 {
        y = 0.5 * (y + x / y);
    }
    y
}
