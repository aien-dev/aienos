//! Forward pass, KV cache and greedy decode (aienos#34 lanes 2 and 3).
//!
//! Scalar f32, one token at a time. Graph per layer (llama.cpp
//! `src/models/llama.cpp`): RMSNorm, Q/K/V, RoPE (adjacent pairs, base
//! `rope_freq_base`, per-pair divisor from `rope_freqs.weight`), causal
//! grouped-query attention over the cache (scale `1/sqrt(head_dim)`), output
//! projection, residual, RMSNorm, SwiGLU (`silu(gate) * up -> down`), residual.

use alloc::vec;
use alloc::vec::Vec;

use crate::math;
use crate::model::{InferError, Model, Weight};
use crate::quant::Q8Act;

/// KV cache plus scratch buffers for one sequence.
pub struct DecodeState {
    capacity: usize,
    pos: usize,
    kv_dim: usize,
    /// `[layer][pos][kv_dim]`
    k: Vec<f32>,
    v: Vec<f32>,
    x: Vec<f32>,
    h: Vec<f32>,
    q: Vec<f32>,
    kk: Vec<f32>,
    vv: Vec<f32>,
    att: Vec<f32>,
    scores: Vec<f32>,
    gate: Vec<f32>,
    up: Vec<f32>,
    tmp: Vec<f32>,
    scr: Vec<f32>,
    rope_cos: Vec<f32>,
    rope_sin: Vec<f32>,
    /// Logits of the last position that asked for them.
    pub logits: Vec<f32>,
    /// Round matvec inputs to the Q8_K grid like ggml does (default off).
    pub emulate_q8k: bool,
    /// Run the quantized matvecs on int8 activations (ggml's Q8_K grid,
    /// i32 dots; aienos#34 L6). Implies the Q8_K rounding. Default off.
    pub int8_dot: bool,
    q8: Q8Act,
}

impl DecodeState {
    /// Cache for up to `capacity` positions of `model`.
    pub fn new(model: &Model<'_>, capacity: usize) -> Self {
        let p = &model.params;
        let (e, ff) = (p.embedding_length as usize, p.feed_forward_length as usize);
        let n_layer = p.block_count as usize;
        let kv = n_layer * capacity * model.kv_dim;
        Self {
            capacity,
            pos: 0,
            kv_dim: model.kv_dim,
            k: vec![0.0; kv],
            v: vec![0.0; kv],
            x: vec![0.0; e],
            h: vec![0.0; e],
            q: vec![0.0; e],
            kk: vec![0.0; model.kv_dim],
            vv: vec![0.0; model.kv_dim],
            att: vec![0.0; e],
            scores: vec![0.0; capacity],
            gate: vec![0.0; ff],
            up: vec![0.0; ff],
            tmp: vec![0.0; e.max(ff)],
            scr: vec![0.0; e.max(ff)],
            rope_cos: vec![0.0; model.head_dim / 2],
            rope_sin: vec![0.0; model.head_dim / 2],
            logits: vec![0.0; p.vocab_size as usize],
            emulate_q8k: false,
            int8_dot: false,
            q8: Q8Act::with_capacity(e.max(ff)),
        }
    }

    /// Positions already in the cache.
    pub fn len(&self) -> usize {
        self.pos
    }
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    /// Forget the sequence (buffers are kept).
    pub fn reset(&mut self) {
        self.pos = 0;
    }
}

/// `x * w / sqrt(mean(x^2) + eps)` into `out`.
pub fn rms_norm(x: &[f32], w: &[f32], eps: f32, out: &mut [f32]) {
    let ss: f32 = x.iter().map(|v| v * v).sum::<f32>() / x.len() as f32;
    let scale = 1.0 / math::sqrt(ss + eps);
    for ((o, v), g) in out.iter_mut().zip(x).zip(w) {
        *o = v * scale * g;
    }
}

/// In-place softmax with max subtraction.
pub fn softmax(x: &mut [f32]) {
    let max = x.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut sum = 0.0;
    for v in x.iter_mut() {
        *v = math::exp(*v - max);
        sum += *v;
    }
    for v in x.iter_mut() {
        *v /= sum;
    }
}

/// Fill cos/sin for one position as ggml's `ggml_rope_cache_init` does:
/// `theta` starts at `pos`, is multiplied by `base^(-2/n_rot)` each pair and
/// divided by that pair's factor.
pub fn rope_cache(pos: usize, base: f32, factors: &[f32], cos: &mut [f32], sin: &mut [f32]) {
    let n_rot = cos.len() * 2;
    let theta_scale = math::powf(base, -2.0 / n_rot as f32);
    let mut theta = pos as f32;
    for i in 0..cos.len() {
        let ff = factors.get(i).copied().unwrap_or(1.0);
        let (s, c) = math::sin_cos(theta / ff);
        cos[i] = c;
        sin[i] = s;
        theta *= theta_scale;
    }
}

/// Rotate adjacent pairs of every head of `x` in place.
pub fn rope_apply(x: &mut [f32], head_dim: usize, cos: &[f32], sin: &[f32]) {
    for head in x.chunks_exact_mut(head_dim) {
        for i in 0..head_dim / 2 {
            let (a, b) = (head[2 * i], head[2 * i + 1]);
            head[2 * i] = a * cos[i] - b * sin[i];
            head[2 * i + 1] = a * sin[i] + b * cos[i];
        }
    }
}

impl DecodeState {
    /// Run one token through the model at the next position, appending to
    /// the cache. Logits are computed (into `self.logits`) only when
    /// `want_logits`, since they cost as much as several layers.
    pub fn forward(
        &mut self,
        m: &Model<'_>,
        token: u32,
        want_logits: bool,
    ) -> Result<(), InferError> {
        let p = &m.params;
        if token >= p.vocab_size {
            return Err(InferError::BadToken(token));
        }
        if self.pos >= self.capacity {
            return Err(InferError::ContextFull);
        }
        let pos = self.pos;
        let hd = m.head_dim;
        let n_head = p.head_count as usize;
        let group = n_head / p.head_count_kv as usize;
        let eps = p.rms_norm_eps;
        let scale = 1.0 / math::sqrt(hd as f32);

        m.tok_embd.row_into(token as usize, &mut self.x)?;
        rope_cache(
            pos,
            p.rope_freq_base,
            &m.rope_factors,
            &mut self.rope_cos,
            &mut self.rope_sin,
        );

        let (int8, round) = (self.int8_dot, self.emulate_q8k);
        for (l, layer) in m.layers.iter().enumerate() {
            rms_norm(&self.x, &layer.attn_norm, eps, &mut self.h);
            prep(&mut self.h, &mut self.q8, int8, round)?;
            mv(
                &layer.wq,
                &self.h,
                &self.q8,
                int8,
                &mut self.q,
                &mut self.scr,
            )?;
            mv(
                &layer.wk,
                &self.h,
                &self.q8,
                int8,
                &mut self.kk,
                &mut self.scr,
            )?;
            mv(
                &layer.wv,
                &self.h,
                &self.q8,
                int8,
                &mut self.vv,
                &mut self.scr,
            )?;
            rope_apply(&mut self.q, hd, &self.rope_cos, &self.rope_sin);
            rope_apply(&mut self.kk, hd, &self.rope_cos, &self.rope_sin);

            let base = l * self.capacity * self.kv_dim;
            let at = base + pos * self.kv_dim;
            self.k[at..at + self.kv_dim].copy_from_slice(&self.kk);
            self.v[at..at + self.kv_dim].copy_from_slice(&self.vv);

            for h in 0..n_head {
                let kvh = (h / group) * hd;
                let q = &self.q[h * hd..(h + 1) * hd];
                let sc = &mut self.scores[..=pos];
                for (t, s) in sc.iter_mut().enumerate() {
                    let kt = &self.k[base + t * self.kv_dim + kvh..][..hd];
                    *s = q.iter().zip(kt).map(|(a, b)| a * b).sum::<f32>() * scale;
                }
                softmax(sc);
                let out = &mut self.att[h * hd..(h + 1) * hd];
                out.fill(0.0);
                for (t, &w) in sc.iter().enumerate() {
                    let vt = &self.v[base + t * self.kv_dim + kvh..][..hd];
                    for (o, v) in out.iter_mut().zip(vt) {
                        *o += w * v;
                    }
                }
            }
            let e = self.x.len();
            prep(&mut self.att, &mut self.q8, int8, round)?;
            mv(
                &layer.wo,
                &self.att,
                &self.q8,
                int8,
                &mut self.tmp[..e],
                &mut self.scr,
            )?;
            for (x, d) in self.x.iter_mut().zip(&self.tmp[..e]) {
                *x += d;
            }

            rms_norm(&self.x, &layer.ffn_norm, eps, &mut self.h);
            prep(&mut self.h, &mut self.q8, int8, round)?;
            mv(
                &layer.w_gate,
                &self.h,
                &self.q8,
                int8,
                &mut self.gate,
                &mut self.scr,
            )?;
            mv(
                &layer.w_up,
                &self.h,
                &self.q8,
                int8,
                &mut self.up,
                &mut self.scr,
            )?;
            for (g, u) in self.gate.iter_mut().zip(&self.up) {
                *g = *g / (1.0 + math::exp(-*g)) * u;
            }
            prep(&mut self.gate, &mut self.q8, int8, round)?;
            mv(
                &layer.w_down,
                &self.gate,
                &self.q8,
                int8,
                &mut self.tmp[..e],
                &mut self.scr,
            )?;
            for (x, d) in self.x.iter_mut().zip(&self.tmp[..e]) {
                *x += d;
            }
        }
        self.pos += 1;
        if want_logits {
            rms_norm(&self.x, &m.output_norm, eps, &mut self.h);
            prep(&mut self.h, &mut self.q8, int8, round)?;
            mv(
                &m.output,
                &self.h,
                &self.q8,
                int8,
                &mut self.logits,
                &mut self.scr,
            )?;
        }
        Ok(())
    }

    /// Feed `ids` in order (prefill); logits are computed for the last one.
    pub fn prefill(&mut self, m: &Model<'_>, ids: &[u32]) -> Result<(), InferError> {
        for (i, &t) in ids.iter().enumerate() {
            self.forward(m, t, i + 1 == ids.len())?;
        }
        Ok(())
    }
}

/// Index of the largest logit (first on ties, like llama.cpp's greedy).
pub fn argmax(logits: &[f32]) -> u32 {
    let mut best = 0usize;
    for (i, &v) in logits.iter().enumerate() {
        if v > logits[best] {
            best = i;
        }
    }
    best as u32
}

/// Greedy generation: prefill `prompt`, then up to `max_new` tokens, stopping
/// after any id in `stop` (that id is included in the result).
pub fn generate_greedy(
    m: &Model<'_>,
    st: &mut DecodeState,
    prompt: &[u32],
    max_new: usize,
    stop: &[u32],
) -> Result<Vec<u32>, InferError> {
    let mut out = Vec::new();
    st.prefill(m, prompt)?;
    for i in 0..max_new {
        let t = argmax(&st.logits);
        out.push(t);
        if stop.contains(&t) || i + 1 == max_new {
            break;
        }
        st.forward(m, t, true)?;
    }
    Ok(out)
}

/// Prepare an activation vector for the quantized matvecs that follow: the
/// int8 path quantizes it into `q8`; the emulation path rounds it in place.
fn prep(x: &mut [f32], q8: &mut Q8Act, int8: bool, round: bool) -> Result<(), InferError> {
    if int8 {
        q8.quantize(x)?;
    } else if round {
        q8k_round(x);
    }
    Ok(())
}

/// One matvec on whichever path applies (int8 only for K-quant weights).
fn mv(
    w: &Weight<'_>,
    x: &[f32],
    q8: &Q8Act,
    int8: bool,
    out: &mut [f32],
    scr: &mut [f32],
) -> Result<(), InferError> {
    if int8 && w.is_kquant() {
        w.matvec_q8(q8, out)
    } else {
        w.matvec(x, out, scr)
    }
}

/// Round activations to ggml's Q8_K grid in place (per 256-block: scale
/// `d = max/-127` where `max` is the signed value of largest magnitude,
/// `q = round-half-even(x / d)` clamped to 127, value `q * d`). ggml quantizes
/// the activations this way before every quantized dot; applying it makes
/// results track llama.cpp more closely (see `DecodeState::emulate_q8k`).
pub fn q8k_round(x: &mut [f32]) {
    for blk in x.chunks_exact_mut(256) {
        let mut amax = 0f32;
        let mut max = 0f32;
        for &v in blk.iter() {
            if v.abs() > amax {
                amax = v.abs();
                max = v;
            }
        }
        if amax == 0.0 {
            continue;
        }
        let iscale = -127.0 / max;
        let d = 1.0 / iscale;
        for v in blk.iter_mut() {
            let t = *v * iscale;
            // nearest_int: magic-number rounding (ties to even), as ggml.
            let q = ((t + 12_582_912.0) - 12_582_912.0).min(127.0);
            *v = q * d;
        }
    }
}

#[cfg(test)]
mod rope_tests {
    //! AO-1 (Drake's attention hardening cut): RoPE relative-position qualification through
    //! this crate's own `rope_cache` + `rope_apply` (ggml adjacent-pair convention), with no
    //! dependency on any other repo's implementation.
    use super::*;

    const HD: usize = 8;
    const BASE: f32 = 10000.0;

    fn absf(x: f32) -> f32 {
        if x < 0.0 {
            -x
        } else {
            x
        }
    }

    fn lcg(seed: &mut u64) -> f32 {
        *seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((*seed >> 33) as f32 / (1u64 << 31) as f32) * 2.0 - 1.0
    }

    fn rot(x: &[f32; HD], pos: usize) -> [f32; HD] {
        let (mut c, mut s) = ([0.0f32; HD / 2], [0.0f32; HD / 2]);
        rope_cache(pos, BASE, &[], &mut c, &mut s);
        let mut y = *x;
        rope_apply(&mut y, HD, &c, &s);
        y
    }

    fn dot(a: &[f32], b: &[f32]) -> f32 {
        a.iter().zip(b).map(|(x, y)| x * y).sum()
    }

    #[test]
    fn pair_zero_rotates_by_the_position_angle() {
        // pair 0 has theta = pos exactly (ggml: theta starts at pos), so e_0 -> (cos pos, sin pos)
        let mut x = [0.0f32; HD];
        x[0] = 1.0;
        let y = rot(&x, 1);
        let (s, c) = math::sin_cos(1.0);
        assert!(absf(y[0] - c) < 1e-6 && absf(y[1] - s) < 1e-6, "{y:?}");
        assert!(y[2..].iter().all(|v| *v == 0.0), "other pairs untouched");
        assert_eq!(rot(&x, 0), x, "position 0 is the identity");
    }

    #[test]
    fn score_depends_on_relative_position_only() {
        let mut seed = 0x5eed_u64;
        let mut q = [0.0f32; HD];
        let mut k = [0.0f32; HD];
        for v in q.iter_mut().chain(k.iter_mut()) {
            *v = lcg(&mut seed);
        }
        let same = dot(&rot(&q, 11), &rot(&k, 11));
        assert!(absf(same - dot(&q, &k)) < 1e-5, "same position must cancel");
        let a = dot(&rot(&q, 5), &rot(&k, 2));
        let b = dot(&rot(&q, 13), &rot(&k, 10));
        let c = dot(&rot(&q, 5), &rot(&k, 3));
        assert!(absf(a - b) < 1e-4, "offset 3 at two bases: {a} vs {b}");
        assert!(
            absf(a - c) > 1e-3,
            "offsets 3 and 2 must differ: {a} vs {c}"
        );
        // the rotation is a rotation: norms are preserved
        assert!(absf(dot(&rot(&q, 97), &rot(&q, 97)) - dot(&q, &q)) < 1e-4);
    }

    #[test]
    fn every_head_is_rotated_independently_with_the_same_table() {
        let mut seed = 7u64;
        let mut x = [0.0f32; 3 * HD];
        for v in x.iter_mut() {
            *v = lcg(&mut seed);
        }
        // head 1 copies head 0, head 2 differs
        for d in 0..HD {
            x[HD + d] = x[d];
        }
        let (mut c, mut s) = ([0.0f32; HD / 2], [0.0f32; HD / 2]);
        rope_cache(9, BASE, &[], &mut c, &mut s);
        let before = x;
        rope_apply(&mut x, HD, &c, &s);
        assert_eq!(x[..HD], x[HD..2 * HD], "equal heads must rotate equally");
        assert!(x[..HD] != before[..HD], "position 9 must change the head");
        let mut diff = false;
        for d in 0..HD {
            diff |= absf(x[2 * HD + d] - x[d]) > 1e-3;
        }
        assert!(diff, "a different head must come out different");
    }

    #[test]
    fn softmax_weights_are_shift_invariant_and_position_sensitive() {
        const T: usize = 5;
        let mut seed = 99u64;
        let mut q = [0.0f32; HD];
        let mut k0 = [0.0f32; HD];
        for v in q.iter_mut().chain(k0.iter_mut()) {
            *v = lcg(&mut seed) * 3.0;
        }
        // K for token t is k0 shifted by t so tokens are distinguishable before rope
        let weights = |base: usize, q_pos: usize| -> [f32; T] {
            let mut w = [0.0f32; T];
            let rq = rot(&q, base + q_pos);
            for (t, wt) in w.iter_mut().enumerate() {
                let mut kt = k0;
                kt[t % HD] += 1.0;
                *wt = dot(&rq, &rot(&kt, base + t)) / math::sqrt(HD as f32);
            }
            softmax(&mut w);
            w
        };
        let w0 = weights(0, T - 1);
        let w23 = weights(23, T - 1);
        let sum: f32 = w0.iter().sum();
        assert!(absf(sum - 1.0) < 1e-5);
        for t in 0..T {
            assert!(
                absf(w0[t] - w23[t]) < 1e-4,
                "token {t}: {} vs {}",
                w0[t],
                w23[t]
            );
        }
        let w_moved = weights(0, T + 4);
        let mut changed = false;
        for t in 0..T {
            changed |= absf(w0[t] - w_moved[t]) > 1e-3;
        }
        assert!(changed, "moving q relative to K must change the weights");
    }
}
