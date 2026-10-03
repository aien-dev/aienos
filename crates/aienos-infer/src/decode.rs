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
use crate::model::{InferError, Model};

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

        for (l, layer) in m.layers.iter().enumerate() {
            rms_norm(&self.x, &layer.attn_norm, eps, &mut self.h);
            if self.emulate_q8k {
                q8k_round(&mut self.h);
            }
            layer.wq.matvec(&self.h, &mut self.q, &mut self.scr)?;
            layer.wk.matvec(&self.h, &mut self.kk, &mut self.scr)?;
            layer.wv.matvec(&self.h, &mut self.vv, &mut self.scr)?;
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
            if self.emulate_q8k {
                q8k_round(&mut self.att);
            }
            layer
                .wo
                .matvec(&self.att, &mut self.tmp[..e], &mut self.scr)?;
            for (x, d) in self.x.iter_mut().zip(&self.tmp[..e]) {
                *x += d;
            }

            rms_norm(&self.x, &layer.ffn_norm, eps, &mut self.h);
            if self.emulate_q8k {
                q8k_round(&mut self.h);
            }
            layer
                .w_gate
                .matvec(&self.h, &mut self.gate, &mut self.scr)?;
            layer.w_up.matvec(&self.h, &mut self.up, &mut self.scr)?;
            for (g, u) in self.gate.iter_mut().zip(&self.up) {
                *g = *g / (1.0 + math::exp(-*g)) * u;
            }
            if self.emulate_q8k {
                q8k_round(&mut self.gate);
            }
            layer
                .w_down
                .matvec(&self.gate, &mut self.tmp[..e], &mut self.scr)?;
            for (x, d) in self.x.iter_mut().zip(&self.tmp[..e]) {
                *x += d;
            }
        }
        self.pos += 1;
        if want_logits {
            rms_norm(&self.x, &m.output_norm, eps, &mut self.h);
            if self.emulate_q8k {
                q8k_round(&mut self.h);
            }
            m.output.matvec(&self.h, &mut self.logits, &mut self.scr)?;
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
