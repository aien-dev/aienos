//! Llama weights bound to a GGUF slice (aienos#34 lane 2).
//!
//! Nothing is copied except the small f32 vectors (norm weights, rope
//! frequency factors). Matrices stay quantized inside the borrowed file and
//! are read one row at a time.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::gguf::{plain_to_f32, GgmlType, Gguf, GgufError, LlamaParams};
use crate::quant::{self, QuantError};

/// Why a model could not be bound or run.
#[derive(Debug, Clone, PartialEq)]
pub enum InferError {
    Gguf(GgufError),
    Quant(QuantError),
    /// Required tensor absent.
    MissingTensor(String),
    /// Tensor shape or type does not fit this architecture.
    BadTensor(String),
    /// Hyperparameters are inconsistent (head sizes, odd rope dim, ...).
    BadParams(&'static str),
    /// Token id outside the vocabulary.
    BadToken(u32),
    /// The KV cache is full.
    ContextFull,
}

impl From<GgufError> for InferError {
    fn from(e: GgufError) -> Self {
        Self::Gguf(e)
    }
}
impl From<QuantError> for InferError {
    fn from(e: QuantError) -> Self {
        Self::Quant(e)
    }
}

/// A 2-D weight matrix inside the GGUF data: `rows` rows of `cols` weights.
#[derive(Clone, Copy)]
pub struct Weight<'a> {
    data: &'a [u8],
    ty: GgmlType,
    pub rows: usize,
    pub cols: usize,
    row_bytes: usize,
}

impl<'a> Weight<'a> {
    fn bind(g: &Gguf<'a>, name: &str, rows: usize, cols: usize) -> Result<Self, InferError> {
        let t = g
            .tensor(name)
            .ok_or_else(|| InferError::MissingTensor(String::from(name)))?;
        let bad = || InferError::BadTensor(format!("{name}: want {cols}x{rows}"));
        if t.n_dims != 2 || t.dims[0] as usize != cols || t.dims[1] as usize != rows {
            return Err(bad());
        }
        let (bw, _) = t.ty.block();
        if cols % bw != 0 {
            return Err(bad());
        }
        match t.ty {
            GgmlType::Q4K | GgmlType::Q6K | GgmlType::F32 | GgmlType::F16 | GgmlType::BF16 => {}
            _ => return Err(bad()),
        }
        let data = g.tensor_data(t);
        let row_bytes = t.row_bytes() as usize;
        if data.len() != row_bytes * rows {
            return Err(bad());
        }
        Ok(Self {
            data,
            ty: t.ty,
            rows,
            cols,
            row_bytes,
        })
    }

    fn row(&self, i: usize) -> &'a [u8] {
        &self.data[i * self.row_bytes..(i + 1) * self.row_bytes]
    }

    /// Dequantize row `i` into `out` (`cols` long).
    pub fn row_into(&self, i: usize, out: &mut [f32]) -> Result<(), InferError> {
        if i >= self.rows || out.len() != self.cols {
            return Err(InferError::BadToken(i as u32));
        }
        if !plain_to_f32(self.ty, self.row(i), out) {
            quant::dequantize(self.ty, self.row(i), out)?;
        }
        Ok(())
    }

    /// `out[r] = row_r . x` for every row. `scratch` is `cols` long and is
    /// used only for the plain float types.
    pub fn matvec(
        &self,
        x: &[f32],
        out: &mut [f32],
        scratch: &mut [f32],
    ) -> Result<(), InferError> {
        if x.len() != self.cols || out.len() != self.rows || scratch.len() < self.cols {
            return Err(InferError::BadParams("matvec shape"));
        }
        // Sub-block sums of x are shared by every Q4_K row (aienos#34 L6).
        let nsums = self.cols / quant::Q4K_SUB;
        if matches!(self.ty, GgmlType::Q4K | GgmlType::Q6K) {
            quant::sub_block_sums(x, &mut scratch[..nsums]);
        }
        for (r, o) in out.iter_mut().enumerate() {
            *o = match self.ty {
                GgmlType::Q4K | GgmlType::Q6K => {
                    quant::dot_row_sums(self.ty, self.row(r), x, &scratch[..nsums])?
                }
                _ => {
                    let s = &mut scratch[..self.cols];
                    plain_to_f32(self.ty, self.row(r), s);
                    s.iter().zip(x).map(|(a, b)| a * b).sum()
                }
            };
        }
        Ok(())
    }

    /// True for the K-quant types the int8 activation path handles.
    pub fn is_kquant(&self) -> bool {
        matches!(self.ty, GgmlType::Q4K | GgmlType::Q6K)
    }

    /// `out[r] = row_r . act` with activations on the Q8_K grid (aienos#34
    /// L6 int8 path); K-quant weights only, see [`Weight::is_kquant`].
    pub fn matvec_q8(&self, act: &quant::Q8Act, out: &mut [f32]) -> Result<(), InferError> {
        if act.len() != self.cols || out.len() != self.rows {
            return Err(InferError::BadParams("matvec shape"));
        }
        if !self.is_kquant() {
            return Err(InferError::BadParams("matvec_q8 needs a K-quant weight"));
        }
        for (r, o) in out.iter_mut().enumerate() {
            *o = quant::dot_row_q8k(self.ty, self.row(r), act)?;
        }
        Ok(())
    }
}

/// One transformer block's tensors.
pub struct Layer<'a> {
    pub attn_norm: Vec<f32>,
    pub wq: Weight<'a>,
    pub wk: Weight<'a>,
    pub wv: Weight<'a>,
    pub wo: Weight<'a>,
    pub ffn_norm: Vec<f32>,
    pub w_gate: Weight<'a>,
    pub w_up: Weight<'a>,
    pub w_down: Weight<'a>,
}

/// A Llama model bound to a GGUF file.
pub struct Model<'a> {
    pub params: LlamaParams,
    pub head_dim: usize,
    pub kv_dim: usize,
    pub layers: Vec<Layer<'a>>,
    pub tok_embd: Weight<'a>,
    /// Output projection: `output.weight` if present, else tied `token_embd`.
    pub output: Weight<'a>,
    pub output_norm: Vec<f32>,
    /// Per rope pair divisors from `rope_freqs.weight` (llama3 scaling as
    /// precomputed by the converter), or empty when absent.
    pub rope_factors: Vec<f32>,
}

fn load_vec(g: &Gguf<'_>, name: &str, n: usize) -> Result<Vec<f32>, InferError> {
    let t = g
        .tensor(name)
        .ok_or_else(|| InferError::MissingTensor(String::from(name)))?;
    if t.n_dims != 1 || t.dims[0] as usize != n || t.ty != GgmlType::F32 {
        return Err(InferError::BadTensor(format!("{name}: want f32[{n}]")));
    }
    let mut v = vec![0f32; n];
    plain_to_f32(t.ty, g.tensor_data(t), &mut v);
    Ok(v)
}

impl<'a> Model<'a> {
    pub fn new(g: &Gguf<'a>) -> Result<Self, InferError> {
        let p = g.llama_params()?;
        let (n_embd, n_head, n_kv, n_ff, vocab) = (
            p.embedding_length as usize,
            p.head_count as usize,
            p.head_count_kv as usize,
            p.feed_forward_length as usize,
            p.vocab_size as usize,
        );
        if n_head == 0 || n_kv == 0 || n_embd % n_head != 0 || n_head % n_kv != 0 {
            return Err(InferError::BadParams("head counts"));
        }
        let head_dim = n_embd / n_head;
        if head_dim % 2 != 0 {
            return Err(InferError::BadParams("odd head dim"));
        }
        let kv_dim = n_kv * head_dim;
        let tok_embd = Weight::bind(g, "token_embd.weight", vocab, n_embd)?;
        let output = if g.tensor("output.weight").is_some() {
            Weight::bind(g, "output.weight", vocab, n_embd)?
        } else {
            tok_embd
        };
        let mut layers = Vec::with_capacity(p.block_count as usize);
        for l in 0..p.block_count {
            let n = |s: &str| format!("blk.{l}.{s}.weight");
            layers.push(Layer {
                attn_norm: load_vec(g, &n("attn_norm"), n_embd)?,
                wq: Weight::bind(g, &n("attn_q"), n_embd, n_embd)?,
                wk: Weight::bind(g, &n("attn_k"), kv_dim, n_embd)?,
                wv: Weight::bind(g, &n("attn_v"), kv_dim, n_embd)?,
                wo: Weight::bind(g, &n("attn_output"), n_embd, n_embd)?,
                ffn_norm: load_vec(g, &n("ffn_norm"), n_embd)?,
                w_gate: Weight::bind(g, &n("ffn_gate"), n_ff, n_embd)?,
                w_up: Weight::bind(g, &n("ffn_up"), n_ff, n_embd)?,
                w_down: Weight::bind(g, &n("ffn_down"), n_embd, n_ff)?,
            });
        }
        let rope_factors = if g.tensor("rope_freqs.weight").is_some() {
            load_vec(g, "rope_freqs.weight", head_dim / 2)?
        } else {
            Vec::new()
        };
        Ok(Self {
            params: p,
            head_dim,
            kv_dim,
            layers,
            tok_embd,
            output,
            output_norm: load_vec(g, "output_norm.weight", n_embd)?,
            rope_factors,
        })
    }
}
