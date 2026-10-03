//! Bounded GGUF v3 reader over a byte slice.
//!
//! Layout (GGUF spec, little endian): magic `GGUF`, u32 version, u64 tensor
//! count, u64 key/value count, the key/value pairs, the tensor infos, padding
//! to `general.alignment` (default 32), then the tensor data.

use alloc::vec::Vec;
use core::fmt;

use crate::half::{bf16_to_f32, f16_to_f32};

/// Everything that can go wrong while reading a GGUF file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GgufError {
    /// A read ran past the end of the input at this byte offset.
    Truncated(usize),
    BadMagic,
    UnsupportedVersion(u32),
    /// A declared count cannot fit in the remaining bytes.
    TooMany,
    BadUtf8,
    /// Unknown or unsupported key/value type code.
    BadValueType(u32),
    /// `general.alignment` is zero, not a power of two, or not a u32.
    BadAlignment,
    /// Arithmetic overflow while computing sizes or offsets.
    Overflow,
    /// Tensor type code this reader cannot size.
    UnsupportedType(u32),
    /// More than 4 dimensions or zero dimensions.
    BadDims,
    /// Tensor offset or byte range falls outside the data section, or its
    /// offset is not a multiple of the alignment.
    TensorOutOfRange,
    /// Required key absent.
    Missing(&'static str),
    /// Key present with a different type than requested.
    WrongType(&'static str),
}

impl fmt::Display for GgufError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// GGUF metadata value type codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueType {
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    F32,
    Bool,
    Str,
    Array,
    U64,
    I64,
    F64,
}

impl ValueType {
    fn from_code(c: u32) -> Result<Self, GgufError> {
        Ok(match c {
            0 => Self::U8,
            1 => Self::I8,
            2 => Self::U16,
            3 => Self::I16,
            4 => Self::U32,
            5 => Self::I32,
            6 => Self::F32,
            7 => Self::Bool,
            8 => Self::Str,
            9 => Self::Array,
            10 => Self::U64,
            11 => Self::I64,
            12 => Self::F64,
            other => return Err(GgufError::BadValueType(other)),
        })
    }

    /// Byte size for fixed-size scalars, `None` for string/array.
    fn fixed_size(self) -> Option<usize> {
        match self {
            Self::U8 | Self::I8 | Self::Bool => Some(1),
            Self::U16 | Self::I16 => Some(2),
            Self::U32 | Self::I32 | Self::F32 => Some(4),
            Self::U64 | Self::I64 | Self::F64 => Some(8),
            Self::Str | Self::Array => None,
        }
    }
}

/// A one-dimensional array of scalars or strings, validated at parse time.
#[derive(Debug, Clone, Copy)]
pub struct ArrayView<'a> {
    pub elem: ValueType,
    len: usize,
    data: &'a [u8],
}

impl<'a> ArrayView<'a> {
    /// Number of elements.
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Iterate strings; empty unless the element type is string.
    pub fn strings(&self) -> impl Iterator<Item = &'a str> + 'a {
        let mut cur = Cursor::new(self.data);
        let n = if self.elem == ValueType::Str {
            self.len
        } else {
            0
        };
        (0..n).map_while(move |_| cur.str().ok())
    }
    fn chunks(&self, want: &[ValueType], size: usize) -> impl Iterator<Item = &'a [u8]> + 'a {
        let ok = want.contains(&self.elem);
        let data = if ok { self.data } else { &[][..] };
        data.chunks_exact(size)
    }
    /// Iterate u32 elements (empty unless element type is u32).
    pub fn u32s(&self) -> impl Iterator<Item = u32> + 'a {
        self.chunks(&[ValueType::U32], 4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
    }
    /// Iterate i32 elements (empty unless element type is i32).
    pub fn i32s(&self) -> impl Iterator<Item = i32> + 'a {
        self.chunks(&[ValueType::I32], 4)
            .map(|c| i32::from_le_bytes([c[0], c[1], c[2], c[3]]))
    }
    /// Iterate f32 elements (empty unless element type is f32).
    pub fn f32s(&self) -> impl Iterator<Item = f32> + 'a {
        self.chunks(&[ValueType::F32], 4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
    }
}

/// A metadata value.
#[derive(Debug, Clone, Copy)]
pub enum Value<'a> {
    U8(u8),
    I8(i8),
    U16(u16),
    I16(i16),
    U32(u32),
    I32(i32),
    F32(f32),
    Bool(bool),
    Str(&'a str),
    Array(ArrayView<'a>),
    U64(u64),
    I64(i64),
    F64(f64),
}

impl<'a> Value<'a> {
    /// Any integer value that fits in u64 (non-negative).
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Value::U8(v) => Some(v as u64),
            Value::U16(v) => Some(v as u64),
            Value::U32(v) => Some(v as u64),
            Value::U64(v) => Some(v),
            Value::I8(v) => u64::try_from(v).ok(),
            Value::I16(v) => u64::try_from(v).ok(),
            Value::I32(v) => u64::try_from(v).ok(),
            Value::I64(v) => u64::try_from(v).ok(),
            _ => None,
        }
    }
    pub fn as_f32(&self) -> Option<f32> {
        match *self {
            Value::F32(v) => Some(v),
            Value::F64(v) => Some(v as f32),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&'a str> {
        match *self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<ArrayView<'a>> {
        match *self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
}

/// ggml tensor storage types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GgmlType {
    F32,
    F16,
    Q4_0,
    Q4_1,
    Q5_0,
    Q5_1,
    Q8_0,
    Q8_1,
    Q2K,
    Q3K,
    Q4K,
    Q5K,
    Q6K,
    Q8K,
    I8,
    I16,
    I32,
    I64,
    F64,
    BF16,
}

impl GgmlType {
    pub fn from_code(c: u32) -> Result<Self, GgufError> {
        Ok(match c {
            0 => Self::F32,
            1 => Self::F16,
            2 => Self::Q4_0,
            3 => Self::Q4_1,
            6 => Self::Q5_0,
            7 => Self::Q5_1,
            8 => Self::Q8_0,
            9 => Self::Q8_1,
            10 => Self::Q2K,
            11 => Self::Q3K,
            12 => Self::Q4K,
            13 => Self::Q5K,
            14 => Self::Q6K,
            15 => Self::Q8K,
            24 => Self::I8,
            25 => Self::I16,
            26 => Self::I32,
            27 => Self::I64,
            28 => Self::F64,
            30 => Self::BF16,
            other => return Err(GgufError::UnsupportedType(other)),
        })
    }

    /// (weights per block, bytes per block).
    pub fn block(self) -> (usize, usize) {
        match self {
            Self::F32 | Self::I32 => (1, 4),
            Self::F16 | Self::BF16 | Self::I16 => (1, 2),
            Self::I8 => (1, 1),
            Self::I64 | Self::F64 => (1, 8),
            Self::Q4_0 => (32, 18),
            Self::Q4_1 => (32, 20),
            Self::Q5_0 => (32, 22),
            Self::Q5_1 => (32, 24),
            Self::Q8_0 => (32, 34),
            Self::Q8_1 => (32, 36),
            Self::Q2K => (256, 84),
            Self::Q3K => (256, 110),
            Self::Q4K => (256, 144),
            Self::Q5K => (256, 176),
            Self::Q6K => (256, 210),
            Self::Q8K => (256, 292),
        }
    }
}

/// One entry of the tensor table.
#[derive(Debug, Clone)]
pub struct TensorInfo<'a> {
    pub name: &'a str,
    /// Dimensions, `dims[0]` is the contiguous (row) length. Only the first
    /// `n_dims` are meaningful.
    pub dims: [u64; 4],
    pub n_dims: u32,
    pub ty: GgmlType,
    /// Offset from the start of the data section.
    pub offset: u64,
    /// Total weights.
    pub n_elements: u64,
    /// Total bytes, from the type's block math.
    pub n_bytes: u64,
}

impl TensorInfo<'_> {
    /// Bytes in one row (`dims[0]` weights).
    pub fn row_bytes(&self) -> u64 {
        let (bw, bb) = self.ty.block();
        self.dims[0] / bw as u64 * bb as u64
    }
}

/// Bounds-checked little-endian reader.
struct Cursor<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.b.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], GgufError> {
        if n > self.remaining() {
            return Err(GgufError::Truncated(self.pos));
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn arr<const N: usize>(&mut self) -> Result<[u8; N], GgufError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, GgufError> {
        Ok(self.arr::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, GgufError> {
        Ok(u16::from_le_bytes(self.arr()?))
    }
    fn u32(&mut self) -> Result<u32, GgufError> {
        Ok(u32::from_le_bytes(self.arr()?))
    }
    fn u64(&mut self) -> Result<u64, GgufError> {
        Ok(u64::from_le_bytes(self.arr()?))
    }
    fn len64(&mut self) -> Result<usize, GgufError> {
        usize::try_from(self.u64()?).map_err(|_| GgufError::Overflow)
    }
    fn str(&mut self) -> Result<&'a str, GgufError> {
        let n = self.len64()?;
        let s = self.take(n)?;
        core::str::from_utf8(s).map_err(|_| GgufError::BadUtf8)
    }

    fn value(&mut self, ty: ValueType) -> Result<Value<'a>, GgufError> {
        Ok(match ty {
            ValueType::U8 => Value::U8(self.u8()?),
            ValueType::I8 => Value::I8(self.u8()? as i8),
            ValueType::U16 => Value::U16(self.u16()?),
            ValueType::I16 => Value::I16(self.u16()? as i16),
            ValueType::U32 => Value::U32(self.u32()?),
            ValueType::I32 => Value::I32(self.u32()? as i32),
            ValueType::F32 => Value::F32(f32::from_bits(self.u32()?)),
            ValueType::Bool => match self.u8()? {
                0 => Value::Bool(false),
                1 => Value::Bool(true),
                other => return Err(GgufError::BadValueType(other as u32)),
            },
            ValueType::Str => Value::Str(self.str()?),
            ValueType::U64 => Value::U64(self.u64()?),
            ValueType::I64 => Value::I64(self.u64()? as i64),
            ValueType::F64 => Value::F64(f64::from_bits(self.u64()?)),
            ValueType::Array => {
                let elem = ValueType::from_code(self.u32()?)?;
                let len = self.len64()?;
                let start = self.pos;
                match elem.fixed_size() {
                    Some(sz) => {
                        let total = len.checked_mul(sz).ok_or(GgufError::Overflow)?;
                        self.take(total)?;
                    }
                    None if elem == ValueType::Str => {
                        // Each string needs at least its 8-byte length.
                        if len > self.remaining() / 8 {
                            return Err(GgufError::TooMany);
                        }
                        for _ in 0..len {
                            self.str()?;
                        }
                    }
                    None => return Err(GgufError::BadValueType(9)), // nested arrays
                }
                Value::Array(ArrayView {
                    elem,
                    len,
                    data: &self.b[start..self.pos],
                })
            }
        })
    }
}

/// A parsed GGUF file borrowing the input bytes.
#[derive(Debug)]
pub struct Gguf<'a> {
    bytes: &'a [u8],
    pub version: u32,
    kv: Vec<(&'a str, Value<'a>)>,
    tensors: Vec<TensorInfo<'a>>,
    pub alignment: u64,
    /// Byte offset of the tensor data section within the input.
    pub data_start: usize,
}

impl<'a> Gguf<'a> {
    /// Parse and fully validate the header, metadata and tensor table.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, GgufError> {
        let mut c = Cursor::new(bytes);
        if c.take(4)? != b"GGUF" {
            return Err(GgufError::BadMagic);
        }
        let version = c.u32()?;
        if version != 3 {
            return Err(GgufError::UnsupportedVersion(version));
        }
        let n_tensors = c.len64()?;
        let n_kv = c.len64()?;
        // A kv needs >= 8 (key len) + 4 (type) bytes; a tensor info >= 8+4+8+4+8.
        if n_kv > c.remaining() / 12 || n_tensors > c.remaining() / 32 {
            return Err(GgufError::TooMany);
        }

        let mut kv = Vec::with_capacity(n_kv);
        for _ in 0..n_kv {
            let key = c.str()?;
            let ty = ValueType::from_code(c.u32()?)?;
            kv.push((key, c.value(ty)?));
        }

        let alignment = match kv.iter().find(|(k, _)| *k == "general.alignment") {
            None => 32,
            Some((_, v)) => match *v {
                Value::U32(a) if a != 0 && a.is_power_of_two() => a as u64,
                _ => return Err(GgufError::BadAlignment),
            },
        };

        let mut tensors: Vec<TensorInfo<'a>> = Vec::with_capacity(n_tensors);
        for _ in 0..n_tensors {
            let name = c.str()?;
            let n_dims = c.u32()?;
            if n_dims == 0 || n_dims > 4 {
                return Err(GgufError::BadDims);
            }
            let mut dims = [1u64; 4];
            for d in dims.iter_mut().take(n_dims as usize) {
                *d = c.u64()?;
            }
            let ty = GgmlType::from_code(c.u32()?)?;
            let offset = c.u64()?;
            let mut n_elements: u64 = 1;
            for d in dims {
                n_elements = n_elements.checked_mul(d).ok_or(GgufError::Overflow)?;
            }
            let (bw, bb) = ty.block();
            if dims[0] % bw as u64 != 0 {
                return Err(GgufError::BadDims);
            }
            let n_bytes = (n_elements / bw as u64)
                .checked_mul(bb as u64)
                .ok_or(GgufError::Overflow)?;
            tensors.push(TensorInfo {
                name,
                dims,
                n_dims,
                ty,
                offset,
                n_elements,
                n_bytes,
            });
        }

        let pos = c.pos as u64;
        let data_start =
            pos.checked_add(alignment - 1).ok_or(GgufError::Overflow)? & !(alignment - 1);
        let data_start = usize::try_from(data_start).map_err(|_| GgufError::Overflow)?;
        if data_start > bytes.len() {
            return Err(GgufError::Truncated(bytes.len()));
        }
        let data_len = (bytes.len() - data_start) as u64;
        for t in &tensors {
            let end = t.offset.checked_add(t.n_bytes).ok_or(GgufError::Overflow)?;
            if end > data_len || t.offset % alignment != 0 {
                return Err(GgufError::TensorOutOfRange);
            }
        }

        Ok(Self {
            bytes,
            version,
            kv,
            tensors,
            alignment,
            data_start,
        })
    }

    /// All key/value pairs in file order.
    pub fn kvs(&self) -> &[(&'a str, Value<'a>)] {
        &self.kv
    }
    /// Look up a metadata value.
    pub fn get(&self, key: &str) -> Option<Value<'a>> {
        self.kv.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }
    /// All tensor infos in file order.
    pub fn tensors(&self) -> &[TensorInfo<'a>] {
        &self.tensors
    }
    /// Find a tensor by name.
    pub fn tensor(&self, name: &str) -> Option<&TensorInfo<'a>> {
        self.tensors.iter().find(|t| t.name == name)
    }
    /// Raw bytes of a tensor (range validated at parse time).
    pub fn tensor_data(&self, t: &TensorInfo<'_>) -> &'a [u8] {
        let s = self.data_start + t.offset as usize;
        &self.bytes[s..s + t.n_bytes as usize]
    }

    fn req(&self, key: &'static str) -> Result<Value<'a>, GgufError> {
        self.get(key).ok_or(GgufError::Missing(key))
    }
    /// Required unsigned integer key.
    pub fn u64_key(&self, key: &'static str) -> Result<u64, GgufError> {
        self.req(key)?.as_u64().ok_or(GgufError::WrongType(key))
    }
    /// Required key that must fit in u32.
    pub fn u32_key(&self, key: &'static str) -> Result<u32, GgufError> {
        u32::try_from(self.u64_key(key)?).map_err(|_| GgufError::WrongType(key))
    }
    pub fn f32_key(&self, key: &'static str) -> Result<f32, GgufError> {
        self.req(key)?.as_f32().ok_or(GgufError::WrongType(key))
    }
    pub fn str_key(&self, key: &'static str) -> Result<&'a str, GgufError> {
        self.req(key)?.as_str().ok_or(GgufError::WrongType(key))
    }
    pub fn array_key(&self, key: &'static str) -> Result<ArrayView<'a>, GgufError> {
        self.req(key)?.as_array().ok_or(GgufError::WrongType(key))
    }

    /// `general.architecture` (for Llama-3.2 this is `llama`).
    pub fn architecture(&self) -> Result<&'a str, GgufError> {
        self.str_key("general.architecture")
    }

    /// Hyperparameters, read from `<arch>.<name>` keys as written by llama.cpp.
    pub fn llama_params(&self) -> Result<LlamaParams, GgufError> {
        if self.architecture()? != "llama" {
            return Err(GgufError::WrongType("general.architecture"));
        }
        let vocab_size = match self.get("llama.vocab_size") {
            Some(v) => v
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(GgufError::WrongType("llama.vocab_size"))?,
            // Not stored by llama.cpp converters; derive from the token list.
            None => u32::try_from(self.array_key("tokenizer.ggml.tokens")?.len())
                .map_err(|_| GgufError::Overflow)?,
        };
        Ok(LlamaParams {
            block_count: self.u32_key("llama.block_count")?,
            embedding_length: self.u32_key("llama.embedding_length")?,
            head_count: self.u32_key("llama.attention.head_count")?,
            head_count_kv: self.u32_key("llama.attention.head_count_kv")?,
            feed_forward_length: self.u32_key("llama.feed_forward_length")?,
            context_length: self.u32_key("llama.context_length")?,
            rope_freq_base: self.f32_key("llama.rope.freq_base")?,
            rms_norm_eps: self.f32_key("llama.attention.layer_norm_rms_epsilon")?,
            vocab_size,
        })
    }

    /// Token strings, scores and types plus special ids.
    pub fn tokenizer(&self) -> Result<TokenizerData<'a>, GgufError> {
        let tokens = self.array_key("tokenizer.ggml.tokens")?;
        let scores = self.array_key("tokenizer.ggml.scores").ok();
        let token_type = self.array_key("tokenizer.ggml.token_type").ok();
        let merges = self.array_key("tokenizer.ggml.merges").ok();
        Ok(TokenizerData {
            tokens,
            scores,
            token_type,
            merges,
            bos_id: self.u32_key("tokenizer.ggml.bos_token_id").ok(),
            eos_id: self.u32_key("tokenizer.ggml.eos_token_id").ok(),
        })
    }
}

/// Model hyperparameters needed by the Llama graph.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LlamaParams {
    pub block_count: u32,
    pub embedding_length: u32,
    pub head_count: u32,
    pub head_count_kv: u32,
    pub feed_forward_length: u32,
    pub context_length: u32,
    pub rope_freq_base: f32,
    pub rms_norm_eps: f32,
    pub vocab_size: u32,
}

/// Tokenizer arrays as stored in the file.
#[derive(Debug, Clone, Copy)]
pub struct TokenizerData<'a> {
    pub tokens: ArrayView<'a>,
    pub scores: Option<ArrayView<'a>>,
    pub token_type: Option<ArrayView<'a>>,
    pub merges: Option<ArrayView<'a>>,
    pub bos_id: Option<u32>,
    pub eos_id: Option<u32>,
}

/// Dequantize any row-contiguous slice of a tensor of the plain float types
/// into `out`; quantized types go through [`crate::quant::dequantize`].
pub(crate) fn plain_to_f32(ty: GgmlType, src: &[u8], out: &mut [f32]) -> bool {
    match ty {
        GgmlType::F32 => {
            for (o, c) in out.iter_mut().zip(src.chunks_exact(4)) {
                *o = f32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            }
        }
        GgmlType::F16 => {
            for (o, c) in out.iter_mut().zip(src.chunks_exact(2)) {
                *o = f16_to_f32(u16::from_le_bytes([c[0], c[1]]));
            }
        }
        GgmlType::BF16 => {
            for (o, c) in out.iter_mut().zip(src.chunks_exact(2)) {
                *o = bf16_to_f32(u16::from_le_bytes([c[0], c[1]]));
            }
        }
        _ => return false,
    }
    true
}
