#![no_std]
#![forbid(unsafe_code)]
// Block loops mirror ggml index arithmetic; as_chunks/is_multiple_of are too
// new for this workspace to rely on.
#![allow(
    clippy::needless_range_loop,
    clippy::chunks_exact_to_as_chunks,
    clippy::manual_is_multiple_of
)]

//! Native inference ingestion (aienos#34 lane 1): a bounded GGUF v3 reader
//! and the ggml block dequantizers (Q4_K, Q6_K and the plain float types)
//! needed to load Llama-3.2-1B-Instruct-Q4_K_M.
//!
//! Everything works on a `&[u8]` slice. Every read is length checked and
//! hostile input yields a [`GgufError`], never a panic. Dequantizers are
//! scalar and written for correctness first.

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod decode;
pub mod dotpath;
pub mod gguf;
pub mod half;
pub mod math;
pub mod model;
pub mod quant;
pub mod tokenizer;

pub use decode::{argmax, generate_greedy, DecodeState};
pub use gguf::{ArrayView, GgmlType, Gguf, GgufError, TensorInfo, Value, ValueType};
pub use model::{InferError, Model};
pub use tokenizer::Tokenizer;
