//! Native CPU inference: tokenizer and compute kernels (host-testable, no system registers).
pub mod attention;
pub mod gemm;
pub mod rope;
pub mod tokenizer;
