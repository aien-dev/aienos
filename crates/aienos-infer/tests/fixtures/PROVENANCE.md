# Fixture provenance

q4k.bin / q6k.bin: 4 blocks each from two tensors of Llama-3.2-1B-Instruct-Q4_K_M.gguf
(sha256 3f5a22426976ab26cfe84dba63c1d08391717abb1af893e10f1b2968d862dcc1).
Absolute file offsets: Q4_K 223309856 (blk.0.attn_k) and 798257184 (blk.15.ffn_up);
Q6_K 228626464 (blk.0.attn_v) and 775049248 (blk.15.ffn_down).
q4k.f32 / q6k.f32: output of ggml dequantize_row_q4_K / dequantize_row_q6_K on those blocks.

Reference library: /home/drakestapleton/.lmstudio/extensions/backends/llama.cpp-linux-arm64-2.33.0/libggml-base.so
llama.cpp backend version 2.33.0 (LM Studio), sha256 3a9c7bf9d5696414839ec441958c469b947437bf1db2f4468272e3731b30378e

Regenerate: make -C crates/aienos-infer/tests/fixtures/gen regen
Generator is C only (gen/gen.c, no Python). Needs the model file and the library above.
