/* Reference harness for the int8 parity diagnosis (aienos#34, 2026-10-11).
 * Links the locally built llama.cpp (libllama), single thread, CPU only, and
 * replays a fixed token history exactly as llama_ref.c does: the first
 * N_PROMPT ids decoded as one batch, every later id decoded one at a time,
 * end-of-generation tokens NOT treated as a stop (the history is given).
 * Prints, for the logits after the last id:
 *   argmax <id> gap <top1-top2>
 *   logit <id> <value>            (for each WATCH id)
 * and writes all n_vocab logits (f32 LE) to LOGITS_OUT.
 * usage: llama_ref_hist MODEL.gguf LOGITS_OUT.bin N_PROMPT WATCH1,WATCH2 id...
 * Build: cc -O2 llama_ref_hist.c -I$LLAMA/include -I$LLAMA/ggml/include \
 *        -L$LLAMA/build/bin -lllama -lggml -lggml-base -Wl,-rpath,$LLAMA/build/bin */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "llama.h"
#include "ggml-backend.h"

int main(int argc, char **argv) {
    if (argc < 6) return 2;
    int np = atoi(argv[3]);
    int n = argc - 5;
    if (np < 1 || np > n || n > 4096) return 2;
    static llama_token toks[4096];
    for (int i = 0; i < n; i++) toks[i] = atoi(argv[5 + i]);
    ggml_backend_load_all();
    llama_backend_init();
    struct llama_model_params mp = llama_model_default_params();
    mp.n_gpu_layers = 0;
    struct llama_model *m = llama_model_load_from_file(argv[1], mp);
    if (!m) return 3;
    int nv = llama_vocab_n_tokens(llama_model_get_vocab(m));
    struct llama_context_params cp = llama_context_default_params();
    cp.n_ctx = 512; cp.n_batch = 512; cp.n_threads = 1; cp.n_threads_batch = 1;
    struct llama_context *c = llama_init_from_model(m, cp);
    if (!c) return 5;
    if (llama_decode(c, llama_batch_get_one(toks, np))) return 6;
    for (int i = np; i < n; i++)
        if (llama_decode(c, llama_batch_get_one(&toks[i], 1))) return 7;
    float *lg = llama_get_logits_ith(c, -1);
    int b = 0; float b1 = lg[0], b2 = -1e30f;
    for (int i = 1; i < nv; i++) {
        if (lg[i] > b1) { b2 = b1; b1 = lg[i]; b = i; } else if (lg[i] > b2) { b2 = lg[i]; }
    }
    printf("argmax %d gap %.6f\n", b, b1 - b2);
    char *w = argv[4];
    while (*w) {
        int id = atoi(w);
        if (id >= 0 && id < nv) printf("logit %d %.6f\n", id, lg[id]);
        char *comma = strchr(w, ',');
        if (!comma) break;
        w = comma + 1;
    }
    FILE *f = fopen(argv[2], "wb");
    if (!f) return 8;
    fwrite(lg, sizeof(float), nv, f);
    fclose(f);
    llama_free(c); llama_model_free(m);
    return 0;
}
