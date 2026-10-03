/* Reference harness for aienos-infer golden tests (aienos#34 lane 2+3).
 * Links the locally built llama.cpp (libllama) and prints, for one raw prompt
 * string (special tokens parsed, BOS NOT added: the string carries it):
 *   ids <prompt token ids>
 *   step <i> <token id> <logit gap top1-top2>   (greedy = argmax, n_predict steps)
 * and writes the first-position logits (f32 LE, n_vocab values) to argv[4].
 * usage: llama_ref MODEL.gguf "PROMPT" N_PREDICT LOGITS_OUT.bin [teacher ids...]
 * Single thread, CPU only (n_gpu_layers = 0). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "llama.h"
#include "ggml-backend.h"

static int argmax2(const float *l, int n, float *gap) {
    int b = 0; float b1 = l[0], b2 = -1e30f;
    for (int i = 1; i < n; i++) {
        if (l[i] > b1) { b2 = b1; b1 = l[i]; b = i; } else if (l[i] > b2) { b2 = l[i]; }
    }
    *gap = b1 - b2;
    return b;
}

int main(int argc, char **argv) {
    if (argc < 5) return 2;
    ggml_backend_load_all();
    llama_backend_init();
    struct llama_model_params mp = llama_model_default_params();
    mp.n_gpu_layers = 0;
    struct llama_model *m = llama_model_load_from_file(argv[1], mp);
    if (!m) return 3;
    const struct llama_vocab *v = llama_model_get_vocab(m);
    int nv = llama_vocab_n_tokens(v);
    const char *p = argv[2];
    llama_token toks[4096];
    int n = llama_tokenize(v, p, (int)strlen(p), toks, 4096, /*add_special*/ 0, /*parse_special*/ 1);
    if (n < 0) return 4;
    printf("ids");
    for (int i = 0; i < n; i++) printf(" %d", toks[i]);
    printf("\n");
    struct llama_context_params cp = llama_context_default_params();
    cp.n_ctx = 512; cp.n_batch = 512; cp.n_threads = 1; cp.n_threads_batch = 1;
    struct llama_context *c = llama_init_from_model(m, cp);
    if (!c) return 5;
    int npred = atoi(argv[3]);
    int nteach = argc - 5;
    struct llama_batch b = llama_batch_get_one(toks, n);
    if (llama_decode(c, b)) return 6;
    for (int i = 0; i < npred; i++) {
        float *lg = llama_get_logits_ith(c, -1);
        if (i == 0) {
            FILE *f = fopen(argv[4], "wb");
            fwrite(lg, sizeof(float), nv, f);
            fclose(f);
        }
        float gap; int t = argmax2(lg, nv, &gap);
        printf("step %d %d %.6f\n", i, t, gap);
        if (llama_vocab_is_eog(v, t)) { printf("eog\n"); break; }
        llama_token nt = (i < nteach) ? atoi(argv[5 + i]) : t;
        struct llama_batch b1 = llama_batch_get_one(&nt, 1);
        if (llama_decode(c, b1)) return 7;
    }
    llama_free(c); llama_model_free(m);
    return 0;
}
