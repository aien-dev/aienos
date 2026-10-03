# Rebuild the ggml golden fixtures: `make -C crates/aienos-infer/tests/fixtures/gen regen`
GGML_DIR ?= /home/drakestapleton/.lmstudio/extensions/backends/llama.cpp-linux-arm64-2.33.0
gen: gen.c
	$(CC) -O1 gen.c -o gen -L$(GGML_DIR) -lggml-base -Wl,-rpath,$(GGML_DIR)
regen: gen
	./gen ..
clean:
	rm -f gen
