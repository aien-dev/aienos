# AIENOS M6-A hosted network stack, in C. No Rust, no Python, no outside
# library: SHA-256 is the in-house copy in ../argus/sha256.c.
# Protocol objects import no heap, clock or I/O; tests use hosted libc.
# Hosted only: native binding waits for a C kernel, production keys for M5.
#
#   make            build out/libaienos_net.a
#   make test       protocol tests + control-transport loss/recovery + lib-checks
#                   + diff-check (pinned C/Rust-reference agreement digest)
#   make sanitize   the same tests under ASan+UBSan (Linux)
#   make receipt    run everything on a clean tree, write receipts/<sha256>.txt
#   make diff-corpus   write out/diff_corpus.bin and out/diff_c.txt for the
#                      external Rust-reference driver (see README.md)
#   make clean

CC ?= cc
AR ?= ar
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out
SEED ?= 0x6a5e11
ITERS ?= 200000

# Differential corpus (fixed) and the output digest both C and the unmodified
# Rust reference produced on it. Change only with a new recorded Rust run.
DIFF_SEED = 0xa1e5
DIFF_COUNT = 200000
DIFF_DIGEST = 9ddf33a859ade2d92d0e86a213d29d682708b0ac308239a7b6f003dbf9a5cdfe

SRCS = aienos_net.c aienos_virtio_pci.c aienos_ctl.c
OBJS = $(SRCS:%.c=$(OUT)/%.o) $(OUT)/sha256.o
LIB = $(OUT)/libaienos_net.a
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g

all: $(LIB)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/%.o: %.c $(wildcard *.h) | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT)/sha256.o: ../argus/sha256.c ../argus/sha256.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ ../argus/sha256.c

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

$(OUT)/net_test: tests/net_test.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)
$(OUT)/ctl_test: tests/ctl_test.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)
$(OUT)/net_diff: tests/net_diff.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

test: lib-checks $(OUT)/net_test $(OUT)/ctl_test diff-check
	./$(OUT)/net_test $(SEED) $(ITERS)
	./$(OUT)/ctl_test

# Protocol objects must not allocate, read a clock or do their own I/O.
lib-checks: $(OBJS)
	@for o in $(SRCS:%.c=$(OUT)/%.o); do \
	  if nm -u $$o | awk '{print $$NF}' | sed 's/^_//' | grep -qxE 'malloc|calloc|realloc|free|clock_gettime|time|gettimeofday|open|read|write|recv|recvfrom|send|sendto|socket|fopen|printf|rand|random|getrandom'; then \
	    echo "lib-checks FAIL: $$o allocates, reads a clock, does I/O or uses ambient randomness"; exit 1; fi; done
	@if grep -n 'CT_IDENTITY_[A-Z]* ' aienos_ctl.h | grep -v 'CT_IDENTITY_TEST' | grep -q .; then \
	  echo "lib-checks FAIL: an identity kind other than TEST is defined (production keys wait for M5)"; exit 1; fi
	@grep -q 'NOT-FOR-PRODUCTION' aienos_ctl.c || { echo "lib-checks FAIL: TEST label missing"; exit 1; }
	@echo "lib-checks PASS (no heap, clock, I/O or ambient randomness; TEST identity only)"

diff-corpus: $(OUT)/net_diff
	./$(OUT)/net_diff gen $(DIFF_SEED) $(DIFF_COUNT) > $(OUT)/diff_corpus.bin
	./$(OUT)/net_diff run < $(OUT)/diff_corpus.bin > $(OUT)/diff_c.txt
	@echo "corpus $$(sha256sum $(OUT)/diff_corpus.bin | cut -d' ' -f1)"
	@echo "c-out  $$(sha256sum $(OUT)/diff_c.txt | cut -d' ' -f1)"

diff-check: diff-corpus
	@got=$$(sha256sum $(OUT)/diff_c.txt | cut -d' ' -f1); \
	if [ "$$got" = "$(DIFF_DIGEST)" ]; then echo "NET_RUST_DIFFERENTIAL_PINNED: PASS ($(DIFF_COUNT) records)"; \
	else echo "NET_RUST_DIFFERENTIAL_PINNED: FAIL (got $$got, pinned $(DIFF_DIGEST))"; exit 1; fi

sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/net_test_asan tests/net_test.c $(SRCS) ../argus/sha256.c
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/ctl_test_asan tests/ctl_test.c $(SRCS) ../argus/sha256.c
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/net_diff_asan tests/net_diff.c $(SRCS) ../argus/sha256.c
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/net_test_asan $(SEED) 50000
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/ctl_test_asan
	./$(OUT)/net_diff_asan gen $(DIFF_SEED) 20000 > $(OUT)/asan_corpus.bin
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/net_diff_asan run < $(OUT)/asan_corpus.bin > /dev/null
	@echo "NET_SANITIZE: PASS"
else
	@echo "sanitize: Linux only"
endif

receipt:
	sh ./receipt.sh

clean:
	rm -rf $(OUT)

.PHONY: all test lib-checks diff-corpus diff-check sanitize receipt clean
