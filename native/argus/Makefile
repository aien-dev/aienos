# ARGUS-0 defensive plane, in C. No outside library; hosted libc + pthreads
# only for tests and benchmarks (the library objects import no heap, I/O or clock).
#
#   make            build out/libargus.a
#   make test       every lane test (B event/fuzz/ring, D core/determinism,
#                   E detectors plain + UBSan) + the integration gates
#   make bench      ring push/pop bench (lane B) + real-core ingest bench
#   make sanitize   integration gates under ASan+UBSan; on Linux also the ring
#                   under TSan (lane B), the detectors under ASan (lane E) and
#                   the integration gates under TSan
#   make clean
#
# Lane makefiles are invoked as sub-makes, never included: they each define
# their own `clean`/`all` targets and their own OUT variables (lane D's default
# out-d sat outside out/ and would be read by the recursive secret-negative
# scan). Every lane's output is redirected under out/ from here; no lane .mk
# file is edited.
#
# macOS (Apple clang 17, macOS 26.6): the ASan and TSan runtimes hang at
# start-up, so there `make test` runs lane B's fuzz under UBSan only and
# `make sanitize` is Linux-only.

CC ?= cc
AR ?= ar
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out
UNAME_S := $(shell uname -s)

SANFLAGS_ASAN = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g
SANFLAGS_TSAN = -fsanitize=thread -fno-omit-frame-pointer -g
# TSan on Linux aarch64 needs ASLR off (same rule as lane_b.mk).
TSAN_RUN := $(shell [ "$$(uname -s)" = Linux ] && command -v setarch >/dev/null 2>&1 && echo setarch $$(uname -m) -R)

LIB_SRC = argus_event.c argus_ring.c argus_core.c argus_detect.c sha256.c
LIB_HDR = argus_abi.h argus_core.h argus_detect.h sha256.h
LIB_OBJ = $(OUT)/obj/argus_event.o $(OUT)/obj/argus_ring.o $(OUT)/obj/argus_core.o \
          $(OUT)/obj/argus_detect.o $(OUT)/obj/sha256.o
LIB = $(OUT)/libargus.a

INT_SRC = tests/test_argus_integration.c tests/stub_state.c
INT_HDR = tests/stub_state.h
INT = $(OUT)/test_argus_integration

SUBMAKE_VARS = CC="$(CC)" CFLAGS="$(CFLAGS)"
ifeq ($(UNAME_S),Darwin)
LANE_B_SAN = SANFLAGS="-fsanitize=undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"
else
LANE_B_SAN =
endif

.PHONY: all lib test test-lanes test-integration bench sanitize clean

all: lib
lib: $(LIB)

$(OUT)/obj:
	mkdir -p $(OUT)/obj

$(OUT)/obj/%.o: %.c $(LIB_HDR) | $(OUT)/obj
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(LIB_OBJ)
	rm -f $@
	$(AR) rcs $@ $(LIB_OBJ)

$(INT): $(INT_SRC) $(INT_HDR) $(LIB)
	$(CC) $(CFLAGS) -I. -Itests -pthread -o $@ $(INT_SRC) $(LIB)

$(OUT)/test_argus_integration_asan: $(INT_SRC) $(INT_HDR) $(LIB_SRC) $(LIB_HDR) | $(OUT)/obj
	$(CC) $(CFLAGS) $(SANFLAGS_ASAN) -I. -Itests -pthread -o $@ $(INT_SRC) $(LIB_SRC)

$(OUT)/test_argus_integration_tsan: $(INT_SRC) $(INT_HDR) $(LIB_SRC) $(LIB_HDR) | $(OUT)/obj
	$(CC) $(CFLAGS) $(SANFLAGS_TSAN) -I. -Itests -pthread -o $@ $(INT_SRC) $(LIB_SRC)

test: test-lanes test-integration

test-lanes:
	$(MAKE) -f lane_b.mk $(SUBMAKE_VARS) $(LANE_B_SAN) LANE_B_OUT=$(OUT)/lane_b test-event fuzz-event test-ring
	$(MAKE) -f lane_d.mk $(SUBMAKE_VARS) OUT=$(OUT)/lane_d test-core test-determinism
	$(MAKE) -f lane_e.mk $(SUBMAKE_VARS) OUT=$(OUT)/lane_e test-detect

test-integration: $(INT)
	./$(INT) $(LIB_OBJ)

bench: $(INT)
	$(MAKE) -f lane_b.mk $(SUBMAKE_VARS) LANE_B_OUT=$(OUT)/lane_b bench-ring
	./$(INT) --bench

ifeq ($(UNAME_S),Darwin)
sanitize:
	@echo "sanitize: skipped on macOS (ASan/TSan runtimes hang at start-up); run on Linux"
else
sanitize: $(OUT)/test_argus_integration_asan $(OUT)/test_argus_integration_tsan $(LIB)
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
		./$(OUT)/test_argus_integration_asan $(LIB_OBJ)
	TSAN_OPTIONS=halt_on_error=1 $(TSAN_RUN) ./$(OUT)/test_argus_integration_tsan $(LIB_OBJ)
	$(MAKE) -f lane_b.mk $(SUBMAKE_VARS) LANE_B_OUT=$(OUT)/lane_b test-ring-tsan
	$(MAKE) -f lane_e.mk $(SUBMAKE_VARS) OUT=$(OUT)/lane_e test-detect-asan
endif

clean:
	rm -rf $(OUT)
