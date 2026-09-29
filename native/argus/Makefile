# ARGUS-0 defensive plane, in C. No outside library; hosted libc + pthreads
# only for tests and benchmarks (the library objects import no heap, I/O or clock).
#
#   make            build out/libargus.a
#   make test       every lane test (B event/fuzz/ring, D core/determinism,
#                   E detectors plain + UBSan) + the integration gates + the
#                   hostile review (lane G; exit code counts: nonzero only on an
#                   UNEXPECTED failure, EXPECTED-FAIL and N/A-v1 are reported)
#   make bench      ring push/pop bench (lane B) + real-core ingest bench
#   make sanitize   integration gates and hostile review under ASan+UBSan, the
#                   integration gates under TSan, the ring under TSan (lane B)
#                   and the detectors under ASan (lane E); Linux only
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

# ---- ARGUS-1 lanes (docs/ARGUS1_PLAN.md) ------------------------------------
# Lanes drop their files in without editing this Makefile. Every ARGUS-1 target is
# guarded by $(wildcard ...): until its sources exist it prints "skipped" and passes.
# Lane C: argus_contain.c/.h join libargus (and so the nm -u memory check, G7).
CONTAIN_SRC := $(wildcard argus_contain.c)
CONTAIN_HDR := $(wildcard argus_contain.h)
LIB_SRC += $(CONTAIN_SRC)
LIB_HDR += $(CONTAIN_HDR)
LIB_OBJ += $(patsubst %.c,$(OUT)/obj/%.o,$(CONTAIN_SRC))
# Lane G gate (native/capability) + lane X bridge: never part of libargus (the
# hostile review links the archive alone and must not see any aienos_cap_* symbol).
CAP_DIR = ../capability
AUTH_SRC := $(wildcard $(CAP_DIR)/aienos_capability.c)
GATE_SRC := $(wildcard $(CAP_DIR)/aienos_contain.c)
BRIDGE_SRC := $(wildcard bridge/argus_aegis_bridge.c)
BRIDGE_HDR := $(wildcard bridge/argus_aegis_bridge.h $(CAP_DIR)/aienos_contain.h $(CAP_DIR)/aienos_capability.h)
# The full containment stack: present only when authority, gate and bridge all exist.
STACK_SRC := $(if $(and $(AUTH_SRC),$(GATE_SRC),$(BRIDGE_SRC)),$(BRIDGE_SRC) $(GATE_SRC) $(AUTH_SRC))
STACK_INC = -I. -Itests -Ibridge -I$(CAP_DIR)

CONTAIN_TEST_SRC := $(wildcard tests/test_argus_contain.c)
E2E_SRC          := $(wildcard tests/test_argus_containment_e2e.c)
CHOSTILE_SRC     := $(wildcard tests/test_argus_contain_hostile.c)
CBENCH_SRC       := $(wildcard tests/bench_argus_contain.c)
CONTAIN_TEST = $(OUT)/test_argus_contain
E2E          = $(OUT)/test_argus_containment_e2e
CHOSTILE     = $(OUT)/test_argus_contain_hostile
CBENCH       = $(OUT)/bench_argus_contain

INT_SRC = tests/test_argus_integration.c tests/stub_state.c
INT_HDR = tests/stub_state.h
INT = $(OUT)/test_argus_integration

# Hostile review: links the library archive only. It must never link the
# capability authority (G-1: any aienos_cap_* reference would fail this link).
HOSTILE_SRC = tests/test_argus_hostile.c
HOSTILE = $(OUT)/test_argus_hostile

SUBMAKE_VARS = CC="$(CC)" CFLAGS="$(CFLAGS)"
ifeq ($(UNAME_S),Darwin)
LANE_B_SAN = SANFLAGS="-fsanitize=undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"
else
LANE_B_SAN =
endif

.PHONY: all lib test test-lanes test-integration test-hostile bench sanitize clean \
        test-argus1 test-contain test-e2e test-contain-hostile test-contain-fp bench-contain sanitize-argus1

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

$(HOSTILE): $(HOSTILE_SRC) $(LIB)
	$(CC) $(CFLAGS) -I. -o $@ $(HOSTILE_SRC) $(LIB)

$(OUT)/test_argus_hostile_asan: $(HOSTILE_SRC) $(LIB_SRC) $(LIB_HDR) | $(OUT)/obj
	$(CC) $(CFLAGS) $(SANFLAGS_ASAN) -I. -o $@ $(HOSTILE_SRC) $(LIB_SRC)

$(OUT)/test_argus_integration_asan: $(INT_SRC) $(INT_HDR) $(LIB_SRC) $(LIB_HDR) | $(OUT)/obj
	$(CC) $(CFLAGS) $(SANFLAGS_ASAN) -I. -Itests -pthread -o $@ $(INT_SRC) $(LIB_SRC)

$(OUT)/test_argus_integration_tsan: $(INT_SRC) $(INT_HDR) $(LIB_SRC) $(LIB_HDR) | $(OUT)/obj
	$(CC) $(CFLAGS) $(SANFLAGS_TSAN) -I. -Itests -pthread -o $@ $(INT_SRC) $(LIB_SRC)

# ---- ARGUS-1 executables and targets (skipped until the lane's files exist) ----
ifneq ($(CONTAIN_TEST_SRC),)
$(CONTAIN_TEST): $(CONTAIN_TEST_SRC) tests/stub_state.c $(INT_HDR) $(LIB)
	$(CC) $(CFLAGS) -I. -Itests -o $@ $(CONTAIN_TEST_SRC) tests/stub_state.c $(LIB)
test-contain: $(CONTAIN_TEST)
	./$(CONTAIN_TEST)
else
test-contain:
	@echo "test-contain: skipped (tests/test_argus_contain.c not present yet, lane C)"
endif

ifneq ($(and $(E2E_SRC),$(STACK_SRC)),)
$(E2E): $(E2E_SRC) $(STACK_SRC) $(BRIDGE_HDR) tests/stub_state.c $(INT_HDR) $(LIB)
	$(CC) $(CFLAGS) $(STACK_INC) -pthread -o $@ $(E2E_SRC) $(STACK_SRC) tests/stub_state.c $(LIB)
test-e2e: $(E2E)
	./$(E2E)
else
test-e2e:
	@echo "test-e2e: skipped (needs tests/test_argus_containment_e2e.c + bridge + gate, lanes X/G)"
endif

ifneq ($(and $(CHOSTILE_SRC),$(STACK_SRC)),)
$(CHOSTILE): $(CHOSTILE_SRC) $(STACK_SRC) $(BRIDGE_HDR) tests/stub_state.c $(INT_HDR) $(LIB)
	$(CC) $(CFLAGS) $(STACK_INC) -pthread -o $@ $(CHOSTILE_SRC) $(STACK_SRC) tests/stub_state.c $(LIB)
test-contain-hostile: $(CHOSTILE)
	./$(CHOSTILE)
else
test-contain-hostile:
	@echo "test-contain-hostile: skipped (needs tests/test_argus_contain_hostile.c + bridge + gate, lanes H/X/G)"
endif

# Bench (lane F): never part of `make test`. Lane F takes ~/workspace/.argus-bench.lock and
# refuses to start while ~/workspace/.spark-quiet exists.
ifneq ($(and $(CBENCH_SRC),$(STACK_SRC)),)
$(CBENCH): $(CBENCH_SRC) $(STACK_SRC) $(BRIDGE_HDR) tests/stub_state.c $(INT_HDR) $(LIB)
	$(CC) $(CFLAGS) $(STACK_INC) -pthread -o $@ $(CBENCH_SRC) $(STACK_SRC) tests/stub_state.c $(LIB)
test-contain-fp: $(CBENCH)
	./$(CBENCH) --gate-only
bench-contain: $(CBENCH)
	./tests/run_argus1_bench.sh "./$(CBENCH)" contain "$(OUT)/test_argus_integration" "$(OUT)/lane_b"
else
test-contain-fp:
	@echo "test-contain-fp: skipped (needs tests/bench_argus_contain.c + bridge + gate, lane F)"
bench-contain:
	@echo "bench-contain: skipped (needs tests/bench_argus_contain.c + bridge + gate, lane F)"
endif

test-argus1: test-contain test-e2e test-contain-hostile test-contain-fp test-containment-authority test-contain-symbols

# The AEGIS gate tests live with the capability authority; keep them in the
# one ARGUS-1 regression command so G12 cannot silently omit the authority path.
test-containment-authority:
	$(MAKE) -C ../capability test-contain

# G11/I4: low-level event/ring code and the authority must not depend upward on
# detection, containment, or the bridge. The gate has its own checks in the
# capability Makefile; this checks the other direction across the three objects.
test-contain-symbols: $(LIB) test-containment-authority
	$(MAKE) -C ../capability out/aienos_capability.o
	./tests/check_argus1_symbols.sh $(OUT)/obj/argus_event.o $(OUT)/obj/argus_ring.o ../capability/out/aienos_capability.o

# Linux only (called from `sanitize`): lane C unit test under ASan+UBSan, e2e under
# ASan+UBSan and TSan, containment hostile under ASan+UBSan. Library sources are
# recompiled with the sanitizer, as for the ARGUS-0 integration binaries.
sanitize-argus1:
ifneq ($(CONTAIN_TEST_SRC),)
	$(CC) $(CFLAGS) $(SANFLAGS_ASAN) -I. -Itests -o $(OUT)/test_argus_contain_asan $(CONTAIN_TEST_SRC) tests/stub_state.c $(LIB_SRC)
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/test_argus_contain_asan
endif
ifneq ($(and $(E2E_SRC),$(STACK_SRC)),)
	$(CC) $(CFLAGS) $(SANFLAGS_ASAN) $(STACK_INC) -pthread -o $(OUT)/test_argus_containment_e2e_asan $(E2E_SRC) $(STACK_SRC) tests/stub_state.c $(LIB_SRC)
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/test_argus_containment_e2e_asan
	$(CC) $(CFLAGS) $(SANFLAGS_TSAN) $(STACK_INC) -pthread -o $(OUT)/test_argus_containment_e2e_tsan $(E2E_SRC) $(STACK_SRC) tests/stub_state.c $(LIB_SRC)
	TSAN_OPTIONS=halt_on_error=1 $(TSAN_RUN) ./$(OUT)/test_argus_containment_e2e_tsan
endif
ifneq ($(and $(CHOSTILE_SRC),$(STACK_SRC)),)
	$(CC) $(CFLAGS) $(SANFLAGS_ASAN) $(STACK_INC) -pthread -o $(OUT)/test_argus_contain_hostile_asan $(CHOSTILE_SRC) $(STACK_SRC) tests/stub_state.c $(LIB_SRC)
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/test_argus_contain_hostile_asan
endif
	$(MAKE) -C ../capability sanitize
	@echo "sanitize-argus1: done (targets whose sources are absent were skipped)"

test: test-lanes test-integration test-hostile test-argus1

test-lanes:
	$(MAKE) -f lane_b.mk $(SUBMAKE_VARS) $(LANE_B_SAN) LANE_B_OUT=$(OUT)/lane_b test-event fuzz-event test-ring
	$(MAKE) -f lane_d.mk $(SUBMAKE_VARS) OUT=$(OUT)/lane_d test-core test-determinism
	$(MAKE) -f lane_e.mk $(SUBMAKE_VARS) OUT=$(OUT)/lane_e test-detect

test-integration: $(INT)
	./$(INT) $(LIB_OBJ)

test-hostile: $(HOSTILE)
	./$(HOSTILE)

bench: $(INT) $(CBENCH)
	./tests/run_argus1_bench.sh "./$(CBENCH)" full "$(OUT)/test_argus_integration" "$(OUT)/lane_b"

ifeq ($(UNAME_S),Darwin)
sanitize:
	@echo "sanitize: skipped on macOS (ASan/TSan runtimes hang at start-up); run on Linux"
else
sanitize: $(OUT)/test_argus_integration_asan $(OUT)/test_argus_integration_tsan $(OUT)/test_argus_hostile_asan $(LIB)
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
		./$(OUT)/test_argus_integration_asan $(LIB_OBJ)
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
		./$(OUT)/test_argus_hostile_asan
	TSAN_OPTIONS=halt_on_error=1 $(TSAN_RUN) ./$(OUT)/test_argus_integration_tsan $(LIB_OBJ)
	$(MAKE) -f lane_b.mk $(SUBMAKE_VARS) LANE_B_OUT=$(OUT)/lane_b test-ring-tsan
	$(MAKE) -f lane_e.mk $(SUBMAKE_VARS) OUT=$(OUT)/lane_e test-detect-asan
	$(MAKE) sanitize-argus1
endif

clean:
	rm -rf $(OUT)

.PHONY: test-argus1 test-containment-authority test-contain-symbols sanitize-argus1
