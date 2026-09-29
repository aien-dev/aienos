# Native AIENOS capability authority, in C. No Rust. Needs only the hosted C
# library and pthreads (it reads /dev/urandom for the office token).
#
#   make          build out/libaienos_capability.a
#   make test     build and run the rule tests (SEED=n picks the random-op seed)
#   make clean

CC ?= cc
AR ?= ar
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out

LIB = $(OUT)/libaienos_capability.a
TEST = $(OUT)/capability_test

all: $(LIB)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/aienos_capability.o: aienos_capability.c aienos_capability.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ aienos_capability.c

$(LIB): $(OUT)/aienos_capability.o
	$(AR) rcs $@ $^

$(TEST): tests/capability_test.c $(LIB)
	$(CC) $(CFLAGS) -pthread -o $@ tests/capability_test.c $(LIB)

test: $(TEST) test-contain
	./$(TEST) $(SEED)

clean:
	rm -rf $(OUT)

.PHONY: all test clean

# ---- ARGUS-1 lane G: AEGIS containment gate (aienos_contain.c) ----------------
# The gate is its own object, never part of the authority archive. Its test
# includes ../argus/argus_abi.h for the layout-twin asserts only (no libargus).
#
#   make test-contain     build and run tests/contain_test.c
#   make contain-checks   symbol and word checks for the gate (I2, I3.a, I4, G7)
#   make sanitize         (Linux) contain_test under ASan+UBSan

GATE_OBJ = $(OUT)/aienos_contain.o
CONTAIN_TEST = $(OUT)/contain_test
SANFLAGS_ASAN = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g
GATE_FILES = aienos_contain.c aienos_contain.h tests/contain_test.c
# Authority symbols the gate may reference (I3.a); anything else from aienos_cap_* fails.
GATE_ALLOWED = aienos_cap_mint aienos_cap_revoke aienos_cap_inspect aienos_cap_office aienos_cap_clock aienos_cap_authorize

$(GATE_OBJ): aienos_contain.c aienos_contain.h aienos_capability.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ aienos_contain.c

$(CONTAIN_TEST): tests/contain_test.c $(GATE_OBJ) $(LIB) ../argus/argus_abi.h
	$(CC) $(CFLAGS) -pthread -o $@ tests/contain_test.c $(GATE_OBJ) $(LIB)

test-contain: $(CONTAIN_TEST) contain-checks
	./$(CONTAIN_TEST)

contain-checks: $(GATE_OBJ) $(OUT)/aienos_capability.o
	@bad=$$(nm -u $(GATE_OBJ) | awk '{print $$NF}' | sed 's/^_//' | grep '^aienos_cap_' | grep -vxF $(foreach s,$(GATE_ALLOWED),-e $(s))); \
	  if [ -n "$$bad" ]; then echo "contain-checks FAIL: gate references $$bad"; exit 1; fi
	@if nm -u $(GATE_OBJ) | awk '{print $$NF}' | sed 's/^_//' | grep -qxE 'malloc|calloc|realloc|free|clock_gettime|time|gettimeofday'; then \
	  echo "contain-checks FAIL: gate allocates or reads a clock (G7)"; exit 1; fi
	@if nm -g $(GATE_OBJ) | awk '$$2 ~ /[TD]/ {print $$3}' | grep -qiE 'freeze|suspend|isolate|pause'; then \
	  echo "contain-checks FAIL: a gate symbol names a suspension primitive (I2)"; exit 1; fi
	@if nm $(OUT)/aienos_capability.o | grep -q 'aienos_contain'; then \
	  echo "contain-checks FAIL: the authority references the gate (I4)"; exit 1; fi
	@if [ "$$(grep -c 'aienos_cap_mint(' aienos_contain.c)" != 1 ]; then \
	  echo "contain-checks FAIL: aienos_cap_mint must be called exactly once, in create (I5.a)"; exit 1; fi
	@if grep -i 'freeze' aienos_contain.c aienos_contain.h | grep -vq 'stand-in'; then \
	  echo "contain-checks FAIL: a freeze mention without stand-in (I2)"; exit 1; fi
	@if grep -il 'tok[e]n' $(GATE_FILES); then echo "contain-checks FAIL: forbidden word"; exit 1; fi
	@echo "contain-checks PASS (I2 words, I3.a symbols, I4 direction, I5.a single mint, G7 no malloc/clock)"

# `make test` runs the gate test alongside the authority rule tests.
sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS_ASAN) -pthread -o $(OUT)/contain_test_asan tests/contain_test.c aienos_contain.c aienos_capability.c
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/contain_test_asan
else
	@echo "sanitize: Linux only"
endif

.PHONY: test-contain contain-checks sanitize
