# lane_d.mk -- ARGUS-0 lane D (resident state core) build + tests.
# Links against tests/stub_lanes_d.c until lanes B (argus_event.c) and
# E (argus_detect.c) merge; the integrator swaps the stub for the real objects.
#
#   make -f lane_d.mk test-core          unit tests + heap/symbol checks
#   make -f lane_d.mk test-determinism   determinism gate + provisional bench

CC ?= cc
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out-d

CORE_OBJ = $(OUT)/argus_core.o
STUB_OBJ = $(OUT)/stub_lanes_d.o
T_HDRS = tests/test_common_d.h tests/stub_lanes_d.h argus_core.h argus_abi.h

# Symbols argus_core.o may import: the four header-declared lane calls, mem*,
# and the stack protector. Anything else (heap, I/O, clock) fails the build.
ALLOWED_UNDEF = argus_event_validate|argus_event_digest|argus_chain_extend|argus_detect_run|memset|memcpy|memcmp|memmove|bzero|__memset_chk|__memcpy_chk|__memmove_chk|__stack_chk_fail|__stack_chk_guard

.PHONY: all test-core test-determinism check-core-symbols clean

all: $(OUT)/test_argus_core $(OUT)/test_argus_determinism

$(OUT):
	mkdir -p $(OUT)

$(CORE_OBJ): argus_core.c argus_core.h argus_abi.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ argus_core.c

$(STUB_OBJ): tests/stub_lanes_d.c tests/stub_lanes_d.h argus_abi.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ tests/stub_lanes_d.c

$(OUT)/test_argus_core: tests/test_argus_core.c $(T_HDRS) $(CORE_OBJ) $(STUB_OBJ)
	$(CC) $(CFLAGS) -o $@ tests/test_argus_core.c $(CORE_OBJ) $(STUB_OBJ)

$(OUT)/test_argus_determinism: tests/test_argus_determinism.c $(T_HDRS) $(CORE_OBJ) $(STUB_OBJ)
	$(CC) $(CFLAGS) -o $@ tests/test_argus_determinism.c $(CORE_OBJ) $(STUB_OBJ)

check-core-symbols: $(CORE_OBJ)
	@if grep -nwE 'malloc|calloc|realloc|free|printf|fopen|clock_gettime|time' argus_core.c; then \
		echo "FAIL: argus_core.c references heap/io/clock"; exit 1; fi
	@if grep -nwiE 'tok[e]n|AIENOS_CAP_TOK[E]N_LEN' argus_core.c argus_core.h tests/*_d.* tests/test_argus_core.c tests/test_argus_determinism.c lane_d.mk; then \
		echo "FAIL: forbidden word in lane D files"; exit 1; fi
	@bad=$$(nm -u $(CORE_OBJ) | awk '{print $$NF}' | sed 's/^_//' | grep -vxE '$(ALLOWED_UNDEF)' || true); \
	if [ -n "$$bad" ]; then echo "FAIL: argus_core.o imports: $$bad"; exit 1; fi
	@echo "check-core-symbols: OK (no heap, no I/O, no clock; imports only: $$(nm -u $(CORE_OBJ) | awk '{print $$NF}' | sed 's/^_//' | tr '\n' ' '))"

test-core: $(OUT)/test_argus_core check-core-symbols
	./$(OUT)/test_argus_core

test-determinism: $(OUT)/test_argus_determinism check-core-symbols
	./$(OUT)/test_argus_determinism

clean:
	rm -rf $(OUT)
