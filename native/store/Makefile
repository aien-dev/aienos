# Torn-write-safe 4096-byte record over 512- or 4096-byte logical blocks, in C.
# No outside library: SHA-256 is the in-house copy in ../argus/sha256.c.
# The library object imports no heap, clock or I/O; tests use hosted libc.
#
#   make            build out/libtorn_slot.a
#   make test       rule tests + exhaustive torn-write fault injection
#                   (host block-device emulation, not QEMU)
#   make sanitize   the same test under ASan+UBSan (Linux)
#   make mutants    remove each lineage rule in turn; the rule tests must fail
#   make clean

CC ?= cc
AR ?= ar
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out

LIB = $(OUT)/libtorn_slot.a
TEST = $(OUT)/torn_slot_test
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g

all: $(LIB)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/torn_slot.o: torn_slot.c torn_slot.h ../argus/sha256.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ torn_slot.c

$(OUT)/sha256.o: ../argus/sha256.c ../argus/sha256.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ ../argus/sha256.c

$(LIB): $(OUT)/torn_slot.o $(OUT)/sha256.o
	$(AR) rcs $@ $^

$(TEST): tests/torn_slot_test.c $(LIB)
	$(CC) $(CFLAGS) -o $@ tests/torn_slot_test.c $(LIB)

test: $(TEST) lib-checks
	./$(TEST)

# The protocol object must not allocate, read a clock, or do its own I/O.
lib-checks: $(OUT)/torn_slot.o
	@if nm -u $(OUT)/torn_slot.o | awk '{print $$NF}' | sed 's/^_//' | grep -qxE 'malloc|calloc|realloc|free|clock_gettime|time|gettimeofday|open|read|write|pread|pwrite|fopen'; then \
	  echo "lib-checks FAIL: torn_slot.o allocates, reads a clock or does its own I/O"; exit 1; fi
	@echo "lib-checks PASS (no heap, clock or direct I/O in torn_slot.o)"

sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/torn_slot_test_asan tests/torn_slot_test.c torn_slot.c ../argus/sha256.c
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/torn_slot_test_asan
else
	@echo "sanitize: Linux only"
endif


# Mutants: remove each GUARD-tagged lineage rule from torn_slot.c in turn.
# The rule tests must fail for every mutant, or that rule is not tested.
GUARDS = parity-a parity-b b-needs-a adjacent first-remnant a-alone-seq1

mutants: | $(OUT)
	@fail=0; for g in $(GUARDS); do \
	  grep -q "GUARD:$$g \*/" torn_slot.c || { echo "mutant $$g: guard tag missing"; fail=1; continue; }; \
	  sed "/GUARD:$$g \*\//d" torn_slot.c > $(OUT)/mut_$$g.c; \
	  $(CC) $(CFLAGS) -Wno-error -I. -o $(OUT)/mut_$$g tests/torn_slot_test.c $(OUT)/mut_$$g.c ../argus/sha256.c || { fail=1; continue; }; \
	  if ./$(OUT)/mut_$$g --rules-only > $(OUT)/mut_$$g.log 2>&1; then \
	    echo "mutant $$g: SURVIVED (FAIL)"; fail=1; \
	  else echo "mutant $$g: killed"; fi; \
	done; \
	if [ $$fail -eq 0 ]; then echo "TORN_SLOT_MUTANTS: PASS"; else echo "TORN_SLOT_MUTANTS: FAIL"; exit 1; fi

clean:
	rm -rf $(OUT)

.PHONY: all test lib-checks sanitize mutants clean
