# AIENOS in-house signatures in C: Ed25519 (RFC 8032, pure Ed25519) and
# SHA-512 (FIPS 180-4). No outside library. Library objects import no heap,
# clock or I/O; the test uses hosted libc.
#
#   make            build out/libaienos_sig.a
#   make test       known-answer + negative + round-trip tests (host, not QEMU)
#   make sanitize   the same test under ASan+UBSan (Linux)
#   make mutants    remove each GUARD-tagged rule in turn; tests must fail
#   make clean

CC ?= cc
AR ?= ar
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out

SRCS = sha512.c ed25519.c ct.c
OBJS = $(SRCS:%.c=$(OUT)/%.o)
LIB = $(OUT)/libaienos_sig.a
TEST = $(OUT)/sig_test
HDRS = aienos_sig.h sig_internal.h
TEST_HDRS = tests/rfc8032_vectors.h
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g

all: $(LIB)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/%.o: %.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJS)
	$(AR) rcs $@ $^

$(TEST): tests/sig_test.c $(TEST_HDRS) $(LIB) $(HDRS)
	$(CC) $(CFLAGS) -o $@ tests/sig_test.c $(LIB)

test: $(TEST) lib-checks
	./$(TEST)

# The library objects must not allocate, read a clock, or do their own I/O.
lib-checks: $(OBJS)
	@bad=$$(nm -u $(OBJS) | awk 'NF {print $$NF}' | sed 's/^_//' | grep -xE 'malloc|calloc|realloc|free|aligned_alloc|posix_memalign|mmap|clock_gettime|time|gettimeofday|open|openat|read|write|pread|pwrite|fopen|fread|fwrite|printf|fprintf|puts|getrandom'); \
	if [ -n "$$bad" ]; then echo "lib-checks FAIL: library imports $$bad"; exit 1; fi
	@echo "lib-checks PASS (no heap, clock or direct I/O in libaienos_sig objects)"

sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/sig_test_asan tests/sig_test.c $(SRCS)
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/sig_test_asan
else
	@echo "sanitize: Linux only"
endif

# Mutants: delete each GUARD-tagged line in turn (file:guard). The tests must
# fail (or crash) for every mutant, or that rule is not tested.
MUTANTS = sha512.c:sha-pad sha512.c:sha-len \
	ed25519.c:clamp-low ed25519.c:clamp-high ed25519.c:clamp-254 \
	ed25519.c:y-canonical ed25519.c:on-curve ed25519.c:x-zero-sign ed25519.c:x-sign \
	ed25519.c:sc-sub ed25519.c:s-range ed25519.c:a-small-order ed25519.c:r-small-order \
	ed25519.c:r-check

$(OUT)/t_sig_test.o: tests/sig_test.c $(TEST_HDRS) $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) -Wno-error -I. -c -o $@ $<

mutants: $(OBJS) $(OUT)/t_sig_test.o | $(OUT)
	@ulimit -c 0; fail=0; n=0; \
	dups=$$(printf '%s\n' $(MUTANTS) | sed 's/.*://' | sort | uniq -d); \
	[ -z "$$dups" ] || { echo "duplicate guard names (parallel runs would collide):" $$dups; echo "AIENOS_SIG_MUTANTS: FAIL"; exit 1; }; \
	for m in $(MUTANTS); do \
	  f=$${m%%:*}; g=$${m#*:}; n=$$((n+1)); \
	  rm -f $(OUT)/mut_$$g.msg $(OUT)/mut_$$g.fail $(OUT)/mut_$$g.killed; \
	  ( grep -q "GUARD:$$g \*/" $$f || { echo "mutant $$g: guard tag missing" > $(OUT)/mut_$$g.msg; echo 1 > $(OUT)/mut_$$g.fail; exit 0; }; \
	    sed "/GUARD:$$g \*\//d" $$f > $(OUT)/mut_$$g.c; \
	    others=$$(for s in $(SRCS); do [ $$s = $$f ] || echo $(OUT)/$${s%.c}.o; done); \
	    $(CC) $(CFLAGS) -Wno-error -I. -c -o $(OUT)/mut_$$g.o $(OUT)/mut_$$g.c \
	      && $(CC) $(CFLAGS) -Wno-error -o $(OUT)/mut_$$g $(OUT)/t_sig_test.o $(OUT)/mut_$$g.o $$others \
	      || { echo "mutant $$g: does not compile" > $(OUT)/mut_$$g.msg; echo 1 > $(OUT)/mut_$$g.fail; exit 0; }; \
	    if ./$(OUT)/mut_$$g > $(OUT)/mut_$$g.log 2>&1; then \
	      echo "mutant $$g: SURVIVED (FAIL)" > $(OUT)/mut_$$g.msg; echo 1 > $(OUT)/mut_$$g.fail; \
	    else echo "mutant $$g: killed" > $(OUT)/mut_$$g.msg; : > $(OUT)/mut_$$g.killed; fi \
	  ) & \
	done; \
	wait; \
	for m in $(MUTANTS); do \
	  g=$${m#*:}; \
	  if [ -f $(OUT)/mut_$$g.msg ]; then cat $(OUT)/mut_$$g.msg; else echo "mutant $$g: no result recorded (FAIL)"; fi; \
	  [ -f $(OUT)/mut_$$g.killed ] && [ ! -f $(OUT)/mut_$$g.fail ] || fail=1; \
	done; \
	if [ $$fail -eq 0 ]; then echo "AIENOS_SIG_MUTANTS: PASS ($$n/$$n killed)"; else echo "AIENOS_SIG_MUTANTS: FAIL"; exit 1; fi

clean:
	rm -rf $(OUT)

.PHONY: all test lib-checks sanitize mutants clean
