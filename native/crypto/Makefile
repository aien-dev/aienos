# AIENOS in-house crypto in C: AES-256, POLYVAL, AES-256-GCM-SIV (RFC 8452),
# HMAC-SHA-256. Port of crates/aienos-crypto. No outside library: SHA-256 is
# the in-house copy in ../argus/sha256.c. Library objects import no heap,
# clock or I/O; the test uses hosted libc.
#
#   make            build out/libaienos_crypto.a
#   make test       known-answer + negative tests (host, not QEMU)
#   make sanitize   the same test under ASan+UBSan (Linux)
#   make mutants    remove each GUARD-tagged rule in gcm_siv.c; tests must fail
#   make clean

CC ?= cc
AR ?= ar
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out

SRCS = aes.c polyval.c gcm_siv.c hmac.c ct.c
OBJS = $(SRCS:%.c=$(OUT)/%.o)
LIB = $(OUT)/libaienos_crypto.a
TEST = $(OUT)/crypto_test
HDRS = aienos_crypto.h crypto_internal.h ../argus/sha256.h
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g

all: $(LIB)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/%.o: %.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT)/sha256.o: ../argus/sha256.c ../argus/sha256.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ ../argus/sha256.c

$(LIB): $(OBJS) $(OUT)/sha256.o
	$(AR) rcs $@ $^

$(TEST): tests/crypto_test.c $(LIB) $(HDRS)
	$(CC) $(CFLAGS) -o $@ tests/crypto_test.c $(LIB)

test: $(TEST) lib-checks
	./$(TEST)

# The library objects must not allocate, read a clock, or do their own I/O.
lib-checks: $(OBJS) $(OUT)/sha256.o
	@bad=$$(nm -u $(OBJS) $(OUT)/sha256.o | awk 'NF {print $$NF}' | sed 's/^_//' | grep -xE 'malloc|calloc|realloc|free|aligned_alloc|posix_memalign|mmap|clock_gettime|time|gettimeofday|open|openat|read|write|pread|pwrite|fopen|fread|fwrite|printf|fprintf|puts|getrandom'); \
	if [ -n "$$bad" ]; then echo "lib-checks FAIL: library imports $$bad"; exit 1; fi
	@echo "lib-checks PASS (no heap, clock or direct I/O in libaienos_crypto objects)"

sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/crypto_test_asan tests/crypto_test.c $(SRCS) ../argus/sha256.c
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/crypto_test_asan
else
	@echo "sanitize: Linux only"
endif

# Mutants: delete each GUARD-tagged line of gcm_siv.c in turn. The tests must
# fail (or crash) for every mutant, or that rule is not tested.
GUARDS = tag-msb ctr-msb pt-max aad-max-seal ct-max aad-max-open tag-check wipe-on-fail

mutants: | $(OUT)
	@ulimit -c 0; fail=0; for g in $(GUARDS); do \
	  grep -q "GUARD:$$g \*/" gcm_siv.c || { echo "mutant $$g: guard tag missing"; fail=1; continue; }; \
	  sed "/GUARD:$$g \*\//d" gcm_siv.c > $(OUT)/mut_$$g.c; \
	  $(CC) $(CFLAGS) -Wno-error -I. -o $(OUT)/mut_$$g tests/crypto_test.c $(OUT)/mut_$$g.c \
	    aes.c polyval.c hmac.c ct.c ../argus/sha256.c || { fail=1; continue; }; \
	  if ./$(OUT)/mut_$$g > $(OUT)/mut_$$g.log 2>&1; then \
	    echo "mutant $$g: SURVIVED (FAIL)"; fail=1; \
	  else echo "mutant $$g: killed"; fi; \
	done; \
	if [ $$fail -eq 0 ]; then echo "AIENOS_CRYPTO_MUTANTS: PASS"; else echo "AIENOS_CRYPTO_MUTANTS: FAIL"; exit 1; fi

clean:
	rm -rf $(OUT)

.PHONY: all test lib-checks sanitize mutants clean
