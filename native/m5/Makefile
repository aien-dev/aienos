# AIENOS M5 encrypted-object envelope and security layer in C: key hierarchy,
# keyslots, SecurityManifest, chunked AES-256-GCM-SIV envelopes, commit
# records, anti-rollback anchors, migration authorization, deterministic
# recovery. Built on ../crypto (in-house AES-256-GCM-SIV, HMAC-SHA-256) and
# ../argus/sha256.c. No outside library. Library objects import no heap,
# clock or I/O; the test uses hosted libc.
#
#   make            build out/libaienos_m5.a
#   make test       rule tests + corruption matrix + header fuzz (host, not QEMU)
#   make sanitize   the same test under ASan+UBSan (Linux)
#   make mutants    remove each GUARD-tagged rule in turn; tests must fail
#   make clean

CC ?= cc
AR ?= ar
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out

SRCS = m5_keys.c m5_envelope.c m5_state.c
CRYPTO_SRCS = ../crypto/aes.c ../crypto/polyval.c ../crypto/gcm_siv.c ../crypto/hmac.c ../crypto/ct.c
OBJS = $(SRCS:%.c=$(OUT)/%.o)
DEP_OBJS = $(CRYPTO_SRCS:../crypto/%.c=$(OUT)/crypto_%.o) $(OUT)/sha256.o
LIB = $(OUT)/libaienos_m5.a
TEST = $(OUT)/m5_test
HDRS = m5.h m5_internal.h ../crypto/aienos_crypto.h ../crypto/crypto_internal.h ../argus/sha256.h
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g

all: $(LIB)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/%.o: %.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT)/crypto_%.o: ../crypto/%.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT)/sha256.o: ../argus/sha256.c ../argus/sha256.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ ../argus/sha256.c

$(LIB): $(OBJS) $(DEP_OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(TEST): tests/m5_test.c $(LIB) $(HDRS)
	$(CC) $(CFLAGS) -o $@ tests/m5_test.c $(LIB)

test: $(TEST) lib-checks
	./$(TEST)

# The library objects must not allocate, read a clock, or do their own I/O.
lib-checks: $(OBJS) $(DEP_OBJS)
	@bad=$$(nm -u $(OBJS) $(DEP_OBJS) | awk 'NF {print $$NF}' | sed 's/^_//' | grep -xE 'malloc|calloc|realloc|free|aligned_alloc|posix_memalign|mmap|clock_gettime|time|gettimeofday|open|openat|read|write|pread|pwrite|fopen|fread|fwrite|printf|fprintf|puts|getrandom|rand|random'); \
	if [ -n "$$bad" ]; then echo "lib-checks FAIL: library imports $$bad"; exit 1; fi
	@echo "lib-checks PASS (no heap, clock or direct I/O in libaienos_m5 objects)"

sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/m5_test_asan tests/m5_test.c $(SRCS) $(CRYPTO_SRCS) ../argus/sha256.c
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/m5_test_asan
else
	@echo "sanitize: Linux only"
endif

# Mutants: delete each GUARD-tagged line (in whichever source holds it) in
# turn. The tests must fail (or crash) for every mutant, or that rule is not
# tested. A mutant that does not compile counts as a harness failure.
GUARDS = class-in-kdf slot-empty slot-check slot-suite slot-kdf slot-flags secman-mac secman-class \
	count-match env-len env-mode env-class env-objid env-keygen env-storegen wipe-all \
	commit-mac commit-class anchor-mac anchor-class anchor-missing anchor-store \
	rb-storegen rb-keygen rb-counter \
	mig-mac mig-class mig-self mig-source mig-dest mig-gen mig-anchor mig-digest mig-replay \
	rec-store rec-conflict rec-torn

mutants: | $(OUT)
	@ulimit -c 0; fail=0; for g in $(GUARDS); do \
	  f=$$(grep -l "GUARD:$$g \*/" $(SRCS)); \
	  if [ $$(echo "$$f" | wc -w) -ne 1 ]; then echo "mutant $$g: guard tag missing or duplicated"; fail=1; continue; fi; \
	  if [ $$(grep -c "GUARD:$$g \*/" $$f) -ne 1 ]; then echo "mutant $$g: guard tag duplicated"; fail=1; continue; fi; \
	  mkdir -p $(OUT)/mut_$$g; \
	  for s in $(SRCS); do if [ $$s = $$f ]; then sed "/GUARD:$$g \*\//d" $$s > $(OUT)/mut_$$g/$$s; else cp $$s $(OUT)/mut_$$g/$$s; fi; done; \
	  $(CC) $(CFLAGS) -Wno-error -I. -o $(OUT)/mut_$$g/t tests/m5_test.c \
	    $(addprefix $(OUT)/mut_$$g/,$(SRCS)) $(CRYPTO_SRCS) ../argus/sha256.c 2> $(OUT)/mut_$$g/cc.log \
	    || { echo "mutant $$g: does not compile (FAIL)"; fail=1; continue; }; \
	  if ./$(OUT)/mut_$$g/t > $(OUT)/mut_$$g/run.log 2>&1; then \
	    echo "mutant $$g: SURVIVED (FAIL)"; fail=1; \
	  else echo "mutant $$g: killed"; fi; \
	done; \
	if [ $$fail -eq 0 ]; then echo "M5_NATIVE_MUTANTS: PASS"; else echo "M5_NATIVE_MUTANTS: FAIL"; exit 1; fi

clean:
	rm -rf $(OUT)

.PHONY: all test lib-checks sanitize mutants clean
