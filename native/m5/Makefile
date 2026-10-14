# AIENOS M5 encrypted-object envelope and security layer in C: key hierarchy,
# keyslots, SecurityManifest, chunked AES-256-GCM-SIV envelopes, commit
# records, anti-rollback anchors, migration authorization, deterministic
# recovery, owner-signed migration records. Built on ../crypto (in-house
# AES-256-GCM-SIV, HMAC-SHA-256), ../sig (in-house Ed25519) and
# ../argus/sha256.c. No outside library. Library objects import no heap,
# clock or I/O; the tests and the m5_migsig tool use hosted libc.
#
#   make            build out/libaienos_m5.a
#   make test       rule tests + corruption matrix + header fuzz + owner-signed
#                   migration tests + m5_migsig tool test (host, not QEMU)
#   make sanitize   the same tests and the tool test under ASan+UBSan (Linux)
#   make mutants    remove each GUARD-tagged rule in turn; tests must fail
#   make clean

CC ?= cc
AR ?= ar
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out

SRCS = m5_keys.c m5_envelope.c m5_state.c m5_owner_sig.c
CRYPTO_SRCS = ../crypto/aes.c ../crypto/polyval.c ../crypto/gcm_siv.c ../crypto/hmac.c ../crypto/ct.c
SIG_SRCS = ../sig/sha512.c ../sig/ed25519.c ../sig/ct.c
OBJS = $(SRCS:%.c=$(OUT)/%.o)
DEP_OBJS = $(CRYPTO_SRCS:../crypto/%.c=$(OUT)/crypto_%.o) $(SIG_SRCS:../sig/%.c=$(OUT)/sig_%.o) $(OUT)/sha256.o
LIB = $(OUT)/libaienos_m5.a
TEST = $(OUT)/m5_test
SIGTEST = $(OUT)/m5_migsig_test
TOOL = $(OUT)/m5_migsig
HDRS = m5.h m5_internal.h ../crypto/aienos_crypto.h ../crypto/crypto_internal.h ../argus/sha256.h ../sig/aienos_sig.h ../sig/sig_internal.h
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g

all: $(LIB)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/%.o: %.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT)/crypto_%.o: ../crypto/%.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT)/sig_%.o: ../sig/%.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT)/sha256.o: ../argus/sha256.c ../argus/sha256.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ ../argus/sha256.c

$(LIB): $(OBJS) $(DEP_OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(TEST): tests/m5_test.c $(LIB) $(HDRS)
	$(CC) $(CFLAGS) -o $@ tests/m5_test.c $(LIB)

$(SIGTEST): tests/m5_migsig_test.c $(LIB) $(HDRS)
	$(CC) $(CFLAGS) -o $@ tests/m5_migsig_test.c $(LIB)

$(TOOL): tools/m5_migsig.c $(LIB) $(HDRS)
	$(CC) $(CFLAGS) -o $@ tools/m5_migsig.c $(LIB)

# M5_NATIVE: PASS is the last line (the qualification gate marker); the
# owner-signed migration verdict AIENOS_M5_MIGRATION_SIG: PASS comes first.
test: $(TEST) $(SIGTEST) $(TOOL) lib-checks
	./$(SIGTEST)
	bash tests/m5_migsig_tool_test.sh $(TOOL) $(OUT)/migsig_tool_work
	./$(TEST)

# The library objects must not allocate, read a clock, or do their own I/O.
lib-checks: $(OBJS) $(DEP_OBJS)
	@bad=$$(nm -u $(OBJS) $(DEP_OBJS) | awk 'NF {print $$NF}' | sed 's/^_//' | grep -xE 'malloc|calloc|realloc|free|aligned_alloc|posix_memalign|mmap|clock_gettime|time|gettimeofday|open|openat|read|write|pread|pwrite|fopen|fread|fwrite|printf|fprintf|puts|getrandom|rand|random'); \
	if [ -n "$$bad" ]; then echo "lib-checks FAIL: library imports $$bad"; exit 1; fi
	@echo "lib-checks PASS (no heap, clock or direct I/O in libaienos_m5 objects)"

sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/m5_test_asan tests/m5_test.c $(SRCS) $(CRYPTO_SRCS) $(SIG_SRCS) ../argus/sha256.c
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/m5_migsig_test_asan tests/m5_migsig_test.c $(SRCS) $(CRYPTO_SRCS) $(SIG_SRCS) ../argus/sha256.c
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/m5_migsig_asan tools/m5_migsig.c $(SRCS) $(CRYPTO_SRCS) $(SIG_SRCS) ../argus/sha256.c
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/m5_migsig_test_asan
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 bash tests/m5_migsig_tool_test.sh $(OUT)/m5_migsig_asan $(OUT)/migsig_tool_work_asan
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/m5_test_asan
else
	@echo "sanitize: Linux only"
endif

# Mutants: delete each GUARD-tagged line (in whichever source holds it) in
# turn. The tests must fail (or crash) for every mutant, or that rule is not
# tested. A mutant that does not compile counts as a harness failure. Each
# mutant runs both test programs; it is killed if either fails.
GUARDS = class-in-kdf slot-empty slot-check slot-suite slot-kdf slot-flags secman-mac \
	ksm-version ksm-reserved ksm-slot-count ksm-payload-range ksm-unused-empty \
	env-len env-mode env-envid env-keygen wipe-all \
	commit-mac commit-class commit-objid commit-envid commit-keygen \
	anchor-mac anchor-class anchor-missing anchor-store \
	rb-storegen rb-keygen rb-counter \
	mig-mac mig-class mig-self mig-source mig-dest mig-gen mig-anchor mig-digest mig-replay \
	rec-store rec-conflict rec-torn \
	osig-envset-order osig-magic osig-version osig-reserved osig-len osig-class osig-keyid osig-sig \
	osig-self osig-source osig-dest osig-agent osig-gen osig-format osig-envcount osig-envset \
	osig-manifest osig-ownergen osig-replay osig-bind-manifest osig-bind-counter

M5_MUT_TEST_OBJS = $(OUT)/t_m5_test.o $(OUT)/t_m5_migsig_test.o
$(OUT)/t_%_test.o: tests/%_test.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) -Wno-error -I. -c -o $@ $<

mutants: $(OBJS) $(DEP_OBJS) $(M5_MUT_TEST_OBJS) | $(OUT)
	@ulimit -c 0; fail=0; \
	dups=$$(printf '%s\n' $(GUARDS) | sort | uniq -d); \
	[ -z "$$dups" ] || { echo "duplicate guard names (parallel runs would collide):" $$dups; echo "M5_NATIVE_MUTANTS: FAIL"; exit 1; }; \
	for g in $(GUARDS); do \
	  d=$(OUT)/mut_$$g; rm -rf $$d; mkdir -p $$d; \
	  ( f=$$(grep -l "GUARD:$$g \*/" $(SRCS)); \
	    if [ $$(echo "$$f" | wc -w) -ne 1 ]; then echo "mutant $$g: guard tag missing or duplicated" > $$d/msg; echo 1 > $$d/fail; exit 0; fi; \
	    if [ $$(grep -c "GUARD:$$g \*/" $$f) -ne 1 ]; then echo "mutant $$g: guard tag duplicated" > $$d/msg; echo 1 > $$d/fail; exit 0; fi; \
	    sed "/GUARD:$$g \*\//d" $$f > $$d/$$f; \
	    others=""; for s in $(SRCS); do [ "$$s" = "$$f" ] || others="$$others $(OUT)/$${s%.c}.o"; done; \
	    $(CC) $(CFLAGS) -Wno-error -I. -c -o $$d/m.o $$d/$$f 2> $$d/cc.log \
	      && $(CC) $(CFLAGS) -Wno-error -o $$d/t $(OUT)/t_m5_test.o $$d/m.o $$others $(DEP_OBJS) 2>> $$d/cc.log \
	      && $(CC) $(CFLAGS) -Wno-error -o $$d/t2 $(OUT)/t_m5_migsig_test.o $$d/m.o $$others $(DEP_OBJS) 2>> $$d/cc.log \
	      || { echo "mutant $$g: does not compile (FAIL)" > $$d/msg; echo 1 > $$d/fail; exit 0; }; \
	    case "$$f" in \
	      m5_owner_sig.c) order="t2 t" ;; \
	      *)              order="t t2" ;; \
	    esac; \
	    pass=1; : > $$d/run.log; \
	    for b in $$order; do ./$$d/$$b >> $$d/run.log 2>&1 || { pass=0; break; }; done; \
	    if [ $$pass -eq 1 ]; then echo "mutant $$g: SURVIVED (FAIL)" > $$d/msg; echo 1 > $$d/fail; \
	    else echo "mutant $$g: killed" > $$d/msg; : > $$d/killed; fi \
	  ) & \
	done; \
	wait; \
	for g in $(GUARDS); do \
	  d=$(OUT)/mut_$$g; \
	  if [ -f $$d/msg ]; then cat $$d/msg; else echo "mutant $$g: no result recorded (FAIL)"; fi; \
	  [ -f $$d/killed ] && [ ! -f $$d/fail ] || fail=1; \
	done; \
	if [ $$fail -eq 0 ]; then echo "M5_NATIVE_MUTANTS: PASS"; else echo "M5_NATIVE_MUTANTS: FAIL"; exit 1; fi

clean:
	rm -rf $(OUT)

.PHONY: all test lib-checks sanitize mutants clean
