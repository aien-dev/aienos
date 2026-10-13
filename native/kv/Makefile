# Native persistent-KV record codec (C, no outside library), cut N1 of aienos#367:
#   kv_record   256-byte record header, 4096-byte header region, compute-config
#               aware namespace id, prefix-chained chunk keys, validation that
#               refuses before any allocation, the native slot header unit and
#               the envelope id / nonce mapping into M5 (sovereign-core ADR 0003).
# Pinned to sovereign-core by CONTRACT.lock and tests/golden/*.json.
# SHA-256 is ../argus/sha256.c; HKDF/HMAC are ../m5 and ../crypto. Library
# objects import no heap, clock or I/O; the test uses hosted libc.
#
#   make              build out/libaienos_kv.a
#   make test         pin check + slot vector regeneration check + the unit tests
#                     (host emulation over memory, not QEMU, not hardware)
#   make pin-check    CONTRACT.lock hashes against the two golden files (sha256sum)
#   make sanitize     the same tests under ASan+UBSan (Linux)
#   make mutants      remove each GUARD-tagged rule in turn; the test must fail
#   make freestanding -ffreestanding -nostdlib build; nm -u must close over
#                     the sibling native objects
#   make clean

CC ?= cc
AR ?= ar
LD ?= ld
NM ?= nm
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out

SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g
INC = -I. -I../argus -I../m5 -I../crypto -Itests

DEP_SRCS = ../argus/sha256.c ../m5/m5_keys.c ../m5/m5_envelope.c ../m5/m5_state.c \
           ../crypto/aes.c ../crypto/polyval.c ../crypto/gcm_siv.c ../crypto/hmac.c ../crypto/ct.c
DEP_OBJS = $(OUT)/sha256.o $(OUT)/dep_m5_keys.o $(OUT)/dep_m5_envelope.o $(OUT)/dep_m5_state.o \
           $(OUT)/dep_aes.o $(OUT)/dep_polyval.o $(OUT)/dep_gcm_siv.o $(OUT)/dep_hmac.o $(OUT)/dep_ct.o
HDRS = kv_record.h ../argus/sha256.h ../m5/m5.h ../crypto/aienos_crypto.h
LIB = $(OUT)/libaienos_kv.a
TEST = $(OUT)/kv_record_test
TEST_OBJ = $(OUT)/t_kv_record_test.o

# Count heap calls in the test (GNU ld --wrap) so "refuses before any
# allocation" is measured, not only argued from nm -u.
ifeq ($(shell uname -s),Linux)
WRAP = -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc
WRAPDEF = -DKV_WRAP_ALLOC
endif

all: $(LIB)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/kv_record.o: kv_record.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) -c -o $@ kv_record.c
$(OUT)/sha256.o: ../argus/sha256.c ../argus/sha256.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ ../argus/sha256.c
$(OUT)/dep_m5_%.o: ../m5/m5_%.c ../m5/m5.h ../m5/m5_internal.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<
$(OUT)/dep_%.o: ../crypto/%.c ../crypto/aienos_crypto.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OUT)/kv_record.o $(DEP_OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(TEST_OBJ): tests/kv_record_test.c tests/json_min.h $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) $(WRAPDEF) -c -o $@ tests/kv_record_test.c

$(TEST): $(TEST_OBJ) $(LIB)
	$(CC) $(CFLAGS) $(WRAP) -o $@ $(TEST_OBJ) $(LIB)

# The last line is the qualification marker: AIENOS_KV_RECORD_NATIVE: PASS.
test: pin-check slot-vectors-check $(TEST) lib-checks
	./$(TEST) tests/golden CONTRACT.lock

# CONTRACT.lock against the golden files, with sha256sum (the C test checks the
# same hashes with the argus SHA-256 and refuses to run on a mismatch).
pin-check:
	@want=$$(sed -n 's/^vectors_sha256 = //p' CONTRACT.lock); got=$$(sha256sum tests/golden/kv_record_v1.json | cut -d' ' -f1); \
	[ -n "$$want" ] && [ "$$want" = "$$got" ] || { echo "pin-check FAIL: kv_record_v1.json $$got != lock $$want"; exit 1; }
	@want=$$(sed -n 's/^slot_vectors_sha256 = //p' CONTRACT.lock); got=$$(sha256sum tests/golden/kv_slot_v1.json | cut -d' ' -f1); \
	[ -n "$$want" ] && [ "$$want" = "$$got" ] || { echo "pin-check FAIL: kv_slot_v1.json $$got != lock $$want"; exit 1; }
	@echo "pin-check PASS (both golden files match CONTRACT.lock)"

# The slot vectors are produced by shell tools only; regenerating them must
# reproduce the committed file exactly (an independent check of the C codec's
# expected values, not only of the C test).
slot-vectors-check: | $(OUT)
	@if command -v xxd >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then \
	  bash tests/gen_slot_vectors.sh tests/golden/kv_record_v1.json > $(OUT)/kv_slot_v1.regen.json && \
	  cmp -s $(OUT)/kv_slot_v1.regen.json tests/golden/kv_slot_v1.json && echo "slot-vectors-check PASS (shell regeneration equals tests/golden/kv_slot_v1.json)" \
	  || { echo "slot-vectors-check FAIL: regeneration differs from tests/golden/kv_slot_v1.json"; exit 1; }; \
	else echo "slot-vectors-check SKIPPED (xxd or openssl missing)"; fi

# Library objects must not allocate, read a clock, or do their own I/O.
lib-checks: $(OUT)/kv_record.o
	@if $(NM) -u $(OUT)/kv_record.o | awk '{print $$NF}' | sed 's/^_//' | grep -qxE 'malloc|calloc|realloc|free|aligned_alloc|posix_memalign|mmap|clock_gettime|time|gettimeofday|open|openat|read|write|pread|pwrite|fopen|fread|fwrite|printf|fprintf|snprintf|puts|abort|exit|getrandom|rand|random'; then \
	  echo "lib-checks FAIL: kv_record.o allocates, reads a clock or does its own I/O"; exit 1; fi
	@echo "lib-checks PASS (no heap, clock or direct I/O in kv_record.o)"

sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) $(INC) $(WRAPDEF) $(WRAP) -o $(OUT)/kv_record_test_asan tests/kv_record_test.c kv_record.c $(DEP_SRCS)
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/kv_record_test_asan tests/golden CONTRACT.lock > $(OUT)/kv_record_test_asan.log 2>&1; rc=$$?; tail -n 3 $(OUT)/kv_record_test_asan.log; \
	if [ $$rc -eq 0 ]; then echo "AIENOS_KV_SANITIZE: PASS"; else echo "AIENOS_KV_SANITIZE: FAIL"; exit 1; fi
else
	@echo "sanitize: Linux only"
endif

# Mutants: remove each GUARD-tagged rule in turn. The test must fail for every
# mutant, or that rule is not tested.
KV_GUARDS = $(shell grep -ho 'GUARD:[a-z0-9-]* \*/' kv_record.c | sed 's/GUARD://; s/ \*\///')
mutants: $(TEST_OBJ) $(DEP_OBJS) | $(OUT)
	@mkdir -p $(OUT)/mut; fail=0; total=0; killed=0; \
	for g in $(KV_GUARDS); do \
	  total=$$((total + 1)); \
	  [ $$(grep -c "GUARD:$$g \*/" kv_record.c) -eq 1 ] || { echo "mutant $$g: tag not unique"; fail=1; continue; }; \
	  sed "/GUARD:$$g \*\//d" kv_record.c > $(OUT)/mut/kv_record.c; \
	  $(CC) $(CFLAGS) -Wno-error $(INC) -c -o $(OUT)/mut/kv_record.o $(OUT)/mut/kv_record.c || { echo "mutant $$g: does not compile"; fail=1; continue; }; \
	  $(CC) $(CFLAGS) $(WRAP) -o $(OUT)/mut/test $(TEST_OBJ) $(OUT)/mut/kv_record.o $(DEP_OBJS) || { echo "mutant $$g: does not link"; fail=1; continue; }; \
	  if ./$(OUT)/mut/test tests/golden CONTRACT.lock > $(OUT)/mut/$$g.log 2>&1; then echo "mutant $$g: SURVIVED (FAIL)"; fail=1; \
	  else echo "mutant $$g: killed"; killed=$$((killed + 1)); fi; \
	done; \
	echo "kv mutants: $$killed of $$total killed"; \
	if [ $$fail -eq 0 ] && [ $$total -ge 15 ]; then echo "AIENOS_KV_MUTANTS: PASS"; else echo "AIENOS_KV_MUTANTS: FAIL"; exit 1; fi

# Freestanding: no libc, no builtins. ../store/store_mem.c supplies mem* for
# this build only (the Store's freestanding build does the same). Every
# undefined symbol of kv_record.o must be defined by a sibling native object,
# so the combined relocatable has none left ("nm -u empty").
FS = $(OUT)/fs
FSFLAGS = -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdlib -fno-builtin \
          -fno-stack-protector -fno-tree-loop-distribute-patterns -fno-pic
freestanding: | $(OUT)
	@mkdir -p $(FS); rm -f $(FS)/*.o
	@$(CC) $(FSFLAGS) $(INC) -c -o $(FS)/kv_record.o kv_record.c || exit 1
	@$(CC) $(FSFLAGS) -c -o $(FS)/store_mem.o ../store/store_mem.c || exit 1
	@for s in $(DEP_SRCS); do b=$$(basename $$s .c); $(CC) $(FSFLAGS) -I../argus -I../m5 -I../crypto -c -o $(FS)/sib_$$b.o $$s || exit 1; done
	@echo "nm -u kv_record.o: $$($(NM) -u $(FS)/kv_record.o | awk '{print $$NF}' | tr '\n' ' ')"
	@$(LD) -r -o $(FS)/kv_all.o $(FS)/*.o
	@u=$$($(NM) -u $(FS)/kv_all.o | awk '{print $$NF}' | tr '\n' ' '); \
	echo "nm -u kv_all.o (kv_record + store_mem + argus/sha256 + m5 + crypto): [$$u]"; \
	if [ -z "$$u" ]; then echo "AIENOS_KV_FREESTANDING: PASS"; else echo "AIENOS_KV_FREESTANDING: FAIL"; exit 1; fi

clean:
	rm -rf $(OUT)

.PHONY: all test pin-check slot-vectors-check lib-checks sanitize mutants freestanding clean
