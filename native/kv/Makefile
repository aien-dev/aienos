# Native persistent-KV codec and slab store (C, no outside library), cuts N1+N2 of aienos#367:
#   kv_record   256-byte record header, 4096-byte header region, compute-config
#               aware namespace id, prefix-chained chunk keys, validation that
#               refuses before any allocation, the native slot header unit and
#               the envelope id / nonce mapping into M5 (sovereign-core ADR 0003).
#   kv_slab     kv_disk_bind with LBA overlap refusal against Store and Anchor
#               regions, kv_slab_format, bounded N-header-unit kv_slab_recover,
#               and the header-last slot write state machine.
# Pinned to sovereign-core by CONTRACT.lock and tests/golden/*.json.
# SHA-256 is ../argus/sha256.c; HKDF/HMAC are ../m5 and ../crypto; block I/O is
# ../disk/disk.c. Library objects import no heap, clock or direct libc I/O;
# the tests use hosted libc and ../disk/disk_file.c.
#
#   make              build out/libaienos_kv.a
#   make test         pin check + slot vector regeneration check + unit tests
#                     (host emulation over memory / disk_file, not hardware)
#   make pin-check    CONTRACT.lock hashes against the two golden files (sha256sum)
#   make sanitize     the same tests under ASan+UBSan (Linux)
#   make mutants      remove each GUARD-tagged rule in turn; the tests must fail
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
INC = -I. -I../argus -I../disk -I../m5 -I../crypto -I../store -Itests

KV_SRCS = kv_record.c kv_slab.c
KV_OBJS = $(OUT)/kv_record.o $(OUT)/kv_slab.o

DEP_SRCS = ../argus/sha256.c ../disk/disk.c ../m5/m5_keys.c ../m5/m5_envelope.c ../m5/m5_state.c \
           ../crypto/aes.c ../crypto/polyval.c ../crypto/gcm_siv.c ../crypto/hmac.c ../crypto/ct.c
DEP_OBJS = $(OUT)/sha256.o $(OUT)/dep_disk.o $(OUT)/dep_m5_keys.o $(OUT)/dep_m5_envelope.o $(OUT)/dep_m5_state.o \
           $(OUT)/dep_aes.o $(OUT)/dep_polyval.o $(OUT)/dep_gcm_siv.o $(OUT)/dep_hmac.o $(OUT)/dep_ct.o

SLAB_TEST_DEP_SRCS = ../disk/disk_file.c ../store/torn_slot.c ../store/store_v1.c \
                     ../store/store_engine.c ../store/store_disk.c ../store/store_sealed.c
SLAB_TEST_DEP_OBJS = $(OUT)/tdep_disk_file.o $(OUT)/tdep_torn_slot.o $(OUT)/tdep_store_v1.o \
                     $(OUT)/tdep_store_engine.o $(OUT)/tdep_store_disk.o $(OUT)/tdep_store_sealed.o

HDRS = kv_record.h kv_slab.h ../argus/sha256.h ../disk/disk.h ../m5/m5.h ../crypto/aienos_crypto.h
LIB = $(OUT)/libaienos_kv.a
RECORD_TEST = $(OUT)/kv_record_test
RECORD_TEST_OBJ = $(OUT)/t_kv_record_test.o
SLAB_TEST = $(OUT)/kv_slab_test
SLAB_TEST_OBJ = $(OUT)/t_kv_slab_test.o

# Count heap calls in the tests (GNU ld --wrap) so "refuses before any
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
$(OUT)/kv_slab.o: kv_slab.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) -c -o $@ kv_slab.c
$(OUT)/sha256.o: ../argus/sha256.c ../argus/sha256.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ ../argus/sha256.c
$(OUT)/dep_disk.o: ../disk/disk.c ../disk/disk.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ ../disk/disk.c
$(OUT)/dep_m5_%.o: ../m5/m5_%.c ../m5/m5.h ../m5/m5_internal.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<
$(OUT)/dep_%.o: ../crypto/%.c ../crypto/aienos_crypto.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(OUT)/tdep_disk_file.o: ../disk/disk_file.c ../disk/disk_file.h ../disk/disk.h | $(OUT)
	$(CC) $(CFLAGS) -I../disk -c -o $@ ../disk/disk_file.c
$(OUT)/tdep_%.o: ../store/%.c | $(OUT)
	$(CC) $(CFLAGS) -I../store -I../argus -I../disk -I../m5 -I../crypto -c -o $@ $<

$(LIB): $(KV_OBJS) $(DEP_OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(RECORD_TEST_OBJ): tests/kv_record_test.c tests/json_min.h $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) $(WRAPDEF) -c -o $@ tests/kv_record_test.c

$(RECORD_TEST): $(RECORD_TEST_OBJ) $(LIB)
	$(CC) $(CFLAGS) $(WRAP) -o $@ $(RECORD_TEST_OBJ) $(LIB)

$(SLAB_TEST_OBJ): tests/kv_slab_test.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) $(WRAPDEF) -c -o $@ tests/kv_slab_test.c

$(SLAB_TEST): $(SLAB_TEST_OBJ) $(SLAB_TEST_DEP_OBJS) $(LIB)
	$(CC) $(CFLAGS) $(WRAP) -o $@ $(SLAB_TEST_OBJ) $(SLAB_TEST_DEP_OBJS) $(LIB)

# Qualification markers: AIENOS_KV_RECORD_NATIVE: PASS and AIENOS_KV_SLAB_NATIVE: PASS.
test: pin-check slot-vectors-check $(RECORD_TEST) $(SLAB_TEST) lib-checks
	./$(RECORD_TEST) tests/golden CONTRACT.lock
	./$(SLAB_TEST) $(OUT)

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
lib-checks: $(KV_OBJS)
	@for o in $(KV_OBJS); do \
	  if $(NM) -u $$o | awk '{print $$NF}' | sed 's/^_//' | grep -qxE 'malloc|calloc|realloc|free|aligned_alloc|posix_memalign|mmap|clock_gettime|time|gettimeofday|open|openat|read|write|pread|pwrite|fopen|fread|fwrite|printf|fprintf|snprintf|puts|abort|exit|getrandom|rand|random'; then \
	    echo "lib-checks FAIL: $$o allocates, reads a clock or does its own I/O"; exit 1; fi; \
	done
	@echo "lib-checks PASS (no heap, clock or direct I/O in $(KV_OBJS))"

sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) $(INC) $(WRAPDEF) $(WRAP) -o $(OUT)/kv_record_test_asan tests/kv_record_test.c $(KV_SRCS) $(DEP_SRCS)
	$(CC) $(CFLAGS) $(SANFLAGS) $(INC) $(WRAPDEF) $(WRAP) -o $(OUT)/kv_slab_test_asan tests/kv_slab_test.c $(KV_SRCS) $(DEP_SRCS) $(SLAB_TEST_DEP_SRCS)
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/kv_record_test_asan tests/golden CONTRACT.lock > $(OUT)/kv_record_test_asan.log 2>&1; rc1=$$?; tail -n 3 $(OUT)/kv_record_test_asan.log; \
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/kv_slab_test_asan $(OUT) > $(OUT)/kv_slab_test_asan.log 2>&1; rc2=$$?; tail -n 3 $(OUT)/kv_slab_test_asan.log; \
	if [ $$rc1 -eq 0 ] && [ $$rc2 -eq 0 ]; then echo "AIENOS_KV_SANITIZE: PASS"; else echo "AIENOS_KV_SANITIZE: FAIL"; exit 1; fi
else
	@echo "sanitize: Linux only"
endif

# Mutants: remove each GUARD-tagged rule in turn. The tests must fail for every
# mutant, or that rule is not tested.
mutants: $(RECORD_TEST_OBJ) $(SLAB_TEST_OBJ) $(KV_OBJS) $(DEP_OBJS) $(SLAB_TEST_DEP_OBJS) | $(OUT)
	@mkdir -p $(OUT)/mut; fail=0; total=0; killed=0; \
	for src in $(KV_SRCS); do \
	  guards=$$(grep -ho 'GUARD:[a-z0-9-]* \*/' $$src | sed 's/GUARD://; s/ \*\///'); \
	  for g in $$guards; do \
	    total=$$((total + 1)); \
	    [ $$(grep -c "GUARD:$$g \*/" $$src) -eq 1 ] || { echo "mutant $$g: tag not unique in $$src"; fail=1; continue; }; \
	    sed "/GUARD:$$g \*\//d" $$src > $(OUT)/mut/$$src; \
	    $(CC) $(CFLAGS) -Wno-error $(INC) -c -o $(OUT)/mut/mut.o $(OUT)/mut/$$src || { echo "mutant $$g: does not compile"; fail=1; continue; }; \
	    if [ "$$src" = "kv_record.c" ]; then \
	      $(CC) $(CFLAGS) $(WRAP) -o $(OUT)/mut/test $(RECORD_TEST_OBJ) $(OUT)/mut/mut.o $(OUT)/kv_slab.o $(DEP_OBJS) || { echo "mutant $$g: does not link"; fail=1; continue; }; \
	      run_cmd="./$(OUT)/mut/test tests/golden CONTRACT.lock"; \
	    else \
	      $(CC) $(CFLAGS) $(WRAP) -o $(OUT)/mut/test $(SLAB_TEST_OBJ) $(OUT)/kv_record.o $(OUT)/mut/mut.o $(DEP_OBJS) $(SLAB_TEST_DEP_OBJS) || { echo "mutant $$g: does not link"; fail=1; continue; }; \
	      run_cmd="./$(OUT)/mut/test $(OUT)"; \
	    fi; \
	    if $$run_cmd > $(OUT)/mut/$$g.log 2>&1; then echo "mutant $$g: SURVIVED (FAIL)"; fail=1; \
	    else echo "mutant $$g: killed"; killed=$$((killed + 1)); fi; \
	  done; \
	done; \
	echo "kv mutants: $$killed of $$total killed"; \
	if [ $$fail -eq 0 ] && [ $$total -ge 30 ]; then echo "AIENOS_KV_MUTANTS: PASS"; else echo "AIENOS_KV_MUTANTS: FAIL"; exit 1; fi

# Freestanding: no libc, no builtins. ../store/store_mem.c supplies mem* for
# this build only (the Store's freestanding build does the same). Every
# undefined symbol of kv_record.o + kv_slab.o must be defined by a sibling
# native object, so the combined relocatable has none left ("nm -u empty").
FS = $(OUT)/fs
FSFLAGS = -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdlib -fno-builtin \
          -fno-stack-protector -fno-tree-loop-distribute-patterns -fno-pic
freestanding: | $(OUT)
	@mkdir -p $(FS); rm -f $(FS)/*.o
	@$(CC) $(FSFLAGS) $(INC) -c -o $(FS)/kv_record.o kv_record.c || exit 1
	@$(CC) $(FSFLAGS) $(INC) -c -o $(FS)/kv_slab.o kv_slab.c || exit 1
	@$(CC) $(FSFLAGS) -c -o $(FS)/store_mem.o ../store/store_mem.c || exit 1
	@for s in $(DEP_SRCS); do b=$$(basename $$s .c); $(CC) $(FSFLAGS) -I../argus -I../disk -I../m5 -I../crypto -c -o $(FS)/sib_$$b.o $$s || exit 1; done
	@echo "nm -u kv_record.o: $$($(NM) -u $(FS)/kv_record.o | awk '{print $$NF}' | tr '\n' ' ')"
	@echo "nm -u kv_slab.o: $$($(NM) -u $(FS)/kv_slab.o | awk '{print $$NF}' | tr '\n' ' ')"
	@$(LD) -r -o $(FS)/kv_all.o $(FS)/*.o
	@u=$$($(NM) -u $(FS)/kv_all.o | awk '{print $$NF}' | tr '\n' ' '); \
	echo "nm -u kv_all.o (kv_record + kv_slab + store_mem + argus/sha256 + disk + m5 + crypto): [$$u]"; \
	if [ -z "$$u" ]; then echo "AIENOS_KV_FREESTANDING: PASS"; else echo "AIENOS_KV_FREESTANDING: FAIL"; exit 1; fi

clean:
	rm -rf $(OUT)

.PHONY: all test pin-check slot-vectors-check lib-checks sanitize mutants freestanding clean
