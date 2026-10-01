# Native Store (C, no outside library):
#   torn_slot      torn-write-safe 4096-byte record over 512/4096-byte blocks
#   store_v1/engine/disk   Store v1 (ADR 0015) C twin of the Rust engine
#   store_sealed   M5 sealed store: envelopes, transaction records, anchor
# SHA-256 is ../argus/sha256.c; crypto is ../crypto and ../m5; block I/O is
# ../disk. Library objects import no heap, clock or I/O; tests use hosted libc.
#
#   make              build out/libtorn_slot.a and out/libaienos_store.a
#   make test         torn_slot test + every Store test + Rust cross-check
#                     (host emulation over files, not QEMU, not hardware)
#   make sanitize     the same tests under ASan+UBSan (Linux)
#   make mutants      remove each GUARD-tagged rule in turn; tests must fail
#   make freestanding -ffreestanding -nostdlib build; nm -u must close over
#                     the sibling native objects
#   make clean
# RUST_STORE_TOOL=<path> selects the Rust aienos-store-tool for the
# cross-check (default ../../target/release/aienos-store-tool; NOT_RUN if absent).

CC ?= cc
AR ?= ar
LD ?= ld
NM ?= nm
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
OUT ?= out

LIB = $(OUT)/libtorn_slot.a
TEST = $(OUT)/torn_slot_test
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g

STORE_SRCS = store_v1.c store_engine.c store_disk.c store_sealed.c
STORE_HDRS = store_v1.h store_engine.h store_sealed.h torn_slot.h ../disk/disk.h ../m5/m5.h ../argus/sha256.h
DEP_SRCS = ../argus/sha256.c ../disk/disk.c ../m5/m5_keys.c ../m5/m5_envelope.c ../m5/m5_state.c \
           ../crypto/aes.c ../crypto/polyval.c ../crypto/gcm_siv.c ../crypto/hmac.c ../crypto/ct.c
STORE_OBJS = $(STORE_SRCS:%.c=$(OUT)/%.o)
DEP_OBJS = $(OUT)/sha256.o $(OUT)/dep_disk.o $(OUT)/dep_m5_keys.o $(OUT)/dep_m5_envelope.o \
           $(OUT)/dep_m5_state.o $(OUT)/dep_aes.o $(OUT)/dep_polyval.o $(OUT)/dep_gcm_siv.o \
           $(OUT)/dep_hmac.o $(OUT)/dep_ct.o
STORE_LIB = $(OUT)/libaienos_store.a
INC = -I. -I../argus -I../disk -Itests -I$(OUT)
GOLDEN_JSON = ../../docs/adr/0015-golden-vectors.json
GOLDEN_H = $(OUT)/golden_vectors.h
TEST_NAMES = store_v1_test store_engine_test store_sealed_test store_powercut_test
TEST_OBJS = $(TEST_NAMES:%=$(OUT)/t_%.o)
STORE_TESTS = $(TEST_NAMES:%=$(OUT)/%)
XCHECK = $(OUT)/store_xcheck
HOST_OBJS = $(OUT)/disk_file.o

all: $(LIB) $(STORE_LIB)

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

# ---- Store objects ----
$(OUT)/store_%.o: store_%.c $(STORE_HDRS) | $(OUT)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<
$(OUT)/dep_disk.o: ../disk/disk.c ../disk/disk.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<
$(OUT)/dep_m5_%.o: ../m5/m5_%.c ../m5/m5.h ../m5/m5_internal.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<
$(OUT)/dep_%.o: ../crypto/%.c ../crypto/aienos_crypto.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<
$(OUT)/disk_file.o: ../disk/disk_file.c ../disk/disk_file.h ../disk/disk.h | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(STORE_LIB): $(STORE_OBJS) $(OUT)/torn_slot.o $(DEP_OBJS)
	$(AR) rcs $@ $^

$(GOLDEN_H): tests/gen_golden.sh $(GOLDEN_JSON) | $(OUT)
	sh tests/gen_golden.sh $(GOLDEN_JSON) $@

$(OUT)/t_%.o: tests/%.c tests/store_test_util.h tests/store_rig.h $(STORE_HDRS) $(GOLDEN_H) | $(OUT)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

$(OUT)/store_%_test: $(OUT)/t_store_%_test.o $(STORE_LIB) $(HOST_OBJS)
	$(CC) $(CFLAGS) -o $@ $< $(HOST_OBJS) $(STORE_LIB)

$(XCHECK): tests/store_xcheck.c tests/store_test_util.h $(STORE_LIB) $(HOST_OBJS)
	$(CC) $(CFLAGS) $(INC) -o $@ tests/store_xcheck.c $(HOST_OBJS) $(STORE_LIB)

test: $(TEST) $(STORE_TESTS) $(XCHECK) lib-checks
	@fail=0; \
	./$(TEST) || fail=1; \
	./$(OUT)/store_v1_test || fail=1; \
	./$(OUT)/store_engine_test $(OUT) || fail=1; \
	./$(OUT)/store_sealed_test $(OUT) || fail=1; \
	./$(OUT)/store_powercut_test $(OUT) || fail=1; \
	RUST_STORE_TOOL=$(RUST_STORE_TOOL) sh tests/rust_crosscheck.sh ./$(XCHECK) $(OUT) || fail=1; \
	if [ $$fail -eq 0 ]; then echo "AIENOS_STORE_NATIVE: PASS"; else echo "AIENOS_STORE_NATIVE: FAIL"; exit 1; fi

# Library objects must not allocate, read a clock, or do their own I/O.
LIB_CHECK_OBJS = $(OUT)/torn_slot.o $(STORE_OBJS)
lib-checks: $(LIB_CHECK_OBJS)
	@for o in $(LIB_CHECK_OBJS); do \
	  if $(NM) -u $$o | awk '{print $$NF}' | sed 's/^_//' | grep -qxE 'malloc|calloc|realloc|free|clock_gettime|time|gettimeofday|open|read|write|pread|pwrite|fopen|printf|fprintf|puts|abort|exit'; then \
	    echo "lib-checks FAIL: $$o allocates, reads a clock or does its own I/O"; exit 1; fi; \
	done
	@echo "lib-checks PASS (no heap, clock or direct I/O in torn_slot.o, store_v1.o, store_engine.o, store_disk.o, store_sealed.o)"

SAN_SRCS = $(STORE_SRCS) torn_slot.c $(DEP_SRCS) ../disk/disk_file.c
sanitize: $(GOLDEN_H) | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/torn_slot_test_asan tests/torn_slot_test.c torn_slot.c ../argus/sha256.c
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/torn_slot_test_asan
	@for t in $(TEST_NAMES); do \
	  $(CC) $(CFLAGS) $(SANFLAGS) $(INC) -o $(OUT)/$${t}_asan tests/$$t.c $(SAN_SRCS) || exit 1; \
	done
	@fail=0; for t in $(TEST_NAMES); do \
	  ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/$${t}_asan $(OUT) > $(OUT)/$${t}_asan.log 2>&1 || fail=1; \
	  tail -n 1 $(OUT)/$${t}_asan.log; \
	done; \
	if [ $$fail -eq 0 ]; then echo "AIENOS_STORE_SANITIZE: PASS"; else echo "AIENOS_STORE_SANITIZE: FAIL"; exit 1; fi
else
	@echo "sanitize: Linux only"
endif

# Mutants: remove each GUARD-tagged rule in turn. The tests must fail for
# every mutant, or that rule is not tested.
GUARDS = parity-a parity-b b-needs-a adjacent first-remnant a-alone-seq1

mutants: torn-slot-mutants store-mutants

torn-slot-mutants: | $(OUT)
	@fail=0; for g in $(GUARDS); do \
	  grep -q "GUARD:$$g \*/" torn_slot.c || { echo "mutant $$g: guard tag missing"; fail=1; continue; }; \
	  sed "/GUARD:$$g \*\//d" torn_slot.c > $(OUT)/mut_$$g.c; \
	  $(CC) $(CFLAGS) -Wno-error -I. -o $(OUT)/mut_$$g tests/torn_slot_test.c $(OUT)/mut_$$g.c ../argus/sha256.c || { fail=1; continue; }; \
	  if ./$(OUT)/mut_$$g --rules-only > $(OUT)/mut_$$g.log 2>&1; then \
	    echo "mutant $$g: SURVIVED (FAIL)"; fail=1; \
	  else echo "mutant $$g: killed"; fi; \
	done; \
	if [ $$fail -eq 0 ]; then echo "TORN_SLOT_MUTANTS: PASS"; else echo "TORN_SLOT_MUTANTS: FAIL"; exit 1; fi

STORE_GUARDS = $(shell grep -ho 'GUARD:[a-z0-9-]* \*/' $(STORE_SRCS) | sed 's/GUARD://; s/ \*\///')
store-mutants: $(STORE_OBJS) $(TEST_OBJS) $(DEP_OBJS) $(OUT)/torn_slot.o $(HOST_OBJS)
	@mkdir -p $(OUT)/mut; fail=0; total=0; killed=0; \
	for g in $(STORE_GUARDS); do \
	  total=$$((total + 1)); \
	  f=$$(grep -l "GUARD:$$g \*/" $(STORE_SRCS)); \
	  [ $$(echo $$f | wc -w) -eq 1 ] || { echo "mutant $$g: tag not unique ($$f)"; fail=1; continue; }; \
	  sed "/GUARD:$$g \*\//d" $$f > $(OUT)/mut/$$f; \
	  $(CC) $(CFLAGS) -Wno-error $(INC) -c -o $(OUT)/mut/m.o $(OUT)/mut/$$f || { echo "mutant $$g: does not compile"; fail=1; continue; }; \
	  objs=""; for s in $(STORE_SRCS); do [ $$s = $$f ] || objs="$$objs $(OUT)/$${s%.c}.o"; done; \
	  dead=0; \
	  for t in $(TEST_NAMES); do \
	    $(CC) $(CFLAGS) -o $(OUT)/mut/$$t $(OUT)/t_$$t.o $(OUT)/mut/m.o $$objs $(OUT)/torn_slot.o $(DEP_OBJS) $(HOST_OBJS) || { dead=2; break; }; \
	    if ! ./$(OUT)/mut/$$t $(OUT)/mut > $(OUT)/mut/$$g.log 2>&1; then dead=1; break; fi; \
	  done; \
	  if [ $$dead -eq 1 ]; then echo "mutant $$g ($$f): killed by $$t"; killed=$$((killed + 1)); \
	  else echo "mutant $$g ($$f): SURVIVED (FAIL)"; fail=1; fi; \
	done; \
	echo "store mutants: $$killed of $$total killed"; \
	if [ $$fail -eq 0 ] && [ $$total -ge 12 ]; then echo "AIENOS_STORE_MUTANTS: PASS"; else echo "AIENOS_STORE_MUTANTS: FAIL"; exit 1; fi

# Freestanding: no libc, no builtins. store_mem.c supplies mem* for this
# build only. Every undefined symbol of the Store objects must be defined by
# a sibling native object, so the combined relocatable has none left.
FS = $(OUT)/fs
FSFLAGS = -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdlib -fno-builtin \
          -fno-stack-protector -fno-tree-loop-distribute-patterns -fno-pic
FS_MINE = $(STORE_SRCS) torn_slot.c store_mem.c
freestanding: | $(OUT)
	@mkdir -p $(FS); rm -f $(FS)/*.o
	@for s in $(FS_MINE); do $(CC) $(FSFLAGS) $(INC) -c -o $(FS)/$${s%.c}.o $$s || exit 1; done
	@for s in $(DEP_SRCS); do b=$$(basename $$s .c); $(CC) $(FSFLAGS) -c -o $(FS)/sib_$$b.o $$s || exit 1; done
	@for s in $(FS_MINE); do echo "nm -u $${s%.c}.o: $$($(NM) -u $(FS)/$${s%.c}.o | awk '{print $$NF}' | tr '\n' ' ')"; done
	@$(LD) -r -o $(FS)/store_all.o $(FS)/*.o
	@u=$$($(NM) -u $(FS)/store_all.o | awk '{print $$NF}' | tr '\n' ' '); \
	echo "nm -u store_all.o (Store + torn_slot + store_mem + argus/sha256 + disk + m5 + crypto): [$$u]"; \
	if [ -z "$$u" ]; then echo "AIENOS_STORE_FREESTANDING: PASS"; else echo "AIENOS_STORE_FREESTANDING: FAIL"; exit 1; fi

clean:
	rm -rf $(OUT)

.PHONY: all test lib-checks sanitize mutants torn-slot-mutants store-mutants freestanding clean
