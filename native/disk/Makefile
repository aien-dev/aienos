# AIENOS native disk layer in C: disk_dev core (bounds, split, ordered queue),
# hosted file backend for tests, and a freestanding polled NVMe driver
# (disk_nvme.c) ported from the audited Rust path. No outside library.
# Library objects (disk.c, disk_nvme.c) import no libc symbols at all; the
# file backend and the tests use hosted libc.
#
#   make              build out/libaienos_disk.a (+ out/disk_file.o, hosted)
#   make test         disk core + file backend + NVMe driver vs software model
#   make freestanding build library objects -ffreestanding; nm -u must be empty
#   make sanitize     the same tests under ASan+UBSan (Linux)
#   make mutants      delete each GUARD-tagged check in turn; tests must fail
#   make clean
#
# Host tests and the NVMe model are not QEMU and not hardware.

CC ?= cc
AR ?= ar
NM ?= nm
LD ?= ld
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Werror -fstack-protector-strong
FREEFLAGS = -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdlib -fno-builtin \
	-fno-stack-protector -fno-tree-loop-distribute-patterns
# On AArch64 also build as the bare-metal payload does (MMU off: no unaligned
# access, no FP/SIMD registers), which catches struct copies lowered to memcpy.
ifeq ($(shell uname -m),aarch64)
FREEFLAGS += -mstrict-align -mgeneral-regs-only
endif
OUT ?= out
MUTANT_TIMEOUT ?= 60

SRCS = disk.c disk_nvme.c
OBJS = $(SRCS:%.c=$(OUT)/%.o)
FILE_OBJ = $(OUT)/disk_file.o
LIB = $(OUT)/libaienos_disk.a
HDRS = disk.h disk_nvme.h disk_file.h
DTEST = $(OUT)/disk_test
NTEST = $(OUT)/nvme_test
SANFLAGS = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -g

all: $(LIB) $(FILE_OBJ)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/%.o: %.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJS)
	rm -f $@
	$(AR) rcs $@ $^

$(DTEST): tests/disk_test.c $(LIB) $(FILE_OBJ) $(HDRS)
	$(CC) $(CFLAGS) -o $@ tests/disk_test.c $(FILE_OBJ) $(LIB)

$(NTEST): tests/nvme_test.c $(LIB) $(HDRS)
	$(CC) $(CFLAGS) -o $@ tests/nvme_test.c $(LIB)

test: $(DTEST) $(NTEST) lib-checks
	@rm -rf $(OUT)/scratch && mkdir -p $(OUT)/scratch; \
	rc=0; ./$(DTEST) $(OUT)/scratch || rc=1; ./$(NTEST) || rc=1; \
	if [ $$rc -eq 0 ]; then echo "AIENOS_DISK_NATIVE: PASS"; else echo "AIENOS_DISK_NATIVE: FAIL"; exit 1; fi

# The library objects must not allocate, read a clock, or do their own I/O.
lib-checks: $(OBJS)
	@bad=$$($(NM) -u $(OBJS) | awk 'NF {print $$NF}' | sed 's/^_//' | grep -xE 'malloc|calloc|realloc|free|aligned_alloc|posix_memalign|mmap|clock_gettime|time|gettimeofday|open|openat|read|write|pread|pwrite|fopen|fread|fwrite|printf|fprintf|puts|getrandom|rand|random'); \
	if [ -n "$$bad" ]; then echo "lib-checks FAIL: library imports $$bad"; exit 1; fi
	@echo "lib-checks PASS (no heap, clock or direct I/O in libaienos_disk objects)"

# Freestanding: no libc at all, not even memcpy/memset.
freestanding: | $(OUT)
	@mkdir -p $(OUT)/free
	$(CC) $(FREEFLAGS) -c -o $(OUT)/free/disk.o disk.c
	$(CC) $(FREEFLAGS) -c -o $(OUT)/free/disk_nvme.o disk_nvme.c
	$(LD) -r -o $(OUT)/free/disk_all.o $(OUT)/free/disk.o $(OUT)/free/disk_nvme.o
	@u=$$($(NM) -u $(OUT)/free/disk_all.o | awk 'NF==2 {print $$2}'); \
	if [ -n "$$u" ]; then echo "freestanding FAIL: undefined symbols: $$u"; echo "AIENOS_DISK_FREESTANDING: FAIL"; exit 1; fi; \
	echo "nm -u: (empty)"; echo "AIENOS_DISK_FREESTANDING: PASS"

sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/disk_test_asan tests/disk_test.c disk_file.c $(SRCS)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/nvme_test_asan tests/nvme_test.c $(SRCS)
	@rm -rf $(OUT)/scratch_asan && mkdir -p $(OUT)/scratch_asan
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/disk_test_asan $(OUT)/scratch_asan
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/nvme_test_asan
	@echo "AIENOS_DISK_SANITIZE: PASS"
else
	@echo "sanitize: Linux only"
endif

# Mutants: delete each GUARD-tagged line in turn. Both test programs run
# against the mutant (under a timeout: deleting a poll bound can hang) and
# at least one must fail, crash or time out.
GUARDS = disk-zero disk-lba disk-end queue-bound queue-failstop \
	nvme-vs nvme-mpsmin nvme-mqes-admin nvme-mqes-io nvme-css \
	nvme-cfs-ready nvme-ready-bound nvme-cfs-cmd nvme-cmd-bound nvme-cid nvme-sqid \
	nvme-sqes nvme-cqes nvme-nsid nvme-nsze nvme-flbas nvme-meta nvme-lbads \
	nvme-failstop nvme-xfer nvme-range \
	prp-len-wrap prp-addr-wrap prp-list-cap atomic-unit atomic-boundary

mutants: | $(OUT)
	@ulimit -c 0; fail=0; n=0; k=0; for g in $(GUARDS); do \
	  n=$$((n+1)); \
	  f=$$(grep -l "GUARD:$$g \*/" $(SRCS)); \
	  if [ $$(echo "$$f" | wc -w) -ne 1 ]; then echo "mutant $$g: guard tag missing or duplicated"; fail=1; continue; fi; \
	  if [ $$(grep -c "GUARD:$$g \*/" $$f) -ne 1 ]; then echo "mutant $$g: guard tag duplicated"; fail=1; continue; fi; \
	  d=$(OUT)/mut_$$g; rm -rf $$d; mkdir -p $$d/scratch; \
	  for s in $(SRCS); do if [ $$s = $$f ]; then sed "/GUARD:$$g \*\//d" $$s > $$d/$$s; else cp $$s $$d/$$s; fi; done; \
	  if cmp -s $$f $$d/$$f; then echo "mutant $$g: sed changed nothing (FAIL)"; fail=1; continue; fi; \
	  $(CC) $(CFLAGS) -Wno-error -I. -o $$d/dt tests/disk_test.c disk_file.c $$d/disk.c $$d/disk_nvme.c 2> $$d/cc.log \
	    && $(CC) $(CFLAGS) -Wno-error -I. -o $$d/nt tests/nvme_test.c $$d/disk.c $$d/disk_nvme.c 2>> $$d/cc.log \
	    || { echo "mutant $$g: does not compile (FAIL)"; fail=1; continue; }; \
	  if timeout $(MUTANT_TIMEOUT) ./$$d/dt $$d/scratch > $$d/run.log 2>&1 && \
	     timeout $(MUTANT_TIMEOUT) ./$$d/nt >> $$d/run.log 2>&1; then \
	    echo "mutant $$g: SURVIVED (FAIL)"; fail=1; \
	  else echo "mutant $$g: killed"; k=$$((k+1)); fi; \
	done; \
	echo "mutants killed: $$k/$$n"; \
	if [ $$fail -eq 0 ] && [ $$n -ge 10 ]; then echo "AIENOS_DISK_MUTANTS: PASS"; else echo "AIENOS_DISK_MUTANTS: FAIL"; exit 1; fi

clean:
	rm -rf $(OUT)

.PHONY: all test lib-checks freestanding sanitize mutants clean
