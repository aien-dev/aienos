# AIENOS native disk layer in C: disk_dev core (bounds, split, ordered queue),
# hosted file backend for tests, and a freestanding polled NVMe driver
# (disk_nvme.c) ported from the audited Rust path, and a polled PIO SD Host
# Controller driver (disk_sdhci.c) for the Pi 5 microSD. No outside library.
# Library objects (disk.c, disk_nvme.c, disk_sdhci.c) import no libc symbols at all; the
# file backend and the tests use hosted libc.
#
#   make              build out/libaienos_disk.a (+ out/disk_file.o, hosted)
#   make test         disk core + file backend + NVMe and SDHCI drivers vs software models
#   make freestanding build library objects -ffreestanding; nm -u must be empty
#   make sanitize     the same tests under ASan+UBSan (Linux)
#   make mutants      delete each GUARD-tagged check in turn; tests must fail
#   make clean
#
# Host tests and the NVMe and SDHCI models are not QEMU and not hardware.

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

SRCS = disk.c disk_nvme.c disk_sdhci.c
OBJS = $(SRCS:%.c=$(OUT)/%.o)
FILE_OBJ = $(OUT)/disk_file.o
LIB = $(OUT)/libaienos_disk.a
HDRS = disk.h disk_nvme.h disk_sdhci.h disk_file.h
DTEST = $(OUT)/disk_test
NTEST = $(OUT)/nvme_test
STEST = $(OUT)/sdhci_test
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

$(STEST): tests/sdhci_test.c $(LIB) $(HDRS)
	$(CC) $(CFLAGS) -o $@ tests/sdhci_test.c $(LIB)

test: $(DTEST) $(NTEST) $(STEST) lib-checks
	@rm -rf $(OUT)/scratch && mkdir -p $(OUT)/scratch; \
	rc=0; ./$(DTEST) $(OUT)/scratch || rc=1; ./$(NTEST) || rc=1; ./$(STEST) > $(OUT)/sdhci_test.log 2>&1 && tail -1 $(OUT)/sdhci_test.log || { cat $(OUT)/sdhci_test.log; rc=1; }; \
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
	$(CC) $(FREEFLAGS) -c -o $(OUT)/free/disk_sdhci.o disk_sdhci.c
	$(LD) -r -o $(OUT)/free/disk_all.o $(OUT)/free/disk.o $(OUT)/free/disk_nvme.o $(OUT)/free/disk_sdhci.o
	@u=$$($(NM) -u $(OUT)/free/disk_all.o | awk 'NF==2 {print $$2}'); \
	if [ -n "$$u" ]; then echo "freestanding FAIL: undefined symbols: $$u"; echo "AIENOS_DISK_FREESTANDING: FAIL"; exit 1; fi; \
	echo "nm -u: (empty)"; echo "AIENOS_DISK_FREESTANDING: PASS"

sanitize: | $(OUT)
ifeq ($(shell uname -s),Linux)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/disk_test_asan tests/disk_test.c disk_file.c $(SRCS)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/nvme_test_asan tests/nvme_test.c $(SRCS)
	$(CC) $(CFLAGS) $(SANFLAGS) -o $(OUT)/sdhci_test_asan tests/sdhci_test.c $(SRCS)
	@rm -rf $(OUT)/scratch_asan && mkdir -p $(OUT)/scratch_asan
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/disk_test_asan $(OUT)/scratch_asan
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/nvme_test_asan
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 ./$(OUT)/sdhci_test_asan > $(OUT)/sdhci_asan.log 2>&1 || { cat $(OUT)/sdhci_asan.log; exit 1; }
	@echo "AIENOS_DISK_SANITIZE: PASS"
else
	@echo "sanitize: Linux only"
endif

# Mutants: delete each GUARD-tagged line in turn. All three test programs run
# against the mutant (under a timeout: deleting a poll bound can hang) and
# at least one must fail, crash or time out.
GUARDS = disk-zero disk-lba disk-end queue-bound queue-failstop \
	nvme-vs nvme-mpsmin nvme-mqes-admin nvme-mqes-io nvme-css \
	nvme-cfs-ready nvme-ready-bound nvme-cfs-cmd nvme-cmd-bound nvme-cid nvme-sqid \
	nvme-sqes nvme-cqes nvme-nsid nvme-nsze nvme-flbas nvme-meta nvme-lbads \
	nvme-failstop nvme-xfer nvme-range \
	prp-len-wrap prp-addr-wrap prp-list-cap atomic-unit atomic-boundary \
	sdhci-err-int sdhci-inhibit sdhci-r1 sdhci-ver sdhci-reset sdhci-volt sdhci-clock0 \
	sdhci-nocard sdhci-cmd8 sdhci-acmd41-bound sdhci-csd-zero sdhci-ready sdhci-range \
	sdhci-tran sdhci-failstop

DISK_MUT_TEST_OBJS = $(OUT)/t_disk_test.o $(OUT)/t_nvme_test.o $(OUT)/t_sdhci_test.o
$(OUT)/t_%_test.o: tests/%_test.c $(HDRS) | $(OUT)
	$(CC) $(CFLAGS) -Wno-error -I. -c -o $@ $<

mutants: $(OBJS) $(FILE_OBJ) $(DISK_MUT_TEST_OBJS) | $(OUT)
	@ulimit -c 0; fail=0; n=0; k=0; \
	dups=$$(printf '%s\n' $(GUARDS) | sort | uniq -d); \
	[ -z "$$dups" ] || { echo "duplicate guard names (parallel runs would collide):" $$dups; echo "AIENOS_DISK_MUTANTS: FAIL"; exit 1; }; \
	for g in $(GUARDS); do \
	  n=$$((n+1)); d=$(OUT)/mut_$$g; rm -rf $$d; mkdir -p $$d/scratch; \
	  ( f=$$(grep -l "GUARD:$$g \*/" $(SRCS)); \
	    if [ $$(echo "$$f" | wc -w) -ne 1 ]; then echo "mutant $$g: guard tag missing or duplicated" > $$d/msg; echo 1 > $$d/fail; exit 0; fi; \
	    if [ $$(grep -c "GUARD:$$g \*/" $$f) -ne 1 ]; then echo "mutant $$g: guard tag duplicated" > $$d/msg; echo 1 > $$d/fail; exit 0; fi; \
	    sed "/GUARD:$$g \*\//d" $$f > $$d/$$f; \
	    if cmp -s $$f $$d/$$f; then echo "mutant $$g: sed changed nothing (FAIL)" > $$d/msg; echo 1 > $$d/fail; exit 0; fi; \
	    others=""; for s in $(SRCS); do [ "$$s" = "$$f" ] || others="$$others $(OUT)/$${s%.c}.o"; done; \
	    $(CC) $(CFLAGS) -Wno-error -I. -c -o $$d/m.o $$d/$$f 2> $$d/cc.log \
	      && $(CC) $(CFLAGS) -Wno-error -o $$d/dt $(OUT)/t_disk_test.o $(FILE_OBJ) $$d/m.o $$others 2>> $$d/cc.log \
	      && $(CC) $(CFLAGS) -Wno-error -o $$d/nt $(OUT)/t_nvme_test.o $$d/m.o $$others 2>> $$d/cc.log \
	      && $(CC) $(CFLAGS) -Wno-error -o $$d/st $(OUT)/t_sdhci_test.o $$d/m.o $$others 2>> $$d/cc.log \
	      || { echo "mutant $$g: does not compile (FAIL)" > $$d/msg; echo 1 > $$d/fail; exit 0; }; \
	    case "$$f" in \
	      disk.c)       order="dt nt st" ;; \
	      disk_nvme.c)  order="nt dt st" ;; \
	      *)            order="st dt nt" ;; \
	    esac; \
	    pass=1; : > $$d/run.log; \
	    for b in $$order; do \
	      if [ "$$b" = "dt" ]; then timeout $(MUTANT_TIMEOUT) ./$$d/dt $$d/scratch >> $$d/run.log 2>&1 || { pass=0; break; }; \
	      else timeout $(MUTANT_TIMEOUT) ./$$d/$$b >> $$d/run.log 2>&1 || { pass=0; break; }; fi; \
	    done; \
	    if [ $$pass -eq 1 ]; then echo "mutant $$g: SURVIVED (FAIL)" > $$d/msg; echo 1 > $$d/fail; \
	    else echo "mutant $$g: killed" > $$d/msg; : > $$d/killed; fi \
	  ) & \
	done; \
	wait; \
	for g in $(GUARDS); do \
	  d=$(OUT)/mut_$$g; \
	  if [ -f $$d/msg ]; then cat $$d/msg; else echo "mutant $$g: no result recorded (FAIL)"; fi; \
	  if [ -f $$d/killed ] && [ ! -f $$d/fail ]; then k=$$((k+1)); else fail=1; fi; \
	done; \
	echo "mutants killed: $$k/$$n"; \
	if [ $$fail -eq 0 ] && [ $$n -ge 10 ]; then echo "AIENOS_DISK_MUTANTS: PASS"; else echo "AIENOS_DISK_MUTANTS: FAIL"; exit 1; fi

clean:
	rm -rf $(OUT)

.PHONY: all test lib-checks freestanding sanitize mutants clean
