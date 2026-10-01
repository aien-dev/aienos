# AIENOS C kernel core (Lane 18): UEFI entry stub + kernel core as one
# AArch64 PE32+ image, plus host unit tests. Toolchain: gcc, binutils, make.
#
#   make                 build $(OUT)/BOOTAA64.EFI (and the .elf)
#   make test            host unit tests            -> CK_CORE_HOST: PASS
#   make sanitize        same under ASan + UBSan    -> CK_CORE_HOST: PASS
#   make print-kcflags   flags stage code must be built with
#
# Stage hook (the stage worker's devices/security/store code):
#   STAGE_SRCS=...   C sources compiled here with the kernel flags,
#                    $(STAGE_CFLAGS) and the native module include paths
#   STAGE_OBJS=...   extra prebuilt freestanding objects linked as given
#   STAGE_CFLAGS=... extra flags for STAGE_SRCS
# The stages are weak in ck.h: with none linked the kernel prints
# "stage <name>: not linked".
#
# Output goes to <repo>/target/native-kernel (ignored by git) unless OUT is set.
# Builds natively on an aarch64 host, else with the aarch64-linux-gnu- prefix.
# QEMU is not hardware: nothing built here is physically qualified.

KDIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
NATIVE := $(abspath $(KDIR)/..)
REPO := $(abspath $(NATIVE)/..)
BOOT := $(NATIVE)/boot

HOST_ARCH := $(shell uname -m)
ifeq ($(HOST_ARCH),aarch64)
CROSS ?=
else
CROSS ?= aarch64-linux-gnu-
endif
KCC := $(CROSS)gcc
KLD := $(CROSS)ld
KOBJCOPY := $(CROSS)objcopy
KNM := $(CROSS)nm
KREADELF := $(CROSS)readelf
HOSTCC ?= cc

OUT ?= $(REPO)/target/native-kernel
AIENOS_COMMIT ?= $(shell git -C $(REPO) rev-parse HEAD 2>/dev/null || echo unknown)

STAGE_SRCS ?=
STAGE_OBJS ?=
STAGE_CFLAGS ?=

KINC := -I$(KDIR)/include -I$(KDIR)/core -I$(KDIR)/mm -I$(KDIR)/arch -I$(BOOT)
MODULE_INC := -I$(NATIVE)/disk -I$(NATIVE)/store -I$(NATIVE)/m5 -I$(NATIVE)/crypto \
	-I$(NATIVE)/capability -I$(NATIVE)/argus -I$(NATIVE)/net
KCFLAGS := -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdlib -fno-builtin \
	-fno-stack-protector -fno-tree-loop-distribute-patterns -mstrict-align \
	-mgeneral-regs-only -fno-asynchronous-unwind-tables -fpie -fvisibility=hidden \
	-fno-plt $(KINC)
KLDFLAGS := -nostdlib -pie --no-dynamic-linker -z norelro -z noexecstack -z max-page-size=4096 --no-warn-rwx-segments \
	-T $(BOOT)/image.ld

CORE_C := $(BOOT)/efi_main.c \
	$(KDIR)/arch/exception.c $(KDIR)/arch/gic.c $(KDIR)/arch/timer.c \
	$(KDIR)/core/acpi.c $(KDIR)/core/console.c $(KDIR)/core/fmt.c \
	$(KDIR)/core/kmain.c $(KDIR)/core/libc_min.c $(KDIR)/core/report.c \
	$(KDIR)/mm/frames.c $(KDIR)/mm/heap.c $(KDIR)/mm/mmu.c $(KDIR)/mm/pt.c
CORE_S := $(BOOT)/efi_entry.S $(KDIR)/arch/vectors.S
HDRS := $(wildcard $(KDIR)/include/*.h $(KDIR)/*/*.h $(BOOT)/*.h)

KOBJ := $(OUT)/obj
CORE_OBJS := $(patsubst $(NATIVE)/%.c,$(KOBJ)/%.o,$(CORE_C)) \
	$(patsubst $(NATIVE)/%.S,$(KOBJ)/%.o,$(CORE_S))
STAGE_BUILT := $(foreach s,$(STAGE_SRCS),$(KOBJ)/stage/$(subst /,_,$(patsubst $(REPO)/%,%,$(abspath $(s)))).o)

ELF := $(OUT)/aienos-ck.elf
EFI := $(OUT)/BOOTAA64.EFI

all: $(EFI)

print-kcflags:
	@echo $(KCFLAGS) $(MODULE_INC)

$(OUT)/commit.stamp: FORCE
	@mkdir -p $(OUT)
	@echo '$(AIENOS_COMMIT)' | cmp -s - $@ || echo '$(AIENOS_COMMIT)' > $@

$(KOBJ)/%.o: $(NATIVE)/%.c $(HDRS)
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -c -o $@ $<

$(KOBJ)/kernel/core/report.o: $(KDIR)/core/report.c $(HDRS) $(OUT)/commit.stamp
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -DAIENOS_COMMIT='"$(AIENOS_COMMIT)"' -c -o $@ $<

$(KOBJ)/%.o: $(NATIVE)/%.S
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -c -o $@ $<

define stage_rule
$(KOBJ)/stage/$(subst /,_,$(patsubst $(REPO)/%,%,$(abspath $(1)))).o: $(1) $(HDRS)
	@mkdir -p $$(dir $$@)
	$(KCC) $(KCFLAGS) $(MODULE_INC) $(STAGE_CFLAGS) -c -o $$@ $(1)
endef
$(foreach s,$(STAGE_SRCS),$(eval $(call stage_rule,$(s))))

$(ELF): $(CORE_OBJS) $(STAGE_BUILT) $(STAGE_OBJS) $(BOOT)/image.ld
	$(KLD) $(KLDFLAGS) -o $@ $(CORE_OBJS) $(STAGE_BUILT) $(STAGE_OBJS)
	@u=$$($(KNM) -u $@ | grep -v ' w ' || true); \
	if [ -n "$$u" ]; then echo "image has undefined symbols: $$u"; rm -f $@; exit 1; fi
	@bad=$$($(KREADELF) -rW $@ | grep -E '^[0-9a-f]+ ' | grep -v R_AARCH64_RELATIVE || true); \
	if [ -n "$$bad" ]; then echo "image has non-RELATIVE relocations:"; echo "$$bad"; rm -f $@; exit 1; fi

$(EFI): $(ELF)
	$(KOBJCOPY) -O binary $< $@
	@sz=$$(stat -c %s $@); pad=$$(( (4096 - sz % 4096) % 4096 )); \
	if [ $$pad -gt 0 ]; then head -c $$pad /dev/zero >> $@; fi
	@[ "$$(head -c 2 $@)" = "MZ" ] || { echo "not a PE image"; rm -f $@; exit 1; }
	@echo "built $@ (commit $(AIENOS_COMMIT))"

# ---- host unit tests ----
HOST_SRCS := $(KDIR)/core/fmt.c $(KDIR)/core/acpi.c $(KDIR)/mm/frames.c \
	$(KDIR)/mm/pt.c $(KDIR)/mm/heap.c
TESTS := test_fmt test_frames test_pt test_acpi test_heap
HCFLAGS := -std=gnu11 -O1 -g -Wall -Wextra -Werror -I$(KDIR)/core -I$(KDIR)/mm -I$(KDIR)/tests
SANFLAGS := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

$(OUT)/host/%: $(KDIR)/tests/%.c $(HOST_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -o $@ $< $(HOST_SRCS)

$(OUT)/host-san/%: $(KDIR)/tests/%.c $(HOST_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) -o $@ $< $(HOST_SRCS)

test: $(addprefix $(OUT)/host/,$(TESTS))
	@fail=0; for t in $^; do $$t || fail=1; done; \
	if [ $$fail = 0 ]; then echo "CK_CORE_HOST: PASS"; else echo "CK_CORE_HOST: FAIL"; exit 1; fi

sanitize: $(addprefix $(OUT)/host-san/,$(TESTS))
	@fail=0; for t in $^; do ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 $$t || fail=1; done; \
	if [ $$fail = 0 ]; then echo "CK_CORE_HOST: PASS (sanitize)"; else echo "CK_CORE_HOST: FAIL (sanitize)"; exit 1; fi

clean:
	rm -rf $(OUT)

FORCE:
.PHONY: all test sanitize clean print-kcflags FORCE
