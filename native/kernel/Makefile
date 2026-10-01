# AIENOS C kernel core (Lane 18): UEFI entry stub + kernel core as one
# AArch64 PE32+ image, plus host unit tests. Toolchain: gcc, binutils, make.
#
#   make                 core-only image $(OUT)/BOOTAA64.EFI (stages print
#                        "not linked"; the M1 gate boots this one)
#   make full            full image with the boot stages (devices, security,
#                        Store) from stage.mk: $(OUT)/full/BOOTAA64.EFI,
#                        NVMe DMA SMMU-confined, refused without an SMMU
#   make full CK_QEMU_UNSAFE_DMA=1
#                        TEST-ONLY QEMU image with the unconfined NVMe DMA bypass:
#                        $(OUT)/full-qemu-unsafe-dma/BOOTAA64.EFI (only
#                        scripts/qemu_ck_store_test.sh sets this; refused
#                        together with CK_HARDWARE_STAGING=1)
#   make test            host unit tests            -> CK_CORE_HOST: PASS
#   make sanitize        same under ASan + UBSan    -> CK_CORE_HOST: PASS
#   make stage-test | stage-sanitize | stage-free   stage host tests (stage.mk)
#   make print-kcflags   flags stage code must be built with
#   make udp-echo        host UDP echo helper for scripts/qemu_ck_net_test.sh:
#                        $(OUT)/host/ck_udp_echo (hosted, test tooling only)
#
#   CK_EXTRA_CFLAGS=... extra kernel flags for one-off checks, e.g.
#                    -DCK_SELFTEST_EL2_FAULT (brk at EL2: the EL2 fatal path)
# The stages are weak references in ck.h (the core defines no defaults):
# with none linked the kernel prints "stage <name>: not linked".
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

CK_EXTRA_CFLAGS ?=
# Build-time DMA policy for the full image (see dev/nvme_bind.c):
# default SMMU-confined or refuse; 1 = TEST-ONLY QEMU unconfined bypass when
# no SMMU exists. Never with hardware staging.
CK_QEMU_UNSAFE_DMA ?=
CK_HARDWARE_STAGING ?=
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_QEMU_UNSAFE_DMA (unconfined DMA, QEMU debug only) cannot be combined with CK_HARDWARE_STAGING: no SMMU confinement means no DMA)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),1)
$(error CK_QEMU_UNSAFE_DMA must be empty or 1)
endif
endif

# SEED-0B qualification build: trusts the RFC 8032 TEST 1 public key only.
# TEST ONLY; never combined with hardware staging. Use its own OUT.
CK_SEED0B_TEST_ANCHOR ?=
ifneq ($(strip $(CK_SEED0B_TEST_ANCHOR)),)
ifneq ($(strip $(CK_SEED0B_TEST_ANCHOR)),1)
$(error CK_SEED0B_TEST_ANCHOR must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_SEED0B_TEST_ANCHOR (TEST key trust) cannot be combined with CK_HARDWARE_STAGING)
endif
ART_TRUST_FLAGS := -DCK_SEED0B_TEST_ANCHOR=1
else
ART_TRUST_FLAGS :=
endif

KINC := -I$(KDIR)/include -I$(KDIR)/core -I$(KDIR)/mm -I$(KDIR)/arch -I$(BOOT)
MODULE_INC := -I$(NATIVE)/disk -I$(NATIVE)/store -I$(NATIVE)/m5 -I$(NATIVE)/crypto \
	-I$(NATIVE)/capability -I$(NATIVE)/argus -I$(NATIVE)/net
KCFLAGS := -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdlib -fno-builtin \
	-fno-stack-protector -fno-tree-loop-distribute-patterns -mstrict-align \
	-mgeneral-regs-only -mno-outline-atomics -fno-asynchronous-unwind-tables -fpie \
	-fvisibility=hidden -fno-plt $(KINC) $(CK_EXTRA_CFLAGS)
KLDFLAGS := -nostdlib -pie --no-dynamic-linker -z norelro -z noexecstack -z max-page-size=4096 --no-warn-rwx-segments \
	-T $(BOOT)/image.ld

CORE_C := $(BOOT)/efi_main.c \
	$(KDIR)/arch/exception.c $(KDIR)/arch/gic.c $(KDIR)/arch/timer.c \
	$(KDIR)/core/acpi.c $(KDIR)/core/console.c $(KDIR)/core/fmt.c \
	$(KDIR)/core/kmain.c $(KDIR)/core/libc_min.c $(KDIR)/core/report.c \
	$(KDIR)/core/smmu.c $(KDIR)/core/smmu_svc.c $(KDIR)/core/sched.c $(KDIR)/core/ipc.c \
	$(KDIR)/core/m3.c \
	$(KDIR)/mm/frames.c $(KDIR)/mm/heap.c $(KDIR)/mm/mmu.c $(KDIR)/mm/pt.c
# P2 sealed-artifact loader: format/admission/receipt (artifact/), SHA-256
# (argus), Ed25519/SHA-512 (sig). Built into the core so every image carries
# the loader; the TEST-anchor qualification build is CK_SEED0B_TEST_ANCHOR=1.
ART_C := $(KDIR)/core/artifact_loader.c $(KDIR)/artifact/format.c $(KDIR)/artifact/admission.c \
	$(KDIR)/artifact/receipt.c $(NATIVE)/argus/sha256.c $(NATIVE)/sig/sha512.c \
	$(NATIVE)/sig/ed25519.c $(NATIVE)/sig/ct.c
ART_INC := -I$(KDIR)/svc/compat -I$(KDIR)/artifact -I$(NATIVE)/sig -I$(NATIVE)/argus
CORE_C += $(ART_C)
CORE_S := $(BOOT)/efi_entry.S $(KDIR)/arch/vectors.S $(KDIR)/arch/m3.S
HDRS := $(wildcard $(KDIR)/include/*.h $(KDIR)/*/*.h $(BOOT)/*.h)

KOBJ := $(OUT)/obj
CORE_OBJS := $(patsubst $(NATIVE)/%.c,$(KOBJ)/%.o,$(CORE_C)) \
	$(patsubst $(NATIVE)/%.S,$(KOBJ)/%.o,$(CORE_S))

.DEFAULT_GOAL := all

# ---- boot stages (stage.mk: STAGE_SRCS, STAGE_CFLAGS, stage-* host targets) ----
include $(KDIR)/stage.mk
ifeq ($(strip $(CK_QEMU_UNSAFE_DMA)),1)
FULL_NAME := full-qemu-unsafe-dma
STAGE_DMA_FLAGS := -DCK_QEMU_UNSAFE_DMA=1
else
FULL_NAME := full
STAGE_DMA_FLAGS :=
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
STAGE_DMA_FLAGS += -DCK_HARDWARE_STAGING=1
endif
FULL_OUT := $(OUT)/$(FULL_NAME)
STAGE_KOBJ := $(OUT)/obj/stage-$(FULL_NAME)
STAGE_HDRS := $(HDRS) $(wildcard $(NATIVE)/*/*.h $(NATIVE)/argus/bridge/*.h $(KDIR)/svc/compat/*.h)
STAGE_BUILT := $(foreach s,$(STAGE_SRCS),$(STAGE_KOBJ)/$(subst /,_,$(patsubst $(REPO)/%,%,$(abspath $(s)))).o)
# STAGE_CFLAGS first: svc/compat must shadow the hosted headers. No fortify.
STAGE_KCFLAGS := $(STAGE_CFLAGS) $(KCFLAGS) $(MODULE_INC) -U_FORTIFY_SOURCE $(STAGE_DMA_FLAGS)
# The core already links argus/sha256.c (artifact loader); link it once.
STAGE_LINK := $(filter-out %/native_argus_sha256.c.o,$(STAGE_BUILT))

ELF := $(OUT)/aienos-ck.elf
EFI := $(OUT)/BOOTAA64.EFI
FULL_ELF := $(FULL_OUT)/aienos-ck.elf
FULL_EFI := $(FULL_OUT)/BOOTAA64.EFI

all: $(EFI)
full: $(FULL_EFI)

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

# Artifact loader objects: compat headers for <string.h>, TEST-anchor flag.
ART_OBJS := $(patsubst $(NATIVE)/%.c,$(KOBJ)/%.o,$(ART_C))
ART_HDRS := $(wildcard $(NATIVE)/sig/*.h $(NATIVE)/argus/sha256.h $(KDIR)/svc/compat/*.h)
$(ART_OBJS): KCFLAGS += $(ART_INC)
$(ART_OBJS): $(ART_HDRS)

$(OUT)/trust.stamp: FORCE
	@mkdir -p $(OUT)
	@echo '$(ART_TRUST_FLAGS)' | cmp -s - $@ || echo '$(ART_TRUST_FLAGS)' > $@

$(KOBJ)/kernel/core/artifact_loader.o: $(KDIR)/core/artifact_loader.c $(HDRS) $(ART_HDRS) \
		$(OUT)/commit.stamp $(OUT)/trust.stamp
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) $(ART_TRUST_FLAGS) -DAIENOS_COMMIT='"$(AIENOS_COMMIT)"' -c -o $@ $<

$(KOBJ)/%.o: $(NATIVE)/%.S
	@mkdir -p $(dir $@)
	$(KCC) $(KCFLAGS) -c -o $@ $<

define stage_rule
$(STAGE_KOBJ)/$(subst /,_,$(patsubst $(REPO)/%,%,$(abspath $(1)))).o: $(1) $(STAGE_HDRS)
	@mkdir -p $$(dir $$@)
	$(KCC) $(STAGE_KCFLAGS) -c -o $$@ $(1)
endef
$(foreach s,$(STAGE_SRCS),$(eval $(call stage_rule,$(s))))

# link_image(output elf, objects): refuses undefined symbols (weak stage
# references excepted) and any relocation other than R_AARCH64_RELATIVE.
define link_image
	@mkdir -p $(dir $(1))
	$(KLD) $(KLDFLAGS) -o $(1) $(2)
	@u=$$($(KNM) -u $(1) | grep -v ' w ' || true); \
	if [ -n "$$u" ]; then echo "image has undefined symbols: $$u"; rm -f $(1); exit 1; fi
	@bad=$$($(KREADELF) -rW $(1) | grep -E '^[0-9a-f]+ ' | grep -v R_AARCH64_RELATIVE || true); \
	if [ -n "$$bad" ]; then echo "image has non-RELATIVE relocations:"; echo "$$bad"; rm -f $(1); exit 1; fi
endef
define pe_image
	$(KOBJCOPY) -O binary $(1) $(2)
	@sz=$$(stat -c %s $(2)); pad=$$(( (4096 - sz % 4096) % 4096 )); \
	if [ $$pad -gt 0 ]; then head -c $$pad /dev/zero >> $(2); fi
	@[ "$$(head -c 2 $(2))" = "MZ" ] || { echo "not a PE image"; rm -f $(2); exit 1; }
	@echo "built $(2) (commit $(AIENOS_COMMIT))"
endef

$(ELF): $(CORE_OBJS) $(BOOT)/image.ld
	$(call link_image,$@,$(CORE_OBJS))
	@s=$$($(KNM) $@ | grep -E ' [TtDdBbWwVv] ck_stage_(devices|security|store|quiesce)$$' || true); \
	if [ -n "$$s" ]; then echo "core image defines stage symbols: $$s"; rm -f $@; exit 1; fi

$(FULL_ELF): $(CORE_OBJS) $(STAGE_BUILT) $(BOOT)/image.ld
	$(call link_image,$@,$(CORE_OBJS) $(STAGE_LINK))
	@for s in ck_stage_devices ck_stage_security ck_stage_store ck_stage_quiesce; do \
	  $(KNM) $@ | grep -qE " [TW] $$s$$" || { echo "full image lacks $$s"; rm -f $@; exit 1; }; done

$(EFI): $(ELF)
	$(call pe_image,$<,$@)

$(FULL_EFI): $(FULL_ELF)
	$(call pe_image,$<,$@)

# ---- host unit tests ----
HOST_SRCS := $(KDIR)/core/fmt.c $(KDIR)/core/acpi.c $(KDIR)/core/smmu.c $(KDIR)/mm/frames.c \
	$(KDIR)/mm/pt.c $(KDIR)/mm/heap.c $(KDIR)/core/sched.c $(KDIR)/core/ipc.c
TESTS := test_fmt test_frames test_pt test_acpi test_heap test_smmu test_sched test_ipc test_artifact
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

# ---- host tool for the AIENOS_CK_NET gate (scripts/qemu_ck_net_test.sh) ----
udp-echo: $(OUT)/host/ck_udp_echo
$(OUT)/host/ck_udp_echo: $(KDIR)/tools/ck_udp_echo.c
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $<

# Artifact library host test and the in-tree C artifact tool (pack, sign with
# TEST keys, negative corpus, bundle, receipt check) used by the QEMU gate.
ART_HOST_SRCS := $(KDIR)/artifact/format.c $(KDIR)/artifact/admission.c $(KDIR)/artifact/receipt.c \
	$(NATIVE)/argus/sha256.c $(NATIVE)/sig/sha512.c $(NATIVE)/sig/ed25519.c $(NATIVE)/sig/ct.c
ART_HOST_INC := -I$(KDIR)/artifact -I$(NATIVE)/sig -I$(NATIVE)/argus
ART_HOST_DEPS := $(ART_HOST_SRCS) $(wildcard $(KDIR)/artifact/*.h) $(ART_HDRS)

$(OUT)/host/test_artifact: $(KDIR)/tests/test_artifact.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(ART_HOST_INC) -o $@ $< $(ART_HOST_SRCS)

$(OUT)/host-san/test_artifact: $(KDIR)/tests/test_artifact.c $(ART_HOST_DEPS) $(KDIR)/tests/ck_test.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(ART_HOST_INC) -o $@ $< $(ART_HOST_SRCS)

ART_TOOL := $(OUT)/host/ck_artifact_tool
$(ART_TOOL): $(KDIR)/tools/ck_artifact_tool.c $(ART_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror $(ART_HOST_INC) -o $@ $< $(ART_HOST_SRCS)
tool: $(ART_TOOL)

clean:
	rm -rf $(OUT)

FORCE:
.PHONY: all full test sanitize clean print-kcflags udp-echo tool FORCE
