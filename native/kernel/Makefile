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
#   make full CK_HARDWARE_STAGING=1 CK_OWNER_PUBKEYS=<file> CK_MACHINE_ID=<file>
#                        hardware staging image $(OUT)/full-hardware-staging/:
#                        no TEST Store keys/uuid/machine id (refused without
#                        both files; tools/ck_owner_gen.c checks them); its
#                        Store stage refuses (production key source is
#                        BLOCKED_OPERATOR). scripts/ck_owner_keys_check.sh
#   make full CK_TEST_XHCI_MUTATION=bm-left-on|no-revoke|grant-no-smmu|no-sweep
#                        TEST-ONLY image that breaks one xHCI DMA fence row on
#                        purpose: $(OUT)/full-test-xhci-<name>/ (only
#                        scripts/qemu_ck_keyboard_test.sh --mutation; refused
#                        with CK_HARDWARE_STAGING=1 or CK_QEMU_UNSAFE_DMA=1)
#   make full CK_TEST_STORE_CRASH=1 [CK_TEST_STORE_CRASH_MUTANT=<name>]
#                        TEST-ONLY Store crash hook image
#                        $(OUT)/full-test-store-crash[-mutant-<name>]/ for
#                        scripts/qemu_ck_store_crash_test.sh (M4_STORE_CRASH);
#                        refused with CK_HARDWARE_STAGING / CK_QEMU_UNSAFE_DMA
#   make owner-gen       host tool $(OUT)/host/ck_owner_gen
#   make [full] CK_TEST_FWCFG_ARTIFACTS=1
#                        TEST-ONLY: loader takes candidates from the QEMU fw_cfg
#                        side channel instead of the boot disk Store; own OUT
#                        (target/native-kernel-test-fwcfg); announces itself and
#                        never counts toward a PASS. Default images are checked
#                        to contain no fw_cfg artifact code.
#   make CK_TEST_SMP_SKIP_CPU=1
#                        TEST-ONLY SMP mutation: CPU_ON skipped for one secondary
#                        core (core/smp.c); own OUT (target/native-kernel-test-smp-skip);
#                        the SMP gate must FAIL on it (scripts/qemu_ck_smp_test.sh
#                        --mutation); refused with CK_HARDWARE_STAGING
#   make store-image     host tool $(OUT)/host/ck_store_image: signed artifacts
#                        into the sealed Store inside the AIENOS GPT partition
#                        of an NVMe disk image
#   make gpt-image       host tool $(OUT)/host/ck_gpt_image: GPT boot-disk images
#                        (AIENOS partition between two sentinels, hostile variants)
#                        for the QEMU gates; "find" runs the kernel GPT parser
#   make full CK_TEST_DISK_XLATE_BYPASS=1
#                        TEST-ONLY mutation image for the DISK_LAYOUT gate: the
#                        LBA translation layer (dev/disk_part.c) adds no partition
#                        offset; $(OUT)/full-test-xlate-bypass/ (refused with
#                        CK_HARDWARE_STAGING; never counted toward a PASS)
#   make test            host unit tests            -> CK_CORE_HOST: PASS
#                        (also builds the handoff_check reserved0 mutant
#                        and requires test_handoff to FAIL against it)
#   make sanitize        same under ASan + UBSan    -> CK_CORE_HOST: PASS
#   make continuity-mutants
#                        TEST-only -D mutants of svc/continuity_codec.c must
#                        each fail test_continuity_codec -> CK_CONTINUITY_CODEC_MUTANTS: PASS
#   make continuity-resolve-mutants
#                        TEST-only -D mutants of svc/continuity_resolve.c must each fail
#                        test_continuity_resolve -> CK_CONTINUITY_RESOLVE_MUTANTS: PASS
#   make continuity-commit-mutants
#                        TEST-only -D mutants of svc/continuity_commit.c (and MC-11 of the codec) must
#                        each fail test_continuity_commit -> CK_CONTINUITY_COMMIT_MUTANTS: PASS
#   make continuity-recovery-mutants
#                        TEST-only -D mutants of svc/continuity_recovery.c (MR-1, MR-5, MR-6, MR-7, MR-9) must
#                        each fail test_continuity_recovery -> CK_CONTINUITY_RECOVERY_MUTANTS: PASS
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

# TEST-ONLY artifact source: CK_TEST_FWCFG_ARTIFACTS=1 compiles the QEMU fw_cfg
# side channel (opt/aienos/artifacts) into the loader instead of the boot disk
# Store. Every image built without it is checked to contain no fw_cfg artifact
# code. Such an image announces itself on the console and never counts toward
# a PASS. Its default OUT is separate so it never replaces a default image.
CK_TEST_FWCFG_ARTIFACTS ?=
ifneq ($(strip $(CK_TEST_FWCFG_ARTIFACTS)),)
ifneq ($(strip $(CK_TEST_FWCFG_ARTIFACTS)),1)
$(error CK_TEST_FWCFG_ARTIFACTS must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_FWCFG_ARTIFACTS (QEMU fw_cfg test source) cannot be combined with CK_HARDWARE_STAGING)
endif
OUT ?= $(REPO)/target/native-kernel-test-fwcfg
endif

# TEST-ONLY SMP mutation: CK_TEST_SMP_SKIP_CPU=1 builds a kernel that never
# calls PSCI CPU_ON for one secondary core (core/smp.c) but still waits for
# it, so the SMP gate must FAIL on it (scripts/qemu_ck_smp_test.sh
# --mutation). Own OUT; announces itself; refused with CK_HARDWARE_STAGING
# and with the fw_cfg test source. Default images are checked to carry no
# trace of it (smp_check).
CK_TEST_SMP_SKIP_CPU ?=
ifneq ($(strip $(CK_TEST_SMP_SKIP_CPU)),)
ifneq ($(strip $(CK_TEST_SMP_SKIP_CPU)),1)
$(error CK_TEST_SMP_SKIP_CPU must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_SMP_SKIP_CPU (TEST-only SMP mutation) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_TEST_FWCFG_ARTIFACTS)),)
$(error CK_TEST_SMP_SKIP_CPU cannot be combined with CK_TEST_FWCFG_ARTIFACTS)
endif
OUT ?= $(REPO)/target/native-kernel-test-smp-skip
SMP_TEST_FLAGS := -DCK_TEST_SMP_SKIP_CPU=1
else
SMP_TEST_FLAGS :=
endif
OUT ?= $(REPO)/target/native-kernel
AIENOS_COMMIT ?= $(shell git -C $(REPO) rev-parse HEAD 2>/dev/null || echo unknown)

CK_EXTRA_CFLAGS ?=
# Build-time DMA policy for the full image (see dev/nvme_bind.c):
# default SMMU-confined or refuse; 1 = TEST-ONLY QEMU unconfined bypass when
# no SMMU exists. Never with hardware staging.
CK_QEMU_UNSAFE_DMA ?=
CK_HARDWARE_STAGING ?=

# FP/SIMD probe (aienos#34 lane 0): CK_RUST_LIBS=<path to libaienos_fpu_probe.a>
# links that Rust no_std staticlib into the image and compiles core/fpu.c's
# probe (-DCK_FPU_PROBE=1). The C compile flags stay -mgeneral-regs-only; only
# the Rust unit uses FP/SIMD. Empty (default) = no Rust, no FP code. QEMU
# gate only: never combined with hardware staging.
CK_RUST_LIBS ?=
ifneq ($(strip $(CK_RUST_LIBS)),)
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_RUST_LIBS (FP probe, QEMU gate only) cannot be combined with CK_HARDWARE_STAGING)
endif
CK_EXTRA_CFLAGS += -DCK_FPU_PROBE=1
endif

# Inference ingest probe (aienos#34 lane 4): CK_INFER_LIB=<path to
# libaienos_infer_kernel.a> links that Rust no_std staticlib (aienos-infer +
# bump allocator) and compiles core/infer.c (-DCK_INFER_PROBE=1): the kernel
# ingests a GGUF from QEMU fw_cfg and calls the Rust unit. C flags stay
# -mgeneral-regs-only. QEMU gate only; not combinable with CK_RUST_LIBS (two
# Rust staticlibs would duplicate compiler_builtins) nor hardware staging.
CK_INFER_LIB ?=
ifneq ($(strip $(CK_INFER_LIB)),)
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_INFER_LIB (inference probe, QEMU gate only) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_RUST_LIBS)),)
$(error CK_INFER_LIB and CK_RUST_LIBS cannot be combined: two Rust staticlibs duplicate compiler_builtins)
endif
CK_EXTRA_CFLAGS += -DCK_INFER_PROBE=1
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_QEMU_UNSAFE_DMA (unconfined DMA, QEMU debug only) cannot be combined with CK_HARDWARE_STAGING: no SMMU confinement means no DMA)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),1)
$(error CK_QEMU_UNSAFE_DMA must be empty or 1)
endif
endif

# TEST-ONLY xHCI DMA fence mutations (dev/xhci_fence.h), for the self-test of
# scripts/qemu_ck_keyboard_test.sh --mutation only: each one breaks one
# keyboard DMA-safety row on purpose. Own FULL_NAME, never a hardware image.
CK_TEST_XHCI_MUTATION ?=
ifneq ($(strip $(CK_TEST_XHCI_MUTATION)),)
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_XHCI_MUTATION (TEST-ONLY xHCI DMA fence mutation) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
$(error CK_TEST_XHCI_MUTATION cannot be combined with CK_QEMU_UNSAFE_DMA)
endif
XHCI_MUT_NUM := $(if $(filter bm-left-on,$(CK_TEST_XHCI_MUTATION)),1,$(if $(filter no-revoke,$(CK_TEST_XHCI_MUTATION)),2,$(if $(filter grant-no-smmu,$(CK_TEST_XHCI_MUTATION)),3,$(if $(filter no-sweep,$(CK_TEST_XHCI_MUTATION)),4,))))
ifeq ($(XHCI_MUT_NUM),)
$(error CK_TEST_XHCI_MUTATION must be one of bm-left-on no-revoke grant-no-smmu no-sweep)
endif
endif

# TEST-ONLY Store crash hook (svc/store_crash.h; only
# scripts/qemu_ck_store_crash_test.sh sets it): the Store stage reads a crash
# plan from the scratch unit, runs on a volatile write cache and halts at the
# planned checkpoint. Own OUT subdirectory; announces itself; never counts
# toward a PASS of M4_STORE; refused with CK_HARDWARE_STAGING and
# CK_QEMU_UNSAFE_DMA. CK_TEST_STORE_CRASH_MUTANT (only with it) builds a
# deliberately broken Store the crash gate must catch:
#   skip_root_flush      no flush between the commit record and the root write
#   accept_bad_root_crc  superblock CRC never checked
CK_TEST_STORE_CRASH ?=
CK_TEST_STORE_CRASH_MUTANT ?=
ifneq ($(strip $(CK_TEST_STORE_CRASH)),)
ifneq ($(strip $(CK_TEST_STORE_CRASH)),1)
$(error CK_TEST_STORE_CRASH must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_STORE_CRASH (TEST-ONLY Store crash hook) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
$(error CK_TEST_STORE_CRASH (TEST-ONLY Store crash hook) cannot be combined with CK_QEMU_UNSAFE_DMA)
endif
endif
ifneq ($(strip $(CK_TEST_STORE_CRASH_MUTANT)),)
ifneq ($(strip $(CK_TEST_STORE_CRASH)),1)
$(error CK_TEST_STORE_CRASH_MUTANT needs CK_TEST_STORE_CRASH=1 (TEST-ONLY))
endif
ifeq ($(strip $(CK_TEST_STORE_CRASH_MUTANT)),skip_root_flush)
STORE_MUTANT_FLAGS := -DCK_TEST_STORE_MUTANT_SKIP_ROOT_FLUSH=1
else ifeq ($(strip $(CK_TEST_STORE_CRASH_MUTANT)),accept_bad_root_crc)
STORE_MUTANT_FLAGS := -DCK_TEST_STORE_MUTANT_ACCEPT_BAD_ROOT_CRC=1
else
$(error CK_TEST_STORE_CRASH_MUTANT must be skip_root_flush or accept_bad_root_crc)
endif
endif


# TEST-ONLY continuity / Recovery Core mode selection (svc/continuity_boot.h,
# contract K-7; only scripts/qemu_ck_continuity_test.sh and
# scripts/qemu_ck_recovery_test.sh set it): the Store stage reads a mode plan
# from the scratch unit and runs the continuity or Recovery Core wiring instead
# of the boot-record commit. Own OUT subdirectory; announces itself; refused
# with CK_HARDWARE_STAGING, CK_QEMU_UNSAFE_DMA and CK_TEST_STORE_CRASH.
# CK_TEST_CONTINUITY_MUTANT (only with it) builds a deliberately broken
# continuity layer the gates must catch:
#   resume_no_commit             resume does not commit the new incarnation
#   resume_provisions            resume mints an identity on an unprovisioned Store
#   degraded_is_unprovisioned    a degraded mount reads as unprovisioned (MR-5)
#   compare_16                   operator response compared on 16 of 32 bytes
#   bare_sha256                  operator response is a bare SHA-256, not an HMAC
CK_TEST_CONTINUITY ?=
CK_TEST_CONTINUITY_MUTANT ?=
ifneq ($(strip $(CK_TEST_CONTINUITY)),)
ifneq ($(strip $(CK_TEST_CONTINUITY)),1)
$(error CK_TEST_CONTINUITY must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_CONTINUITY (TEST-ONLY continuity mode selection) cannot be combined with CK_HARDWARE_STAGING)
endif
ifneq ($(strip $(CK_QEMU_UNSAFE_DMA)),)
$(error CK_TEST_CONTINUITY (TEST-ONLY continuity mode selection) cannot be combined with CK_QEMU_UNSAFE_DMA)
endif
ifneq ($(strip $(CK_TEST_STORE_CRASH)),)
$(error CK_TEST_CONTINUITY (TEST-ONLY continuity mode selection) cannot be combined with CK_TEST_STORE_CRASH)
endif
endif
ifneq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),)
ifneq ($(strip $(CK_TEST_CONTINUITY)),1)
$(error CK_TEST_CONTINUITY_MUTANT needs CK_TEST_CONTINUITY=1 (TEST-ONLY))
endif
ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),resume_no_commit)
CONT_MUTANT_FLAGS := -DCM_MUTANT_RESUME_NO_COMMIT=1
else ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),resume_provisions)
CONT_MUTANT_FLAGS := -DCM_MUTANT_RESUME_PROVISIONS=1
else ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),degraded_is_unprovisioned)
CONT_MUTANT_FLAGS := -DRC_MUTANT_DEGRADED_IS_UNPROVISIONED=1
else ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),compare_16)
CONT_MUTANT_FLAGS := -DCR_MUTANT_COMPARE_16=1
else ifeq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),bare_sha256)
CONT_MUTANT_FLAGS := -DCR_MUTANT_BARE_SHA256=1
else
$(error CK_TEST_CONTINUITY_MUTANT must be resume_no_commit, resume_provisions, degraded_is_unprovisioned, compare_16 or bare_sha256)
endif
endif

# Owner provisioning. The hardware staging image never embeds the TEST Store
# keys, the TEST store uuid or the TEST machine id: it needs owner PUBLIC
# material and the machine identity as files (format: tools/ck_owner_gen.c;
# relative paths are relative to native/kernel), checked and turned into a
# generated header that refuses every known TEST value. Nothing secret is
# read: the production Store key source stays BLOCKED_OPERATOR
# (svc/store_boot.c ck_store_production_keys, TRUST-1 key ceremony).
CK_OWNER_PUBKEYS ?=
CK_MACHINE_ID ?=
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
ifneq ($(strip $(CK_HARDWARE_STAGING)),1)
$(error CK_HARDWARE_STAGING must be empty or 1)
endif
ifeq ($(strip $(CK_OWNER_PUBKEYS)),)
$(error CK_HARDWARE_STAGING refuses the TEST Store keys and TEST machine id: give CK_OWNER_PUBKEYS=<owner public keys file> and CK_MACHINE_ID=<machine id file> (native/kernel/README.md, Owner provisioning))
endif
ifeq ($(strip $(CK_MACHINE_ID)),)
$(error CK_HARDWARE_STAGING refuses the TEST Store keys and TEST machine id: give CK_OWNER_PUBKEYS=<owner public keys file> and CK_MACHINE_ID=<machine id file> (native/kernel/README.md, Owner provisioning))
endif
OWNER_PUBKEYS_FILE := $(abspath $(CK_OWNER_PUBKEYS))
OWNER_MACHINE_FILE := $(abspath $(CK_MACHINE_ID))
ifeq ($(wildcard $(OWNER_PUBKEYS_FILE)),)
$(error CK_OWNER_PUBKEYS file not found: $(OWNER_PUBKEYS_FILE))
endif
ifeq ($(wildcard $(OWNER_MACHINE_FILE)),)
$(error CK_MACHINE_ID file not found: $(OWNER_MACHINE_FILE))
endif
else
ifneq ($(strip $(CK_OWNER_PUBKEYS)$(CK_MACHINE_ID)),)
$(error CK_OWNER_PUBKEYS and CK_MACHINE_ID are only used with CK_HARDWARE_STAGING=1 (the default QEMU build keeps the labelled TEST keys))
endif
endif

# TEST-ONLY DISK_LAYOUT mutation (dev/disk_part.h): the partition translation
# layer is bypassed. Its own FULL_NAME; never with hardware staging.
CK_TEST_DISK_XLATE_BYPASS ?=
ifneq ($(strip $(CK_TEST_DISK_XLATE_BYPASS)),)
ifneq ($(strip $(CK_TEST_DISK_XLATE_BYPASS)),1)
$(error CK_TEST_DISK_XLATE_BYPASS must be empty or 1)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
$(error CK_TEST_DISK_XLATE_BYPASS (TEST-ONLY translation bypass mutation) cannot be combined with CK_HARDWARE_STAGING)
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
ifeq ($(strip $(CK_TEST_FWCFG_ARTIFACTS)),1)
ART_TRUST_FLAGS += -DCK_TEST_FWCFG_ARTIFACTS=1
endif

KINC := -I$(KDIR)/include -I$(KDIR)/core -I$(KDIR)/mm -I$(KDIR)/arch -I$(BOOT)
MODULE_INC := -I$(NATIVE)/disk -I$(NATIVE)/store -I$(NATIVE)/m5 -I$(NATIVE)/crypto \
	-I$(NATIVE)/capability -I$(NATIVE)/argus -I$(NATIVE)/net
KCFLAGS := -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdlib -fno-builtin \
	-fno-stack-protector -fno-tree-loop-distribute-patterns -mstrict-align \
	-mgeneral-regs-only -mno-outline-atomics -fno-asynchronous-unwind-tables -fpie \
	-fvisibility=hidden -fno-plt $(KINC) $(SMP_TEST_FLAGS) $(CK_EXTRA_CFLAGS)
KLDFLAGS := -nostdlib -pie --no-dynamic-linker -z norelro -z noexecstack -z max-page-size=4096 --no-warn-rwx-segments \
	-T $(BOOT)/image.ld

CORE_C := $(BOOT)/efi_main.c $(BOOT)/efi_model.c \
	$(KDIR)/arch/exception.c $(KDIR)/arch/gic.c $(KDIR)/arch/timer.c \
	$(KDIR)/core/acpi.c $(KDIR)/core/console.c $(KDIR)/core/fmt.c \
	$(KDIR)/core/kmain.c $(KDIR)/core/handoff_check.c $(KDIR)/core/libc_min.c $(KDIR)/core/report.c \
	$(KDIR)/core/smmu.c $(KDIR)/core/smmu_svc.c $(KDIR)/core/sched.c $(KDIR)/core/ipc.c \
	$(KDIR)/core/fpu.c $(KDIR)/core/infer.c $(KDIR)/core/m3.c $(KDIR)/core/entropy.c $(KDIR)/arch/rndr.c $(KDIR)/core/smp.c \
	$(KDIR)/mm/frames.c $(KDIR)/mm/heap.c $(KDIR)/mm/mmu.c $(KDIR)/mm/pt.c
# P2 sealed-artifact loader: format/admission/receipt (artifact/), SHA-256
# (argus), Ed25519/SHA-512 (sig). Built into the core so every image carries
# the loader; the TEST-anchor qualification build is CK_SEED0B_TEST_ANCHOR=1.
ART_C := $(KDIR)/core/artifact_loader.c $(KDIR)/artifact/format.c $(KDIR)/artifact/admission.c \
	$(KDIR)/artifact/receipt.c $(NATIVE)/argus/sha256.c $(NATIVE)/sig/sha512.c \
	$(NATIVE)/sig/ed25519.c $(NATIVE)/sig/ct.c
ART_INC := -I$(KDIR)/svc/compat -I$(KDIR)/artifact -I$(NATIVE)/sig -I$(NATIVE)/argus
CORE_C += $(ART_C)
CORE_S := $(BOOT)/efi_entry.S $(KDIR)/arch/vectors.S $(KDIR)/arch/m3.S $(KDIR)/arch/smp_entry.S
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
ifneq ($(strip $(CK_TEST_XHCI_MUTATION)),)
FULL_NAME := full-test-xhci-$(strip $(CK_TEST_XHCI_MUTATION))
STAGE_DMA_FLAGS += -DCK_TEST_XHCI_MUTATION=$(XHCI_MUT_NUM)
endif
ifneq ($(strip $(CK_HARDWARE_STAGING)),)
# Own OUT subdirectory: stage objects built with these flags never mix with
# the default full image's objects.
FULL_NAME := full-hardware-staging
OWNER_HDR := $(OUT)/gen-$(FULL_NAME)/ck_owner_prov.h
STAGE_DMA_FLAGS += -DCK_HARDWARE_STAGING=1 -I$(dir $(OWNER_HDR))
else
OWNER_HDR :=
endif
ifeq ($(strip $(CK_TEST_STORE_CRASH)),1)
# Own OUT subdirectory: TEST hook objects never mix with a default image.
ifneq ($(strip $(CK_TEST_STORE_CRASH_MUTANT)),)
FULL_NAME := full-test-store-crash-mutant-$(strip $(CK_TEST_STORE_CRASH_MUTANT))
else
FULL_NAME := full-test-store-crash
endif
STAGE_DMA_FLAGS += -DCK_TEST_STORE_CRASH=1 $(STORE_MUTANT_FLAGS)
endif
ifeq ($(strip $(CK_TEST_CONTINUITY)),1)
# Own OUT subdirectory: TEST objects never mix with a default image. The
# continuity layer is linked only here (default images carry none of it).
ifneq ($(strip $(CK_TEST_CONTINUITY_MUTANT)),)
FULL_NAME := full-test-continuity-mutant-$(strip $(CK_TEST_CONTINUITY_MUTANT))
else
FULL_NAME := full-test-continuity
endif
STAGE_DMA_FLAGS += -DCK_TEST_CONTINUITY=1 $(CONT_MUTANT_FLAGS) -I$(KDIR)/core
STAGE_SRCS += $(KDIR)/svc/continuity_codec.c $(KDIR)/svc/continuity_resolve.c \
	$(KDIR)/svc/continuity_resolve_sealed.c $(KDIR)/svc/continuity_commit.c $(KDIR)/svc/continuity_recovery.c \
	$(KDIR)/svc/continuity_boot.c
endif
ifeq ($(strip $(CK_TEST_DISK_XLATE_BYPASS)),1)
FULL_NAME := $(FULL_NAME)-test-xlate-bypass
STAGE_DMA_FLAGS += -DCK_TEST_DISK_XLATE_BYPASS=1
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

# core/infer.c uses the in-core SHA-256 (argus) to prove the ingested bytes.
$(KOBJ)/kernel/core/infer.o: KCFLAGS += -I$(NATIVE)/argus

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
$(STAGE_KOBJ)/$(subst /,_,$(patsubst $(REPO)/%,%,$(abspath $(1)))).o: $(1) $(STAGE_HDRS) $(OWNER_HDR)
	@mkdir -p $$(dir $$@)
	$(KCC) $(STAGE_KCFLAGS) -c -o $$@ $(1)
endef
$(foreach s,$(STAGE_SRCS),$(eval $(call stage_rule,$(s))))

# fwcfg_check(elf): a default image (no CK_TEST_FWCFG_ARTIFACTS) must carry no
# fw_cfg artifact code or strings; a test image must carry its announcement.
# The inference probe image (CK_INFER_LIB, aienos#34 lane 4) reads its model over
# fw_cfg by design: it must carry its own TEST-ONLY announcement instead.
define fwcfg_check
	@if [ -n "$(strip $(CK_INFER_LIB))" ]; then \
	  grep -aqF "TEST-ONLY QEMU fw_cfg model ingest" $(1) || { echo "inference probe image lacks its TEST-ONLY fw_cfg announcement"; rm -f $(1); exit 1; }; \
	elif [ "$(strip $(CK_TEST_FWCFG_ARTIFACTS))" = 1 ]; then \
	  grep -aqF "TEST-ONLY QEMU fw_cfg side channel" $(1) || { echo "test fw_cfg image lacks its TEST-ONLY announcement"; rm -f $(1); exit 1; }; \
	else \
	  s=$$(grep -aoE "opt/aienos/artifacts|fw_cfg|QEMU0002" $(1) | sort -u | tr "\n" " "); \
	  y=$$($(KNM) $(1) | grep -E " (fw_select|fw_read|fw_skip|fw_find|fwcfg_from_dsdt|fwcfg_source|fwcfg)$$" | tr "\n" " "); \
	  if [ -n "$$s$$y" ]; then echo "default image carries fw_cfg artifact code: $$s$$y"; rm -f $(1); exit 1; fi; \
	  echo "no fw_cfg artifact code in $(1)"; \
	fi
endef

# xhci_mut_check(elf): only a CK_TEST_XHCI_MUTATION image may carry the
# TEST-ONLY xHCI mutation banner (and it must carry it).
define xhci_mut_check
	@if [ -n "$(strip $(CK_TEST_XHCI_MUTATION))" ]; then \
	  grep -aqF "TEST-ONLY xHCI MUTATION BUILD" $(1) || { echo "xHCI mutation image lacks its TEST-ONLY banner"; rm -f $(1); exit 1; }; \
	else \
	  if grep -aqF "TEST-ONLY xHCI MUTATION" $(1); then echo "default image carries the TEST-ONLY xHCI mutation"; rm -f $(1); exit 1; fi; \
	  echo "no xHCI mutation code in $(1)"; \
	fi
endef

# owner_check(elf): a hardware staging image must carry no TEST Store label,
# TEST store uuid, TEST Store print lines or TEST key symbols.
define owner_check
	@if [ "$(strip $(CK_HARDWARE_STAGING))" = 1 ]; then \
	  s=$$(grep -aoE "AIENOS-LANE18-TEST-KVOL-NOT-SECRET|AIEN-TEST-BOOT01|TEST identity, TEST keys|formatted TEST store|TEST machine id 0xA1" $(1) | sort -u | tr "\n" " "); \
	  y=$$($(KNM) $(1) | grep -E " (ck_store_test_keys|ck_store_test_uuid)$$" | tr "\n" " "); \
	  if [ -n "$$s$$y" ]; then echo "hardware staging image carries the TEST Store identity: $$s$$y"; rm -f $(1); exit 1; fi; \
	  echo "no TEST Store label, uuid or key code in $(1)"; \
	fi
endef

# smp_check(elf): only a CK_TEST_SMP_SKIP_CPU image may carry the SMP mutation
# announcement, and such an image must carry it.
define smp_check
	@if [ "$(strip $(CK_TEST_SMP_SKIP_CPU))" = 1 ]; then \
	  grep -aqF "TEST-ONLY SMP mutation" $(1) || { echo "SMP mutation image lacks its TEST-ONLY announcement"; rm -f $(1); exit 1; }; \
	else \
	  if grep -aqF "TEST-ONLY SMP mutation" $(1); then echo "default image carries the TEST-ONLY SMP mutation"; rm -f $(1); exit 1; fi; \
	fi
endef

# crash_check(elf): a full image built without CK_TEST_STORE_CRASH must carry
# no Store crash hook code or strings; a TEST crash image must announce itself.
define crash_check
	@if [ "$(strip $(CK_TEST_STORE_CRASH))" = 1 ]; then \
	  grep -aqF "TEST-ONLY Store crash hook image" $(1) || { echo "TEST crash image lacks its TEST-ONLY announcement"; rm -f $(1); exit 1; }; \
	else \
	  s=$$(grep -aoE "store_crash:|AIENCRSH|TEST-ONLY MUTANT" $(1) | sort -u | tr "\n" " "); \
	  y=$$($(KNM) $(1) | grep -E " ck_store_crash_[a-z_]+$$" | tr "\n" " "); \
	  if [ -n "$$s$$y" ]; then echo "default image carries the TEST Store crash hook: $$s$$y"; rm -f $(1); exit 1; fi; \
	  echo "no Store crash hook code in $(1)"; \
	fi
endef

# cont_check(elf): a full image built without CK_TEST_CONTINUITY must carry no
# continuity wiring code or strings; a TEST continuity image must announce itself.
define cont_check
	@if [ "$(strip $(CK_TEST_CONTINUITY))" = 1 ]; then \
	  grep -aqF "TEST-ONLY continuity mode selection image" $(1) || { echo "TEST continuity image lacks its TEST-ONLY announcement"; rm -f $(1); exit 1; }; \
	else \
	  s=$$(grep -aoE "AIENCONT|RECOVERY_OPERATOR_KEY|RECOVERY_CORE:|CONTINUITY: |TEST-ONLY MUTANT" $(1) | sort -u | tr "\n" " "); \
	  y=$$($(KNM) $(1) | grep -E " (ck_cont_boot_stage|cr_resume|cr_provision|rc_inspect)$$" | tr "\n" " "); \
	  if [ -n "$$s$$y" ]; then echo "default image carries the TEST continuity wiring: $$s$$y"; rm -f $(1); exit 1; fi; \
	  echo "no continuity wiring code in $(1)"; \
	fi
endef

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
	$(call link_image,$@,$(CORE_OBJS) $(CK_RUST_LIBS) $(CK_INFER_LIB))
	@s=$$($(KNM) $@ | grep -E ' [TtDdBbWwVv] ck_stage_(devices|security|store|quiesce)$$' || true); \
	if [ -n "$$s" ]; then echo "core image defines stage symbols: $$s"; rm -f $@; exit 1; fi
	$(call fwcfg_check,$@)
	$(call smp_check,$@)

$(FULL_ELF): $(CORE_OBJS) $(STAGE_BUILT) $(BOOT)/image.ld
	$(call link_image,$@,$(CORE_OBJS) $(STAGE_LINK) $(CK_RUST_LIBS) $(CK_INFER_LIB))
	@for s in ck_stage_devices ck_stage_security ck_stage_store ck_stage_quiesce ck_stage_disk_artifacts; do \
	  $(KNM) $@ | grep -qE " [TW] $$s$$" || { echo "full image lacks $$s"; rm -f $@; exit 1; }; done
	$(call fwcfg_check,$@)
	$(call owner_check,$@)
	$(call xhci_mut_check,$@)
	$(call smp_check,$@)
	$(call crash_check,$@)
	$(call cont_check,$@)

$(EFI): $(ELF)
	$(call pe_image,$<,$@)

$(FULL_EFI): $(FULL_ELF)
	$(call pe_image,$<,$@)

# ---- host unit tests ----
HOST_SRCS := $(KDIR)/core/fmt.c $(KDIR)/core/acpi.c $(KDIR)/core/smmu.c $(KDIR)/mm/frames.c \
	$(KDIR)/mm/pt.c $(KDIR)/mm/heap.c $(KDIR)/core/sched.c $(KDIR)/core/ipc.c $(KDIR)/core/entropy.c \
	$(KDIR)/core/handoff_check.c
TESTS := test_fmt test_frames test_pt test_acpi test_heap test_smmu test_sched test_ipc test_artifact test_entropy test_handoff \
	test_continuity_codec test_continuity_resolve test_continuity_commit test_continuity_recovery test_continuity_geometry
HCFLAGS := -std=gnu11 -O1 -g -Wall -Wextra -Werror -I$(KDIR)/core -I$(KDIR)/mm -I$(KDIR)/tests -I$(BOOT)
SANFLAGS := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

$(OUT)/host/%: $(KDIR)/tests/%.c $(HOST_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -o $@ $< $(HOST_SRCS)

$(OUT)/host-san/%: $(KDIR)/tests/%.c $(HOST_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) -o $@ $< $(HOST_SRCS)

# TEST-ONLY mutant of core/handoff_check.c (reserved0 check removed): the
# handoff test must FAIL against it, so "make test" fails if the test stops
# catching the mutation. Host only (handoff_check.c refuses it freestanding
# and with CK_HARDWARE_STAGING); never part of an image.
$(OUT)/host/test_handoff_mutant: $(KDIR)/tests/test_handoff.c $(HOST_SRCS) $(KDIR)/tests/ck_test.h $(HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) -DCK_HANDOFF_MUTANT_SKIP_RESERVED -o $@ $< $(HOST_SRCS)

handoff-mutant: $(OUT)/host/test_handoff_mutant
	@if $< > $<.log 2>&1; then cat $<.log; echo "test_handoff mutant (reserved0 check removed): PASSED, test does not catch it"; exit 1; \
	else grep -F "test_handoff: FAIL" $<.log && echo "test_handoff mutant (reserved0 check removed): FAILS as required"; fi

test: $(addprefix $(OUT)/host/,$(TESTS)) handoff-mutant
	@fail=0; for t in $(filter-out handoff-mutant,$^); do $$t || fail=1; done; \
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

# Continuity codec (C port cut 1, contract CONTINUITY_RECOVERY_CONTRACT.md,
# aienos#222): host test plus TEST-only -D mutants, each of which must make
# the test print its FAIL verdict. Mutant flags are refused under
# CK_HARDWARE_STAGING (svc/continuity_codec.h).
CC_HOST_SRCS := $(KDIR)/svc/continuity_codec.c $(NATIVE)/argus/sha256.c $(NATIVE)/store/store_v1.c
CC_HOST_INC := -I$(KDIR)/svc -I$(NATIVE)/argus -I$(NATIVE)/store
CC_HOST_DEPS := $(wildcard $(KDIR)/tests/fixtures/continuity_*.txt) $(CC_HOST_SRCS) $(KDIR)/svc/continuity_codec.h $(NATIVE)/argus/sha256.h \
	$(NATIVE)/store/store_v1.h $(KDIR)/tests/ck_test.h
# Cut 2 adds UNCHECKED_FORK_SUM (wrapping fork-count sum), MANIFEST_LAST_WAL_ZERO
# (only the golden vectors see it), SKIP_D1 and SKIP_D2 (test-side: the golden
# or the decode-agreement comparison is skipped; the test counts its
# comparisons, so skipping one is a FAIL).
CC_MUTANTS := CC_MUTANT_SKIP_TAKE_BOUND CC_MUTANT_ACCEPT_RESERVED CC_MUTANT_CHILD_INDEX_LE \
	CC_MUTANT_TRUNCATE_AT_CAP CC_MUTANT_UNCHECKED_FORK_SUM CC_MUTANT_MANIFEST_LAST_WAL_ZERO \
	CC_MUTANT_SKIP_D1 CC_MUTANT_SKIP_D2
# Rust-emitted fixtures (D-1, D-2) read by the test at run time.
CC_FIXTURES := $(abspath $(KDIR)/tests/fixtures)
CC_FIXTURE_DEF := -DCC_FIXTURE_DIR='"$(CC_FIXTURES)"'

$(OUT)/host/test_continuity_codec: $(KDIR)/tests/test_continuity_codec.c $(CC_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CC_HOST_INC) $(CC_FIXTURE_DEF) -o $@ $< $(CC_HOST_SRCS)

$(OUT)/host-san/test_continuity_codec: $(KDIR)/tests/test_continuity_codec.c $(CC_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CC_HOST_INC) $(CC_FIXTURE_DEF) -o $@ $< $(CC_HOST_SRCS)

continuity-mutants: $(OUT)/host/test_continuity_codec continuity-resolve-mutants continuity-commit-mutants continuity-recovery-mutants
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_continuity_codec > $(OUT)/host-mut/base.log 2>&1 || { echo "unmutated test_continuity_codec fails"; fail=1; }; \
	for m in $(CC_MUTANTS); do \
	  b=$(OUT)/host-mut/test_continuity_codec_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) $(CC_HOST_INC) $(CC_FIXTURE_DEF) -D$$m -o $$b $(KDIR)/tests/test_continuity_codec.c $(CC_HOST_SRCS); then \
	    echo "mutant $$m: does not build (FAIL)"; fail=1; continue; fi; \
	  if $$b > $$b.log 2>&1; then echo "mutant $$m: SURVIVED (FAIL)"; fail=1; \
	  elif grep -q "^test_continuity_codec: FAIL" $$b.log; then \
	    echo "mutant $$m: killed ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m: no FAIL verdict (crashed?) (FAIL)"; fail=1; fi; \
	done; \
	if $(HOSTCC) $(HCFLAGS) $(CC_HOST_INC) -DCK_HARDWARE_STAGING=1 -DCC_MUTANT_SKIP_TAKE_BOUND \
	    -fsyntax-only $(KDIR)/svc/continuity_codec.c 2>/dev/null; then \
	  echo "mutant flag accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	else echo "mutant flag refused under CK_HARDWARE_STAGING"; fi; \
	if [ $$fail = 0 ]; then echo "CK_CONTINUITY_CODEC_MUTANTS: PASS"; else echo "CK_CONTINUITY_CODEC_MUTANTS: FAIL"; exit 1; fi

# Continuity resolve + challenge/HMAC (C port cut 3): host test over the REAL
# sealed Store in a file (native/store + m5 + crypto + disk), TEST-only -D
# mutants, each of which must make the test print its FAIL verdict. Mutant flags
# are refused under CK_HARDWARE_STAGING (svc/continuity_resolve.h).
CR_STORE_SRCS := $(NATIVE)/store/store_v1.c $(NATIVE)/store/store_engine.c $(NATIVE)/store/store_disk.c \
	$(NATIVE)/store/store_sealed.c $(NATIVE)/store/torn_slot.c $(NATIVE)/disk/disk.c $(NATIVE)/disk/disk_file.c \
	$(NATIVE)/m5/m5_keys.c $(NATIVE)/m5/m5_envelope.c $(NATIVE)/m5/m5_state.c $(NATIVE)/crypto/aes.c \
	$(NATIVE)/crypto/polyval.c $(NATIVE)/crypto/gcm_siv.c $(NATIVE)/crypto/hmac.c $(NATIVE)/crypto/ct.c
CR_HOST_SRCS := $(KDIR)/svc/continuity_resolve.c $(KDIR)/svc/continuity_resolve_sealed.c \
	$(KDIR)/svc/continuity_codec.c $(NATIVE)/argus/sha256.c $(CR_STORE_SRCS)
CR_HOST_INC := -I$(KDIR)/svc -I$(NATIVE)/argus -I$(NATIVE)/store -I$(NATIVE)/disk -I$(NATIVE)/m5 -I$(NATIVE)/crypto
CR_HOST_DEPS := $(wildcard $(KDIR)/tests/fixtures/continuity_*.txt) $(CR_HOST_SRCS) $(wildcard $(KDIR)/svc/continuity_*.h) \
	$(wildcard $(NATIVE)/store/*.h $(NATIVE)/m5/*.h $(NATIVE)/disk/*.h $(NATIVE)/crypto/*.h) $(KDIR)/tests/ck_test.h
CR_FIXTURE_DEF := -DCR_FIXTURE_DIR='"$(CC_FIXTURES)"'
# MC-2 orphan check, MC-4 previous, MC-12 conflict, MR-2 digest, MR-3 action,
# MR-4 16-byte compare, MR-8 bare SHA-256 and no domain.
CR_MUTANTS := CR_MUTANT_NO_ORPHAN_CHECK CR_MUTANT_IGNORE_PREVIOUS CR_MUTANT_SKIP_CONFLICT \
	CR_MUTANT_CHALLENGE_NO_DIGEST CR_MUTANT_CHALLENGE_NO_ACTION CR_MUTANT_COMPARE_16 \
	CR_MUTANT_BARE_SHA256 CR_MUTANT_NO_DOMAIN

$(OUT)/host/test_continuity_resolve: $(KDIR)/tests/test_continuity_resolve.c $(CR_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CR_HOST_INC) $(CR_FIXTURE_DEF) -o $@ $< $(CR_HOST_SRCS)

$(OUT)/host-san/test_continuity_resolve: $(KDIR)/tests/test_continuity_resolve.c $(CR_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CR_HOST_INC) $(CR_FIXTURE_DEF) -o $@ $< $(CR_HOST_SRCS)

continuity-resolve-mutants: $(OUT)/host/test_continuity_resolve
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_continuity_resolve > $(OUT)/host-mut/resolve_base.log 2>&1 || { echo "unmutated test_continuity_resolve fails"; fail=1; }; \
	for m in $(CR_MUTANTS); do \
	  b=$(OUT)/host-mut/test_continuity_resolve_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) $(CR_HOST_INC) $(CR_FIXTURE_DEF) -D$$m -o $$b $(KDIR)/tests/test_continuity_resolve.c $(CR_HOST_SRCS); then \
	    echo "mutant $$m: does not build (FAIL)"; fail=1; continue; fi; \
	  if $$b > $$b.log 2>&1; then echo "mutant $$m: SURVIVED (FAIL)"; fail=1; \
	  elif grep -q "^test_continuity_resolve: FAIL" $$b.log; then \
	    echo "mutant $$m: killed ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m: no FAIL verdict (crashed?) (FAIL)"; fail=1; fi; \
	done; \
	for m in $(CR_MUTANTS); do \
	  if $(HOSTCC) $(HCFLAGS) $(CR_HOST_INC) -DCK_HARDWARE_STAGING=1 -D$$m \
	      -fsyntax-only $(KDIR)/svc/continuity_resolve.c 2>/dev/null; then \
	    echo "mutant flag $$m accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	  else echo "mutant flag $$m refused under CK_HARDWARE_STAGING"; fi; \
	done; \
	if [ $$fail = 0 ]; then echo "CK_CONTINUITY_RESOLVE_MUTANTS: PASS"; else echo "CK_CONTINUITY_RESOLVE_MUTANTS: FAIL"; exit 1; fi


# Continuity provision/commit/resume (C port cut 4): host test over the REAL sealed
# Store in a file with the real ck_rng over a mocked RNDR, power cuts at every
# checkpoint and block boundary, and TEST-only -D mutants, each of which must make
# the test print its FAIL verdict. Mutant flags are refused under
# CK_HARDWARE_STAGING (svc/continuity_commit.h; MC-11 in svc/continuity_codec.h).
CM_HOST_SRCS := $(KDIR)/svc/continuity_commit.c $(CR_HOST_SRCS) $(KDIR)/core/entropy.c
CM_HOST_INC := $(CR_HOST_INC) -I$(KDIR)/core
CM_HOST_DEPS := $(CM_HOST_SRCS) $(wildcard $(KDIR)/svc/continuity_*.h) $(KDIR)/core/entropy.h \
	$(wildcard $(NATIVE)/store/*.h $(NATIVE)/m5/*.h $(NATIVE)/disk/*.h $(NATIVE)/crypto/*.h) $(KDIR)/tests/ck_test.h
# MC-1 resume provisions, MC-3 resume skips the commit, MC-7 provision with a root,
# MC-8 split transaction, MC-9 writable check removed, MC-10 fixed agent id,
# MC-11 silent truncation (the codec's CC_MUTANT_TRUNCATE_AT_CAP).
CM_MUTANTS := CM_MUTANT_RESUME_PROVISIONS CM_MUTANT_RESUME_NO_COMMIT CM_MUTANT_PROVISION_WITH_ROOT \
	CM_MUTANT_SPLIT_TXN CM_MUTANT_NO_WRITABLE_CHECK CM_MUTANT_FIXED_AGENT CC_MUTANT_TRUNCATE_AT_CAP

$(OUT)/host/test_continuity_commit: $(KDIR)/tests/test_continuity_commit.c $(CM_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -o $@ $< $(CM_HOST_SRCS)

$(OUT)/host-san/test_continuity_commit: $(KDIR)/tests/test_continuity_commit.c $(CM_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CM_HOST_INC) -o $@ $< $(CM_HOST_SRCS)

continuity-commit-mutants: $(OUT)/host/test_continuity_commit
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_continuity_commit > $(OUT)/host-mut/commit_base.log 2>&1 || { echo "unmutated test_continuity_commit fails"; fail=1; }; \
	for m in $(CM_MUTANTS); do \
	  b=$(OUT)/host-mut/test_continuity_commit_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -D$$m -o $$b $(KDIR)/tests/test_continuity_commit.c $(CM_HOST_SRCS); then \
	    echo "mutant $$m: does not build (FAIL)"; fail=1; continue; fi; \
	  if $$b > $$b.log 2>&1; then echo "mutant $$m: SURVIVED (FAIL)"; fail=1; \
	  elif grep -q "^test_continuity_commit: FAIL" $$b.log; then \
	    echo "mutant $$m: killed ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m: no FAIL verdict (crashed?) (FAIL)"; fail=1; fi; \
	done; \
	for m in $(CM_MUTANTS); do \
	  if $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -DCK_HARDWARE_STAGING=1 -D$$m \
	      -fsyntax-only $(KDIR)/svc/continuity_commit.c 2>/dev/null; then \
	    echo "mutant flag $$m accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	  else echo "mutant flag $$m refused under CK_HARDWARE_STAGING"; fi; \
	done; \
	if [ $$fail = 0 ]; then echo "CK_CONTINUITY_COMMIT_MUTANTS: PASS"; else echo "CK_CONTINUITY_COMMIT_MUTANTS: FAIL"; exit 1; fi

# Continuity Recovery Core (C port cut 5): host test over the REAL sealed Store in a
# file, TEST-only -D mutants, each of which must make the test print its FAIL verdict.
# Mutant flags are refused under CK_HARDWARE_STAGING (svc/continuity_recovery.h).
RC_HOST_SRCS := $(KDIR)/svc/continuity_recovery.c $(CM_HOST_SRCS)
RC_HOST_DEPS := $(RC_HOST_SRCS) $(wildcard $(KDIR)/svc/continuity_*.h) $(KDIR)/core/entropy.h \
	$(wildcard $(NATIVE)/store/*.h $(NATIVE)/m5/*.h $(NATIVE)/disk/*.h $(NATIVE)/crypto/*.h) $(KDIR)/tests/ck_test.h
# MR-1 inspection writes, MR-5 degraded mount read as Unprovisioned, MR-6 repair zeroes the
# active slot, MR-7 repair without a resolved identity, MR-9 operator provisioning writes
# source Qualification. (MR-2, MR-3, MR-4, MR-8 are the cut 3 mutants.)
RC_MUTANTS := RC_MUTANT_INSPECT_WRITES RC_MUTANT_DEGRADED_IS_UNPROVISIONED RC_MUTANT_REPAIR_ACTIVE \
	RC_MUTANT_REPAIR_NO_IDENTITY RC_MUTANT_PROVISION_QUALIFICATION

$(OUT)/host/test_continuity_recovery: $(KDIR)/tests/test_continuity_recovery.c $(RC_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -o $@ $< $(RC_HOST_SRCS)

$(OUT)/host-san/test_continuity_recovery: $(KDIR)/tests/test_continuity_recovery.c $(RC_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CM_HOST_INC) -o $@ $< $(RC_HOST_SRCS)

# K-6 region geometry (cut 7): host test over the real sealed Store in a file; needs dev/disk_layout.h.
$(OUT)/host/test_continuity_geometry: $(KDIR)/tests/test_continuity_geometry.c $(RC_HOST_DEPS) $(KDIR)/dev/disk_layout.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -I$(KDIR)/dev -o $@ $< $(RC_HOST_SRCS)

$(OUT)/host-san/test_continuity_geometry: $(KDIR)/tests/test_continuity_geometry.c $(RC_HOST_DEPS) $(KDIR)/dev/disk_layout.h
	@mkdir -p $(dir $@)
	$(HOSTCC) $(HCFLAGS) $(SANFLAGS) $(CM_HOST_INC) -I$(KDIR)/dev -o $@ $< $(RC_HOST_SRCS)

continuity-recovery-mutants: $(OUT)/host/test_continuity_recovery
	@mkdir -p $(OUT)/host-mut; fail=0; \
	$(OUT)/host/test_continuity_recovery > $(OUT)/host-mut/recovery_base.log 2>&1 || { echo "unmutated test_continuity_recovery fails"; fail=1; }; \
	for m in $(RC_MUTANTS); do \
	  b=$(OUT)/host-mut/test_continuity_recovery_$$m; \
	  if ! $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -D$$m -o $$b $(KDIR)/tests/test_continuity_recovery.c $(RC_HOST_SRCS); then \
	    echo "mutant $$m: does not build (FAIL)"; fail=1; continue; fi; \
	  if $$b > $$b.log 2>&1; then echo "mutant $$m: SURVIVED (FAIL)"; fail=1; \
	  elif grep -q "^test_continuity_recovery: FAIL" $$b.log; then \
	    echo "mutant $$m: killed ($$(grep -c '^  FAIL ' $$b.log) checks failed)"; \
	  else echo "mutant $$m: no FAIL verdict (crashed?) (FAIL)"; fail=1; fi; \
	done; \
	for m in $(RC_MUTANTS); do \
	  if $(HOSTCC) $(HCFLAGS) $(CM_HOST_INC) -DCK_HARDWARE_STAGING=1 -D$$m \
	      -fsyntax-only $(KDIR)/svc/continuity_recovery.c 2>/dev/null; then \
	    echo "mutant flag $$m accepted under CK_HARDWARE_STAGING (FAIL)"; fail=1; \
	  else echo "mutant flag $$m refused under CK_HARDWARE_STAGING"; fi; \
	done; \
	if [ $$fail = 0 ]; then echo "CK_CONTINUITY_RECOVERY_MUTANTS: PASS"; else echo "CK_CONTINUITY_RECOVERY_MUTANTS: FAIL"; exit 1; fi

ART_TOOL := $(OUT)/host/ck_artifact_tool
$(ART_TOOL): $(KDIR)/tools/ck_artifact_tool.c $(ART_HOST_DEPS)
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror $(ART_HOST_INC) -o $@ $< $(ART_HOST_SRCS)
tool: $(ART_TOOL)

# Boot-disk image tool (scripts/qemu_ck_artifact_test.sh): writes signed artifacts
# into the sealed Store on a raw NVMe image with the kernel's own Store code
# (store_boot.c, artifact_store.c). Hosted; never part of an image.
STORE_IMG_TOOL := $(OUT)/host/ck_store_image
STORE_IMG_SRCS := $(STAGE_OWN_SRCS) $(STAGE_NATIVE_SRCS) $(NATIVE)/disk/disk_file.c \
	$(KDIR)/svc/tests/ck_host.c $(KDIR)/tools/ck_store_image.c
$(STORE_IMG_TOOL): $(STORE_IMG_SRCS) $(STAGE_HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(STAGE_HOST_FLAGS) $(STAGE_INC) -o $@ $(STORE_IMG_SRCS)
store-image: $(STORE_IMG_TOOL)

# Continuity / Recovery Core QEMU gate tool (scripts/qemu_ck_continuity_test.sh,
# scripts/qemu_ck_recovery_test.sh): operator response, degraded-peer injection,
# AgentRoot corruption on a boot-disk image. Hosted; never part of an image.
CONT_TOOL := $(OUT)/host/ck_cont_tool
CONT_TOOL_SRCS := $(STAGE_OWN_SRCS) $(STAGE_NATIVE_SRCS) $(NATIVE)/disk/disk_file.c \
	$(KDIR)/svc/tests/ck_host.c $(KDIR)/svc/continuity_resolve.c $(KDIR)/svc/continuity_codec.c \
	$(KDIR)/tools/ck_cont_tool.c
$(CONT_TOOL): $(CONT_TOOL_SRCS) $(STAGE_HDRS)
	@mkdir -p $(dir $@)
	$(HOSTCC) $(STAGE_HOST_FLAGS) $(STAGE_INC) -o $@ $(CONT_TOOL_SRCS)
cont-tool: $(CONT_TOOL)

# GPT boot-disk image tool (QEMU gates; hosted, never part of an image).
GPT_IMG_TOOL := $(OUT)/host/ck_gpt_image
GPT_IMG_SRCS := $(KDIR)/dev/disk_part.c $(NATIVE)/disk/disk.c $(NATIVE)/disk/disk_file.c \
	$(KDIR)/tools/gpt_write.c $(KDIR)/tools/ck_gpt_image.c
$(GPT_IMG_TOOL): $(GPT_IMG_SRCS) $(KDIR)/dev/disk_part.h $(KDIR)/tools/gpt_write.h $(NATIVE)/disk/disk.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -I$(KDIR)/dev -I$(KDIR)/tools -I$(NATIVE)/disk -o $@ $(GPT_IMG_SRCS)
gpt-image: $(GPT_IMG_TOOL)

# MODEL.MAP tool (model ingest gate + the attended-boot staging; hosted, never
# part of an image). SHA-256 is the kernel's own (argus).
MODEL_MAP_TOOL := $(OUT)/host/ck_model_map
$(MODEL_MAP_TOOL): $(KDIR)/tools/ck_model_map.c $(NATIVE)/argus/sha256.c $(BOOT)/model_map.h $(NATIVE)/argus/sha256.h
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -I$(BOOT) -I$(NATIVE)/argus -o $@ $(KDIR)/tools/ck_model_map.c $(NATIVE)/argus/sha256.c
model-map: $(MODEL_MAP_TOOL)

# Owner provisioning generator (hosted; never part of an image) and the
# generated header for the hardware staging image.
OWNER_GEN := $(OUT)/host/ck_owner_gen
$(OWNER_GEN): $(KDIR)/tools/ck_owner_gen.c
	@mkdir -p $(dir $@)
	$(HOSTCC) -std=gnu11 -O2 -Wall -Wextra -Werror -o $@ $<
owner-gen: $(OWNER_GEN)
ifneq ($(OWNER_HDR),)
$(OWNER_HDR): $(OWNER_GEN) $(OWNER_PUBKEYS_FILE) $(OWNER_MACHINE_FILE)
	@mkdir -p $(dir $@)
	$(OWNER_GEN) $(OWNER_PUBKEYS_FILE) $(OWNER_MACHINE_FILE) $@
endif

clean:
	rm -rf $(OUT)

FORCE:
.PHONY: all full test sanitize handoff-mutant clean print-kcflags udp-echo tool store-image gpt-image cont-tool owner-gen continuity-mutants continuity-resolve-mutants FORCE
