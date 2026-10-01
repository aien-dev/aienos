# stage.mk -- Lane 18 boot stages (devices, security, Store) for the AIENOS
# C kernel. Included by native/kernel/Makefile, or run alone:
#   make -C native/kernel -f stage.mk stage-test       host tests (libc, pthreads)
#   make -C native/kernel -f stage.mk stage-sanitize   same under ASan + UBSan
#   make -C native/kernel -f stage.mk stage-free       freestanding compile + nm -u check
# Exports for the kernel image build:
#   STAGE_SRCS    every .c the stages need (own files + unmodified native/*)
#   STAGE_CFLAGS  include paths and defines; add to the kernel's freestanding CFLAGS
# No Python, no Rust, no outside libraries.

STAGE_DIR := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
STAGE_NATIVE := $(STAGE_DIR)/..
STAGE_OUT ?= /tmp/aienos-ck-stage-$(shell id -u)

# Own sources (image).
STAGE_OWN_SRCS := $(STAGE_DIR)/dev/pci.c $(STAGE_DIR)/dev/nvme_bind.c $(STAGE_DIR)/dev/nvme_shutdown.c $(STAGE_DIR)/dev/virtio_net.c \
                  $(STAGE_DIR)/dev/devices.c $(STAGE_DIR)/svc/security.c $(STAGE_DIR)/svc/store_boot.c
# Native modules, compiled unmodified.
STAGE_NATIVE_SRCS := \
  $(STAGE_NATIVE)/disk/disk.c $(STAGE_NATIVE)/disk/disk_nvme.c \
  $(STAGE_NATIVE)/store/store_v1.c $(STAGE_NATIVE)/store/store_engine.c $(STAGE_NATIVE)/store/store_disk.c \
  $(STAGE_NATIVE)/store/store_sealed.c $(STAGE_NATIVE)/store/torn_slot.c \
  $(STAGE_NATIVE)/m5/m5_keys.c $(STAGE_NATIVE)/m5/m5_envelope.c $(STAGE_NATIVE)/m5/m5_state.c \
  $(STAGE_NATIVE)/crypto/aes.c $(STAGE_NATIVE)/crypto/polyval.c $(STAGE_NATIVE)/crypto/gcm_siv.c \
  $(STAGE_NATIVE)/crypto/hmac.c $(STAGE_NATIVE)/crypto/ct.c \
  $(STAGE_NATIVE)/argus/sha256.c $(STAGE_NATIVE)/argus/argus_event.c $(STAGE_NATIVE)/argus/argus_core.c \
  $(STAGE_NATIVE)/argus/argus_detect.c $(STAGE_NATIVE)/argus/argus_contain.c \
  $(STAGE_NATIVE)/argus/bridge/argus_aegis_bridge.c \
  $(STAGE_NATIVE)/capability/aienos_capability.c $(STAGE_NATIVE)/capability/aienos_contain.c \
  $(STAGE_NATIVE)/net/aienos_virtio_pci.c
# Kernel-only glue: hosted-header stand-ins for capability/ARGUS + weak mem*.
STAGE_KERNEL_SRCS := $(STAGE_DIR)/svc/ck_compat.c

STAGE_SRCS := $(STAGE_OWN_SRCS) $(STAGE_NATIVE_SRCS) $(STAGE_KERNEL_SRCS)

STAGE_INC := -I$(STAGE_DIR)/include -I$(STAGE_DIR)/dev -I$(STAGE_DIR)/svc \
             -I$(STAGE_NATIVE)/disk -I$(STAGE_NATIVE)/store -I$(STAGE_NATIVE)/m5 -I$(STAGE_NATIVE)/crypto \
             -I$(STAGE_NATIVE)/argus -I$(STAGE_NATIVE)/capability -I$(STAGE_NATIVE)/net
# compat first: <pthread.h> <stdlib.h> <stdio.h> <time.h> resolve to the stand-ins.
# NVMe DMA: SMMU-confined (ck_dma_confine) or refused. The kernel Makefile
# adds -DCK_QEMU_UNSAFE_DMA=1 only for "make full CK_QEMU_UNSAFE_DMA=1" (TEST-ONLY,
# one boot of the QEMU store gate); dev/nvme_bind.c refuses it together with CK_HARDWARE_STAGING.
STAGE_CFLAGS := -I$(STAGE_DIR)/svc/compat $(STAGE_INC)

# ---- freestanding check --------------------------------------------------
STAGE_CC ?= cc
STAGE_LD ?= ld
STAGE_NM ?= nm
STAGE_FREE_FLAGS := -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdlib -fno-builtin \
  -fno-stack-protector -fno-tree-loop-distribute-patterns -mgeneral-regs-only -mno-outline-atomics \
  -fno-pic -fno-pie -fstack-usage -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
# The only undefined symbols the stages may leave for the core: ck.h services.
STAGE_ALLOWED_U := ck_puts ck_printf ck_vprintf ck_panic ck_alloc ck_free ck_dma_alloc ck_mmio_map \
  ck_dma_confine ck_dma_unconfine ck_dma_faults \
  ck_mb ck_acpi_find ck_time_us ck_udelay ck_commit

STAGE_FREE_OBJS := $(foreach s,$(STAGE_SRCS),$(STAGE_OUT)/free/$(subst /,_,$(subst $(STAGE_NATIVE)/,,$(s:.c=.o))))

define stage_free_rule
$(STAGE_OUT)/free/$(subst /,_,$(subst $(STAGE_NATIVE)/,,$(1:.c=.o))): $(1)
	@mkdir -p $$(@D)
	$$(STAGE_CC) $$(STAGE_FREE_FLAGS) $$(STAGE_CFLAGS) -c -o $$@ $$<
endef
$(foreach s,$(STAGE_SRCS),$(eval $(call stage_free_rule,$(s))))

$(STAGE_OUT)/stage_all.o: $(STAGE_FREE_OBJS)
	$(STAGE_LD) -r -o $@ $^

.PHONY: stage-free stage-test stage-sanitize stage-clean
stage-free: $(STAGE_OUT)/stage_all.o
	@bad=$$($(STAGE_NM) -u $< | awk '{print $$2}' | grep -vxF $(foreach a,$(STAGE_ALLOWED_U),-e $(a)) || true); \
	if [ -n "$$bad" ]; then echo "CK_STAGE_FREE: FAIL undefined: $$bad"; exit 1; fi; \
	echo "undefined (ck.h services only): $$($(STAGE_NM) -u $< | awk '{print $$2}' | tr '\n' ' ')"; \
	echo "weak symbols defined here: $$($(STAGE_NM) $< | awk '$$2=="W"{print $$3}' | tr '\n' ' ')"; \
	echo "largest stack frames: $$(cat $(STAGE_OUT)/free/*.su | sort -t'	' -k2 -n -r | head -3 | awk -F'	' '{printf "%s=%s ", $$1, $$2}')"; \
	echo "CK_STAGE_FREE: PASS objects=$(words $(STAGE_FREE_OBJS))"

# ---- host tests ----------------------------------------------------------
STAGE_HOST_SRCS := $(STAGE_OWN_SRCS) $(STAGE_NATIVE_SRCS) $(STAGE_NATIVE)/disk/disk_file.c \
  $(STAGE_DIR)/svc/tests/ck_host.c $(STAGE_DIR)/svc/tests/stage_test.c
STAGE_HOST_FLAGS := -std=gnu11 -O1 -g -Wall -Wextra -Werror -pthread
STAGE_SAN_FLAGS := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

$(STAGE_OUT)/stage_test: $(STAGE_HOST_SRCS) $(wildcard $(STAGE_DIR)/dev/*.h $(STAGE_DIR)/svc/*.h $(STAGE_DIR)/include/*.h)
	@mkdir -p $(@D)
	$(STAGE_CC) $(STAGE_HOST_FLAGS) $(STAGE_INC) -o $@ $(STAGE_HOST_SRCS)

$(STAGE_OUT)/stage_test_san: $(STAGE_HOST_SRCS) $(wildcard $(STAGE_DIR)/dev/*.h $(STAGE_DIR)/svc/*.h $(STAGE_DIR)/include/*.h)
	@mkdir -p $(@D)
	$(STAGE_CC) $(STAGE_HOST_FLAGS) $(STAGE_SAN_FLAGS) $(STAGE_INC) -o $@ $(STAGE_HOST_SRCS)

stage-test: $(STAGE_OUT)/stage_test
	$<

stage-sanitize: $(STAGE_OUT)/stage_test_san
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 $<

stage-clean:
	rm -rf $(STAGE_OUT)
