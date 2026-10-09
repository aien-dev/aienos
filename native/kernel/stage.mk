# stage.mk -- Lane 18 boot stages (devices, security, Store) for the AIENOS
# C kernel. Included by native/kernel/Makefile, or run alone:
#   make -C native/kernel -f stage.mk stage-test       host tests (libc, pthreads)
#   make -C native/kernel -f stage.mk stage-sanitize   same under ASan + UBSan
#   make -C native/kernel -f stage.mk stage-free       freestanding compile + nm -u check
#   make -C native/kernel -f stage.mk disk-part-test   GPT parser + LBA translation host test
#        (dev/tests/disk_part_test.c), built normally (must PASS) and as the
#        TEST-ONLY translation-bypass mutant (must FAIL); stage-test and
#        stage-sanitize run it too
# Exports for the kernel image build:
#   STAGE_SRCS    every .c the stages need (own files + unmodified native/*)
#   STAGE_CFLAGS  include paths and defines; add to the kernel's freestanding CFLAGS
# No Python, no Rust, no outside libraries.

STAGE_DIR := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))
STAGE_NATIVE := $(STAGE_DIR)/..
# Per-tree default (inside this checkout, under the git-ignored /target/), so two
# clones never share object files. Override with STAGE_OUT=<dir> if needed.
STAGE_OUT ?= $(abspath $(STAGE_DIR)/../../target/stage)

# Own sources (image).
STAGE_OWN_SRCS := $(STAGE_DIR)/dev/pci.c $(STAGE_DIR)/dev/mmio_window.c $(STAGE_DIR)/dev/disk_part.c $(STAGE_DIR)/dev/nvme_bind.c $(STAGE_DIR)/dev/nvme_shutdown.c $(STAGE_DIR)/dev/virtio_net.c \
                  $(STAGE_DIR)/dev/net_bind.c $(STAGE_DIR)/dev/net_udp.c $(STAGE_DIR)/dev/xhci_fence.c \
                  $(STAGE_DIR)/dev/usb_hid.c $(STAGE_DIR)/dev/usb_kbd.c \
                  $(STAGE_DIR)/dev/devices.c $(STAGE_DIR)/svc/security.c $(STAGE_DIR)/svc/store_boot.c \
                  $(STAGE_DIR)/svc/artifact_store.c $(STAGE_DIR)/svc/store_crash.c
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
  $(STAGE_NATIVE)/net/aienos_virtio_pci.c $(STAGE_NATIVE)/net/aienos_virtio_net.c $(STAGE_NATIVE)/net/aienos_net.c
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
  ck_mb ck_acpi_find ck_time_us ck_udelay ck_commit ck_exception_level ck_conventional_memory_kb \
  ck_acpi_platform_devices ck_dma_confine_named ck_mmio_try_map ck_mmio_map_exclusive ck_mmio_unmap_exclusive ck_mmio_is_mapped \
  ck_cap_init ck_cap_insert ck_cap_lookup ck_cap_revoke \
  ck_entropy_fill ck_entropy_status ck_entropy_reason \
  ck_console_rx_ready ck_console_rx_poll ck_console_uart_name ck_console_uart_base

STAGE_FREE_OBJS := $(foreach s,$(STAGE_SRCS),$(STAGE_OUT)/free/$(subst /,_,$(subst $(STAGE_NATIVE)/,,$(s:.c=.o))))

define stage_free_rule
$(STAGE_OUT)/free/$(subst /,_,$(subst $(STAGE_NATIVE)/,,$(1:.c=.o))): $(1)
	@mkdir -p $$(@D)
	$$(STAGE_CC) $$(STAGE_FREE_FLAGS) $$(STAGE_CFLAGS) -c -o $$@ $$<
endef
$(foreach s,$(STAGE_SRCS),$(eval $(call stage_free_rule,$(s))))

$(STAGE_OUT)/stage_all.o: $(STAGE_FREE_OBJS)
	$(STAGE_LD) -r -o $@ $^

.PHONY: stage-free stage-test stage-sanitize stage-clean disk-part-test disk-part-sanitize
stage-free: $(STAGE_OUT)/stage_all.o
	@bad=$$($(STAGE_NM) -u $< | awk '{print $$2}' | grep -vxF $(foreach a,$(STAGE_ALLOWED_U),-e $(a)) || true); \
	if [ -n "$$bad" ]; then echo "CK_STAGE_FREE: FAIL undefined: $$bad"; exit 1; fi; \
	echo "undefined (ck.h services only): $$($(STAGE_NM) -u $< | awk '{print $$2}' | tr '\n' ' ')"; \
	echo "weak symbols defined here: $$($(STAGE_NM) $< | awk '$$2=="W"{print $$3}' | tr '\n' ' ')"; \
	echo "largest stack frames: $$(cat $(STAGE_OUT)/free/*.su | sort -t'	' -k2 -n -r | head -3 | awk -F'	' '{printf "%s=%s ", $$1, $$2}')"; \
	echo "CK_STAGE_FREE: PASS objects=$(words $(STAGE_FREE_OBJS))"

# ---- host tests ----------------------------------------------------------
STAGE_HOST_SRCS := $(STAGE_OWN_SRCS) $(STAGE_DIR)/core/ipc.c $(STAGE_NATIVE_SRCS) $(STAGE_NATIVE)/disk/disk_file.c \
  $(STAGE_DIR)/svc/tests/ck_host.c $(STAGE_DIR)/svc/tests/stage_test.c
STAGE_HOST_FLAGS := -std=gnu11 -O1 -g -Wall -Wextra -Werror -pthread -DCK_ART_STORE_WRITER -DCK_HOST_TEST
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

# ---- GPT parser / translation layer host test (dev/tests/disk_part_test.c) ----
# Linked with the same stage sources as stage_test (a whole Store boot runs on
# the partition view) plus the hosted GPT writer tools/gpt_write.c. The mutant
# is the same test built with -DCK_TEST_DISK_XLATE_BYPASS (translation layer
# adds no partition offset): it must FAIL, so the checks are shown to catch a
# bypass.
DISK_PART_TEST_SRCS := $(STAGE_OWN_SRCS) $(STAGE_DIR)/core/ipc.c $(STAGE_NATIVE_SRCS) $(STAGE_NATIVE)/disk/disk_file.c \
  $(STAGE_DIR)/svc/tests/ck_host.c $(STAGE_DIR)/tools/gpt_write.c $(STAGE_DIR)/dev/tests/disk_part_test.c
DISK_PART_TEST_DEPS := $(DISK_PART_TEST_SRCS) $(wildcard $(STAGE_DIR)/dev/*.h $(STAGE_DIR)/svc/*.h \
  $(STAGE_DIR)/include/*.h $(STAGE_DIR)/tools/*.h)
DISK_PART_INC := $(STAGE_INC) -I$(STAGE_DIR)/tools -I$(STAGE_DIR)/svc/tests

$(STAGE_OUT)/disk_part_test: $(DISK_PART_TEST_DEPS)
	@mkdir -p $(@D)
	$(STAGE_CC) $(STAGE_HOST_FLAGS) $(DISK_PART_INC) -o $@ $(DISK_PART_TEST_SRCS)
$(STAGE_OUT)/disk_part_test_mutant: $(DISK_PART_TEST_DEPS)
	@mkdir -p $(@D)
	$(STAGE_CC) $(STAGE_HOST_FLAGS) -DCK_TEST_DISK_XLATE_BYPASS=1 $(DISK_PART_INC) -o $@ $(DISK_PART_TEST_SRCS)
$(STAGE_OUT)/disk_part_test_san: $(DISK_PART_TEST_DEPS)
	@mkdir -p $(@D)
	$(STAGE_CC) $(STAGE_HOST_FLAGS) $(STAGE_SAN_FLAGS) $(DISK_PART_INC) -o $@ $(DISK_PART_TEST_SRCS)

disk-part-test: $(STAGE_OUT)/disk_part_test $(STAGE_OUT)/disk_part_test_mutant
	$(STAGE_OUT)/disk_part_test
	@if $(STAGE_OUT)/disk_part_test_mutant >$(STAGE_OUT)/disk_part_test_mutant.log 2>&1; then \
	  echo "CK_DISK_PART_MUTANT: FAIL (translation bypass mutant passed the host checks)"; exit 1; fi; \
	n=$$(grep -c "^  FAIL " $(STAGE_OUT)/disk_part_test_mutant.log || true); \
	if [ "$$n" -lt 1 ]; then echo "CK_DISK_PART_MUTANT: FAIL (mutant exited non-zero without a failing check: crash?)"; exit 1; fi; \
	echo "CK_DISK_PART_MUTANT: PASS (translation bypass mutant caught by $$n failing checks)"

disk-part-sanitize: $(STAGE_OUT)/disk_part_test_san
	ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1 $<

stage-test: disk-part-test
stage-sanitize: disk-part-sanitize
