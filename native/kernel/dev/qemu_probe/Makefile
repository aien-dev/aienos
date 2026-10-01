# PROBE, not a gate: the Lane 18 stages on QEMU virt with a throwaway ck.h
# (ck_probe.c) until the real core exists. QEMU is an emulator.
#   make -C native/kernel/dev/qemu_probe        build the ELF
#   native/kernel/dev/qemu_probe/run.sh         three boots on one NVMe image
STAGE_OUT := $(or $(PROBE_OUT),/tmp/aienos-ck-probe-$(shell id -u))
include ../../stage.mk
PROBE_OUT ?= $(STAGE_OUT)
PROBE_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# MMU off: every access is Device memory, so no unaligned accesses.
STAGE_FREE_FLAGS += -mstrict-align -fno-asynchronous-unwind-tables
ELF := $(PROBE_OUT)/ck_probe.elf

$(PROBE_OUT)/start.o: start.S
	@mkdir -p $(@D)
	$(STAGE_CC) -c -o $@ $<
$(PROBE_OUT)/ck_probe.o: ck_probe.c ../../include/ck.h
	@mkdir -p $(@D)
	$(STAGE_CC) $(STAGE_FREE_FLAGS) -DPROBE_COMMIT='"$(PROBE_COMMIT)"' -I../../include -c -o $@ $<

$(ELF): $(PROBE_OUT)/start.o $(PROBE_OUT)/ck_probe.o $(STAGE_FREE_OBJS) probe.ld
	$(STAGE_LD) -nostdlib -static -T probe.ld -o $@ $(PROBE_OUT)/start.o $(PROBE_OUT)/ck_probe.o $(STAGE_FREE_OBJS)
	@u=$$($(STAGE_NM) -u $@); if [ -n "$$u" ]; then echo "probe has undefined symbols: $$u"; rm -f $@; exit 1; fi

.DEFAULT_GOAL := probe
.PHONY: probe
probe: $(ELF)
