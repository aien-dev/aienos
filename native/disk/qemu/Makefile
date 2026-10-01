# Bare-metal AArch64 payload: the C NVMe driver (../disk_nvme.c, ../disk.c)
# against QEMU's emulated NVMe on the virt machine. Run it with
# scripts/qemu_native_nvme_test.sh. QEMU is not hardware.
#
#   make            build out/nvme_payload.elf
#   STORE_OBJS=...  extra freestanding objects (e.g. native/store) to link in
#                   later; empty by default, nothing here depends on them.

CC ?= cc
LD ?= ld
NM ?= nm
OUT ?= out
STORE_OBJS ?=
PFLAGS = -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -nostdlib -fno-builtin \
	-fno-stack-protector -fno-tree-loop-distribute-patterns -mstrict-align \
	-mgeneral-regs-only -fno-pic -fno-pie -fno-asynchronous-unwind-tables

OBJS = $(OUT)/start.o $(OUT)/payload.o $(OUT)/disk.o $(OUT)/disk_nvme.o
ELF = $(OUT)/nvme_payload.elf

all: $(ELF)

$(OUT):
	mkdir -p $(OUT)

$(OUT)/start.o: start.S | $(OUT)
	$(CC) -c -o $@ $<
$(OUT)/payload.o: payload.c ../disk.h ../disk_nvme.h | $(OUT)
	$(CC) $(PFLAGS) -c -o $@ $<
$(OUT)/disk.o: ../disk.c ../disk.h | $(OUT)
	$(CC) $(PFLAGS) -c -o $@ $<
$(OUT)/disk_nvme.o: ../disk_nvme.c ../disk_nvme.h ../disk.h | $(OUT)
	$(CC) $(PFLAGS) -c -o $@ $<

$(ELF): $(OBJS) $(STORE_OBJS) payload.ld
	$(LD) -nostdlib -static -T payload.ld -o $@ $(OBJS) $(STORE_OBJS)
	@u=$$($(NM) -u $@); if [ -n "$$u" ]; then echo "payload has undefined symbols: $$u"; rm -f $@; exit 1; fi

clean:
	rm -rf $(OUT)

.PHONY: all clean
