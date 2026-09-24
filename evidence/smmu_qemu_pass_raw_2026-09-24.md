# Raw evidence: SMMUv3 xHCI DMA confinement PASS in QEMU

Commit under test: c2cf564 (fix/m3-smmuv3-ste-cd-layout)
Environment: spark-b87b, QEMU 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18),
rustc 1.98.1 (48a229cea 2026-09-01).

## Exact successful invocations

    # standard acceptance run
    AIENOS_QEMU_TIMEOUT=90 bash scripts/qemu_smmu_test.sh

    # verbose capture (serial console + QEMU smmuv3 trace)
    AIENOS_QEMU_VERBOSE=1 AIENOS_QEMU_SMMU_TRACE=1 AIENOS_QEMU_TIMEOUT=90 \
        bash scripts/qemu_smmu_test.sh

Both exited 0 and ended with "QEMU_KEYBOARD: PASS".

## Full raw logs (sha256, on the run host)

    075457e5f33f55d99f66ba0d4a6ddec8c20f17801a37fa54ebb088886938552e  smmu_verbose.log  (1633 lines)
    cd3102654313d43e87ee379132f7811f9e5551be26213ac1262d59e133ea1c5c  smmu_pass.log     (23 lines)

## QEMU smmuv3 trace: command queue, STE, CD, config decode

    smmuv3_cmdq_opcode <--- SMMU_CMD_CFGI_STE
    smmuv3_cmdq_cfgi_ste streamid= 0x10
    smmuv3_config_cache_inv Config cache INV for sid=0x10
    smmuv3_cmdq_opcode <--- SMMU_CMD_TLBI_NSNH_ALL
    smmuv3_cmdq_tlbi_nh
    smmuv3_cmdq_opcode <--- SMMU_CMD_SYNC
    smmuv3_config_cache_miss Config cache MISS for sid=0x10 (hits=0, misses=1, hit rate=0)
    smmuv3_find_ste sid=0x10 features:0x0, sid_split:0x0
    smmuv3_get_ste STE addr: 0xbbf40400
    smmuv3_get_cd CD addr: 0xbbf80300
    smmuv3_decode_cd oas=44
    smmuv3_decode_cd_tt TT[0]:tsz:16 ttb:0xbc32f000 granule_sz:12 had:0

## QEMU smmuv3 trace: event counts

    583 smmuv3_translate_success
    582 smmuv3_config_cache_hit
    192 smmuv3_translate_disable   (pre-enable bypass)
      1 smmuv3_get_ste
      1 smmuv3_get_cd
      1 smmuv3_decode_cd
      1 smmuv3_config_cache_miss
      1 smmuv3_config_cache_inv
      1 smmuv3_cmdq_cfgi_ste
      1 smmuv3_cmdq_tlbi_nh
      0 smmuv3_record_event
      0 fault events

## AIENOS serial console (raw lines)

    kernel_el: EL1h
    mmu: enabled
    smmu: enabled base=0x9050000 stream_id=0x10
    smmu_dma_window: xhci only, translation active
    keyboard: xhci 0000:00:02.0 mmio 0x8000004000
    keyboard: ready (port 5, slot 1, endpoint 0x81)
    keyboard_echo: abc
    keyboard_line: abc
    keyboard: done (enter)
    keyboard_echo: help
    keyboard_line: help
    keyboard: done (enter)
    keyboard_echo: el
    keyboard_line: el
    keyboard: done (enter)
    keyboard_echo: mem
    keyboard_line: mem
    keyboard: done (enter)
    keyboard_echo: exit
    keyboard_line: exit
    keyboard: done (exit)

## Script verdict

    QEMU_KEYBOARD: PASS
