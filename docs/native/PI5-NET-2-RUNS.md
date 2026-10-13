# PI5-NET-2 runs: inbound DMA window confinement and RP1 Ethernet up to the PHY

Image: `make pi5-net` (flag `CK_PI5_NET=1`, refuses every other Pi image flag). Code: `native/kernel/dev/pi5_net.c`, `pi5_net.h`. Host tests: `tests/test_pi5_net.c` (fake registers, 23 mutants, all killed by `make pi5-net-mutants`). Base: main 5429602 (cut 1, #363). A host test proves the decisions and the register write order, not the hardware.

## Run pi5-net-1 (real Raspberry Pi 5)

Evidence file: `~/workspace/pi5-runs/pi5-net-1/kernel.log` (image sha256 f42298cb40d39d20375a4659d18b76a5971ca7c2816c49cbf93b13189d27181b). `\EFI\AIENOS\` had no MODEL.MAP. Exact lines:

```
pi5_net: root 00:00.0 14e4:2712 class=060400 sec=1 sub=1
pi5_net: rp1 01:00.0 1de4:0001 MATCH cmd=0x0006
pi5_dma: bounce cpu=0x4400000 size=0x200000 (ADR 0020 rule 1)
pi5_net: inbound before win0 bus=0x0 size=0x1000000000 cpu=0x0 remap=1 valid=1
pi5_dma: hw_window before=NOT_CONFINED [NOT_CONFINED] reach=0x1000000000 inside=0x200000 outside=0xfffe00000
pi5_dma: plan bus=0x4400000 cpu=0x4400000 size=0x200000 code=6 extra_beyond_bounce=0x0
pi5_dma: rp1 bus-master off for the window change: rc=0 cmd_was=0x0006 cmd_now=0x00100002
pi5_dma: apply rc=0 (0 = window now matches the plan); other_windows_disabled=0
pi5_net: inbound after win0 bus=0x4400000 size=0x200000 cpu=0x4400000 remap=1 valid=1
pi5_dma: hw_window after=CONFINED [CONFINED] reach=0x200000 inside=0x200000 outside=0x0
pi5_dma: rp1 bus-master is LEFT OFF (cmd=0x00100002); the GEM driver turns it on when it needs it
pi5_net: outbound win0 bus=0xc0000000 cpu=0x1f00000000 size=0x40000000
pi5_net: rp1 bar1 bus=0xc0000000 -> cpu=0x1f00000000 chip_id=0x20001927 platform=0x00000002
pi5_net: gem before: MID=0x00070109 NCR=0x00000000 NCFGR=0x00540000 NSR=0x00000006 eth_cfg CONTROL=0x00000000 CLKGEN=0x00000080
pi5_net: rp1 clocks before: pll_core=1000000000 pll_sec=125000000 clk_sys=200000000 clk_eth=125000000 clk_eth_tsu=50000000 Hz (0 = off/unknown)
pi5_net: clk_eth: ALREADY_ON (already enabled: left as found) | clk_eth_tsu: ALREADY_ON (already enabled: left as found)
pi5_net: phy reset gpio32 rc=0 ctrl 0000009f->00000085 pad 000000d6->00000056 oe_before=00000000 out_before=00000000 in: before=00000002 low=00000002 high=00000010
pi5_net: mdio enable rc=0 NCR=0x00000010 NCFGR=0x00540000 (MDC divider code 5 for pclk 200000000 Hz)
pi5_net: phy addr=1 id=0x600d84a2 oui=18-c0-86 model=0x0a rev=2 class=BCM54213PE attempts=1
pi5_net: done: no frames sent; GEM tx/rx not enabled; rp1 bus-master left off
```

## Results

- **A. Confinement: CONFINED, exact.** Window 0 went from the firmware's 64 GiB (bus 0 to cpu 0) to exactly the 2 MiB bounce block (0x4400000, size code 6). Extra bytes beyond the bounce region: 0. Readback of all four registers matched the plan; no other inbound window was enabled (0 disabled).
- **B. PHY ID: 0x600d84a2**, OUI 18-C0-86 (Broadcom in the IEEE registry), model 0x0a, revision 2, matches Linux `PHY_ID_BCM54213PE` exactly. Found at MDIO address 1 on the first attempt.
- **Clocks.** The firmware had already enabled `clk_eth` (125 MHz) and `clk_eth_tsu` (50 MHz). They were left exactly as found (no write). The decide/apply path that would enable them is tested on host only (UNVERIFIED on hardware, since not needed).
- **PHY reset.** GPIO32 was driven low then released; the pin input read low during the pulse (bit 4 clear) and high afterwards. This shows the line moved; a PHY ID answer after it shows the PHY came out of reset.

## Order and safety

RP1 bus mastering (PCI command BME on 01:00.0) was cleared first and read back off, then 2 ms wait, then window 0 was switched off, HI/REMAP changed, LO written last with the size code. On any failed readback the firmware window is restored. BME is left off afterwards (the later GEM driver must turn it on).

## UNVERIFIED

- **Blocking was not exercised.** The register readback proves the window is programmed; no RP1 DMA was issued at an address outside it, because there is no safe DMA master yet (no GEM descriptors in this cut). The safe test belongs to the cut that has the GEM: with BME on, point one descriptor just outside the bounce and expect an abort or error status, then one inside and expect success.
- **"No DMA in flight"** is established by BME off plus a 2 ms wait, not by observing RP1 internal queues.
- **MSI.** MSI writes also pass an inbound window (Linux uses a window to the MSI target). A 2 MiB window excludes it. This kernel polls and uses no MSI, so nothing breaks now; an MSI-using driver must add a window for it (ADR 0020 rule 6 already says the MSI path is UNVERIFIED).
- **Controller-wide.** The window covers all devices behind this root complex (RP1 DMA and USB), as ADR 0020 states.
- Clock enable path, MDC divider at other rates, and a stuck-PHY reset are host-tested only.

## Sources read (see header of `dev/pi5_net.h`)

edk2-platforms Bcm2712PciHostBridge.c and Bcm2712Pcie.h (inbound/outbound window registers), Rp1.h, Linux rpi-6.12.y pcie-brcmstb.c, clk-rp1.c, pinctrl-rp1.c, macb_main.c, broadcom.c, brcmphy.h, rp1.dtsi, and the RP1 datasheet (outbound direct mapped space, GEM, ETH_CFG). The Pi run is the final authority for what the firmware actually left in place.
