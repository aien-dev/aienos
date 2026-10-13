# PI5-NET-3 runs: one Ethernet frame through the RP1 GEM, descriptors inside the bounce window only

Image: `make pi5-net` (`CK_PI5_NET=1`). Code: `native/kernel/dev/pi5_gem.c`, `pi5_gem.h` (library plus image glue), called from `pi5_net.c`. Host tests: `tests/test_pi5_gem.c` (fake GEM that flags any DMA outside the window, DMA without bus-master, bus-master dropped while the transmitter runs, malformed rings; 281 checks, 23 mutants, all killed by `make pi5-gem-mutants`).

Register sources (cited in the code comments): Linux `macb.h` and `macb_main.c` [M1, M2], Linux `broadcom.c`, `bcm-phy-lib.c`, `mii.h`, `phy_device.c` [P1], RP1 datasheet ethernet chapter [D1], IEEE 802.3 clause 22 [I1].

## Run pi5-net-3-r1 (real Raspberry Pi 5)

Evidence file: `~/workspace/pi5-runs/pi5-net-3-r1/kernel.log` (image sha256 7693ccde4ca62422dcd60e50efbe515d3992ad052baa36f32cccb54b1bb9eaf5). `\EFI\AIENOS\` had no MODEL.MAP. KLOG=1, tryboot soft reset. Exact lines (all `pi5_` lines of the log):

```
pi5_watchdog: armed 15 s (PM block 0x107d200000), petted at every stage
pi5_sd: host 0x1000fff000 version=0x1002 caps=0x15eac832 caps_base_mhz=200 using 200 MHz (clk_emmc2)
pi5_sd: card ready spec=2 card_hz=25000000 high_capacity=1 blocks=250347520 (122240 MiB) rca=0x59b4 bus=4bit
pi5_sd: read sector 0 rc=0 signature=55aa (MBR ok)
pi5_part: AIENOS partition first_lba=1050624 blocks=8388608 (4096 MiB) entries_used=3 index=1 via GPT (CRC32 primary+backup ok)
pi5_store_view: lba 0..8388543 (1048568 units) for the Store; marker reserved at 8388544..8388607
pi5_store_layer: reopened (payload identical to the pattern, generation bumped and read back) generation=22 region=64 sectors at partition block 8388544
pi5_net: cut 3: hardware DMA confinement, RP1 Ethernet up to the PHY, then one frame through the GEM (descriptors inside the bounce window only)
pi5_net: software-only DMA confinement (Pi 5, weaker than the Spark) plus the root-complex window below
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
pi5_net: rp1 clock regs: PLL cs=0x80000001 fbint=0x00000014 frac=0x00000000 prim=0x00051010 sec=0x80000800 | SYS ctrl=0x00000002 div=1 sel=0x4 | ETH ctrl=0x10000800 div=1 sel=0x1 | TSU ctrl=0x10000800 div=1 sel=0x1
pi5_net: rp1 clocks before: pll_core=1000000000 pll_sec=125000000 clk_sys=200000000 clk_eth=125000000 clk_eth_tsu=50000000 Hz (0 = off/unknown)
pi5_net: clk_eth: ALREADY_ON (already enabled: left as found) | clk_eth_tsu: ALREADY_ON (already enabled: left as found)
pi5_net: rp1 clocks after: pll_core=1000000000 pll_sec=125000000 clk_sys=200000000 clk_eth=125000000 clk_eth_tsu=50000000 Hz (0 = off/unknown)
pi5_net: clock apply rc=0
pi5_net: phy reset gpio32 rc=0 ctrl 0000009f->00000085 pad 000000d6->00000056 oe_before=00000000 out_before=00000000 in: before=00000000 low=00000000 high=00000012
pi5_net: mdio enable rc=0 NCR=0x00000010 NCFGR=0x00540000 (MDC divider code 5 for pclk 200000000 Hz)
pi5_net: phy addr=1 id=0x600d84a2 oui=18-c0-86 model=0x0a rev=2 class=BCM54213PE attempts=1
pi5_net: phy found; handing over to the GEM frame test (hw window confined=1)
pi5_gem: cut 3: one frame through the RP1 GEM with descriptors only inside the bounce window; software-only DMA confinement (Pi 5, weaker than the Spark)
pi5_gem: caps rc=0 MID=0x00070109 DCFG1=0x08508513 DCFG2=0x6eb13fff DCFG6=0x08820000 gem=1 daw64=1 queue_mask=0x1 queues=1 desc_bytes=16 dbw_code=2
pi5_gem: state before: NCR=0x00000010 NCFGR=0x00540000 USRIO=0x00000000 DMACFG=0x00020704 AMP=0x00000101 TBQP=0x00000000 RBQP=0x00000000 eth_cfg STATUS=0x00000000 CLKGEN=0x00000080 rp1 pci cmd=0x00100002
pi5_gem: link (first read, read-only): BMCR=0x1140 BMSR=0x7949/0x7949 ADV=0x01e1 LPA=0x0000 CTRL1000=0x0200 STAT1000=0x0000 link=0 aneg_done=0 speed=0 duplex=half | eth_cfg STATUS=0x00000000 link=0 speed=10 duplex=half
pi5_gem: link UP: BMCR=0x1140 BMSR=0x7969/0x796d ADV=0x01e1 LPA=0xcde1 CTRL1000=0x0200 STAT1000=0x0800 link=1 aneg_done=1 speed=1000 duplex=full | eth_cfg STATUS=0x00000000 link=0 speed=10 duplex=half
pi5_gem: LINK FOUND
pi5_gem: phy rgmii-id delays rc=0 AUXCTL_MISC before=0x71e7 after=0x71e7 CLK_CTL before=0x200 after=0x200
pi5_gem: loopback gem-local(NCR.LLB) seq=1 rc=0 tx_done=1 rx_done=1 rx_frames=1 tx_ctrl=0x8000803c rx_word0=0x04400181 rx_ctrl=0x8000c03c rx_len=60 frame_diff=0
pi5_gem: loopback gem-local(NCR.LLB) seq=1 regs: tsr=0x00000021 rsr=0x00000002 isr=0x00000000 ncr_run=0x0000001e ncfgr=0x00560402 dmacfg=0x40180710 ncr_end=0x00000010 tsr_end=0x00000000 bme_on_for_us=1 bme_off_at_end=1 tx_bus=0x4400140 rx_bus=0x4400180
pi5_gem: LOOPBACK gem-local PASS (sent seq=1 60 bytes, received 60 bytes, byte compare identical)
pi5_gem: phy loopback enter rc=0 BMCR_was=0x1140 BMSR_now=0x794d (link in loopback=1)
pi5_gem: loopback phy(BMCR.LOOPBACK) seq=2 rc=0 tx_done=1 rx_done=1 rx_frames=1 tx_ctrl=0x8000803c rx_word0=0x04400181 rx_ctrl=0x8000c03c rx_len=60 frame_diff=0
pi5_gem: loopback phy(BMCR.LOOPBACK) seq=2 regs: tsr=0x00000021 rsr=0x00000002 isr=0x00000000 ncr_run=0x0000001c ncfgr=0x00560402 dmacfg=0x40180710 ncr_end=0x00000010 tsr_end=0x00000000 bme_on_for_us=1 bme_off_at_end=1 tx_bus=0x4400140 rx_bus=0x4400180
pi5_gem: LOOPBACK phy PASS (sent seq=2 60 bytes, received 60 bytes, byte compare identical)
pi5_gem: phy loopback exit rc=0 BMCR restored to 0x1140
pi5_gem: link after loopback (UP): BMCR=0x1140 BMSR=0x7969/0x796d ADV=0x01e1 LPA=0xcde1 CTRL1000=0x0200 STAT1000=0x3800 link=1 aneg_done=1 speed=1000 duplex=full | eth_cfg STATUS=0x00000000 link=0 speed=10 duplex=half
pi5_gem: wire arp-probe 192.168.1.1 seq=3 rc=0 tx_done=1 rx_done=0 rx_frames=0 tx_ctrl=0x8000803c rx_word0=0x00000000 rx_ctrl=0x00000000 rx_len=0 frame_diff=4294967295
pi5_gem: wire arp-probe 192.168.1.1 seq=3 regs: tsr=0x00000021 rsr=0x00000000 isr=0x00000000 ncr_run=0x0000001c ncfgr=0x00560402 dmacfg=0x40180710 ncr_end=0x00000010 tsr_end=0x00000000 bme_on_for_us=1 bme_off_at_end=1 tx_bus=0x4400140 rx_bus=0x4400180
pi5_gem: WIRE tx PASS (ARP probe 60 bytes at 1000 Mbit full duplex, TX complete=1, tx_ctrl error bits=0x00000000)
pi5_gem: WIRE rx (bonus) none within 400 ms
pi5_gem: confinement setup: canary page cpu=0x4600000 (outside window 0x4400000..+0x200000); validator on a scratch copy of the window says 2 (2 = E_RANGE, refused) for a 64 byte buffer there
pi5_gem: CONFINEMENT A: the RX descriptor points at 0x4600000 outside the window, buffer size 64 bytes (the device can write at most 64 bytes there)
pi5_gem: confinement A (rx write outside) seq=4 rc=0 tx_done=1 rx_done=1 rx_frames=1 tx_ctrl=0x8000803c rx_word0=0x04600001 rx_ctrl=0x8000c03c rx_len=60 frame_diff=1
pi5_gem: confinement A (rx write outside) seq=4 regs: tsr=0x00000021 rsr=0x00000003 isr=0x00000000 ncr_run=0x0000001e ncfgr=0x00560402 dmacfg=0x40010710 ncr_end=0x00000010 tsr_end=0x00000000 bme_on_for_us=1 bme_off_at_end=1 tx_bus=0x4400140 rx_bus=0x4400180
pi5_gem: CONFINEMENT A result: canary bytes changed=0 first_changed_offset=-1 device_says_rx_done=1 hresp=0
pi5_gem: CONFINEMENT A BLOCKED: the write did not reach the outside page
pi5_gem: CONFINEMENT B: the TX descriptor points at 0x4601000 outside the window, which holds a different frame (marker seq=0xdead0005)
pi5_gem: confinement B (tx read outside) seq=5 rc=0 tx_done=1 rx_done=0 rx_frames=0 tx_ctrl=0x8000803c rx_word0=0x00000000 rx_ctrl=0x00000000 rx_len=0 frame_diff=4294967295
pi5_gem: confinement B (tx read outside) seq=5 regs: tsr=0x00000021 rsr=0x00000000 isr=0x00000000 ncr_run=0x0000001e ncfgr=0x00560402 dmacfg=0x40180710 ncr_end=0x00000010 tsr_end=0x00000000 bme_on_for_us=1 bme_off_at_end=1 tx_bus=0x4400140 rx_bus=0x4400180
pi5_gem: CONFINEMENT B result: rx_done=0 diff_vs_outside_marker=4294967295 diff_vs_inside_frame=4294967295 tsr_bex=0 hresp=0
pi5_gem: CONFINEMENT B BLOCKED: the outside page was not delivered as the frame
pi5_gem: done: GEM RE/TE/LLB off, halted=0 bme_on=0 rp1 pci cmd=0x00100002 NCR=0x00000010
pi5_net: done: rp1 bus-master off unless the line above says otherwise
```

## What the run shows

- Link: FOUND. The PHY (BCM54213PE at addr 1) reports link up, autoneg done, 1000 Mbit full duplex, partner LPA 0xcde1. A cable and a partner exist.
- Loopback, GEM local (NCR.LLB): PASS. Frame seq=1, 60 bytes sent, 60 received, byte compare identical.
- Loopback, PHY (BMCR bit 14): PASS. Frame seq=2, same result. The PHY was put back to its original BMCR afterwards.
- Wire: TX PASS. One ARP probe (60 bytes, sender IP 0.0.0.0, target 192.168.1.1) at 1000 Mbit full duplex, TX complete, no error bits. RX of an incoming frame: none within 400 ms (bonus, not required).
- Every descriptor went through the ADR 0020 validator before bus-master was turned on. Bus-master was on only during each transfer and was off again at the end of each (`bme_off_at_end=1`, final `rp1 pci cmd=0x00100002`). The GEM was left with RE/TE/LLB off.
- Confinement A (device WRITE outside the window): BLOCKED by the readback. The RX descriptor pointed at a private page at cpu 0x4600000 (outside the window), buffer 64 bytes. The canary page (filled with 0xa5) had 0 changed bytes. Note: the GEM itself reported the frame as received (rx_word0 used bit set, rx_len=60), and the in-window buffer stayed empty, so the device believed it wrote; the root complex dropped the write. No fault, no hang, `hresp=0`.
- Confinement B (device READ outside the window): the frame at the outside page (marker seq=0xdead0005) was not delivered (rx_done=0). The TX descriptor was consumed (TX complete, no error bits). This shows the marker frame did not come back, which is consistent with a blocked read.

## UNVERIFIED

- Confinement B is inferred from "marker frame not received". The run does not prove what the read returned (zeros, all ones, or an error response were not captured), so it does not prove the device never saw our bytes, only that they were not delivered as the frame. A wire-side capture would settle it.
- Confinement A and B each ran once on one board.
- What GEM NCR.LLB does at the RGMII pins was not measured; the result only shows the frame returned.
- Whether the TX frame in the wire test reached the partner (no capture on the partner side). TX complete only means the MAC finished sending.
- RX of an incoming frame from the network: not seen.
- The local MAC 02:41:49:45:4e:03 is a locally administered address, not the board's OTP MAC (not read).
- ETH_CFG STATUS read 0x00000000 (link=0) while the PHY reported link up. The register was not interpreted further; its decode is unverified on this board.
- RGMII-ID delay config is copied from Linux; before and after read back identical (AUXCTL_MISC 0x71e7, CLK_CTL 0x200), so the PHY already had the delays set and the write was not shown to change anything. The data path worked in loopback and on the wire at TX only.
- No interrupts or MSI used; polling only.
