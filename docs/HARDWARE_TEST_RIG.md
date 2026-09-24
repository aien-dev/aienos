# Machine 1 hardware test rig

**Status: proposed design (2026-09-24). Nothing is wired or enabled yet. The
operator chooses and approves the parts; maintainers wire it up. Until then,
M2C power, capture and input stay pending and boots stay attended.**

Governing: [ADR 0010](adr/0010-machine-1-hardware-test-rig.md),
[MILESTONES.md gate M2C](MILESTONES.md), [NATIVE_BOOT_ONE_TIME.md](NATIVE_BOOT_ONE_TIME.md),
issue [#25](https://github.com/aien-dev/aienos/issues/25).

## Why

Every Spark boot currently needs a person at the machine: someone holds the
power button when a boot hangs, photographs the screen because the post-exit
report has no other record, and types at the firmware menus. That does not
scale, and it cannot run unattended. The rig gives three **independent**
functions for Machine 1, all serialized through
`aien-proof hold --resource machine-1` (see
[Serialization](#serialization-through-aien-proof)):

1. **Power and reset control**: momentary press, long press (force off),
   and a hard power cut that always works.
2. **Display or console capture**: the screen from cold boot through the
   post-exit report, replacing the operator photograph.
3. **Deterministic input and boot selection**: scripted keystrokes into the
   firmware boot menu, the firmware setup screen, and later the AIENOS early
   console, so the same image boot can be driven the same way every time.

Independence matters: a hung capture dongle must not block a power cut, and a
dead HID gadget must not trap the machine with no way to reboot it. Each
function below fails without breaking the other two.

A Raspberry Pi is already cabled to the Spark and acts as the rig controller:
USB keyboard gadget, capture host, relay driver, and the place `aien-proof`
runs.

## Parts list

Prices are approximate, one unit each, 2026. Nothing here is proprietary; every
part is replaceable with an equivalent.

| Function | Part | Role | Approx. cost |
| --- | --- | --- | --- |
| Controller | Raspberry Pi 5 (already cabled to the Spark) | Runs `aien-proof`, the gadget stack, capture and relay control | owned |
| Power sense | Spark ATX 24-pin sense lead (`PWR_OK`, green wire `PS_ON`) tapped at the PSU connector | Ground `PS_ON` to force the PSU on; read `PWR_OK` to know the board has power | cable only |
| Power cut | SPDT relay board, 5 V coil, 10 A mains-rated contacts (for example an opto-isolated Songle SRD-05VDC module) | Inline with the mains feed or the PSU enable; drops power unconditionally | ~5 USD |
| Power/reset buttons | 2x reed or opto-isolated reed relays (for example Omron G3VM SIP MOSFET relays) | One across the Spark front-panel power-header pins, one across the reset-header pins; momentary closure only | ~4 USD |
| Display capture | USB 3 HDMI capture dongle, UVC class, 1080p60 (for example an MS2109 or MS2130 based dongle) | Spark HDMI out to dongle input; appears as a webcam on the Pi; loop-through port passes the desk monitor | ~20 to 40 USD |
| Input emulation | The Pi itself, USB OTG port in HID gadget mode (Linux `configfs`, `dwc2` overlay) | Presents a standard USB boot-protocol keyboard to the Spark | included |
| Console capture | Pi GPIO UART (TX/RX) wired to the Spark UART at `0x16A00000` | Bounded serial console once [#22](https://github.com/aien-dev/aienos/issues/22) lands; 3.3 V levels only | jumper wires |
| Enclosure and safety | Fused mains inlet box for the relay, insulated standoffs, labeled header leads | Mains stays in a closed, fused box; low voltage leaves it | ~20 USD |

Total new spend is roughly 50 to 70 USD. No part is on the Spark's boot
critical path except by explicit command: with every relay at rest and every
cable disconnected, the Spark boots exactly as it does today.

## Function 1: power and reset control

The Spark exposes standard PC-style front-panel pins. Shorting the power pins
briefly is a press; shorting them for about five seconds forces power off. The
relay board gives a hard cut that works even when the board is wedged.

- `power.press` and `reset.press`: close the matching reed relay for about
  500 ms, then open. Reed relays are used for the button lines because they are
  isolated, polarity-tolerant and cannot drive the header.
- `power.forceoff`: hold the power relay closed for 5 s.
- `power.cut` / `power.restore`: energize or release the mains relay. This is
  the last resort and the recovery path for every wedged state.
- `power.status`: read the PSU `PWR_OK` sense line, so a script can wait for
  power-good instead of sleeping a fixed time.

Safety invariants (enforced by the control scripts, reviewed in the ledger):

- The mains relay is **fail-on**: power flows when the relay is at rest, so a
  dead Pi or a crashed script never holds the machine dark.
- The button relays are **momentary-only**: the driver enforces a maximum
  closure time in software and the hardware timer on the relay board enforces
  it if the Pi hangs.
- `power.cut` is the only destructive action, and it is always available to
  the operator and to a failing script.

## Function 2: display and console capture

Two capture paths, both terminating on the Pi:

- **HDMI**: the Spark's display output goes through the capture dongle's
  loop-through port to the desk monitor, and the dongle's USB side lands on
  the Pi as a UVC webcam. A capture run records video from before power-on
  until the machine is back in Linux, plus a still frame at each stage gate
  (firmware logo, pre-exit report, post-exit report, countdown). This replaces
  the "photograph the screen" step in
  [NATIVE_BOOT_ONE_TIME.md](NATIVE_BOOT_ONE_TIME.md) and records the post-exit
  drawing that the M2 evidence
  ([evidence/m2_first_boot_2026-09-24.md](../evidence/m2_first_boot_2026-09-24.md))
  lists as a gap.
- **UART**: the kernel already has a bounded 16550-style UART writer at
  `0x16A00000`, 921600 baud (`crates/aienos-kernel/src/arch/aarch64.rs`),
  skipped on the first boot because GB10 discovery failed. Once [#22](https://github.com/aien-dev/aienos/issues/22)
  (SPCR-based discovery) lands, the Pi's GPIO UART records it at 3.3 V
  levels. Until then, HDMI capture is the only post-exit record and stays
  mandatory.

Capture is read-only: nothing in this function can change what the machine
does. A failed capture never blocks power control.

## Function 3: deterministic input and boot selection

The Pi's OTG port runs the Linux HID gadget (`configfs` + `dwc2`) and appears
to the Spark as a plain USB keyboard. The gadget implements the HID boot
protocol, so it works in the firmware setup screen and boot menu where no OS
driver exists, and later against the native xHCI/HID driver from
[#24](https://github.com/aien-dev/aienos/issues/24).

Boot selection is deterministic: the rig never types blind. Each scripted
sequence is a list of (wait for capture frame matching X, send keystrokes Y)
steps. Examples:

- Boot menu: `power.press`, wait for the firmware logo frame, send `Esc`,
  wait for the boot-menu frame, send the arrow-key count for the `ubuntu`
  entry, send `Enter`.
- Firmware setup: the documented `systemctl reboot --firmware-setup` path is
  preferred; the gadget is the fallback when Linux is not running.
- AIENOS console: once the early console takes keyboard input, sequences come
  from the same runner.

The keystroke sets, frame references and expected end states are versioned in
this repository next to the scripts that use them, so a boot sequence maps to
one exact commit, same rule as the staged image.

## Serialization through `aien-proof`

`aien-proof` and its `machine-1` resource lock live in the
[aien-sovereign-core](https://github.com/aien-dev/aien-sovereign-core)
repository; this repository holds the rig design and the contract the control
surface must meet. The contract is the one already used for staging:

```text
aien-proof hold --resource machine-1 --job <name> -- <rig command>
```

Rules:

- Every rig function, including capture, runs only inside a
  `machine-1` hold. The hold's full output becomes the ledger event, exactly
  as `stage_one_time_boot.sh` and `collect_boot_report.sh` already work.
- A hold runs one rig command. The rig never acts outside a hold; an attended
  boot by the operator is recorded as one too.
- `power.cut` is the single exception reachable in an emergency and is still
  wrapped by the hold when scripted; physically, the operator can always cut
  power by hand.
- Scripts that run under the hold get no stdin, so anything privileged is
  pre-authorized (`sudo -v`) before the hold, as in
  [NATIVE_BOOT_ONE_TIME.md](NATIVE_BOOT_ONE_TIME.md).

The M2 evidence flow changes in one place: the photograph rows
(`framebuffer:` line and post-exit drawing) come from capture stills named in
the ledger payload, and the collector checks them the way it checks the
firmware-variable report today.

## Attended-to-unattended boot contract

The current attended procedure ([NATIVE_BOOT_ONE_TIME.md](NATIVE_BOOT_ONE_TIME.md))
maps onto the rig without changing the image:

| Attended step today | With the rig |
| --- | --- |
| Operator holds power button after a hang | `power.forceoff`, then `power.press` |
| Monitor attached; operator photographs the screen | HDMI capture stills and video, recorded in the ledger payload |
| Keyboard attached; operator picks entries in firmware | HID gadget sequences, matched against capture frames |
| Recovery USB stick chosen from the boot menu by hand | Boot-menu sequence against the same capture frames |

Until the owner-controlled boot chain exists (see the Secure Boot note in
[MILESTONES.md](MILESTONES.md)), the rig changes how boots are driven, not
what is booted: Secure Boot stays on, native AIENOS boots stay paused, and the
rig's first job is running attended flows like recovery-media testing and the
TRUST-1 100-boot campaign without a person in front of the machine.

## Wiring checklist (maintainers)

1. Bench-test the relay board on a lamp before touching the Spark.
2. Tap `PS_ON`/`PWR_OK` at the ATX connector; verify sense reads on the Pi.
3. Identify the Spark front-panel header; wire the two reed relays; verify a
   500 ms closure powers the machine on and off.
4. Route HDMI through the capture dongle to the desk monitor; verify the Pi
   sees a UVC device and a frame.
5. Enable the HID gadget on the Pi OTG port; verify the Spark firmware sees a
   keyboard (boot-menu navigation by script).
6. Wire the UART (3.3 V only); leave it disconnected until [#22](https://github.com/aien-dev/aienos/issues/22)
   makes the Spark side real.
7. Run the attended procedure once under the rig, end to end, and record the
   ledger events as the rig's commissioning evidence.

Each step is independently verifiable and independently reversible; a step
that fails leaves the previous functions working.
