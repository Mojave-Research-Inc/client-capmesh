# the primary node — FAILING DIMM (P2-DIMMI1), root cause of repeated crashes

**Action required: replace the module. No firmware or software change will fix this.**

**Warranty case:** Supermicro cross-shipment request [`296598-1`](RMA-2026-07-19.md) was
submitted on 2026-07-19 and is **Under confirm**; the assigned RMA number is pending.

## The module

    Slot          P2-DIMMI1   (SEL reports it as "DIMMI1(CPU2)")
    Bank          P1_Node0_Channel8_Dimm0
    Manufacturer  Samsung
    Part Number   M321R4GA3EB2-CCPPF
    Serial        80CE012515017B8A0E
    Size          32 GiB

Do not confuse it with **P1-DIMMI1** (serial `…7B902C`), the same slot position on the other
socket. The SEL's "CPU2" maps to the **P2** locator.

## Evidence

`ipmitool sel elist` — 43 `Uncorrectable ECC` events, 11 of them in July 2026 alone:

    07/16 06:27  Uncorrectable ECC @ DIMMI1(CPU2)
    07/16 08:15  Uncorrectable ECC @ DIMMI1(CPU2)
    07/16 10:54  Uncorrectable ECC @ DIMMI1(CPU2)
    07/16 13:17  Uncorrectable ECC @ DIMMI2(CPU2)      <- second module on the same socket
    07/17 03:38  Uncorrectable ECC @ DIMMI1(CPU2)
    07/18 07:26  Uncorrectable ECC @ DIMMI1(CPU2)
    07/18 12:44  Uncorrectable ECC @ DIMMI1(CPU2)
    07/18 22:40  Uncorrectable ECC @ DIMMI1(CPU2)

Earliest event in the SEL: **2025-08-01**. This is a long-standing fault, not a new one.

An uncorrectable ECC error takes the machine down abruptly, which matches the primary node's reboot
pattern — three boots on 2026-07-18 alone (03:27, 08:45, 18:40), each with a truncated journal
and no clean shutdown sequence.

## Why every OS-level check said "clean" — read this before trusting the next one

    rasdaemon --summary     "No Memory errors"
    EDAC mc0/mc1            ce=0  ue=0
    journalctl              no genuine MCE entries

None of that contradicts the SEL. **An uncorrectable ECC error kills the machine before the OS
can write anything**, and EDAC counters reset on every boot. The BMC records it out-of-band
because it does not depend on the CPU surviving. Diagnosing memory faults from OS telemetry
alone will produce a false all-clear on this class of failure every time — check
`ipmitool sel elist` first.

This also corrected a wrong conclusion reached earlier the same day: the 18:36 crash was
initially attributed to a `kdumpctl`/`dracut` initramfs rebuild that ran at 18:30, purely on
timing correlation. The SEL shows the box has been dying this way since July 16, before any of
that work started, and threw another event at 22:40 while nothing was running.

## BIOS is not the fix

BIOS 3.9 (02/05/2026) [Fixes] #1 reads:

    [Turin][Genoa] Fix DIMM number information incorrect for uncorrectable Memory error.

That is a **reporting** fix — it makes the SEL name the correct DIMM. It does not prevent
errors. the primary node is on 3.9 and has logged **43 uncorrectable ECC events since that release**.

As reverified against Supermicro's official H13DSH download page on 2026-07-19, the published
bundle is `H13DSH_3.9_AS01.09.02_SAA1.4.0` (BIOS 3.9, BMC 01.09.02). An earlier version of this
record incorrectly described an unverified 3.9a/01.09.05 bundle as current; the official vendor
page supersedes that claim. **No published firmware note makes firmware a remedy for this DIMM's
repeated uncorrectable ECC events.**

For any future bundle update, follow the vendor's mandatory **BMC → CPLD → BIOS** sequence.
The CPLD image is H13DSH-only; applying it to another product risks permanent board damage.

## Mitigations already in place (they reduce blast radius, not the fault)

- `service-watchdog.timer` — probes real service endpoints every 5 min, fails loudly
- `podman-restart.service` enabled — containers return after an abrupt reboot
- kdump ACTIVE, dumping over SSH to `kdumpdrop@${CAPMESH_REPLICA_HOST:-127.0.0.1}:/srv/crash-remote/the primary node` (1.3T)
- LUKS auto-unlocks via clevis, so the box recovers headless

## Hardware context

    System   Supermicro AS-1125HS-TNR / H13DSH
    CPU      2x AMD EPYC 9454 48-Core
    BIOS     3.9 (02/05/2026)   BMC 1.09   Platform Firmware Revision 5.27

Note DIMMI2(CPU2) also threw one event (07/16 13:17). If replacing I1 does not stop the
crashes, suspect the second module or the CPU2 memory channel itself.
