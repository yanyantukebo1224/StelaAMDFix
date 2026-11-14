# StelaAMDFix — Experimental Preview

> **Status: diagnostic / developer preview only. This is not a working AMD LPC/BME fix.**

StelaAMDFix is an experimental fork used to investigate a PCI containment failure seen on some AMD systems. The current preview adds diagnostics and automated regression tests; it does **not** change the runtime BME containment policy and does **not** claim to make the affected system boot.

## What this preview contains

- Additional boot-log identification for the AMD FCH LPC device (`1022:790e`).
- Regression tests for PCI class-code decoding and the generic hardwired-Bus-Master exception.
- CI validation of the `stela-driver-base` tests and Clippy.

## What it does not contain

- No workaround that ignores a failed PCI Bus Master Enable (BME) containment check.
- No validated Family 19h / B550 FCH DMA-isolation implementation.
- No claim of successful macOS boot on Ryzen 7 5700X or B550M Pro4.
- No ready-to-install Windows executable or USB image attached to this preview.

## Intended test platform

The investigation currently targets this reported configuration:

| Component | Reported value |
|---|---|
| CPU | AMD Ryzen 7 5700X (Family 19h, Model 21h) |
| Motherboard | MouseComputer B550M-P4 / ASRock B550M Pro4 |
| BIOS | P3.90 |
| FCH LPC | PCI `1022:790e`, revision `0x51`, BDF `00:14.3` |
| GPU | NVIDIA GeForce RTX 3060 Ti |

Other AMD systems are not assumed compatible. The same PCI device ID does not prove that register semantics or DMA behavior are identical across chipset generations.

## Before testing

- Treat this as development software, not a production bootloader.
- Do not use a disk containing the only copy of important data.
- Do not change firmware security, DMA, IOMMU, or PCI settings just to force a boot.
- Stop if the boot log reports a containment, DMA-isolation, or device-ownership failure.
- Do not interpret a successful build or passing unit tests as proof that the hardware is safe or supported.

## Reporting results

If you are already testing Stela and can safely reproduce the issue, include:

1. CPU and motherboard model.
2. BIOS version.
3. GPU model.
4. The complete Stela boot log (`log.txt`).
5. Whether the failure occurs before or after the GPU-start step.

Remove serial numbers, UUIDs, disk identifiers, and other personal/device-specific identifiers before posting logs publicly.

## Current validation

- [x] PCI containment unit tests
- [x] Clippy for `stela-driver-base`
- [ ] Family 19h FCH DMA-control semantics independently verified
- [ ] AMD-IOMMU requester coverage and deny-DMA state verified on target hardware
- [ ] End-to-end boot test on Ryzen 7 5700X + B550M Pro4
- [ ] Packaged Windows release artifact

A proper public pre-release with downloadable binaries should be published only after the runtime change and the required safety checks are complete.
