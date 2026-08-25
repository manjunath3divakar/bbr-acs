// AArch64 register access for the 64 KiB page-attribute checker.
//
// Copyright (c) 2026, Arm Ltd. All rights reserved.<BR>
// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// Call EL-specific accessors only at that EL. These helpers do not install
// exception vectors: traps to a higher EL remain controlled by that firmware.
// x0..x3 are caller-saved; x18 and all callee-saved registers are untouched.

  .text
  .align 2

// Return CurrentEL in x0. Preconditions are enforced by the C caller.
  .global R64KReadCurrentEl
  .type R64KReadCurrentEl, %function
R64KReadCurrentEl:
  mrs x0, CurrentEL
  ret
  .size R64KReadCurrentEl, . - R64KReadCurrentEl

// Return S3_0_C0_C7_3 in x0. Preconditions are enforced by the C caller.
  .global R64KReadMmfr3
  .type R64KReadMmfr3, %function
R64KReadMmfr3:
  mrs x0, S3_0_C0_C7_3
  ret
  .size R64KReadMmfr3, . - R64KReadMmfr3

// Return ttbr0_el1 in x0. Preconditions are enforced by the C caller.
  .global R64KReadTtbr0El1
  .type R64KReadTtbr0El1, %function
R64KReadTtbr0El1:
  mrs x0, ttbr0_el1
  ret
  .size R64KReadTtbr0El1, . - R64KReadTtbr0El1

// Return ttbr1_el1 in x0. Preconditions are enforced by the C caller.
  .global R64KReadTtbr1El1
  .type R64KReadTtbr1El1, %function
R64KReadTtbr1El1:
  mrs x0, ttbr1_el1
  ret
  .size R64KReadTtbr1El1, . - R64KReadTtbr1El1

// Return tcr_el1 in x0. Preconditions are enforced by the C caller.
  .global R64KReadTcrEl1
  .type R64KReadTcrEl1, %function
R64KReadTcrEl1:
  mrs x0, tcr_el1
  ret
  .size R64KReadTcrEl1, . - R64KReadTcrEl1

// Return mair_el1 in x0. Preconditions are enforced by the C caller.
  .global R64KReadMairEl1
  .type R64KReadMairEl1, %function
R64KReadMairEl1:
  mrs x0, mair_el1
  ret
  .size R64KReadMairEl1, . - R64KReadMairEl1

// Return sctlr_el1 in x0. Preconditions are enforced by the C caller.
  .global R64KReadSctlrEl1
  .type R64KReadSctlrEl1, %function
R64KReadSctlrEl1:
  mrs x0, sctlr_el1
  ret
  .size R64KReadSctlrEl1, . - R64KReadSctlrEl1

// Return ttbr0_el2 in x0. Preconditions are enforced by the C caller.
  .global R64KReadTtbr0El2
  .type R64KReadTtbr0El2, %function
R64KReadTtbr0El2:
  mrs x0, ttbr0_el2
  ret
  .size R64KReadTtbr0El2, . - R64KReadTtbr0El2

// Return tcr_el2 in x0. Preconditions are enforced by the C caller.
  .global R64KReadTcrEl2
  .type R64KReadTcrEl2, %function
R64KReadTcrEl2:
  mrs x0, tcr_el2
  ret
  .size R64KReadTcrEl2, . - R64KReadTcrEl2

// Return mair_el2 in x0. Preconditions are enforced by the C caller.
  .global R64KReadMairEl2
  .type R64KReadMairEl2, %function
R64KReadMairEl2:
  mrs x0, mair_el2
  ret
  .size R64KReadMairEl2, . - R64KReadMairEl2

// Return sctlr_el2 in x0. Preconditions are enforced by the C caller.
  .global R64KReadSctlrEl2
  .type R64KReadSctlrEl2, %function
R64KReadSctlrEl2:
  mrs x0, sctlr_el2
  ret
  .size R64KReadSctlrEl2, . - R64KReadSctlrEl2

// Return hcr_el2 in x0. Preconditions are enforced by the C caller.
  .global R64KReadHcrEl2
  .type R64KReadHcrEl2, %function
R64KReadHcrEl2:
  mrs x0, hcr_el2
  ret
  .size R64KReadHcrEl2, . - R64KReadHcrEl2

// Probe the VA in x0 without loading target bytes. Return PAR_EL1 in x0.
// Preserve PAR_EL1 and DAIF, masking asynchronous exceptions only for this
// short instruction sequence. No firmware calls occur while masked.
  .global R64KAddressTranslateS1E1R
  .type R64KAddressTranslateS1E1R, %function
R64KAddressTranslateS1E1R:
  mrs x2, daif
  msr daifset, #0xf
  mrs x1, par_el1
  at s1e1r, x0
  isb
  mrs x0, par_el1
  msr par_el1, x1
  msr daif, x2
  ret
  .size R64KAddressTranslateS1E1R, . - R64KAddressTranslateS1E1R

// Probe the VA in x0 without loading target bytes. Return PAR_EL1 in x0.
// Preserve PAR_EL1 and DAIF, masking asynchronous exceptions only for this
// short instruction sequence. No firmware calls occur while masked.
  .global R64KAddressTranslateS1E2R
  .type R64KAddressTranslateS1E2R, %function
R64KAddressTranslateS1E2R:
  mrs x2, daif
  msr daifset, #0xf
  mrs x1, par_el1
  at s1e2r, x0
  isb
  mrs x0, par_el1
  msr par_el1, x1
  msr daif, x2
  ret
  .size R64KAddressTranslateS1E2R, . - R64KAddressTranslateS1E2R

  .section .note.GNU-stack,"",%progbits
