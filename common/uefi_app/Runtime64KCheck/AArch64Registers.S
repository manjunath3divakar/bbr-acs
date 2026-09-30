//
// Copyright (c) 2026, Arm Ltd. All rights reserved.<BR>
// SPDX-License-Identifier: BSD-2-Clause-Patent
//
// AArch64 system-register accessors used by Runtime64KCheck.
//

  .text
  .align 2

  .global ReadTtbr0El1
  .type ReadTtbr0El1, %function
ReadTtbr0El1:
  mrs x0, ttbr0_el1
  ret

  .global ReadTtbr1El1
  .type ReadTtbr1El1, %function
ReadTtbr1El1:
  mrs x0, ttbr1_el1
  ret

  .global ReadTcrEl1
  .type ReadTcrEl1, %function
ReadTcrEl1:
  mrs x0, tcr_el1
  ret

  .global ReadMairEl1
  .type ReadMairEl1, %function
ReadMairEl1:
  mrs x0, mair_el1
  ret

  .global ReadSctlrEl1
  .type ReadSctlrEl1, %function
ReadSctlrEl1:
  mrs x0, sctlr_el1
  ret

  .global ReadTtbr0El2
  .type ReadTtbr0El2, %function
ReadTtbr0El2:
  mrs x0, ttbr0_el2
  ret

  .global ReadTcrEl2
  .type ReadTcrEl2, %function
ReadTcrEl2:
  mrs x0, tcr_el2
  ret

  .global ReadMairEl2
  .type ReadMairEl2, %function
ReadMairEl2:
  mrs x0, mair_el2
  ret

  .global ReadSctlrEl2
  .type ReadSctlrEl2, %function
ReadSctlrEl2:
  mrs x0, sctlr_el2
  ret

  .global ReadHcrEl2
  .type ReadHcrEl2, %function
ReadHcrEl2:
  mrs x0, hcr_el2
  ret

  .global AddressTranslateS1E1R
  .type AddressTranslateS1E1R, %function
AddressTranslateS1E1R:
  at s1e1r, x0
  isb
  mrs x0, par_el1
  ret

  .global AddressTranslateS1E2R
  .type AddressTranslateS1E2R, %function
AddressTranslateS1E2R:
  at s1e2r, x0
  isb
  mrs x0, par_el1
  ret
