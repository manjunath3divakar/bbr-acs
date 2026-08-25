/** @file
  Shared memory-map, translation context, and register-access interfaces.

  Copyright (c) 2026, Arm Ltd. All rights reserved.<BR>

  This program and the accompanying materials are licensed and made available
  under the terms and conditions of the BSD License which accompanies this
  distribution. The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef AARCH64_PAGE_TABLE_H_
#define AARCH64_PAGE_TABLE_H_

#include <Uefi.h>

#define R64K_PAGE_SIZE              0x1000ULL
#define R64K_BLOCK_SIZE             0x10000ULL
#define R64K_PAGES_PER_BLOCK        16U
#define R64K_MAX_CONSTRAINT_BLOCKS  65536U

#define R64K_TRIGGER_RT_CODE   BIT0
#define R64K_TRIGGER_RT_DATA   BIT1
#define R64K_TRIGGER_RESERVED  BIT2
#define R64K_TRIGGER_ACPI_NVS  BIT3

#define R64K_WALK_SUCCESS            0U
#define R64K_WALK_UNMAPPED           1U
#define R64K_WALK_UNSUPPORTED        2U
#define R64K_WALK_UNSAFE_TABLE       3U
#define R64K_WALK_MALFORMED          4U
#define R64K_WALK_TTBR1_NOT_ALLOWED  5U
#define R64K_WALK_CHANGED            6U

#define R64K_EL1  4U
#define R64K_EL2  8U

typedef struct {
  EFI_MEMORY_DESCRIPTOR  *Map;
  UINTN                  MapSize;
  UINTN                  DescriptorSize;
  UINT32                 DescriptorVersion;
} R64K_MEMORY_MAP;

typedef struct {
  UINTN         CurrentEl;
  UINT64        Tcr;
  UINT64        Mair;
  UINT64        Ttbr0;
  UINT64        Ttbr1;
  UINT64        Sctlr;
  UINT64        Hcr;
  BOOLEAN       El2Vhe;
  BOOLEAN       HierarchicalPermissions;
  UINTN         VaBits;
  UINT64        PaMask;
  CONST CHAR16  *Reason;
} R64K_TRANSLATION_CONTEXT;

typedef struct {
  UINT64  BaseAddress;
  UINT32  TriggerTypes;
} R64K_BLOCK_INFO;

typedef struct {
  BOOLEAN  Mapped;
  UINT64   PhysicalAddress;
  UINT64   Descriptor;
  UINT64   AttributeSignature;
  UINT8    Level;
  UINT8    AttrIndex;
  UINT8    MairAttribute;
  UINT8    AccessPermissions;
  UINT8    Shareability;
  BOOLEAN  PrivilegedExecuteNever;
  BOOLEAN  UnprivilegedExecuteNever;
  BOOLEAN  El2Translation;
  BOOLEAN  UsedTtbr1;
} R64K_WALK_RESULT;

/**
  Allocate and capture a memory map using a bounded retry loop.

  @param[out] Snapshot  Validated map; zeroed on failure. Free with R64KFreeMemoryMap().

  @retval EFI_SUCCESS           A validated map was captured.
  @retval EFI_OUT_OF_RESOURCES  The map is too large or allocation failed.
  @return                      An error from GetMemoryMap() or validation.
**/
EFI_STATUS
R64KGetMemoryMap (
  OUT R64K_MEMORY_MAP  *Snapshot
  );

/**
  Release a captured memory map and clear its owner structure.

  @param[in,out] Snapshot  Captured memory-map state.
**/
VOID
R64KFreeMemoryMap (
  IN OUT R64K_MEMORY_MAP  *Snapshot
  );

/**
  Find the UEFI descriptor containing a physical address.

  @param[in] Snapshot  Validated memory-map snapshot.
  @param[in] Address   Physical address to locate.

  @return The matching descriptor, or NULL when not described or malformed.
**/
EFI_MEMORY_DESCRIPTOR *
R64KFindMemoryDescriptor (
  IN R64K_MEMORY_MAP       *Snapshot,
  IN EFI_PHYSICAL_ADDRESS  Address
  );

/**
  Check whether an address belongs to one of the four selected UEFI types.

  @param[in] Snapshot  Captured memory-map state.
  @param[in] Address   Address to inspect.

  @return TRUE if the condition holds, otherwise FALSE.
**/
BOOLEAN
R64KAddressIsConstraintType (
  IN R64K_MEMORY_MAP  *Snapshot,
  IN UINT64           Address
  );

/**
  Build a sorted, deduplicated list of all selected physical 64 KiB blocks.

  The first and last included bytes are aligned down. This is equivalent
  to rounding an exclusive end up. Bounds are checked
  before rounding, summing capacities, allocating, or advancing pointers.
  Allocation is bounded by R64K_MAX_CONSTRAINT_BLOCKS, including duplicates.

  @param[in]  Snapshot    Captured memory map.
  @param[out] Blocks      Allocated block list, or NULL on error.
  @param[out] BlockCount  Number of unique blocks, or zero on error.

  @retval EFI_SUCCESS           Blocks were collected.
  @retval EFI_NOT_FOUND         No descriptor selected any blocks.
  @retval EFI_OUT_OF_RESOURCES  The configured limit or allocation was exceeded.
  @return                      A parameter or memory-map validation error.
**/
EFI_STATUS
R64KCollectConstraintBlocks (
  IN  R64K_MEMORY_MAP  *Snapshot,
  OUT R64K_BLOCK_INFO  **Blocks,
  OUT UINTN            *BlockCount
  );

/**
  Capture and validate the supported AArch64 translation configuration.

  EL2 registers are never read at EL1. No TTBR1_EL2 register is accessed.
  The walker supports baseline 4 KiB, 64-bit descriptors, 25..48 VA bits and
  at most 48 output bits. New extended permission/table formats are rejected
  conservatively before accessing their optional control registers.

  @param[out] Context  Captured state. Reason describes unsupported state.

  @retval EFI_SUCCESS            Supported context captured.
  @retval EFI_INVALID_PARAMETER  Context is NULL.
  @retval EFI_UNSUPPORTED        Configuration cannot be interpreted safely.
**/
EFI_STATUS
R64KInitializeTranslationContext (
  OUT R64K_TRANSLATION_CONTEXT  *Context
  );

/**
  Walk a baseline stage-1 mapping without reading the target memory page.

  TTBR1 ranges are rejected before any TTBR1 table is read. The initial
  TTBR0 table may be smaller than a page; subsequent tables are 4 KiB.
  A changing table/context returns an incomplete result, not UNMAPPED.

  @param[in]  Context         Supported register snapshot.
  @param[in]  Snapshot        Validated UEFI memory map.
  @param[in]  VirtualAddress  Untagged address to translate.
  @param[out] Result          Translation and attributes; valid on success.

  @return One of the R64K_WALK_* status constants.
**/
UINTN
R64KWalkTranslation (
  IN  R64K_TRANSLATION_CONTEXT  *Context,
  IN  R64K_MEMORY_MAP           *Snapshot,
  IN  UINT64                    VirtualAddress,
  OUT R64K_WALK_RESULT          *Result
  );

/**
  Convert a page-walk status into a constant diagnostic string.

  @param[in] WalkStatus  Status returned by R64KWalkTranslation().

  @return The matching constant diagnostic string, or the documented default.
**/
CONST CHAR16 *
R64KWalkStatusString (
  IN UINTN  WalkStatus
  );

/**
  Convert a UEFI memory type into a constant diagnostic string.

  @param[in] Type  UEFI memory type.

  @return The matching constant diagnostic string, or the documented default.
**/
CONST CHAR16 *
R64KMemoryTypeString (
  IN UINT32  Type
  );

/**
  Read Ttbr0El1 for the translation checker.

  @pre Execute at EL1; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadTtbr0El1 (
  VOID
  );
/**
  Read Ttbr1El1 for the translation checker.

  @pre Execute at EL1; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadTtbr1El1 (
  VOID
  );
/**
  Read TcrEl1 for the translation checker.

  @pre Execute at EL1; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadTcrEl1 (
  VOID
  );
/**
  Read MairEl1 for the translation checker.

  @pre Execute at EL1; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadMairEl1 (
  VOID
  );
/**
  Read SctlrEl1 for the translation checker.

  @pre Execute at EL1; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadSctlrEl1 (
  VOID
  );
/**
  Read Ttbr0El2 for the translation checker.

  @pre Execute at non-VHE EL2; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadTtbr0El2 (
  VOID
  );
/**
  Read TcrEl2 for the translation checker.

  @pre Execute at non-VHE EL2; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadTcrEl2 (
  VOID
  );
/**
  Read MairEl2 for the translation checker.

  @pre Execute at non-VHE EL2; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadMairEl2 (
  VOID
  );
/**
  Read SctlrEl2 for the translation checker.

  @pre Execute at non-VHE EL2; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadSctlrEl2 (
  VOID
  );
/**
  Read HcrEl2 for the translation checker.

  @pre Execute at non-VHE EL2; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadHcrEl2 (
  VOID
  );
/**
  Probe an address using the EL1 stage-1 read-translation instruction.

  PAR_EL1 and DAIF are restored. The target memory is not dereferenced.
  System-register traps to higher firmware are outside this helper's control.

  @param[in] Address  Virtual address to probe.
  @pre Execute at EL1 with system-register access permitted.
  @return Translation result from PAR_EL1.
**/
UINT64
EFIAPI
R64KAddressTranslateS1E1R (
  IN UINT64  Address
  );
/**
  Probe an address using the EL2 (non-VHE) stage-1 read-translation instruction.

  PAR_EL1 and DAIF are restored. The target memory is not dereferenced.
  System-register traps to higher firmware are outside this helper's control.

  @param[in] Address  Virtual address to probe.
  @pre Execute at EL2 (non-VHE) with system-register access permitted.
  @return Translation result from PAR_EL1.
**/
UINT64
EFIAPI
R64KAddressTranslateS1E2R (
  IN UINT64  Address
  );

/**
  Read CurrentEl for the translation checker.

  @pre Execute at EL1 or non-VHE EL2; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadCurrentEl (
  VOID
  );

/**
  Read Mmfr3 for the translation checker.

  @pre Execute at EL1 or non-VHE EL2; the C caller checks CurrentEL first.
  @return Raw architectural register value.
**/
UINT64
EFIAPI
R64KReadMmfr3 (
  VOID
  );

#endif
