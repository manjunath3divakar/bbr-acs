/** @file

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

#define R64K_PAGE_SIZE            0x1000ULL
#define R64K_BLOCK_SIZE           0x10000ULL
#define R64K_PAGES_PER_BLOCK      16U
#define R64K_MAX_CONSTRAINT_BLOCKS  65536U

#define R64K_TRIGGER_RT_CODE       BIT0
#define R64K_TRIGGER_RT_DATA       BIT1
#define R64K_TRIGGER_RESERVED      BIT2
#define R64K_TRIGGER_ACPI_NVS      BIT3

#define R64K_WALK_SUCCESS           0U
#define R64K_WALK_UNMAPPED          1U
#define R64K_WALK_UNSUPPORTED       2U
#define R64K_WALK_UNSAFE_TABLE      3U
#define R64K_WALK_MALFORMED         4U
#define R64K_WALK_TTBR1_NOT_ALLOWED 5U

typedef struct {
  EFI_MEMORY_DESCRIPTOR  *Map;
  UINTN                  MapSize;
  UINTN                  DescriptorSize;
  UINT32                 DescriptorVersion;
} R64K_MEMORY_MAP;

typedef struct {
  UINTN    CurrentEl;
  UINT64   Tcr;
  UINT64   Mair;
  UINT64   Ttbr0;
  UINT64   Ttbr1;
  UINT64   Sctlr;
  UINT64   Hcr;
  BOOLEAN  El2Vhe;
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

EFI_STATUS
R64KGetMemoryMap (
  OUT R64K_MEMORY_MAP  *Snapshot
  );

VOID
R64KFreeMemoryMap (
  IN OUT R64K_MEMORY_MAP  *Snapshot
  );

EFI_MEMORY_DESCRIPTOR *
R64KFindMemoryDescriptor (
  IN R64K_MEMORY_MAP       *Snapshot,
  IN EFI_PHYSICAL_ADDRESS  Address
  );

BOOLEAN
R64KAddressIsConstraintType (
  IN R64K_MEMORY_MAP  *Snapshot,
  IN UINT64           Address
  );

EFI_STATUS
R64KCollectConstraintBlocks (
  IN  R64K_MEMORY_MAP  *Snapshot,
  OUT R64K_BLOCK_INFO  **Blocks,
  OUT UINTN            *BlockCount
  );

EFI_STATUS
R64KInitializeTranslationContext (
  OUT R64K_TRANSLATION_CONTEXT  *Context
  );

UINTN
R64KWalkTranslation (
  IN  R64K_TRANSLATION_CONTEXT  *Context,
  IN  R64K_MEMORY_MAP           *Snapshot,
  IN  UINT64                    VirtualAddress,
  OUT R64K_WALK_RESULT          *Result
  );

CONST CHAR16 *
R64KWalkStatusString (
  IN UINTN  WalkStatus
  );

CONST CHAR16 *
R64KMemoryTypeString (
  IN UINT32  Type
  );

UINT64
EFIAPI
ReadTtbr0El1 (
  VOID
  );
UINT64
EFIAPI
ReadTtbr1El1 (
  VOID
  );
UINT64
EFIAPI
ReadTcrEl1 (
  VOID
  );
UINT64
EFIAPI
ReadMairEl1 (
  VOID
  );
UINT64
EFIAPI
ReadSctlrEl1 (
  VOID
  );
UINT64
EFIAPI
ReadTtbr0El2 (
  VOID
  );
UINT64
EFIAPI
ReadTcrEl2 (
  VOID
  );
UINT64
EFIAPI
ReadMairEl2 (
  VOID
  );
UINT64
EFIAPI
ReadSctlrEl2 (
  VOID
  );
UINT64
EFIAPI
ReadHcrEl2 (
  VOID
  );
UINT64
EFIAPI
AddressTranslateS1E1R (
  IN UINT64  Address
  );
UINT64
EFIAPI
AddressTranslateS1E2R (
  IN UINT64  Address
  );

#endif
