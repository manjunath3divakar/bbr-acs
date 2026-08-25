/** @file
  Bounded AArch64 stage-1 inspection for the UEFI 64 KiB attribute check.

  Copyright (c) 2026, Arm Ltd. All rights reserved.<BR>

  This program and the accompanying materials are licensed and made available
  under the terms and conditions of the BSD License which accompanies this
  distribution. The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "AArch64PageTable.h"

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#define TTBR_BADDR_MASK_48      0x0000FFFFFFFFF000ULL
#define DESC_VALID              BIT0
#define DESC_TYPE               BIT1
#define DESC_PXN                BIT53
#define DESC_UXN                BIT54
#define SCTLR_M                 BIT0
#define HCR_E2H                 BIT34
#define R64K_TCR_EL1_DS         BIT59
#define R64K_TCR_EL2_DS         BIT32
#define R64K_TCR_EL1_HPD0       BIT41
#define R64K_TCR_EL2_HPD        BIT24
#define R64K_TCR_EL1_EPD0       BIT7
#define R64K_SCTLR_EE           BIT25
#define R64K_SCTLR_WXN          BIT19
#define R64K_TTBR_ADDRESS_MASK  0x0000FFFFFFFFFFFEULL
#define R64K_DESC_ADDRESS_MASK  0x0000FFFFFFFFF000ULL
#define R64K_MAX_MAP_SIZE       (16U * 1024U * 1024U)
#define PAR_FAULT               BIT0
#define MAX_MEMORY_MAP_RETRIES  4U

/**
  Determine whether a UEFI memory descriptor selects 64 KiB blocks.

  @param[in] Descriptor  UEFI memory descriptor to inspect; NULL is accepted.

  @return TRUE if the condition holds, otherwise FALSE.
**/
STATIC
BOOLEAN
Is64KConstraintDescriptor (
  IN CONST EFI_MEMORY_DESCRIPTOR  *Descriptor
  )
{
  if (Descriptor == NULL) {
    return FALSE;
  }

  // UEFI AArch64 64 KiB compatibility rule: if a physical 64 KiB
  // page contains any 4 KiB page of one of these four UEFI memory
  // types, all mapped 4 KiB pages in the physical 64 KiB page must
  // use identical ARM memory page attributes. EFI_MEMORY_RUNTIME
  // is not a prerequisite for selecting these descriptor types.
  switch (Descriptor->Type) {
    case EfiRuntimeServicesCode:
    case EfiRuntimeServicesData:
    case EfiReservedMemoryType:
    case EfiACPIMemoryNVS:
      return TRUE;

    default:
      return FALSE;
  }
}

/**
  Convert a selected UEFI memory type into its block-selection flag.

  @param[in] Type  UEFI memory type.

  @return The corresponding R64K_TRIGGER_* bit, or zero for other types.
**/
STATIC
UINT32
MemoryTypeToTriggerFlag (
  IN EFI_MEMORY_TYPE  Type
  )
{
  switch (Type) {
    case EfiRuntimeServicesCode:
      return R64K_TRIGGER_RT_CODE;
    case EfiRuntimeServicesData:
      return R64K_TRIGGER_RT_DATA;
    case EfiReservedMemoryType:
      return R64K_TRIGGER_RESERVED;
    case EfiACPIMemoryNVS:
      return R64K_TRIGGER_ACPI_NVS;
    default:
      return 0;
  }
}

/**
  Check whether table storage has an ordinary RAM-like UEFI memory type.

  @param[in] Descriptor  UEFI memory descriptor to inspect; NULL is accepted.

  @return TRUE if the condition holds, otherwise FALSE.
**/
STATIC
BOOLEAN
IsRamLikeDescriptor (
  IN EFI_MEMORY_DESCRIPTOR  *Descriptor
  )
{
  if (Descriptor == NULL) {
    return FALSE;
  }

  switch (Descriptor->Type) {
    case EfiLoaderCode:
    case EfiLoaderData:
    case EfiBootServicesCode:
    case EfiBootServicesData:
    case EfiRuntimeServicesCode:
    case EfiRuntimeServicesData:
    case EfiConventionalMemory:
    case EfiACPIReclaimMemory:
    case EfiACPIMemoryNVS:
    case EfiPersistentMemory:
      return TRUE;
    default:
      return FALSE;
  }
}

/**
  Validate the layout and physical ranges of a captured UEFI memory map.

  @param[in] Snapshot  Captured memory map.

  @retval EFI_SUCCESS            The descriptor buffer and ranges are valid.
  @retval EFI_INVALID_PARAMETER  A required pointer is NULL.
  @retval EFI_COMPROMISED_DATA   The descriptor buffer or a range is malformed.
**/
STATIC
EFI_STATUS
ValidateMemoryMap (
  IN CONST R64K_MEMORY_MAP  *Snapshot
  )
{
  CONST EFI_MEMORY_DESCRIPTOR  *Descriptor;
  UINTN                        Offset;

  if ((Snapshot == NULL) || (Snapshot->Map == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Snapshot->DescriptorSize < sizeof (EFI_MEMORY_DESCRIPTOR)) ||
      ((Snapshot->DescriptorSize % sizeof (UINT64)) != 0U) ||
      (Snapshot->MapSize == 0U) || (Snapshot->MapSize > R64K_MAX_MAP_SIZE) ||
      ((Snapshot->MapSize % Snapshot->DescriptorSize) != 0U) ||
      (((UINTN)Snapshot->Map % sizeof (UINT64)) != 0U)) {
    return EFI_COMPROMISED_DATA;
  }

  for (Offset = 0; Offset < Snapshot->MapSize; Offset += Snapshot->DescriptorSize) {
    Descriptor = (CONST EFI_MEMORY_DESCRIPTOR *)((CONST UINT8 *)Snapshot->Map + Offset);
    if (((Descriptor->PhysicalStart & (R64K_PAGE_SIZE - 1ULL)) != 0ULL) ||
        (Descriptor->NumberOfPages == 0ULL) ||
        (Descriptor->NumberOfPages > ((MAX_UINT64 - Descriptor->PhysicalStart) / R64K_PAGE_SIZE))) {
      return EFI_COMPROMISED_DATA;
    }
  }

  return EFI_SUCCESS;
}

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
  )
{
  EFI_STATUS  Status;
  UINTN       MapKey;
  UINTN       RequiredSize;
  UINTN       AllocationSize;
  UINTN       DescriptorSize;
  UINT32      DescriptorVersion;
  UINTN       Retry;
  UINTN       Slack;

  if (Snapshot == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Snapshot, sizeof (*Snapshot));
  if ((gBS == NULL) || (gBS->GetMemoryMap == NULL)) {
    return EFI_UNSUPPORTED;
  }

  RequiredSize      = 0;
  DescriptorSize    = 0;
  DescriptorVersion = 0;
  Status            = gBS->GetMemoryMap (&RequiredSize, NULL, &MapKey, &DescriptorSize, &DescriptorVersion);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA;
  }

  for (Retry = 0; Retry < MAX_MEMORY_MAP_RETRIES; Retry++) {
    if ((DescriptorSize < sizeof (EFI_MEMORY_DESCRIPTOR)) ||
        (DescriptorSize > R64K_MAX_MAP_SIZE / 8U) ||
        ((DescriptorSize % sizeof (UINT64)) != 0U)) {
      Status = EFI_COMPROMISED_DATA;
      break;
    }

    Slack = DescriptorSize * 8U + (UINTN)(2U * R64K_PAGE_SIZE);
    if ((Slack > R64K_MAX_MAP_SIZE) || (RequiredSize > R64K_MAX_MAP_SIZE - Slack)) {
      Status = EFI_OUT_OF_RESOURCES;
      break;
    }

    AllocationSize = RequiredSize + Slack;
    Snapshot->Map  = AllocatePool (AllocationSize);
    if (Snapshot->Map == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      break;
    }

    Snapshot->MapSize = AllocationSize;
    Status            = gBS->GetMemoryMap (
                    &Snapshot->MapSize,
                    Snapshot->Map,
                    &MapKey,
                    &Snapshot->DescriptorSize,
                    &Snapshot->DescriptorVersion
                    );
    if (!EFI_ERROR (Status)) {
      if (Snapshot->MapSize > AllocationSize) {
        Status = EFI_COMPROMISED_DATA;
      } else {
        Status = ValidateMemoryMap (Snapshot);
      }

      if (!EFI_ERROR (Status)) {
        return EFI_SUCCESS;
      }
    }

    RequiredSize   = Snapshot->MapSize;
    DescriptorSize = Snapshot->DescriptorSize;
    FreePool (Snapshot->Map);
    Snapshot->Map = NULL;
    if (Status != EFI_BUFFER_TOO_SMALL) {
      break;
    }
  }

  ZeroMem (Snapshot, sizeof (*Snapshot));
  return Status;
}

/**
  Release a captured memory map and clear its owner structure.

  @param[in,out] Snapshot  Captured memory-map state.
**/
VOID
R64KFreeMemoryMap (
  IN OUT R64K_MEMORY_MAP  *Snapshot
  )
{
  if ((Snapshot != NULL) && (Snapshot->Map != NULL)) {
    FreePool (Snapshot->Map);
    ZeroMem (Snapshot, sizeof (*Snapshot));
  }
}

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
  )
{
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  UINTN                  Offset;
  UINT64                 Size;

  if ((Snapshot == NULL) || (Snapshot->Map == NULL) ||
      (Snapshot->DescriptorSize < sizeof (EFI_MEMORY_DESCRIPTOR)) ||
      ((Snapshot->DescriptorSize % sizeof (UINT64)) != 0U) ||
      ((Snapshot->MapSize % Snapshot->DescriptorSize) != 0U)) {
    return NULL;
  }

  for (Offset = 0; Offset < Snapshot->MapSize; Offset += Snapshot->DescriptorSize) {
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Snapshot->Map + Offset);
    if ((Descriptor->NumberOfPages == 0ULL) ||
        (Descriptor->NumberOfPages > (MAX_UINT64 - Descriptor->PhysicalStart) / R64K_PAGE_SIZE)) {
      continue;
    }

    Size = Descriptor->NumberOfPages * R64K_PAGE_SIZE;
    if ((Address >= Descriptor->PhysicalStart) && (Address - Descriptor->PhysicalStart < Size)) {
      return Descriptor;
    }
  }

  return NULL;
}

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
  )
{
  EFI_MEMORY_DESCRIPTOR  *Descriptor;

  Descriptor = R64KFindMemoryDescriptor (Snapshot, Address);
  return Is64KConstraintDescriptor (Descriptor);
}

/**
  Restore a max-heap after moving an element in a block list.

  @param[in,out] List   Block list.
  @param[in]     Root   Root of the subtree to restore.
  @param[in]     Count  Number of entries in the heap.
**/
STATIC
VOID
SiftBlocks (
  IN OUT R64K_BLOCK_INFO  *List,
  IN     UINTN            Root,
  IN     UINTN            Count
  )
{
  UINTN            Child;
  R64K_BLOCK_INFO  Swap;

  while (Root < Count / 2U) {
    Child = Root * 2U + 1U;
    if ((Child + 1U < Count) && (List[Child].BaseAddress < List[Child + 1U].BaseAddress)) {
      Child++;
    }

    if (List[Root].BaseAddress >= List[Child].BaseAddress) {
      break;
    }

    Swap        = List[Root];
    List[Root]  = List[Child];
    List[Child] = Swap;
    Root        = Child;
  }
}

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
  )
{
  EFI_STATUS             Status;
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  R64K_BLOCK_INFO        *List;
  R64K_BLOCK_INFO        Swap;
  UINTN                  Offset;
  UINTN                  Capacity;
  UINTN                  Count;
  UINTN                  Unique;
  UINTN                  Index;
  UINT64                 Start;
  UINT64                 Last;
  UINT64                 Block;
  UINT64                 Needed;

  if ((Blocks == NULL) || (BlockCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *Blocks     = NULL;
  *BlockCount = 0;
  Status      = ValidateMemoryMap (Snapshot);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Capacity = 0;
  for (Offset = 0; Offset < Snapshot->MapSize; Offset += Snapshot->DescriptorSize) {
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Snapshot->Map + Offset);
    if (!Is64KConstraintDescriptor (Descriptor)) {
      continue;
    }

    Start = Descriptor->PhysicalStart & ~(R64K_BLOCK_SIZE - 1ULL);
    Last  = Descriptor->PhysicalStart + Descriptor->NumberOfPages * R64K_PAGE_SIZE - 1ULL;
    Last &= ~(R64K_BLOCK_SIZE - 1ULL);
    Needed = (Last - Start) / R64K_BLOCK_SIZE + 1ULL;
    if (Needed > R64K_MAX_CONSTRAINT_BLOCKS - Capacity) {
      return EFI_OUT_OF_RESOURCES;
    }

    Capacity += (UINTN)Needed;
  }

  if (Capacity == 0U) {
    return EFI_NOT_FOUND;
  }

  if (Capacity > MAX_UINTN / sizeof (*List)) {
    return EFI_OUT_OF_RESOURCES;
  }

  List = AllocateZeroPool (Capacity * sizeof (*List));
  if (List == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Count = 0;
  for (Offset = 0; Offset < Snapshot->MapSize; Offset += Snapshot->DescriptorSize) {
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Snapshot->Map + Offset);
    if (!Is64KConstraintDescriptor (Descriptor)) {
      continue;
    }

    Start = Descriptor->PhysicalStart & ~(R64K_BLOCK_SIZE - 1ULL);
    Last  = Descriptor->PhysicalStart + Descriptor->NumberOfPages * R64K_PAGE_SIZE - 1ULL;
    Last &= ~(R64K_BLOCK_SIZE - 1ULL);
    Block = Start;
    for (;;) {
      if (Count >= Capacity) {
        FreePool (List);
        return EFI_COMPROMISED_DATA;
      }

      List[Count].BaseAddress  = Block;
      List[Count].TriggerTypes = MemoryTypeToTriggerFlag ((EFI_MEMORY_TYPE)Descriptor->Type);
      Count++;
      if (Block == Last) {
        break;
      }

      Block += R64K_BLOCK_SIZE;
    }
  }

  for (Index = Count / 2U; Index > 0U; Index--) {
    SiftBlocks (List, Index - 1U, Count);
  }

  for (Index = Count; Index > 1U; Index--) {
    Swap             = List[0];
    List[0]          = List[Index - 1U];
    List[Index - 1U] = Swap;
    SiftBlocks (List, 0, Index - 1U);
  }

  Unique = 0;
  for (Index = 0; Index < Count; Index++) {
    if ((Unique != 0U) && (List[Unique - 1U].BaseAddress == List[Index].BaseAddress)) {
      List[Unique - 1U].TriggerTypes |= List[Index].TriggerTypes;
    } else {
      List[Unique++] = List[Index];
    }
  }

  *Blocks     = List;
  *BlockCount = Unique;
  return EFI_SUCCESS;
}

/**
  Check the granule encoding for a selected translation range.

  @param[in] Tcr        Translation control register value.
  @param[in] UseTtbr1   TRUE for the upper EL1 range; FALSE for TTBR0.
  @param[in] El2NonVhe  TRUE for the single-range EL2 translation regime.

  @return TRUE if the condition holds, otherwise FALSE.
**/
STATIC
BOOLEAN
IsFourKilobyteGranule (
  IN UINT64   Tcr,
  IN BOOLEAN  UseTtbr1,
  IN BOOLEAN  El2NonVhe
  )
{
  UINT64  Tg;

  if (El2NonVhe || !UseTtbr1) {
    Tg = (Tcr >> 14) & 0x3ULL;
    return (BOOLEAN)(Tg == 0);
  }

  Tg = (Tcr >> 30) & 0x3ULL;
  return (BOOLEAN)(Tg == 2);
}

/**
  Decode the number of virtual address bits from the selected TCR size field.

  @param[in] Tcr        Translation control register value.
  @param[in] UseTtbr1   TRUE for the upper EL1 range; FALSE for TTBR0.
  @param[in] El2NonVhe  TRUE for the single-range EL2 translation regime.

  @return Virtual address width, or zero for an invalid encoding.
**/
STATIC
UINTN
GetVaBits (
  IN UINT64   Tcr,
  IN BOOLEAN  UseTtbr1,
  IN BOOLEAN  El2NonVhe
  )
{
  UINTN  Tsz;

  if (El2NonVhe || !UseTtbr1) {
    Tsz = (UINTN)(Tcr & 0x3FULL);
  } else {
    Tsz = (UINTN)((Tcr >> 16) & 0x3FULL);
  }

  if (Tsz >= 64U) {
    return 0;
  }

  return 64U - Tsz;
}

/**
  Select a translation range; selecting TTBR1 does not read its tables.

  The walker rejects a TRUE UseTtbr1 result before touching table memory.

  @param[in]  Context         Captured, supported translation configuration.
  @param[in]  VirtualAddress  Untagged virtual address to classify or translate.
  @param[out] UseTtbr1        TRUE for the upper EL1 range; FALSE for TTBR0.
  @param[out] Ttbr            Selected translation table base register value.
  @param[out] VaBits          Number of virtual address bits for this range.

  @return TRUE for a supported address range, or FALSE when it cannot be selected.
**/
STATIC
BOOLEAN
SelectTranslationBase (
  IN  R64K_TRANSLATION_CONTEXT  *Context,
  IN  UINT64                    VirtualAddress,
  OUT BOOLEAN                   *UseTtbr1,
  OUT UINT64                    *Ttbr,
  OUT UINTN                     *VaBits
  )
{
  UINTN   VaBits0;
  UINTN   VaBits1;
  UINT64  LowerLimit;
  UINT64  UpperBase;

  *UseTtbr1 = FALSE;
  *Ttbr     = 0;
  *VaBits   = 0;

  if ((Context->CurrentEl == R64K_EL2) && !Context->El2Vhe) {
    VaBits0 = GetVaBits (Context->Tcr, FALSE, TRUE);
    if ((VaBits0 < 25U) || (VaBits0 > 48U)) {
      return FALSE;
    }

    LowerLimit = 1ULL << VaBits0;
    if (VirtualAddress >= LowerLimit) {
      return FALSE;
    }

    *Ttbr   = Context->Ttbr0;
    *VaBits = VaBits0;
    return TRUE;
  }

  VaBits0 = GetVaBits (Context->Tcr, FALSE, FALSE);
  VaBits1 = GetVaBits (Context->Tcr, TRUE, FALSE);

  if ((VaBits0 >= 25U) && (VaBits0 <= 48U)) {
    LowerLimit = 1ULL << VaBits0;
    if (VirtualAddress < LowerLimit) {
      *Ttbr   = Context->Ttbr0;
      *VaBits = VaBits0;
      return TRUE;
    }
  }

  if ((VaBits1 >= 25U) && (VaBits1 <= 48U)) {
    UpperBase = MAX_UINT64 - ((1ULL << VaBits1) - 1ULL);
    if (VirtualAddress >= UpperBase) {
      *UseTtbr1 = TRUE;
      *Ttbr     = Context->Ttbr1;
      *VaBits   = VaBits1;
      return TRUE;
    }
  }

  return FALSE;
}

/**
  Calculate the initial lookup level for a baseline 4 KiB translation.

  @param[in] VaBits  Number of virtual address bits for this range.

  @return Initial level 0..3, or 4 for an unsupported address width.
**/
STATIC
UINTN
GetStartLevelFor4K (
  IN UINTN  VaBits
  )
{
  UINTN  IndexBits;
  UINTN  Levels;

  if ((VaBits < 25U) || (VaBits > 48U)) {
    return 4U;
  }

  IndexBits = VaBits - 12U;
  Levels    = (IndexBits + 8U) / 9U;
  if ((Levels == 0U) || (Levels > 4U)) {
    return 4U;
  }

  return 4U - Levels;
}

/**
  Probe read translation at the current EL without loading target memory.

  @param[in] Context  Captured, supported translation configuration.
  @param[in] Address  Address to inspect.

  @return PAR_EL1 as returned by AT; a set bit 0 reports a translation fault.
**/
STATIC
UINT64
TranslateAddressForRead (
  IN R64K_TRANSLATION_CONTEXT  *Context,
  IN UINT64                    Address
  )
{
  if (Context->CurrentEl == R64K_EL1) {
    return R64KAddressTranslateS1E1R (Address);
  }

  return R64KAddressTranslateS1E2R (Address);
}

/**
  Check that a table byte range is RAM-like and identity-readable.

  This is a preflight, not an exception handler. It cannot prevent a later
  external abort, a concurrent remap, or a system-register trap to a higher EL.
  AT checks translations without loading the target table bytes.

  @param[in] Context    Supported current translation context.
  @param[in] Snapshot   Validated memory map.
  @param[in] TableBase  Table address, possibly a sub-page initial table.
  @param[in] TableSize  Actual table size in bytes (16 to 4096).

  @retval TRUE   Both endpoints are identity-readable Normal memory.
  @retval FALSE  Access must not be attempted.
**/
STATIC
BOOLEAN
CanSafelyReadTable (
  IN R64K_TRANSLATION_CONTEXT  *Context,
  IN R64K_MEMORY_MAP           *Snapshot,
  IN UINT64                    TableBase,
  IN UINTN                     TableSize
  )
{
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  UINT64                 End;
  UINT64                 Par;
  UINT64                 Address;
  UINT64                 Translated;
  UINTN                  Endpoint;

  if ((TableBase == 0ULL) || (TableSize < 16U) || (TableSize > R64K_PAGE_SIZE) ||
      ((TableSize & (TableSize - 1U)) != 0U) ||
      ((TableBase & (TableSize - 1U)) != 0ULL) ||
      (TableBase > MAX_UINT64 - (TableSize - 1U))) {
    return FALSE;
  }

  End        = TableBase + TableSize - 1U;
  Descriptor = R64KFindMemoryDescriptor (Snapshot, TableBase);
  if (!IsRamLikeDescriptor (Descriptor) ||
      (R64KFindMemoryDescriptor (Snapshot, End) != Descriptor)) {
    return FALSE;
  }

  for (Endpoint = 0; Endpoint < 2U; Endpoint++) {
    Address = (Endpoint == 0U) ? TableBase : End;
    Par     = TranslateAddressForRead (Context, Address);
    if (((Par & PAR_FAULT) != 0ULL) || (((Par >> 56) & 0xF0ULL) == 0ULL)) {
      return FALSE;
    }

    Translated = (Par & TTBR_BADDR_MASK_48) | (Address & (R64K_PAGE_SIZE - 1ULL));
    if (Translated != Address) {
      return FALSE;
    }
  }

  return TRUE;
}

/**
  Pack the compared memory, shareability, and access-permission attributes.

  Descriptor includes inherited table restrictions applied by the caller.

  @param[in]  Descriptor     Final mapping descriptor, including inherited table permissions.
  @param[in]  Mair           Memory attribute register value.
  @param[in]  CurrentEl      Current exception level encoding (4 for EL1, 8 for EL2).
  @param[out] AttrIndex      Descriptor MAIR index, retained for diagnostics only.
  @param[out] MairAttribute  Resolved byte selected from MAIR.

  @return An equality-comparison signature; raw AttrIndx and metadata are excluded.
**/
STATIC
UINT64
BuildAttributeSignature (
  IN  UINT64  Descriptor,
  IN  UINT64  Mair,
  IN  UINTN   CurrentEl,
  OUT UINT8   *AttrIndex,
  OUT UINT8   *MairAttribute
  )
{
  UINT64  Signature;
  UINT64  Shareability;
  UINT64  ReadOnly;
  UINT64  ExecutePermission;

  *AttrIndex     = (UINT8)((Descriptor >> 2) & 0x7ULL);
  *MairAttribute = (UINT8)((Mair >> (*AttrIndex * 8U)) & 0xFFULL);

  //
  // The comparison intentionally uses the effective ARM attributes that
  // correspond to the UEFI AArch64 mappings in Tables 2.5 and 2.6:
  //
  //   Table 2.5: effective MAIR Attr<n> encoding and SH[1:0].
  //   Table 2.6: EFI_MEMORY_RO -> AP[2], and EFI_MEMORY_XP ->
  //              PXN/UXN for the EL1/0 translation regime or XN for EL2.
  //
  // Raw AttrIndx is not compared because different indices may resolve to
  // the same MAIR Attr<n> byte.  AP[1], NS, DBM, AF, nG and Contiguous are
  // not part of this signature.
  //
  // Signature layout used only for equality comparison and logging:
  //   [7:0]   resolved MAIR Attr<n> byte
  //   [9:8]   SH[1:0]
  //   [10]    AP[2] (1 == read-only)
  //   [12:11] EL1: bit11=PXN, bit12=UXN
  //            EL2: bit11=XN,  bit12=0
  //
  Shareability = (Descriptor >> 8) & 0x3ULL;
  ReadOnly     = (Descriptor >> 7) & 0x1ULL;

  if (CurrentEl == R64K_EL1) {
    ExecutePermission  = ((Descriptor >> 53) & 0x1ULL) << 11;
    ExecutePermission |= ((Descriptor >> 54) & 0x1ULL) << 12;
  } else {
    // Table 2.6 defines a single XN attribute for the EL2 translation
    // regime.  For stage-1 EL2 descriptors it is encoded in bit[54].
    ExecutePermission = ((Descriptor >> 54) & 0x1ULL) << 11;
  }

  Signature  = (UINT64)(*MairAttribute);
  Signature |= Shareability << 8;
  Signature |= ReadOnly << 10;
  Signature |= ExecutePermission;
  return Signature;
}

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
  )
{
  UINTN        Ps;
  CONST UINT8  PaWidths[] = { 32, 36, 40, 42, 44, 48 };
  UINT64       Mmfr3;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (*Context));
  Context->Reason    = L"Unsupported exception level (EL1 or non-VHE EL2 is required)";
  Context->CurrentEl = (UINTN)R64KReadCurrentEl ();
  if (Context->CurrentEl == R64K_EL1) {
    Context->Ttbr0 = R64KReadTtbr0El1 ();
    Context->Ttbr1 = R64KReadTtbr1El1 ();
    Context->Tcr   = R64KReadTcrEl1 ();
    Context->Mair  = R64KReadMairEl1 ();
    Context->Sctlr = R64KReadSctlrEl1 ();
  } else if (Context->CurrentEl == R64K_EL2) {
    Context->Hcr    = R64KReadHcrEl2 ();
    Context->El2Vhe = (BOOLEAN)((Context->Hcr & HCR_E2H) != 0ULL);
    if (Context->El2Vhe) {
      Context->Reason = L"EL2 VHE is not supported";
      return EFI_UNSUPPORTED;
    }

    Context->Ttbr0 = R64KReadTtbr0El2 ();
    Context->Tcr   = R64KReadTcrEl2 ();
    Context->Mair  = R64KReadMairEl2 ();
    Context->Sctlr = R64KReadSctlrEl2 ();
  } else {
    return EFI_UNSUPPORTED;
  }

  if ((Context->Sctlr & SCTLR_M) == 0ULL) {
    Context->Reason = L"The stage-1 MMU is disabled";
    return EFI_UNSUPPORTED;
  }

  if ((Context->Sctlr & (R64K_SCTLR_EE | R64K_SCTLR_WXN)) != 0ULL) {
    Context->Reason = L"Big-endian translation or SCTLR.WXN requires an unsupported interpretation";
    return EFI_UNSUPPORTED;
  }

  if (!IsFourKilobyteGranule (Context->Tcr, FALSE, (BOOLEAN)(Context->CurrentEl == R64K_EL2))) {
    Context->Reason = L"The TTBR0 translation granule is not 4 KiB";
    return EFI_UNSUPPORTED;
  }

  if (Context->CurrentEl == R64K_EL1) {
    if ((Context->Tcr & (R64K_TCR_EL1_DS | BIT37 | BIT40 | R64K_TCR_EL1_EPD0)) != 0ULL) {
      Context->Reason = L"EL1 LPA2, TBI0, hardware dirty management, or EPD0 is enabled";
      return EFI_UNSUPPORTED;
    }

    Ps                               = (UINTN)((Context->Tcr >> 32) & 7ULL);
    Context->HierarchicalPermissions = (BOOLEAN)((Context->Tcr & R64K_TCR_EL1_HPD0) == 0ULL);
  } else {
    if ((Context->Tcr & (R64K_TCR_EL2_DS | BIT20 | BIT22)) != 0ULL) {
      Context->Reason = L"EL2 LPA2, tagged-address translation, or hardware dirty management is enabled";
      return EFI_UNSUPPORTED;
    }

    Ps                               = (UINTN)((Context->Tcr >> 16) & 7ULL);
    Context->HierarchicalPermissions = (BOOLEAN)((Context->Tcr & R64K_TCR_EL2_HPD) == 0ULL);
  }

  if (Ps >= ARRAY_SIZE (PaWidths)) {
    Context->Reason = L"Output address widths above 48 bits are not supported";
    return EFI_UNSUPPORTED;
  }

  Context->PaMask = (1ULL << PaWidths[Ps]) - 1ULL;
  Context->VaBits = GetVaBits (Context->Tcr, FALSE, (BOOLEAN)(Context->CurrentEl == R64K_EL2));
  if ((Context->VaBits < 25U) || (Context->VaBits > 48U)) {
    Context->Reason = L"Only baseline virtual address widths of 25..48 bits are supported";
    return EFI_UNSUPPORTED;
  }

  // ID_AA64MMFR3_EL1 is an architectural ID register (RAZ for absent features).
  // Avoid reading optional TCR2/permission registers. Conservatively decline
  // CPUs advertising those formats until their enabled state is decoded.
  Mmfr3 = R64KReadMmfr3 ();
  if ((Mmfr3 & 0x0000000F0F0F0F0FULL) != 0ULL) {
    Context->Reason = L"TCR2, extended permissions, MAIR indirection extensions, or D128 are unsupported";
    return EFI_UNSUPPORTED;
  }

  Context->Reason = L"Supported baseline EL1/non-VHE EL2 translation context";
  return EFI_SUCCESS;
}

/**
  Test whether the control registers still match the captured context.

  @param[in] Context  Original register snapshot.

  @retval TRUE   The registers read by this walker are unchanged.
  @retval FALSE  CurrentEL or translation controls changed; stop the walk.
**/
STATIC
BOOLEAN
ContextUnchanged (
  IN CONST R64K_TRANSLATION_CONTEXT  *Context
  )
{
  if (R64KReadCurrentEl () != Context->CurrentEl) {
    return FALSE;
  }

  if (Context->CurrentEl == R64K_EL1) {
    return (BOOLEAN)((R64KReadTtbr0El1 () == Context->Ttbr0) &&
                     (R64KReadTcrEl1 () == Context->Tcr) &&
                     (R64KReadMairEl1 () == Context->Mair) &&
                     (R64KReadSctlrEl1 () == Context->Sctlr));
  }

  return (BOOLEAN)((Context->CurrentEl == R64K_EL2) &&
                   (R64KReadHcrEl2 () == Context->Hcr) &&
                   (R64KReadTtbr0El2 () == Context->Ttbr0) &&
                   (R64KReadTcrEl2 () == Context->Tcr) &&
                   (R64KReadMairEl2 () == Context->Mair) &&
                   (R64KReadSctlrEl2 () == Context->Sctlr));
}

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
  )
{
  BOOLEAN  UseTtbr1;
  UINT64   Ttbr;
  UINTN    VaBits;
  UINTN    StartLevel;
  UINTN    Level;
  UINTN    Shift;
  UINTN    Index;
  UINTN    EntryCount;
  UINTN    TableSize;
  UINT64   TableBase;
  UINT64   Descriptor;
  UINT64   EffectiveDescriptor;
  UINT64   DescriptorType;
  UINT64   OutputMask;
  UINT64   OffsetMask;
  UINT64   AddressBits;
  UINT64   TablePermissions;

  if (Result == NULL) {
    return R64K_WALK_MALFORMED;
  }

  ZeroMem (Result, sizeof (*Result));
  if ((Context == NULL) || (Snapshot == NULL) || (Snapshot->Map == NULL) ||
      (Context->PaMask == 0ULL)) {
    return R64K_WALK_MALFORMED;
  }

  if (!ContextUnchanged (Context)) {
    return R64K_WALK_CHANGED;
  }

  if (!SelectTranslationBase (Context, VirtualAddress, &UseTtbr1, &Ttbr, &VaBits)) {
    return R64K_WALK_UNSUPPORTED;
  }

  Result->UsedTtbr1      = UseTtbr1;
  Result->El2Translation = (BOOLEAN)(Context->CurrentEl == R64K_EL2);
  if (UseTtbr1) {
    return R64K_WALK_TTBR1_NOT_ALLOWED;
  }

  StartLevel = GetStartLevelFor4K (VaBits);
  if (StartLevel > 3U) {
    return R64K_WALK_UNSUPPORTED;
  }

  Shift      = 12U + 9U * (3U - StartLevel);
  EntryCount = (UINTN)1U << (VaBits - Shift);
  TableSize  = EntryCount * sizeof (UINT64);
  // Unlike a next-level descriptor, TTBR can point inside a 4 KiB page.
  // CnP (bit 0) is not part of BADDR. Do not discard valid low BADDR bits.
  TableBase = Ttbr & R64K_TTBR_ADDRESS_MASK;
  if (((TableBase & (TableSize - 1U)) != 0ULL) ||
      ((TableBase & ~Context->PaMask) != 0ULL)) {
    return R64K_WALK_MALFORMED;
  }

  TablePermissions = 0;
  for (Level = StartLevel; Level <= 3U; Level++) {
    if (!CanSafelyReadTable (Context, Snapshot, TableBase, TableSize)) {
      return R64K_WALK_UNSAFE_TABLE;
    }

    Shift = 12U + 9U * (3U - Level);
    Index = (UINTN)((VirtualAddress >> Shift) & (EntryCount - 1U));
    MemoryFence ();
    Descriptor = ((volatile UINT64 *)(UINTN)TableBase)[Index];
    MemoryFence ();
    if (Descriptor != ((volatile UINT64 *)(UINTN)TableBase)[Index]) {
      return R64K_WALK_CHANGED;
    }

    Result->Descriptor = Descriptor;
    Result->Level      = (UINT8)Level;
    if ((Descriptor & DESC_VALID) == 0ULL) {
      return ContextUnchanged (Context) ? R64K_WALK_UNMAPPED : R64K_WALK_CHANGED;
    }

    DescriptorType = Descriptor & (DESC_VALID | DESC_TYPE);
    AddressBits    = Descriptor & R64K_DESC_ADDRESS_MASK;
    // Bits 49:48 are reserved in this non-LPA2 descriptor format.
    if (((Descriptor & (BIT49 | BIT48)) != 0ULL) || ((AddressBits & ~Context->PaMask) != 0ULL)) {
      return R64K_WALK_MALFORMED;
    }

    if (Level == 3U) {
      if (DescriptorType != (DESC_VALID | DESC_TYPE)) {
        return R64K_WALK_MALFORMED;
      }
    } else if (DescriptorType == (DESC_VALID | DESC_TYPE)) {
      if (Context->HierarchicalPermissions) {
        TablePermissions |= Descriptor & (BIT62 | BIT61 | BIT60 | BIT59);
      }

      TableBase  = AddressBits;
      EntryCount = 512U;
      TableSize  = (UINTN)R64K_PAGE_SIZE;
      continue;
    } else if ((DescriptorType != DESC_VALID) || (Level == 0U)) {
      return R64K_WALK_MALFORMED;
    }

    OffsetMask = (1ULL << Shift) - 1ULL;
    if ((AddressBits & OffsetMask) != 0ULL) {
      return R64K_WALK_MALFORMED;
    }

    if (!ContextUnchanged (Context)) {
      return R64K_WALK_CHANGED;
    }

    OutputMask              = R64K_DESC_ADDRESS_MASK & ~OffsetMask;
    Result->PhysicalAddress = (Descriptor & OutputMask) | (VirtualAddress & OffsetMask);
    if ((Result->PhysicalAddress & ~Context->PaMask) != 0ULL) {
      return R64K_WALK_MALFORMED;
    }

    EffectiveDescriptor = Descriptor;
    if ((TablePermissions & BIT62) != 0ULL) {
      EffectiveDescriptor |= BIT7; // APTable[1]: no writes.
    }

    if ((TablePermissions & BIT60) != 0ULL) {
      EffectiveDescriptor |= DESC_UXN; // UXNTable at EL1, XNTable at EL2.
    }

    if (Context->CurrentEl == R64K_EL1) {
      if ((TablePermissions & BIT61) != 0ULL) {
        EffectiveDescriptor &= ~BIT6; // APTable[0]: no EL0 access.
      }

      if ((TablePermissions & BIT59) != 0ULL) {
        EffectiveDescriptor |= DESC_PXN;
      }
    }

    Result->Mapped             = TRUE;
    Result->AttributeSignature = BuildAttributeSignature (
                                   EffectiveDescriptor,
                                   Context->Mair,
                                   Context->CurrentEl,
                                   &Result->AttrIndex,
                                   &Result->MairAttribute
                                   );
    Result->AccessPermissions        = (UINT8)((EffectiveDescriptor >> 6) & 3ULL);
    Result->Shareability             = (UINT8)((EffectiveDescriptor >> 8) & 3ULL);
    Result->PrivilegedExecuteNever   = (BOOLEAN)((EffectiveDescriptor & DESC_PXN) != 0ULL);
    Result->UnprivilegedExecuteNever = (BOOLEAN)((EffectiveDescriptor & DESC_UXN) != 0ULL);
    return R64K_WALK_SUCCESS;
  }

  return R64K_WALK_MALFORMED;
}

/**
  Convert a page-walk status into a constant diagnostic string.

  @param[in] WalkStatus  Status returned by R64KWalkTranslation().

  @return The matching constant diagnostic string, or the documented default.
**/
CONST CHAR16 *
R64KWalkStatusString (
  IN UINTN  WalkStatus
  )
{
  switch (WalkStatus) {
    case R64K_WALK_SUCCESS:
      return L"SUCCESS";
    case R64K_WALK_UNMAPPED:
      return L"UNMAPPED";
    case R64K_WALK_UNSUPPORTED:
      return L"UNSUPPORTED";
    case R64K_WALK_UNSAFE_TABLE:
      return L"UNSAFE_TABLE";
    case R64K_WALK_MALFORMED:
      return L"MALFORMED";
    case R64K_WALK_TTBR1_NOT_ALLOWED:
      return L"TTBR1_NOT_ALLOWED";
    case R64K_WALK_CHANGED:
      return L"TRANSLATION_CHANGED";
    default:
      return L"UNKNOWN";
  }
}

/**
  Convert a UEFI memory type into a constant diagnostic string.

  @param[in] Type  UEFI memory type.

  @return The matching constant diagnostic string, or the documented default.
**/
CONST CHAR16 *
R64KMemoryTypeString (
  IN UINT32  Type
  )
{
  switch (Type) {
    case EfiReservedMemoryType:
      return L"Reserved";
    case EfiLoaderCode:
      return L"LoaderCode";
    case EfiLoaderData:
      return L"LoaderData";
    case EfiBootServicesCode:
      return L"BS_Code";
    case EfiBootServicesData:
      return L"BS_Data";
    case EfiRuntimeServicesCode:
      return L"RT_Code";
    case EfiRuntimeServicesData:
      return L"RT_Data";
    case EfiConventionalMemory:
      return L"Conventional";
    case EfiUnusableMemory:
      return L"Unusable";
    case EfiACPIReclaimMemory:
      return L"ACPI_Reclaim";
    case EfiACPIMemoryNVS:
      return L"ACPI_NVS";
    case EfiMemoryMappedIO:
      return L"MMIO";
    case EfiMemoryMappedIOPortSpace:
      return L"MMIO_Port";
    case EfiPalCode:
      return L"PalCode";
    case EfiPersistentMemory:
      return L"Persistent";
    default:
      return L"Unknown";
  }
}
