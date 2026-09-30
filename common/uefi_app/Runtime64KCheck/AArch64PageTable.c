/** @file

  Copyright (c) 2026, Arm Ltd. All rights reserved.<BR>

  This program and the accompanying materials are licensed and made available
  under the terms and conditions of the BSD License which accompanies this
  distribution. The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "AArch64PageTable.h"

#include <Library/ArmLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#define TTBR_BADDR_MASK_48       0x0000FFFFFFFFF000ULL
#define DESC_VALID               BIT0
#define DESC_TYPE                BIT1
#define DESC_PXN                 BIT53
#define DESC_UXN                 BIT54
#define SCTLR_M                  BIT0
#define HCR_E2H                  BIT34
#define R64K_TCR_DS              BIT59
#define PAR_FAULT                BIT0
#define MAX_MEMORY_MAP_RETRIES   4U


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

  if (Snapshot == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Snapshot, sizeof (*Snapshot));
  RequiredSize     = 0;
  DescriptorSize   = 0;
  DescriptorVersion = 0;

  Status = gBS->GetMemoryMap (
                  &RequiredSize,
                  NULL,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return Status;
  }

  if (DescriptorSize < sizeof (EFI_MEMORY_DESCRIPTOR)) {
    return EFI_COMPROMISED_DATA;
  }

  for (Retry = 0; Retry < MAX_MEMORY_MAP_RETRIES; Retry++) {
    if (RequiredSize > MAX_UINTN - (DescriptorSize * 8U) - (UINTN)(2U * R64K_PAGE_SIZE)) {
      return EFI_OUT_OF_RESOURCES;
    }

    AllocationSize = RequiredSize + DescriptorSize * 8U + (UINTN)(2U * R64K_PAGE_SIZE);
    Snapshot->Map = AllocatePool (AllocationSize);
    if (Snapshot->Map == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    Snapshot->MapSize = AllocationSize;
    Status = gBS->GetMemoryMap (
                    &Snapshot->MapSize,
                    Snapshot->Map,
                    &MapKey,
                    &Snapshot->DescriptorSize,
                    &Snapshot->DescriptorVersion
                    );
    if (!EFI_ERROR (Status)) {
      return EFI_SUCCESS;
    }

    FreePool (Snapshot->Map);
    Snapshot->Map = NULL;
    if (Status != EFI_BUFFER_TOO_SMALL) {
      return Status;
    }

    RequiredSize = Snapshot->MapSize;
  }

  return EFI_BUFFER_TOO_SMALL;
}

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

EFI_MEMORY_DESCRIPTOR *
R64KFindMemoryDescriptor (
  IN R64K_MEMORY_MAP       *Snapshot,
  IN EFI_PHYSICAL_ADDRESS  Address
  )
{
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  EFI_PHYSICAL_ADDRESS   End;
  UINTN                  Offset;

  if ((Snapshot == NULL) || (Snapshot->Map == NULL) || (Snapshot->DescriptorSize == 0)) {
    return NULL;
  }

  for (Offset = 0; Offset + Snapshot->DescriptorSize <= Snapshot->MapSize; Offset += Snapshot->DescriptorSize) {
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Snapshot->Map + Offset);
    if (Descriptor->NumberOfPages > (MAX_UINT64 / R64K_PAGE_SIZE)) {
      continue;
    }

    End = Descriptor->PhysicalStart + Descriptor->NumberOfPages * R64K_PAGE_SIZE;
    if ((End < Descriptor->PhysicalStart) || (Address < Descriptor->PhysicalStart)) {
      continue;
    }

    if (Address < End) {
      return Descriptor;
    }
  }

  return NULL;
}

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

STATIC
INTN
FindBlockIndex (
  IN R64K_BLOCK_INFO  *Blocks,
  IN UINTN            Count,
  IN UINT64           BlockBase
  )
{
  UINTN  Index;

  for (Index = 0; Index < Count; Index++) {
    if (Blocks[Index].BaseAddress == BlockBase) {
      return (INTN)Index;
    }
  }

  return -1;
}

EFI_STATUS
R64KCollectConstraintBlocks (
  IN  R64K_MEMORY_MAP  *Snapshot,
  OUT R64K_BLOCK_INFO  **Blocks,
  OUT UINTN            *BlockCount
  )
{
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  UINTN                  Offset;
  UINTN                  Capacity;
  UINTN                  Count;
  UINT64                 Start;
  UINT64                 EndExclusive;
  UINT64                 Block;
  R64K_BLOCK_INFO        *List;
  INTN                   ExistingIndex;
  UINT32                 TriggerFlag;

  if ((Snapshot == NULL) || (Blocks == NULL) || (BlockCount == NULL) ||
      (Snapshot->Map == NULL) || (Snapshot->DescriptorSize == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  *Blocks = NULL;
  *BlockCount = 0;
  Capacity = 0;

  for (Offset = 0; Offset + Snapshot->DescriptorSize <= Snapshot->MapSize; Offset += Snapshot->DescriptorSize) {
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Snapshot->Map + Offset);
    if (!Is64KConstraintDescriptor (Descriptor)) {
      continue;
    }

    if ((Descriptor->NumberOfPages == 0) ||
        (Descriptor->NumberOfPages > ((MAX_UINT64 - Descriptor->PhysicalStart) / R64K_PAGE_SIZE))) {
      return EFI_COMPROMISED_DATA;
    }

    Start = Descriptor->PhysicalStart & ~(R64K_BLOCK_SIZE - 1ULL);
    EndExclusive = Descriptor->PhysicalStart + Descriptor->NumberOfPages * R64K_PAGE_SIZE;
    if ((EndExclusive <= Descriptor->PhysicalStart) ||
        (EndExclusive > MAX_UINT64 - (R64K_BLOCK_SIZE - 1ULL))) {
      return EFI_COMPROMISED_DATA;
    }

    EndExclusive = (EndExclusive + R64K_BLOCK_SIZE - 1ULL) & ~(R64K_BLOCK_SIZE - 1ULL);
    Capacity += (UINTN)((EndExclusive - Start) / R64K_BLOCK_SIZE);
    if (Capacity > R64K_MAX_CONSTRAINT_BLOCKS) {
      return EFI_OUT_OF_RESOURCES;
    }
  }

  if (Capacity == 0) {
    return EFI_NOT_FOUND;
  }

  List = AllocateZeroPool (Capacity * sizeof (*List));
  if (List == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Count = 0;
  for (Offset = 0; Offset + Snapshot->DescriptorSize <= Snapshot->MapSize; Offset += Snapshot->DescriptorSize) {
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Snapshot->Map + Offset);
    if (!Is64KConstraintDescriptor (Descriptor)) {
      continue;
    }

    TriggerFlag = MemoryTypeToTriggerFlag ((EFI_MEMORY_TYPE)Descriptor->Type);
    Start = Descriptor->PhysicalStart & ~(R64K_BLOCK_SIZE - 1ULL);
    EndExclusive = Descriptor->PhysicalStart + Descriptor->NumberOfPages * R64K_PAGE_SIZE;
    EndExclusive = (EndExclusive + R64K_BLOCK_SIZE - 1ULL) & ~(R64K_BLOCK_SIZE - 1ULL);

    for (Block = Start; Block < EndExclusive; Block += R64K_BLOCK_SIZE) {
      ExistingIndex = FindBlockIndex (List, Count, Block);
      if (ExistingIndex >= 0) {
        List[ExistingIndex].TriggerTypes |= TriggerFlag;
        continue;
      }

      if (Count >= Capacity) {
        FreePool (List);
        return EFI_COMPROMISED_DATA;
      }

      List[Count].BaseAddress = Block;
      List[Count].TriggerTypes = TriggerFlag;
      Count++;
    }
  }

  *Blocks = List;
  *BlockCount = Count;
  return EFI_SUCCESS;
}

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
  *Ttbr = 0;
  *VaBits = 0;

  if ((Context->CurrentEl == AARCH64_EL2) && !Context->El2Vhe) {
    VaBits0 = GetVaBits (Context->Tcr, FALSE, TRUE);
    if ((VaBits0 < 13U) || (VaBits0 > 48U)) {
      return FALSE;
    }

    LowerLimit = 1ULL << VaBits0;
    if (VirtualAddress >= LowerLimit) {
      return FALSE;
    }

    *Ttbr = Context->Ttbr0;
    *VaBits = VaBits0;
    return TRUE;
  }

  VaBits0 = GetVaBits (Context->Tcr, FALSE, FALSE);
  VaBits1 = GetVaBits (Context->Tcr, TRUE, FALSE);

  if ((VaBits0 >= 13U) && (VaBits0 <= 48U)) {
    LowerLimit = 1ULL << VaBits0;
    if (VirtualAddress < LowerLimit) {
      *Ttbr = Context->Ttbr0;
      *VaBits = VaBits0;
      return TRUE;
    }
  }

  if ((VaBits1 >= 13U) && (VaBits1 <= 48U)) {
    UpperBase = MAX_UINT64 - ((1ULL << VaBits1) - 1ULL);
    if (VirtualAddress >= UpperBase) {
      *UseTtbr1 = TRUE;
      *Ttbr = Context->Ttbr1;
      *VaBits = VaBits1;
      return TRUE;
    }
  }

  return FALSE;
}

STATIC
UINTN
GetStartLevelFor4K (
  IN UINTN  VaBits
  )
{
  UINTN  IndexBits;
  UINTN  Levels;

  if ((VaBits < 13U) || (VaBits > 48U)) {
    return 4U;
  }

  IndexBits = VaBits - 12U;
  Levels = (IndexBits + 8U) / 9U;
  if ((Levels == 0U) || (Levels > 4U)) {
    return 4U;
  }

  return 4U - Levels;
}

STATIC
UINT64
TranslateAddressForRead (
  IN R64K_TRANSLATION_CONTEXT  *Context,
  IN UINT64                    Address
  )
{
  if (Context->CurrentEl == AARCH64_EL1) {
    return AddressTranslateS1E1R (Address);
  }

  return AddressTranslateS1E2R (Address);
}

STATIC
BOOLEAN
CanSafelyReadTable (
  IN R64K_TRANSLATION_CONTEXT  *Context,
  IN R64K_MEMORY_MAP           *Snapshot,
  IN UINT64                    TableBase
  )
{
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  UINT64                 Par;
  UINT64                 TranslatedPage;

  if ((TableBase & (R64K_PAGE_SIZE - 1ULL)) != 0) {
    return FALSE;
  }

  Descriptor = R64KFindMemoryDescriptor (Snapshot, TableBase);
  if (!IsRamLikeDescriptor (Descriptor)) {
    return FALSE;
  }

  if ((TableBase > MAX_UINT64 - R64K_PAGE_SIZE) ||
      (R64KFindMemoryDescriptor (Snapshot, TableBase + R64K_PAGE_SIZE - 1ULL) != Descriptor)) {
    return FALSE;
  }

  Par = TranslateAddressForRead (Context, TableBase);
  if ((Par & PAR_FAULT) != 0) {
    return FALSE;
  }

  TranslatedPage = Par & TTBR_BADDR_MASK_48;
  return (BOOLEAN)(TranslatedPage == TableBase);
}

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

  *AttrIndex = (UINT8)((Descriptor >> 2) & 0x7ULL);
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

  if (CurrentEl == AARCH64_EL1) {
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

EFI_STATUS
R64KInitializeTranslationContext (
  OUT R64K_TRANSLATION_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (*Context));
  Context->CurrentEl = ArmReadCurrentEL ();

  if (Context->CurrentEl == AARCH64_EL1) {
    Context->Ttbr0 = ReadTtbr0El1 ();
    Context->Ttbr1 = ReadTtbr1El1 ();
    Context->Tcr   = ReadTcrEl1 ();
    Context->Mair  = ReadMairEl1 ();
    Context->Sctlr = ReadSctlrEl1 ();
  } else if (Context->CurrentEl == AARCH64_EL2) {
    Context->Hcr = ReadHcrEl2 ();
    Context->El2Vhe = (BOOLEAN)((Context->Hcr & HCR_E2H) != 0);
    if (Context->El2Vhe) {
      return EFI_UNSUPPORTED;
    }

    Context->Ttbr0 = ReadTtbr0El2 ();
    Context->Ttbr1 = 0;
    Context->Tcr   = ReadTcrEl2 ();
    Context->Mair  = ReadMairEl2 ();
    Context->Sctlr = ReadSctlrEl2 ();
  } else {
    return EFI_UNSUPPORTED;
  }

  if ((Context->Sctlr & SCTLR_M) == 0) {
    return EFI_UNSUPPORTED;
  }

  if ((Context->Tcr & R64K_TCR_DS) != 0) {
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

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
  UINT64   TableBase;
  UINT64   Descriptor;
  UINT64   DescriptorType;
  UINT64   OutputMask;
  UINT64   OffsetMask;

  if ((Context == NULL) || (Snapshot == NULL) || (Result == NULL)) {
    return R64K_WALK_MALFORMED;
  }

  ZeroMem (Result, sizeof (*Result));

  if (!SelectTranslationBase (Context, VirtualAddress, &UseTtbr1, &Ttbr, &VaBits)) {
    return R64K_WALK_UNSUPPORTED;
  }

  Result->UsedTtbr1 = UseTtbr1;
  Result->El2Translation = (BOOLEAN)(Context->CurrentEl == AARCH64_EL2);

  //
  // UEFI AArch64 Boot Services mappings must use TTBR0 solely.  Detect an
  // address that selects the TTBR1 range, but do not walk or dereference any
  // TTBR1 translation tables.  The caller reports this as a compliance error.
  //
  if (UseTtbr1) {
    return R64K_WALK_TTBR1_NOT_ALLOWED;
  }

  if (!IsFourKilobyteGranule (
         Context->Tcr,
         UseTtbr1,
         (BOOLEAN)((Context->CurrentEl == AARCH64_EL2) && !Context->El2Vhe)
         )) {
    return R64K_WALK_UNSUPPORTED;
  }

  StartLevel = GetStartLevelFor4K (VaBits);
  if (StartLevel > 3U) {
    return R64K_WALK_UNSUPPORTED;
  }

  TableBase = Ttbr & TTBR_BADDR_MASK_48;
  for (Level = StartLevel; Level <= 3U; Level++) {
    if (!CanSafelyReadTable (Context, Snapshot, TableBase)) {
      return R64K_WALK_UNSAFE_TABLE;
    }

    Shift = 12U + 9U * (3U - Level);
    Index = (UINTN)((VirtualAddress >> Shift) & 0x1FFULL);
    Descriptor = ((volatile UINT64 *)(UINTN)TableBase)[Index];

    if ((Descriptor & DESC_VALID) == 0) {
      return R64K_WALK_UNMAPPED;
    }

    DescriptorType = Descriptor & (DESC_VALID | DESC_TYPE);
    if (Level == 3U) {
      if (DescriptorType != (DESC_VALID | DESC_TYPE)) {
        return R64K_WALK_MALFORMED;
      }
    } else if (DescriptorType == (DESC_VALID | DESC_TYPE)) {
      TableBase = Descriptor & TTBR_BADDR_MASK_48;
      continue;
    } else if ((DescriptorType != DESC_VALID) || (Level == 0U)) {
      return R64K_WALK_MALFORMED;
    }

    OffsetMask = (1ULL << Shift) - 1ULL;
    OutputMask = TTBR_BADDR_MASK_48 & ~OffsetMask;
    Result->PhysicalAddress = (Descriptor & OutputMask) | (VirtualAddress & OffsetMask);
    Result->Descriptor      = Descriptor;
    Result->Level           = (UINT8)Level;
    Result->Mapped          = TRUE;
    Result->AttributeSignature = BuildAttributeSignature (
                                   Descriptor,
                                   Context->Mair,
                                   Context->CurrentEl,
                                   &Result->AttrIndex,
                                   &Result->MairAttribute
                                   );
    Result->AccessPermissions = (UINT8)((Descriptor >> 6) & 0x3ULL);
    Result->Shareability = (UINT8)((Descriptor >> 8) & 0x3ULL);
    Result->PrivilegedExecuteNever = (BOOLEAN)((Descriptor & DESC_PXN) != 0);
    Result->UnprivilegedExecuteNever = (BOOLEAN)((Descriptor & DESC_UXN) != 0);
    return R64K_WALK_SUCCESS;
  }

  return R64K_WALK_MALFORMED;
}

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
    default:
      return L"UNKNOWN";
  }
}

CONST CHAR16 *
R64KMemoryTypeString (
  IN UINT32  Type
  )
{
  switch (Type) {
    case EfiReservedMemoryType: return L"Reserved";
    case EfiLoaderCode: return L"LoaderCode";
    case EfiLoaderData: return L"LoaderData";
    case EfiBootServicesCode: return L"BS_Code";
    case EfiBootServicesData: return L"BS_Data";
    case EfiRuntimeServicesCode: return L"RT_Code";
    case EfiRuntimeServicesData: return L"RT_Data";
    case EfiConventionalMemory: return L"Conventional";
    case EfiUnusableMemory: return L"Unusable";
    case EfiACPIReclaimMemory: return L"ACPI_Reclaim";
    case EfiACPIMemoryNVS: return L"ACPI_NVS";
    case EfiMemoryMappedIO: return L"MMIO";
    case EfiMemoryMappedIOPortSpace: return L"MMIO_Port";
    case EfiPalCode: return L"PalCode";
    case EfiPersistentMemory: return L"Persistent";
    default: return L"Unknown";
  }
}
