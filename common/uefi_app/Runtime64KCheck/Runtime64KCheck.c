/** @file

  Copyright (c) 2026, Arm Ltd. All rights reserved.<BR>

  This program and the accompanying materials are licensed and made available
  under the terms and conditions of the BSD License which accompanies this
  distribution. The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "Runtime64KCheck.h"
#include "AArch64PageTable.h"

#include <Guid/FileInfo.h>
#include <Library/BaseLib.h>
#include <Library/ArmLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>

#define LOG_BUFFER_CHARS  1024U

typedef enum {
  R64K_RESULT_PASS,
  R64K_RESULT_FAIL,
  R64K_RESULT_WARNING,
  R64K_RESULT_SKIP
} R64K_RESULT;

typedef struct {
  EFI_FILE_PROTOCOL  *Root;
  EFI_FILE_PROTOCOL  *File;
} R64K_LOGGER;

typedef struct {
  UINTN  RuntimeCodeDescriptors;
  UINTN  RuntimeDataDescriptors;
  UINTN  ReservedDescriptors;
  UINTN  AcpiNvsDescriptors;
  UINTN  ConstraintBlocks;
  UINTN  BlocksPassed;
  UINTN  BlocksFailed;
  UINTN  BlocksIncomplete;
  UINTN  TriggerPagesUnmapped;
  UINTN  TriggerPagesNonIdentity;
  UINTN  NonTriggerPagesUnmapped;
  UINTN  NonTriggerPagesNonIdentity;
  UINTN  ReservedPagesUnmappedAccepted;
  UINTN  FullyReservedUnmappedBlocksPassed;
  UINTN  Ttbr1UsageErrors;
  UINTN  AttributeMismatchErrors;
  UINTN  WalkWarnings;
  UINTN  NoComparableMappedBlocks;
  UINTN  RuntimeAttributeWarnings;
  UINTN  InvalidDescriptorWarnings;
  UINTN  Warnings;
} R64K_SUMMARY;

STATIC
EFI_STATUS
EnsureDirectory (
  IN EFI_FILE_PROTOCOL  *Root,
  IN CONST CHAR16       *Path
  )
{
  EFI_STATUS         Status;
  EFI_FILE_PROTOCOL  *Directory;

  Status = Root->Open (
                   Root,
                   &Directory,
                   (CHAR16 *)Path,
                   EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                   EFI_FILE_DIRECTORY
                   );
  if (Status == EFI_NOT_FOUND) {
    Status = Root->Open (
                     Root,
                     &Directory,
                     (CHAR16 *)Path,
                     EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                     EFI_FILE_DIRECTORY
                     );
  }

  if (!EFI_ERROR (Status)) {
    Directory->Close (Directory);
  }

  return Status;
}

STATIC
EFI_STATUS
OpenLogger (
  IN  EFI_HANDLE   ImageHandle,
  OUT R64K_LOGGER  *Logger
  )
{
  EFI_STATUS                        Status;
  EFI_LOADED_IMAGE_PROTOCOL         *LoadedImage;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL   *FileSystem;

  ZeroMem (Logger, sizeof (*Logger));
  Status = gBS->HandleProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&LoadedImage
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->HandleProtocol (
                  LoadedImage->DeviceHandle,
                  &gEfiSimpleFileSystemProtocolGuid,
                  (VOID **)&FileSystem
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = FileSystem->OpenVolume (FileSystem, &Logger->Root);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = EnsureDirectory (Logger->Root, L"\\acs_results_template");
  if (!EFI_ERROR (Status)) {
    Status = EnsureDirectory (Logger->Root, L"\\acs_results_template\\acs_results");
  }
  if (!EFI_ERROR (Status)) {
    Status = EnsureDirectory (Logger->Root, RUNTIME64K_LOG_DIR);
  }
  if (EFI_ERROR (Status)) {
    Logger->Root->Close (Logger->Root);
    ZeroMem (Logger, sizeof (*Logger));
    return Status;
  }

  Status = Logger->Root->Open (
                         Logger->Root,
                         &Logger->File,
                         RUNTIME64K_LOG_PATH,
                         EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                         0
                         );
  if (EFI_ERROR (Status)) {
    Logger->Root->Close (Logger->Root);
    ZeroMem (Logger, sizeof (*Logger));
    return Status;
  }

  Status = Logger->File->SetPosition (Logger->File, 0);
  if (EFI_ERROR (Status)) {
    Logger->File->Close (Logger->File);
    Logger->Root->Close (Logger->Root);
    ZeroMem (Logger, sizeof (*Logger));
  }

  return Status;
}

STATIC
VOID
CloseLogger (
  IN OUT R64K_LOGGER  *Logger
  )
{
  if (Logger->File != NULL) {
    Logger->File->Flush (Logger->File);
    Logger->File->Close (Logger->File);
  }

  if (Logger->Root != NULL) {
    Logger->Root->Close (Logger->Root);
  }

  ZeroMem (Logger, sizeof (*Logger));
}

STATIC
VOID
LogLine (
  IN R64K_LOGGER  *Logger,
  IN CONST CHAR16 *Format,
  ...
  )
{
  VA_LIST  Marker;
  CHAR16   Buffer[LOG_BUFFER_CHARS];
  CHAR8    AsciiBuffer[LOG_BUFFER_CHARS];
  UINTN    WriteSize;

  VA_START (Marker, Format);
  UnicodeVSPrint (Buffer, sizeof (Buffer), Format, Marker);
  VA_END (Marker);

  Print (L"%s", Buffer);
  if ((Logger == NULL) || (Logger->File == NULL)) {
    return;
  }

  if (EFI_ERROR (UnicodeStrToAsciiStrS (Buffer, AsciiBuffer, sizeof (AsciiBuffer)))) {
    return;
  }

  WriteSize = AsciiStrLen (AsciiBuffer);
  Logger->File->Write (Logger->File, &WriteSize, AsciiBuffer);
}

STATIC
VOID
DumpConstraintDescriptors (
  IN R64K_LOGGER      *Logger,
  IN R64K_MEMORY_MAP  *Snapshot,
  IN OUT R64K_SUMMARY *Summary
  )
{
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  UINTN                  Offset;
  UINTN                  Index;
  UINT64                 End;

  Index = 0;
  for (Offset = 0; Offset + Snapshot->DescriptorSize <= Snapshot->MapSize; Offset += Snapshot->DescriptorSize) {
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Snapshot->Map + Offset);

    switch (Descriptor->Type) {
      case EfiRuntimeServicesCode:
        Summary->RuntimeCodeDescriptors++;
        break;
      case EfiRuntimeServicesData:
        Summary->RuntimeDataDescriptors++;
        break;
      case EfiReservedMemoryType:
        Summary->ReservedDescriptors++;
        break;
      case EfiACPIMemoryNVS:
        Summary->AcpiNvsDescriptors++;
        break;
      default:
        Index++;
        continue;
    }

    if ((Descriptor->NumberOfPages == 0) ||
        (Descriptor->NumberOfPages > ((MAX_UINT64 - Descriptor->PhysicalStart) / R64K_PAGE_SIZE))) {
      LogLine (
        Logger,
        L"WARNING: Constraint descriptor[%u] has an invalid range and will "
        L"cause block collection to stop.\r\n",
        Index
        );
      Summary->InvalidDescriptorWarnings++;
      Summary->Warnings++;
      Index++;
      continue;
    }

    End = Descriptor->PhysicalStart + Descriptor->NumberOfPages * R64K_PAGE_SIZE - 1ULL;
    LogLine (Logger, L"INFO: Constraint descriptor[%u]\r\n", Index);
    LogLine (
      Logger,
      L"INFO:   Type           : %s (%u)\r\n",
      R64KMemoryTypeString (Descriptor->Type),
      Descriptor->Type
      );
    LogLine (Logger, L"INFO:   PhysicalStart  : 0x%016lx\r\n", Descriptor->PhysicalStart);
    LogLine (Logger, L"INFO:   VirtualStart   : 0x%016lx\r\n", Descriptor->VirtualStart);
    LogLine (Logger, L"INFO:   NumberOfPages  : 0x%016lx\r\n", Descriptor->NumberOfPages);
    LogLine (Logger, L"INFO:   End            : 0x%016lx\r\n", End);
    LogLine (Logger, L"INFO:   UEFI Attribute : 0x%016lx\r\n", Descriptor->Attribute);
    LogLine (Logger, L"INFO:   EFI_RUNTIME    : %s\r\n\r\n",
             ((Descriptor->Attribute & EFI_MEMORY_RUNTIME) != 0) ? L"YES" : L"NO");

    if (((Descriptor->Type == EfiRuntimeServicesCode) ||
         (Descriptor->Type == EfiRuntimeServicesData)) &&
        ((Descriptor->Attribute & EFI_MEMORY_RUNTIME) == 0)) {
      LogLine (Logger, L"WARNING: Runtime code/data descriptor[%u] does not carry EFI_MEMORY_RUNTIME.\r\n\r\n", Index);
      Summary->RuntimeAttributeWarnings++;
      Summary->Warnings++;
    }

    Index++;
  }
}

STATIC
VOID
LogBlockTriggerTypes (
  IN R64K_LOGGER  *Logger,
  IN UINT32       TriggerTypes
  )
{
  LogLine (Logger, L"INFO: Block selected by      :");
  if ((TriggerTypes & R64K_TRIGGER_RT_CODE) != 0) {
    LogLine (Logger, L" EfiRuntimeServicesCode");
  }
  if ((TriggerTypes & R64K_TRIGGER_RT_DATA) != 0) {
    LogLine (Logger, L" EfiRuntimeServicesData");
  }
  if ((TriggerTypes & R64K_TRIGGER_RESERVED) != 0) {
    LogLine (Logger, L" EfiReservedMemoryType");
  }
  if ((TriggerTypes & R64K_TRIGGER_ACPI_NVS) != 0) {
    LogLine (Logger, L" EfiACPIMemoryNVS");
  }
  LogLine (Logger, L"\r\n\r\n");
}

STATIC
VOID
LogPageDetails (
  IN R64K_LOGGER             *Logger,
  IN UINTN                   PageIndex,
  IN UINT64                  Address,
  IN BOOLEAN                 IsTriggerType,
  IN EFI_MEMORY_DESCRIPTOR   *MemoryDescriptor,
  IN R64K_WALK_RESULT        *Walk
  )
{
  LogLine (Logger, L"INFO: Page[%02u]\r\n", PageIndex);
  LogLine (Logger, L"INFO:   VA             : 0x%016lx\r\n", Address);
  if (MemoryDescriptor != NULL) {
    LogLine (
      Logger,
      L"INFO:   UEFI type      : %s (%u)\r\n",
      R64KMemoryTypeString (MemoryDescriptor->Type),
      MemoryDescriptor->Type
      );
    LogLine (Logger, L"INFO:   UEFI attr      : 0x%016lx\r\n", MemoryDescriptor->Attribute);
  } else {
    LogLine (Logger, L"INFO:   UEFI type      : No descriptor\r\n");
  }
  LogLine (Logger, L"INFO:   Trigger type   : %s\r\n", IsTriggerType ? L"YES" : L"NO");
  LogLine (Logger, L"INFO:   TTBR range     : %s\r\n", Walk->UsedTtbr1 ? L"TTBR1" : L"TTBR0");
  LogLine (Logger, L"INFO:   Final level    : L%u\r\n", Walk->Level);
  LogLine (Logger, L"INFO:   Descriptor     : 0x%016lx\r\n", Walk->Descriptor);
  LogLine (Logger, L"INFO:   PA             : 0x%016lx\r\n", Walk->PhysicalAddress);
  LogLine (Logger, L"INFO:   AttrIndx       : %u\r\n", Walk->AttrIndex);
  LogLine (Logger, L"INFO:   MAIR byte      : 0x%02x\r\n", Walk->MairAttribute);
  LogLine (Logger, L"INFO:   AP[2:1]        : %u\r\n", Walk->AccessPermissions);
  LogLine (Logger, L"INFO:   AP[2] / RO     : %u\r\n", (Walk->AccessPermissions >> 1) & 0x1U);
  LogLine (Logger, L"INFO:   SH             : %u\r\n", Walk->Shareability);
  if (Walk->El2Translation) {
    LogLine (Logger, L"INFO:   XN (EL2)       : %u\r\n", Walk->UnprivilegedExecuteNever);
  } else {
    LogLine (Logger, L"INFO:   PXN            : %u\r\n", Walk->PrivilegedExecuteNever);
    LogLine (Logger, L"INFO:   UXN            : %u\r\n", Walk->UnprivilegedExecuteNever);
  }
  LogLine (Logger, L"INFO:   Attribute sig  : 0x%04lx\r\n\r\n", Walk->AttributeSignature);
}

STATIC
CONST CHAR16 *
ResultString (
  IN R64K_RESULT  Result
  )
{
  switch (Result) {
    case R64K_RESULT_PASS: return L"PASS";
    case R64K_RESULT_FAIL: return L"FAIL";
    case R64K_RESULT_WARNING: return L"WARNING";
    default: return L"SKIP";
  }
}


STATIC
VOID
LogResultReason (
  IN R64K_LOGGER   *Logger,
  IN R64K_RESULT   FinalResult,
  IN R64K_SUMMARY  *Summary
  )
{
  BOOLEAN  ReasonWritten;

  ReasonWritten = FALSE;
  LogLine (Logger, L"REASON: ");

  if (FinalResult == R64K_RESULT_FAIL) {
    if (Summary->Ttbr1UsageErrors != 0U) {
      LogLine (
        Logger,
        L"TTBR1 was selected for %u page(s); UEFI requires TTBR0 to be used solely",
        Summary->Ttbr1UsageErrors
        );
      ReasonWritten = TRUE;
    }

    if (Summary->TriggerPagesUnmapped != 0U) {
      if (ReasonWritten) {
        LogLine (Logger, L"; ");
      }
      LogLine (
        Logger,
        L"%u trigger page(s) other than accepted EfiReservedMemoryType pages were unmapped",
        Summary->TriggerPagesUnmapped
        );
      ReasonWritten = TRUE;
    }

    if (Summary->TriggerPagesNonIdentity != 0U) {
      if (ReasonWritten) {
        LogLine (Logger, L"; ");
      }
      LogLine (
        Logger,
        L"%u trigger page(s) were non-identity mapped",
        Summary->TriggerPagesNonIdentity
        );
      ReasonWritten = TRUE;
    }

    if (Summary->AttributeMismatchErrors != 0U) {
      if (ReasonWritten) {
        LogLine (Logger, L"; ");
      }
      LogLine (
        Logger,
        L"%u incompatible page-attribute mapping(s) were detected within selected 64 KiB blocks",
        Summary->AttributeMismatchErrors
        );
      ReasonWritten = TRUE;
    }

    if (!ReasonWritten) {
      LogLine (Logger, L"One or more selected 64 KiB blocks failed validation");
    }
  } else if (FinalResult == R64K_RESULT_WARNING) {
    if (Summary->WalkWarnings != 0U) {
      LogLine (
        Logger,
        L"%u translation walk(s) returned unsupported, unsafe-table, or malformed status",
        Summary->WalkWarnings
        );
      ReasonWritten = TRUE;
    }

    if (Summary->NonTriggerPagesNonIdentity != 0U) {
      if (ReasonWritten) {
        LogLine (Logger, L"; ");
      }
      LogLine (
        Logger,
        L"%u non-trigger page(s) were non-identity mapped",
        Summary->NonTriggerPagesNonIdentity
        );
      ReasonWritten = TRUE;
    }

    if (Summary->NoComparableMappedBlocks != 0U) {
      if (ReasonWritten) {
        LogLine (Logger, L"; ");
      }
      LogLine (
        Logger,
        L"%u block(s) had no comparable mapped pages",
        Summary->NoComparableMappedBlocks
        );
      ReasonWritten = TRUE;
    }

    if (!ReasonWritten) {
      LogLine (Logger, L"One or more selected 64 KiB blocks could not be completely validated");
    }
  } else {
    LogLine (Logger, L"All selected 64 KiB blocks passed");
    ReasonWritten = TRUE;

    if (Summary->ReservedPagesUnmappedAccepted != 0U) {
      LogLine (
        Logger,
        L"; %u unmapped EfiReservedMemoryType page(s) were accepted",
        Summary->ReservedPagesUnmappedAccepted
        );
    }

    if (Summary->Warnings != 0U) {
      LogLine (
        Logger,
        L"; %u diagnostic warning(s) were recorded",
        Summary->Warnings
        );
    }
  }

  LogLine (Logger, L".\r\n");
}

STATIC
EFI_STATUS
RunCheck (
  IN EFI_HANDLE   ImageHandle,
  IN R64K_LOGGER  *Logger
  )
{
  EFI_STATUS                Status;
  R64K_MEMORY_MAP           Snapshot;
  R64K_TRANSLATION_CONTEXT Context;
  R64K_SUMMARY              Summary;
  R64K_BLOCK_INFO           *Blocks;
  UINTN                     BlockCount;
  UINTN                     BlockIndex;
  UINTN                     PageIndex;
  UINT64                    Address;
  BOOLEAN                   IsTriggerType;
  EFI_MEMORY_DESCRIPTOR     *MemoryDescriptor;
  R64K_WALK_RESULT          Walk;
  UINTN                     WalkStatus;
  BOOLEAN                   HaveReference;
  UINT64                    ReferenceSignature;
  UINT64                    ReferenceAddress;
  BOOLEAN                   BlockFailed;
  BOOLEAN                   BlockIncomplete;
  BOOLEAN                   AllPagesReserved;
  BOOLEAN                   AllPagesUnmapped;
  UINTN                     MappedPages;
  R64K_RESULT               FinalResult;

  (VOID)ImageHandle;
  ZeroMem (&Snapshot, sizeof (Snapshot));
  ZeroMem (&Context, sizeof (Context));
  ZeroMem (&Summary, sizeof (Summary));
  Blocks = NULL;
  BlockCount = 0;

  LogLine (Logger, L"============================================================\r\n");
  LogLine (Logger, L"AArch64 UEFI 64 KiB Page Attribute Check\r\n");
  LogLine (Logger, L"============================================================\r\n");

  Status = R64KGetMemoryMap (&Snapshot);
  if (EFI_ERROR (Status)) {
    LogLine (Logger, L"ERROR: GetMemoryMap failed: %r\r\n", Status);
    LogLine (Logger, L"RESULT: SKIP\r\n");
    return Status;
  }

  LogLine (Logger, L"INFO: Memory map size       : %u bytes\r\n", Snapshot.MapSize);
  LogLine (Logger, L"INFO: Descriptor size       : %u bytes\r\n", Snapshot.DescriptorSize);
  LogLine (Logger, L"INFO: Descriptor version    : %u\r\n\r\n", Snapshot.DescriptorVersion);
  DumpConstraintDescriptors (Logger, &Snapshot, &Summary);

  Status = R64KInitializeTranslationContext (&Context);
  if (EFI_ERROR (Status)) {
    LogLine (Logger, L"WARNING: Translation-table inspection is unsupported: %r\r\n", Status);
    LogLine (Logger, L"INFO: CurrentEL raw         : 0x%lx\r\n", (UINT64)ArmReadCurrentEL ());
    LogLine (Logger, L"RESULT: SKIP\r\n");
    R64KFreeMemoryMap (&Snapshot);
    return EFI_SUCCESS;
  }

  LogLine (Logger, L"INFO: CurrentEL             : EL%u\r\n", (UINT32)((Context.CurrentEl >> 2) & 0x3U));
  LogLine (Logger, L"INFO: SCTLR                 : 0x%016lx\r\n", Context.Sctlr);
  LogLine (Logger, L"INFO: TCR                   : 0x%016lx\r\n", Context.Tcr);
  LogLine (Logger, L"INFO: MAIR                  : 0x%016lx\r\n", Context.Mair);
  LogLine (Logger, L"INFO: TTBR0                 : 0x%016lx\r\n", Context.Ttbr0);
  LogLine (Logger, L"INFO: TTBR1                 : 0x%016lx\r\n", Context.Ttbr1);
  LogLine (Logger, L"INFO: HCR                   : 0x%016lx\r\n", Context.Hcr);
  LogLine (Logger, L"INFO: EL2 VHE               : %s\r\n\r\n", Context.El2Vhe ? L"YES" : L"NO");

  Status = R64KCollectConstraintBlocks (&Snapshot, &Blocks, &BlockCount);
  if (EFI_ERROR (Status)) {
    LogLine (Logger, L"WARNING: Unable to collect 64 KiB constraint blocks: %r\r\n", Status);
    LogLine (Logger, L"RESULT: SKIP\r\n");
    R64KFreeMemoryMap (&Snapshot);
    return EFI_SUCCESS;
  }

  Summary.ConstraintBlocks = BlockCount;
  LogLine (Logger, L"INFO: Unique four-type-related 64 KiB blocks: %u\r\n\r\n", BlockCount);

  for (BlockIndex = 0; BlockIndex < BlockCount; BlockIndex++) {
    HaveReference = FALSE;
    ReferenceSignature = 0;
    ReferenceAddress = 0;
    BlockFailed = FALSE;
    BlockIncomplete = FALSE;
    AllPagesReserved = TRUE;
    AllPagesUnmapped = TRUE;
    MappedPages = 0;

    LogLine (Logger, L"------------------------------------------------------------\r\n");
    LogLine (Logger, L"INFO: Checking block 0x%016lx-0x%016lx\r\n",
             Blocks[BlockIndex].BaseAddress,
             Blocks[BlockIndex].BaseAddress + R64K_BLOCK_SIZE - 1ULL);
    LogBlockTriggerTypes (Logger, Blocks[BlockIndex].TriggerTypes);

    for (PageIndex = 0; PageIndex < R64K_PAGES_PER_BLOCK; PageIndex++) {
      Address = Blocks[BlockIndex].BaseAddress + PageIndex * R64K_PAGE_SIZE;
      IsTriggerType = R64KAddressIsConstraintType (&Snapshot, Address);
      MemoryDescriptor = R64KFindMemoryDescriptor (&Snapshot, Address);
      if ((MemoryDescriptor == NULL) ||
          (MemoryDescriptor->Type != EfiReservedMemoryType)) {
        AllPagesReserved = FALSE;
      }

      WalkStatus = R64KWalkTranslation (&Context, &Snapshot, Address, &Walk);

      if (WalkStatus != R64K_WALK_UNMAPPED) {
        AllPagesUnmapped = FALSE;
      }

      if (WalkStatus == R64K_WALK_TTBR1_NOT_ALLOWED) {
        Summary.Ttbr1UsageErrors++;
        LogLine (
          Logger,
          L"ERROR: Page[%02u] 0x%016lx selects the TTBR1 translation range. "
          L"UEFI requires TTBR0 to be used solely; TTBR1 must not be used. "
          L"TTBR1 page tables were not walked.\r\n\r\n",
          PageIndex,
          Address
          );
        BlockFailed = TRUE;
        continue;
      }

      if (WalkStatus == R64K_WALK_UNMAPPED) {
        if ((MemoryDescriptor != NULL) &&
            (MemoryDescriptor->Type == EfiReservedMemoryType)) {
          Summary.ReservedPagesUnmappedAccepted++;
          LogLine (
            Logger,
            L"INFO: Page[%02u] 0x%016lx is unmapped EfiReservedMemoryType; "
            L"this is accepted and no page attributes are available to compare.\r\n\r\n",
            PageIndex,
            Address
            );
          continue;
        }

        LogLine (Logger, L"%s: Page[%02u] 0x%016lx is unmapped\r\n\r\n",
                 IsTriggerType ? L"FAIL" : L"INFO", PageIndex, Address);
        if (IsTriggerType) {
          Summary.TriggerPagesUnmapped++;
          BlockFailed = TRUE;
        } else {
          Summary.NonTriggerPagesUnmapped++;
        }
        continue;
      }

      if (WalkStatus != R64K_WALK_SUCCESS) {
        LogLine (
          Logger,
          L"WARNING: Page[%02u] 0x%016lx walk status: %s (%u)\r\n\r\n",
          PageIndex,
          Address,
          R64KWalkStatusString (WalkStatus),
          WalkStatus
          );
        BlockIncomplete = TRUE;
        Summary.WalkWarnings++;
        Summary.Warnings++;
        continue;
      }

      LogPageDetails (Logger, PageIndex, Address, IsTriggerType, MemoryDescriptor, &Walk);

      if (Walk.PhysicalAddress != Address) {
        LogLine (
          Logger,
          L"%s: VA 0x%016lx resolves to PA 0x%016lx; this physical 64 KiB "
          L"comparison requires a known PA-to-VA relationship\r\n\r\n",
                 IsTriggerType ? L"FAIL" : L"WARNING", Address, Walk.PhysicalAddress);
        if (IsTriggerType) {
          Summary.TriggerPagesNonIdentity++;
          BlockFailed = TRUE;
        } else {
          Summary.NonTriggerPagesNonIdentity++;
          BlockIncomplete = TRUE;
          Summary.Warnings++;
        }
        continue;
      }

      MappedPages++;
      if (!HaveReference) {
        HaveReference = TRUE;
        ReferenceSignature = Walk.AttributeSignature;
        ReferenceAddress = Address;
      } else if (ReferenceSignature != Walk.AttributeSignature) {
        BlockFailed = TRUE;
        Summary.AttributeMismatchErrors++;
        LogLine (Logger, L"FAIL: Incompatible page attributes in 64 KiB block\r\n");
        LogLine (Logger, L"FAIL:   Block base          : 0x%016lx\r\n", Blocks[BlockIndex].BaseAddress);
        LogLine (Logger, L"FAIL:   Reference page      : 0x%016lx\r\n", ReferenceAddress);
        LogLine (Logger, L"FAIL:   Reference signature : 0x%04lx\r\n", ReferenceSignature);
        LogLine (Logger, L"FAIL:   Conflicting page    : 0x%016lx\r\n", Address);
        LogLine (Logger, L"FAIL:   Conflict signature  : 0x%04lx\r\n\r\n", Walk.AttributeSignature);
      }
    }

    if (BlockFailed) {
      Summary.BlocksFailed++;
      LogLine (Logger, L"BLOCK RESULT: FAIL\r\n");
    } else if (AllPagesReserved && AllPagesUnmapped) {
      Summary.FullyReservedUnmappedBlocksPassed++;
      Summary.BlocksPassed++;
      LogLine (
        Logger,
        L"BLOCK RESULT: PASS - fully EfiReservedMemoryType and fully unmapped; "
        L"no mapped page attributes require comparison.\r\n"
        );
    } else if (BlockIncomplete || (MappedPages == 0U)) {
      if (MappedPages == 0U) {
        Summary.NoComparableMappedBlocks++;
        Summary.Warnings++;
      }
      Summary.BlocksIncomplete++;
      LogLine (Logger, L"BLOCK RESULT: WARNING\r\n");
    } else {
      Summary.BlocksPassed++;
      LogLine (Logger, L"BLOCK RESULT: PASS\r\n");
    }
  }

  if (Summary.BlocksFailed != 0U) {
    FinalResult = R64K_RESULT_FAIL;
  } else if (Summary.BlocksIncomplete != 0U) {
    FinalResult = R64K_RESULT_WARNING;
  } else {
    FinalResult = R64K_RESULT_PASS;
  }

  LogLine (Logger, L"\r\n============================================================\r\n");
  LogLine (Logger, L"AArch64 UEFI 64 KiB Page Attribute Check Summary\r\n");
  LogLine (Logger, L"============================================================\r\n");
  LogLine (Logger, L"EfiRuntimeServicesCode descriptors  : %u\r\n", Summary.RuntimeCodeDescriptors);
  LogLine (Logger, L"EfiRuntimeServicesData descriptors  : %u\r\n", Summary.RuntimeDataDescriptors);
  LogLine (Logger, L"EfiReservedMemoryType descriptors   : %u\r\n", Summary.ReservedDescriptors);
  LogLine (Logger, L"EfiACPIMemoryNVS descriptors        : %u\r\n", Summary.AcpiNvsDescriptors);
  LogLine (Logger, L"Four-type-related 64 KiB blocks     : %u\r\n", Summary.ConstraintBlocks);
  LogLine (Logger, L"Blocks passed                       : %u\r\n", Summary.BlocksPassed);
  LogLine (Logger, L"Blocks failed                       : %u\r\n", Summary.BlocksFailed);
  LogLine (Logger, L"Blocks incomplete                   : %u\r\n", Summary.BlocksIncomplete);
  LogLine (Logger, L"Trigger pages unmapped              : %u\r\n", Summary.TriggerPagesUnmapped);
  LogLine (Logger, L"Trigger pages non-identity mapped   : %u\r\n", Summary.TriggerPagesNonIdentity);
  LogLine (Logger, L"Other pages unmapped                : %u\r\n", Summary.NonTriggerPagesUnmapped);
  LogLine (Logger, L"Other pages non-identity mapped     : %u\r\n", Summary.NonTriggerPagesNonIdentity);
  LogLine (Logger, L"TTBR1 usage errors                  : %u\r\n", Summary.Ttbr1UsageErrors);
  LogLine (Logger, L"Warnings                            : %u\r\n", Summary.Warnings);
  LogLine (
    Logger,
    L"Block-selection types: EfiRuntimeServicesCode, "
    L"EfiRuntimeServicesData, EfiReservedMemoryType, and "
    L"EfiACPIMemoryNVS. Runtime MMIO does not select blocks.\r\n"
    );
  LogLine (
    Logger,
    L"Comparison signature: resolved MAIR memory type, SH, AP[2], "
    L"PXN/UXN (EL1) or XN (EL2).\r\n"
    );
  LogLine (Logger, L"RESULT: %s\r\n", ResultString (FinalResult));
  LogResultReason (Logger, FinalResult, &Summary);
  LogLine (Logger, L"============================================================\r\n");

  FreePool (Blocks);
  R64KFreeMemoryMap (&Snapshot);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Runtime64KCheckEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS   Status;
  R64K_LOGGER  Logger;

  (VOID)SystemTable;
  Status = OpenLogger (ImageHandle, &Logger);
  if (EFI_ERROR (Status)) {
    Print (L"WARNING: Could not open %s: %r\r\n", RUNTIME64K_LOG_PATH, Status);
    Print (L"The check will continue with console output only.\r\n");
    ZeroMem (&Logger, sizeof (Logger));
  } else {
    Print (L"Detailed log: %s\r\n", RUNTIME64K_LOG_PATH);
  }

  Status = RunCheck (ImageHandle, &Logger);
  CloseLogger (&Logger);
  return Status;
}
