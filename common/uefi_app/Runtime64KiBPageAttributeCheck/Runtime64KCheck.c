/** @file
  UEFI application orchestration, result policy, and persistent logging.

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
  EFI_STATUS         Status;
  BOOLEAN            ErrorPrinted;
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
  UINTN  WalkUnsupportedWarnings;
  UINTN  UnsafeTableWarnings;
  UINTN  MalformedWalkWarnings;
  UINTN  ChangedWalkWarnings;
  UINTN  IoWarnings;
  UINTN  NoComparableMappedBlocks;
  UINTN  RuntimeAttributeWarnings;
  UINTN  InvalidDescriptorWarnings;
  UINTN  Warnings;
} R64K_SUMMARY;

/**
  Record the first file-logging error and report it once on the console.

  @param[in,out] Logger  Logging state; may be NULL for console-only output.
  @param[in]     Status  Error status to record.
**/
STATIC
VOID
RecordLogError (
  IN OUT R64K_LOGGER  *Logger,
  IN     EFI_STATUS   Status
  )
{
  if ((Logger == NULL) || !EFI_ERROR (Status)) {
    return;
  }

  if (!EFI_ERROR (Logger->Status)) {
    Logger->Status = Status;
  }

  if (!Logger->ErrorPrinted) {
    Print (L"WARNING: File logging failed: %r. Console output will continue.\r\n", Logger->Status);
    Logger->ErrorPrinted = TRUE;
  }
}

/**
  Obtain bounded, structurally validated EFI_FILE_INFO data.

  @param[in]  File  Open file or directory.
  @param[out] Info  Allocated information. The caller must FreePool() it.

  @retval EFI_SUCCESS            Information returned.
  @retval EFI_COMPROMISED_DATA   The returned information has invalid bounds.
  @return                       A file-protocol or allocation error.
**/
STATIC
EFI_STATUS
GetFileInformation (
  IN  EFI_FILE_PROTOCOL  *File,
  OUT EFI_FILE_INFO      **Info
  )
{
  EFI_STATUS     Status;
  EFI_FILE_INFO  *Buffer;
  UINTN          Size;
  UINTN          Capacity;
  UINTN          NameChars;
  UINTN          Index;

  if ((File == NULL) || (Info == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *Info = NULL;
  if (File->GetInfo == NULL) {
    return EFI_UNSUPPORTED;
  }

  Size   = 0;
  Status = File->GetInfo (File, &gEfiFileInfoGuid, &Size, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA;
  }

  if ((Size < SIZE_OF_EFI_FILE_INFO + sizeof (CHAR16)) || (Size > 65536U)) {
    return EFI_COMPROMISED_DATA;
  }

  Capacity = Size;
  Buffer   = AllocateZeroPool (Capacity);
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = File->GetInfo (File, &gEfiFileInfoGuid, &Size, Buffer);
  if (EFI_ERROR (Status)) {
    FreePool (Buffer);
    return Status;
  }

  if ((Size > Capacity) || (Buffer->Size > Size) ||
      (Buffer->Size < SIZE_OF_EFI_FILE_INFO + sizeof (CHAR16))) {
    FreePool (Buffer);
    return EFI_COMPROMISED_DATA;
  }

  NameChars = ((UINTN)Buffer->Size - SIZE_OF_EFI_FILE_INFO) / sizeof (CHAR16);
  for (Index = 0; Index < NameChars; Index++) {
    if (Buffer->FileName[Index] == L'\0') {
      *Info = Buffer;
      return EFI_SUCCESS;
    }
  }

  FreePool (Buffer);
  return EFI_COMPROMISED_DATA;
}

/**
  Open or create a directory and verify that it is not an ordinary file.

  @param[in] Root  Filesystem root.
  @param[in] Path  Absolute directory path.

  @return EFI_SUCCESS, or the first open, information, or close error.
**/
STATIC
EFI_STATUS
EnsureDirectory (
  IN EFI_FILE_PROTOCOL  *Root,
  IN CONST CHAR16       *Path
  )
{
  EFI_STATUS         Status;
  EFI_STATUS         CloseStatus;
  EFI_FILE_PROTOCOL  *Directory;
  EFI_FILE_INFO      *Info;

  if ((Root == NULL) || (Path == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (Root->Open == NULL) {
    return EFI_UNSUPPORTED;
  }

  Directory = NULL;
  Status    = Root->Open (
                   Root,
                   &Directory,
                   (CHAR16 *)Path,
                   EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                   EFI_FILE_DIRECTORY
                   );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((Directory == NULL) || (Directory->Close == NULL)) {
    return EFI_COMPROMISED_DATA;
  }

  Status = GetFileInformation (Directory, &Info);
  if (!EFI_ERROR (Status)) {
    if ((Info->Attribute & EFI_FILE_DIRECTORY) == 0ULL) {
      Status = EFI_ACCESS_DENIED;
    }

    FreePool (Info);
  }

  CloseStatus = Directory->Close (Directory);
  return EFI_ERROR (Status) ? Status : CloseStatus;
}

/**
  Open the application log and truncate any previous contents.

  @param[in]  ImageHandle  Running image handle.
  @param[out] Logger       Open handles and logging status.

  @return EFI_SUCCESS or the first protocol, allocation, or filesystem error.
**/
STATIC
EFI_STATUS
OpenLogger (
  IN  EFI_HANDLE   ImageHandle,
  OUT R64K_LOGGER  *Logger
  )
{
  EFI_STATUS                       Status;
  EFI_LOADED_IMAGE_PROTOCOL        *LoadedImage;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *FileSystem;
  EFI_FILE_INFO                    *Info;

  if (Logger == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Logger, sizeof (*Logger));
  if ((gBS == NULL) || (gBS->HandleProtocol == NULL)) {
    Logger->Status = EFI_UNSUPPORTED;
    return EFI_UNSUPPORTED;
  }

  LoadedImage = NULL;
  FileSystem  = NULL;
  Status      = gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&LoadedImage);
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  if ((LoadedImage == NULL) || (LoadedImage->DeviceHandle == NULL)) {
    Status = EFI_NOT_FOUND;
    goto Error;
  }

  Status = gBS->HandleProtocol (
                  LoadedImage->DeviceHandle,
                  &gEfiSimpleFileSystemProtocolGuid,
                  (VOID **)&FileSystem
                  );
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  if ((FileSystem == NULL) || (FileSystem->OpenVolume == NULL)) {
    Status = EFI_COMPROMISED_DATA;
    goto Error;
  }

  Status = FileSystem->OpenVolume (FileSystem, &Logger->Root);
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  if ((Logger->Root == NULL) || (Logger->Root->Open == NULL) || (Logger->Root->Close == NULL)) {
    Status = EFI_COMPROMISED_DATA;
    goto Error;
  }

  Status = EnsureDirectory (Logger->Root, L"\\acs_results_template");
  if (!EFI_ERROR (Status)) {
    Status = EnsureDirectory (Logger->Root, L"\\acs_results_template\\acs_results");
  }

  if (!EFI_ERROR (Status)) {
    Status = EnsureDirectory (Logger->Root, RUNTIME64K_LOG_DIR);
  }

  if (EFI_ERROR (Status)) {
    goto Error;
  }

  Status = Logger->Root->Open (
                          Logger->Root,
                          &Logger->File,
                          RUNTIME64K_LOG_PATH,
                          EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE,
                          0
                          );
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  if ((Logger->File == NULL) || (Logger->File->SetInfo == NULL) ||
      (Logger->File->SetPosition == NULL) || (Logger->File->Write == NULL) ||
      (Logger->File->Flush == NULL) || (Logger->File->Close == NULL)) {
    Status = EFI_COMPROMISED_DATA;
    goto Error;
  }

  Status = GetFileInformation (Logger->File, &Info);
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  if ((Info->Attribute & EFI_FILE_DIRECTORY) != 0ULL) {
    Status = EFI_ACCESS_DENIED;
  } else {
    Info->FileSize = 0;
    Status         = Logger->File->SetInfo (Logger->File, &gEfiFileInfoGuid, (UINTN)Info->Size, Info);
  }

  FreePool (Info);
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  Status = Logger->File->SetPosition (Logger->File, 0);
  if (!EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

Error:
  if (Logger->File != NULL) {
    if (Logger->File->Close != NULL) {
      Logger->File->Close (Logger->File);
    }

    Logger->File = NULL;
  }

  if (Logger->Root != NULL) {
    if (Logger->Root->Close != NULL) {
      Logger->Root->Close (Logger->Root);
    }

    Logger->Root = NULL;
  }

  Logger->Status = Status;
  return Status;
}

/**
  Flush and close logging handles, preserving/reporting the first error.

  @param[in,out] Logger  Logging state.

  @return EFI_SUCCESS or a logging, flush, or close error.
**/
STATIC
EFI_STATUS
CloseLogger (
  IN OUT R64K_LOGGER  *Logger
  )
{
  EFI_STATUS  Status;

  if (Logger == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Logger->File != NULL) {
    Status = Logger->File->Flush (Logger->File);
    RecordLogError (Logger, Status);
    Status = Logger->File->Close (Logger->File);
    RecordLogError (Logger, Status);
    Logger->File = NULL;
  }

  if (Logger->Root != NULL) {
    Status = Logger->Root->Close (Logger->Root);
    RecordLogError (Logger, Status);
    Logger->Root = NULL;
  }

  return Logger->Status;
}

/**
  Format one bounded message and mirror it to the console and ASCII log.

  Short writes are completed in a bounded loop; failures disable further
  file writes but do not stop console diagnostics. No newline is implicit.

  @param[in,out] Logger  Logging state; NULL is allowed for console-only output.
  @param[in]     Format  EDK II Unicode print format.
  @param[in]     ...     Arguments matching Format.
**/
STATIC
VOID
LogLine (
  IN OUT R64K_LOGGER   *Logger OPTIONAL,
  IN     CONST CHAR16  *Format,
  ...
  )
{
  VA_LIST     Marker;
  CHAR16      Buffer[LOG_BUFFER_CHARS];
  CHAR8       AsciiBuffer[LOG_BUFFER_CHARS];
  UINTN       Length;
  UINTN       Offset;
  UINTN       WriteSize;
  UINTN       Index;
  EFI_STATUS  Status;

  if (Format == NULL) {
    RecordLogError (Logger, EFI_INVALID_PARAMETER);
    return;
  }

  VA_START (Marker, Format);
  Length = UnicodeVSPrint (Buffer, sizeof (Buffer), Format, Marker);
  VA_END (Marker);
  Print (L"%s", Buffer);
  if (Length >= ARRAY_SIZE (Buffer) - 1U) {
    RecordLogError (Logger, EFI_BAD_BUFFER_SIZE);
  }

  if ((Logger == NULL) || (Logger->File == NULL) || EFI_ERROR (Logger->Status)) {
    return;
  }

  // All messages in this application are ASCII. Check before converting so
  // an unexpected high character cannot trigger a DEBUG-library ASSERT.
  for (Index = 0; Index < Length; Index++) {
    if (Buffer[Index] > 0x7FU) {
      RecordLogError (Logger, EFI_UNSUPPORTED);
      return;
    }

    AsciiBuffer[Index] = (CHAR8)Buffer[Index];
  }

  Offset = 0;
  while (Offset < Length) {
    WriteSize = Length - Offset;
    Status    = Logger->File->Write (Logger->File, &WriteSize, AsciiBuffer + Offset);
    if (EFI_ERROR (Status) || (WriteSize == 0U) || (WriteSize > Length - Offset)) {
      RecordLogError (Logger, EFI_ERROR (Status) ? Status : EFI_DEVICE_ERROR);
      return;
    }

    Offset += WriteSize;
  }
}

/**
  Log selected descriptors and collect descriptor-level diagnostic counts.

  @param[in]     Logger    Console/file logging state.
  @param[in]     Snapshot  Captured memory-map state.
  @param[in,out] Summary   Result and diagnostic counters.
**/
STATIC
VOID
DumpConstraintDescriptors (
  IN     R64K_LOGGER      *Logger,
  IN     R64K_MEMORY_MAP  *Snapshot,
  IN OUT R64K_SUMMARY     *Summary
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
    LogLine (Logger, L"INFO: Constraint descriptor[%Lu]\r\n", (UINT64)Index);
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
      LogLine (
        Logger,
        L"WARNING: Runtime code/data descriptor[%Lu] does not carry EFI_MEMORY_RUNTIME.\r\n\r\n",
        (UINT64)Index
        );
      Summary->RuntimeAttributeWarnings++;
      Summary->Warnings++;
    }

    Index++;
  }
}

/**
  Log the UEFI memory types which selected a physical 64 KiB block.

  @param[in] Logger        Console/file logging state.
  @param[in] TriggerTypes  Bitmask of types selecting the block.
**/
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

/**
  Log a successful translation and its decoded comparison attributes.

  @param[in] Logger            Console/file logging state.
  @param[in] PageIndex         Index of the 4 KiB subrange within the block.
  @param[in] Address           Address to inspect.
  @param[in] IsTriggerType     Whether this page belongs to a block-selection type.
  @param[in] MemoryDescriptor  Covering UEFI descriptor, or NULL for an undescribed address.
  @param[in] Walk              Successful page-table translation result.
**/
STATIC
VOID
LogPageDetails (
  IN R64K_LOGGER            *Logger,
  IN UINTN                  PageIndex,
  IN UINT64                 Address,
  IN BOOLEAN                IsTriggerType,
  IN EFI_MEMORY_DESCRIPTOR  *MemoryDescriptor,
  IN R64K_WALK_RESULT       *Walk
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

/**
  Convert the application result to a constant printable string.

  @param[in] Result  Application result.

  @return The matching constant diagnostic string, or the documented default.
**/
STATIC
CONST CHAR16 *
ResultString (
  IN R64K_RESULT  Result
  )
{
  switch (Result) {
    case R64K_RESULT_PASS:
      return L"PASS";
    case R64K_RESULT_FAIL:
      return L"FAIL";
    case R64K_RESULT_WARNING:
      return L"WARNING";
    default:
      return L"SKIP";
  }
}

/**
  Append a nonzero reason count, separating reasons with semicolons.

  @param[in,out] Logger   Logging state.
  @param[in,out] Written  Whether another reason has already been emitted.
  @param[in]     Count    Number of occurrences.
  @param[in]     Format   Format accepting one UINT64 decimal argument (%Lu).
**/
STATIC
VOID
LogCountReason (
  IN OUT R64K_LOGGER   *Logger,
  IN OUT BOOLEAN       *Written,
  IN     UINTN         Count,
  IN     CONST CHAR16  *Format
  )
{
  if (Count != 0U) {
    if (*Written) {
      LogLine (Logger, L"; ");
    }

    LogLine (Logger, Format, (UINT64)Count);
    *Written = TRUE;
  }
}

/**
  Print exactly one REASON line, including every recorded cause.

  @param[in,out] Logger       Logging state.
  @param[in]     FinalResult  Overall result.
  @param[in]     Summary      Counts of failures, incomplete checks and exceptions.
  @param[in]     SkipReason   Explanation of a setup failure, or NULL.
  @param[in]     SetupStatus  Status accompanying SkipReason.
**/
STATIC
VOID
LogResultReason (
  IN OUT R64K_LOGGER         *Logger,
  IN     R64K_RESULT         FinalResult,
  IN     CONST R64K_SUMMARY  *Summary,
  IN     CONST CHAR16        *SkipReason OPTIONAL,
  IN     EFI_STATUS          SetupStatus
  )
{
  BOOLEAN  Written;

  Written = FALSE;
  LogLine (Logger, L"REASON: ");
  if (FinalResult == R64K_RESULT_SKIP) {
    LogLine (Logger, L"%s (%r)", SkipReason != NULL ? SkipReason : L"Test could not run", SetupStatus);
    Written = TRUE;
  } else if (FinalResult == R64K_RESULT_PASS) {
    LogLine (Logger, L"All selected 64 KiB blocks passed");
    Written = TRUE;
  }

  LogCountReason (Logger, &Written, Summary->Ttbr1UsageErrors,
                  L"TTBR1 was selected for %Lu page(s); UEFI requires TTBR0 to be used solely");
  LogCountReason (Logger, &Written, Summary->TriggerPagesUnmapped,
                  L"%Lu non-Reserved trigger page(s) were unmapped");
  LogCountReason (Logger, &Written, Summary->TriggerPagesNonIdentity,
                  L"%Lu trigger page(s) were non-identity mapped");
  LogCountReason (Logger, &Written, Summary->AttributeMismatchErrors,
                  L"%Lu incompatible page-attribute mapping(s) were detected");
  LogCountReason (Logger, &Written, Summary->WalkUnsupportedWarnings,
                  L"%Lu page(s) used an unsupported translation configuration or address range");
  LogCountReason (Logger, &Written, Summary->UnsafeTableWarnings,
                  L"%Lu table walk(s) could not confirm identity-readable Normal table memory");
  LogCountReason (Logger, &Written, Summary->MalformedWalkWarnings,
                  L"%Lu walk(s) contained malformed descriptors or table addresses");
  LogCountReason (Logger, &Written, Summary->ChangedWalkWarnings,
                  L"%Lu walk(s) saw changing translation controls or descriptors");
  LogCountReason (Logger, &Written, Summary->NonTriggerPagesNonIdentity,
                  L"%Lu non-trigger page(s) were non-identity mapped");
  LogCountReason (Logger, &Written, Summary->NoComparableMappedBlocks,
                  L"%Lu block(s) had no comparable mapped pages");
  LogCountReason (Logger, &Written, Summary->RuntimeAttributeWarnings,
                  L"%Lu runtime descriptor(s) lacked EFI_MEMORY_RUNTIME (diagnostic warning)");
  LogCountReason (Logger, &Written, Summary->InvalidDescriptorWarnings,
                  L"%Lu constraint descriptor(s) had invalid ranges");
  LogCountReason (Logger, &Written, Summary->ReservedPagesUnmappedAccepted,
                  L"%Lu unmapped EfiReservedMemoryType page(s) were accepted");
  LogCountReason (Logger, &Written, Summary->FullyReservedUnmappedBlocksPassed,
                  L"%Lu fully Reserved and fully unmapped block(s) passed without attribute comparison");
  if (Summary->IoWarnings != 0U) {
    if (Written) {
      LogLine (Logger, L"; ");
    }

    LogLine (Logger, L"file logging failed (%r); the saved log may be incomplete", Logger->Status);
    Written = TRUE;
  }

  if (!Written) {
    LogLine (Logger, L"The selected blocks could not be fully validated; see per-page diagnostics");
  }

  LogLine (Logger, L".\r\n");
}

/**
  Inspect selected 64 KiB blocks and emit the summary and single reason line.

  @param[in] ImageHandle  Running UEFI image handle.
  @param[in] Logger       Console/file logging state.

  @return EFI_SUCCESS when the test ran; its compliance result is in RESULT. A setup error may be returned.
**/
STATIC
EFI_STATUS
RunCheck (
  IN EFI_HANDLE   ImageHandle,
  IN R64K_LOGGER  *Logger
  )
{
  EFI_STATUS                Status;
  R64K_MEMORY_MAP           Snapshot;
  R64K_TRANSLATION_CONTEXT  Context;
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
  CONST CHAR16              *SkipReason;
  EFI_STATUS                SetupStatus;
  EFI_STATUS                ExecutionStatus;

  (VOID)ImageHandle;
  if (Logger == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&Snapshot, sizeof (Snapshot));
  ZeroMem (&Context, sizeof (Context));
  ZeroMem (&Summary, sizeof (Summary));
  Blocks          = NULL;
  BlockCount      = 0;
  FinalResult     = R64K_RESULT_SKIP;
  SkipReason      = NULL;
  SetupStatus     = EFI_SUCCESS;
  ExecutionStatus = EFI_SUCCESS;

  LogLine (Logger, L"============================================================\r\n");
  LogLine (Logger, L"AArch64 UEFI 64 KiB Page Attribute Check\r\n");
  LogLine (Logger, L"============================================================\r\n");

  Status = R64KGetMemoryMap (&Snapshot);
  if (EFI_ERROR (Status)) {
    LogLine (Logger, L"ERROR: GetMemoryMap failed: %r\r\n", Status);
    SkipReason      = L"UEFI memory-map acquisition or validation failed";
    SetupStatus     = Status;
    ExecutionStatus = Status;
    goto Finish;
  }

  LogLine (Logger, L"INFO: Memory map size       : %Lu bytes\r\n", (UINT64)Snapshot.MapSize);
  LogLine (Logger, L"INFO: Descriptor size       : %Lu bytes\r\n", (UINT64)Snapshot.DescriptorSize);
  LogLine (Logger, L"INFO: Descriptor version    : %Lu\r\n\r\n", (UINT64)Snapshot.DescriptorVersion);
  DumpConstraintDescriptors (Logger, &Snapshot, &Summary);

  Status = R64KInitializeTranslationContext (&Context);
  if (EFI_ERROR (Status)) {
    LogLine (Logger, L"WARNING: Translation-table inspection is unsupported: %r\r\n", Status);
    SkipReason  = Context.Reason;
    SetupStatus = Status;
    goto Finish;
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
    SkipReason = (Status == EFI_NOT_FOUND) ? L"No applicable 64 KiB blocks were found" :
                 L"Block collection failed (invalid ranges, allocation failure, or block limit)";
    SetupStatus = Status;
    goto Finish;
  }

  Summary.ConstraintBlocks = BlockCount;
  LogLine (Logger, L"INFO: Unique four-type-related 64 KiB blocks: %Lu\r\n\r\n", (UINT64)BlockCount);

  for (BlockIndex = 0; BlockIndex < BlockCount; BlockIndex++) {
    HaveReference      = FALSE;
    ReferenceSignature = 0;
    ReferenceAddress   = 0;
    BlockFailed        = FALSE;
    BlockIncomplete    = FALSE;
    AllPagesReserved   = TRUE;
    AllPagesUnmapped   = TRUE;
    MappedPages        = 0;

    LogLine (Logger, L"------------------------------------------------------------\r\n");
    LogLine (Logger, L"INFO: Checking block 0x%016lx-0x%016lx\r\n",
             Blocks[BlockIndex].BaseAddress,
             Blocks[BlockIndex].BaseAddress + R64K_BLOCK_SIZE - 1ULL);
    LogBlockTriggerTypes (Logger, Blocks[BlockIndex].TriggerTypes);

    for (PageIndex = 0; PageIndex < R64K_PAGES_PER_BLOCK; PageIndex++) {
      Address          = Blocks[BlockIndex].BaseAddress + PageIndex * R64K_PAGE_SIZE;
      IsTriggerType    = R64KAddressIsConstraintType (&Snapshot, Address);
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
        switch (WalkStatus) {
          case R64K_WALK_UNSAFE_TABLE:
            Summary.UnsafeTableWarnings++;
            break;
          case R64K_WALK_MALFORMED:
            Summary.MalformedWalkWarnings++;
            break;
          case R64K_WALK_CHANGED:
            Summary.ChangedWalkWarnings++;
            break;
          default:
            Summary.WalkUnsupportedWarnings++;
            break;
        }
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
        HaveReference      = TRUE;
        ReferenceSignature = Walk.AttributeSignature;
        ReferenceAddress   = Address;
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

Finish:
  if (Logger->File != NULL) {
    Status = Logger->File->Flush (Logger->File);
    RecordLogError (Logger, Status);
  }

  if (EFI_ERROR (Logger->Status)) {
    Summary.IoWarnings++;
    Summary.Warnings++;
    if (FinalResult == R64K_RESULT_PASS) {
      FinalResult = R64K_RESULT_WARNING;
    }
  }

  LogLine (Logger, L"\r\n============================================================\r\n");
  LogLine (Logger, L"AArch64 UEFI 64 KiB Page Attribute Check Summary\r\n");
  LogLine (Logger, L"============================================================\r\n");
  LogLine (Logger, L"EfiRuntimeServicesCode descriptors  : %Lu\r\n", (UINT64)Summary.RuntimeCodeDescriptors);
  LogLine (Logger, L"EfiRuntimeServicesData descriptors  : %Lu\r\n", (UINT64)Summary.RuntimeDataDescriptors);
  LogLine (Logger, L"EfiReservedMemoryType descriptors   : %Lu\r\n", (UINT64)Summary.ReservedDescriptors);
  LogLine (Logger, L"EfiACPIMemoryNVS descriptors        : %Lu\r\n", (UINT64)Summary.AcpiNvsDescriptors);
  LogLine (Logger, L"Four-type-related 64 KiB blocks     : %Lu\r\n", (UINT64)Summary.ConstraintBlocks);
  LogLine (Logger, L"Blocks passed                       : %Lu\r\n", (UINT64)Summary.BlocksPassed);
  LogLine (Logger, L"Blocks failed                       : %Lu\r\n", (UINT64)Summary.BlocksFailed);
  LogLine (Logger, L"Blocks incomplete                   : %Lu\r\n", (UINT64)Summary.BlocksIncomplete);
  LogLine (Logger, L"Trigger pages unmapped              : %Lu\r\n", (UINT64)Summary.TriggerPagesUnmapped);
  LogLine (Logger, L"Trigger pages non-identity mapped   : %Lu\r\n", (UINT64)Summary.TriggerPagesNonIdentity);
  LogLine (Logger, L"Other pages unmapped                : %Lu\r\n", (UINT64)Summary.NonTriggerPagesUnmapped);
  LogLine (Logger, L"Other pages non-identity mapped     : %Lu\r\n", (UINT64)Summary.NonTriggerPagesNonIdentity);
  LogLine (Logger, L"TTBR1 usage errors                  : %Lu\r\n", (UINT64)Summary.Ttbr1UsageErrors);
  LogLine (Logger, L"Warnings                            : %Lu\r\n", (UINT64)Summary.Warnings);
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
  LogResultReason (Logger, FinalResult, &Summary, SkipReason, SetupStatus);
  LogLine (Logger, L"============================================================\r\n");

  if (Blocks != NULL) {
    FreePool (Blocks);
  }

  R64KFreeMemoryMap (&Snapshot);
  return ExecutionStatus;
}

/**
  Open logging, run the check, and close all application-owned resources.

  @param[in] ImageHandle  Running UEFI image handle.
  @param[in] SystemTable  UEFI system table provided by the image loader.

  @return Execution or logging status. Read RESULT/REASON for the compliance result.
**/
EFI_STATUS
EFIAPI
Runtime64KCheckEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS   Status;
  EFI_STATUS   LogStatus;
  R64K_LOGGER  Logger;

  (VOID)SystemTable;
  Status = OpenLogger (ImageHandle, &Logger);
  if (EFI_ERROR (Status)) {
    Print (L"WARNING: Could not open %s: %r\r\n", RUNTIME64K_LOG_PATH, Status);
    Print (L"The check will continue with console output only.\r\n");
    RecordLogError (&Logger, Status);
  } else {
    Print (L"Detailed log: %s\r\n", RUNTIME64K_LOG_PATH);
  }

  Status    = RunCheck (ImageHandle, &Logger);
  LogStatus = CloseLogger (&Logger);
  return EFI_ERROR (Status) ? Status : LogStatus;
}
