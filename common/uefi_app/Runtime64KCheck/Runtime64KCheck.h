/** @file

  Copyright (c) 2026, Arm Ltd. All rights reserved.<BR>

  This program and the accompanying materials are licensed and made available
  under the terms and conditions of the BSD License which accompanies this
  distribution. The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php.

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef RUNTIME_64K_CHECK_H_
#define RUNTIME_64K_CHECK_H_

#include <Uefi.h>

#define RUNTIME64K_LOG_PATH     L"\\acs_results_template\\acs_results\\uefi_checks\\runtime_64k_page_attributes.log"
#define RUNTIME64K_LOG_DIR      L"\\acs_results_template\\acs_results\\uefi_checks"

EFI_STATUS
EFIAPI
Runtime64KCheckEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

#endif
