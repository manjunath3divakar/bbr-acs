# Runtime64KiBPageAttributeCheck

Standalone AARCH64 UEFI application shared by the SBBR and EBBR BBR-ACS builds.
This revision is based on the supplied v3 source. The seven source/build files
are retained; the INF and DSC names now match the application name.

## Location and build integration

```
common/uefi_app/Runtime64KiBPageAttributeCheck/
  AArch64PageTable.c
  AArch64PageTable.h
  AArch64Registers.S
  Runtime64KCheck.c
  Runtime64KCheck.h
  Runtime64KiBPageAttributeCheck.inf
  Runtime64KiBPageAttributeCheck.dsc
```

`common/scripts/build-uefi-apps.sh` invokes the shared DSC for BOTH `SBBR` and
`EBBR`. PCIe Option ROM auditing remains SBBR-only. UefiDump remains EBBR-only.
The old `sbbr/uefi_app/Runtime64KCheck/` application is removed by the patch.
Do not keep two copies of the module in the repository.

After the normal source/dependency setup, use the existing standalone entry
points from the repository root:

```sh
(cd sbbr/scripts && ./build-scripts/build_sbbr.sh)
(cd ebbr/scripts && ./build-scripts/build_ebbr.sh)
```

The app build command in the shared script is:

```sh
build -a "$TARGET_ARCH" -b "$UEFI_BUILD_MODE" -t "$UEFI_TOOLCHAIN" \
  -p common/uefi_app/Runtime64KiBPageAttributeCheck/Runtime64KiBPageAttributeCheck.dsc
```

The EDK II workspace's output is:

```
Build/MdeModule/<TARGET>_<TOOLCHAIN>/AARCH64/Runtime64KiBPageAttributeCheck.efi
```

For standalone builds (`BUILD_TYPE=S`), the package destinations are:

```
SBBR-SCT/acs_tests/app/Runtime64KiBPageAttributeCheck.efi
EBBR-SCT/acs_tests/app/Runtime64KiBPageAttributeCheck.efi
```

For `BUILD_TYPE=F`, the shared script signs the built application using the
existing ACS signing flow. Full SystemReady SR/DT image inclusion and launch
scripts are outside this BBR-only change. In particular, a separate DT Yocto
recipe must reference this new DSC/source path if that build does not call
`common/scripts/build-uefi-apps.sh`.

The internal C entry point remains `Runtime64KCheckEntryPoint`; no callers need
an entry-point name change. The module has no ArmPkg/ArmLib dependency: uniquely
prefixed assembly helpers provide the required AArch64 register reads.

## Run and log

From the ACS volume in the UEFI Shell:

```
FS2:\> \acs_tests\app\Runtime64KiBPageAttributeCheck.efi
```

Use the filesystem mapping appropriate to the test media, not necessarily FS2.
The application writes its own ASCII log, and mirrors output to the CHAR16
console. The v3 destination is deliberately unchanged:

```
\acs_results_template\acs_results\uefi_checks\runtime_64k_page_attributes.log
```

`RUNTIME64K_LOG_DIR` and `RUNTIME64K_LOG_PATH` in `Runtime64KCheck.h` configure it.
The existing log is truncated with `EFI_FILE_INFO`/`SetInfo` before new output.
Short writes are completed. Failed, zero-progress, oversized, and truncated
writes are reported on the console without an unbounded retry. A first logging
error is retained and returned at application exit.

## Scope and result policy

The memory map selects every physical 64 KiB block intersecting any of:
`EfiRuntimeServicesCode`, `EfiRuntimeServicesData`, `EfiReservedMemoryType`, or
`EfiACPIMemoryNVS`. Both range boundaries are included, with deduplication of
blocks shared by descriptors. Runtime MMIO does not select blocks.

Every mapped, identity-correlated 4 KiB subrange in a selected block is compared,
including subranges described by another memory type. The comparison is unchanged
from v3: resolved MAIR byte, SH, AP[2], and PXN/UXN at EL1 or XN at non-VHE EL2.
Raw AttrIndx is diagnostic only. Parent-table RO/XN restrictions are included
when hierarchical permissions are enabled. The printed descriptor remains the
raw leaf descriptor; decoded permissions include those inherited restrictions.

| Condition | Result behavior |
| --- | --- |
| Compared attributes agree | Block PASS |
| Selected VA falls in the TTBR1 range | FAIL; never probe/walk its TTBR1 tables |
| Non-Reserved trigger page is unmapped | FAIL |
| Trigger page maps non-identity | FAIL |
| Compared attributes disagree | FAIL |
| Individual Reserved page is unmapped | Accepted; excluded from attribute comparison |
| All 16 pages are Reserved and unmapped | Block PASS, with accepted-condition reason |
| Unsupported/malformed/unsafe/changing table inspection | Block WARNING, not invented attributes |
| Non-trigger page maps non-identity | Block WARNING |
| No comparable mapped pages, except wholly Reserved/unmapped | Block WARNING |
| Unsupported initial context, no selected blocks, setup error | SKIP, with reason/status |
| Logging error known before summary, otherwise PASS | Overall WARNING; console still works |

Reserved-page acceptance preserves the requested v3 project policy. It is broader
than accepting only entirely Reserved/unmapped blocks; it also accepts an unmapped
Reserved page in a mixed block. This is a test-policy choice, not an assertion that
a new universal UEFI exception has been standardized. A mapped Reserved page is
still compared. An unsafe or changed walk is NOT treated as an unmapped page.

TTBR1 detection is per requested virtual address/range. A nonzero but unused
`TTBR1_EL1` value alone does not trigger a failure. This is not an enumeration of
all mappings or a proof that no unexamined high-VA alias exists.

The summary retains the original descriptor/page/block counters plus the TTBR1
counter. It ends with `RESULT: ...` and exactly one `REASON: ...` line. Multiple
causes are joined on that line; no separate reason tables are printed. FAIL takes
precedence over WARNING. Diagnostic missing-EFI_MEMORY_RUNTIME warnings retain
v3 policy: they are counted and explained but alone do not fail a block.

A completed compliance FAIL still returns `EFI_SUCCESS`, as in v3. Automation
must parse `RESULT` and `REASON` for the compliance verdict, not assume the Shell
exit status equals PASS. Execution and logging failures return an EFI error.
A storage failure while writing/closing the summary may occur after its verdict
has been printed; that late failure is reported on the console and by exit status,
not guaranteed to be captured in an already failing file.

## Walker hardening and supported configurations

Supported baseline: little-endian EL1 or non-VHE EL2, MMU enabled, 4 KiB granule,
64-bit descriptors, 25..48 VA bits, and up to 48 output address bits. L1 blocks,
L2 blocks, and L3 pages are handled. The initial TTBR0 table size/alignment/index
are derived from T0SZ and the start level; reduced initial tables need not have
4 KiB alignment. Subsequent tables remain 4 KiB.

The implementation checks descriptor kinds, output widths, block alignment,
range arithmetic, array limits, and memory-map stride. Table access is preflighted
against RAM-like descriptors and address-translation results for both endpoints
of the actual table. Table address zero is rejected instead of invoking C null
pointer behavior. Only table bytes are read, never the target Reserved/MMIO data.

Controls and descriptor reads are checked for observable changes. Detected
changes return an incomplete result. This is not an atomic snapshot of all MMU
state; concurrent changes can still escape these checks.

Unsupported cases are reported rather than interpreted with guessed masks:
non-4-KiB granules, EL2 VHE, LPA2, tagged-address configurations, hardware dirty
management, disabled TTBR0 walks, SCTLR.WXN, big-endian configuration, and extended
address/permission formats. The MMFR3 guard conservatively rejects CPUs advertising
TCR2, S1PIE, S1POE, AIE, or D128 support; it does NOT read optional feature control
registers to discover whether each feature is enabled. Such a CPU may therefore
SKIP even when its current tables use a simple format. Extending that support is
separate work, not silently included in a PASS.

The map buffer is limited to 16 MiB and collection to 65,536 block entries before
deduplication. These bounds avoid unbounded allocation. Exhaustion is reported,
not treated as success. Block sorting/deduplication is O(N log N), replacing the
v3 repeated linear duplicate search.

## Register and exception safety boundary

CurrentEL is checked before reading EL-specific registers. The app never reads
TTBR1_EL2. Assembly helpers preserve the required general-purpose registers and
leave x18 untouched. AT helpers save/restore PAR_EL1 and DAIF, masking exceptions
only for that short sequence. No TTBR, TCR, MAIR, page table, or vector table is
written by the test.

This is a read-only diagnostic with preflight checks, NOT a fault-contained VM
or an exception-recovery framework. A hypervisor may trap register/AT instructions;
a later external abort, firmware bug, hardware error, or concurrent remap can
still fault a software load. There is no portable guarantee that arbitrary broken
firmware cannot crash. The app relies on the ordinary UEFI privileged execution
contract and valid firmware protocol implementations. It does not dereference
TTBR1 tables after rejecting that range and does not install a global exception
handler that could disrupt existing firmware handlers.

Only stage-1 is inspected. Under virtualization, its output may be guest physical
(IPA), not host PA; stage-2 attributes/protection are not independently validated.
Firmware page tables observed before ExitBootServices do not certify later OS
mappings or runtime virtual-address conversions.

## Coding and validation

Application source/build files are ASCII, CRLF, tab-free, and at most 120 columns.
File/function documentation and header guards are present. Shell scripts retain
LF. Existing license notices are preserved; no blanket relicensing was performed.

The accompanying validation package records actual AARCH64 DEBUG and RELEASE
CLANGDWARF application builds, 32 host-test groups with ASan/UBSan, four mocked
build/package dispatch combinations, and patch/style checks. The host tests use
real EDK II headers/PrintLib plus mocked firmware/register interfaces; they are
not linked into the EFI app. No production fault injection is enabled.

The exact BBR-pinned edk2-stable202511/GCC5 environment, full SBBR/EBBR suites,
physical-board execution, and official TianoCore UncrustifyCheck still need to be
run in the target development environment. They are not claimed as tested here.
Use the TianoCore Uncrustify fork and your checkout's uncrustify.cfg before review.

Primary references:
- UEFI 2.11, section 2.3.6: https://uefi.org/specs/UEFI/2.11/02_Overview.html
- UEFI file protocol: https://uefi.org/specs/UEFI/2.11/13_Protocols_Media_Access.html
- EDK II formatting: https://www.tianocore.org/tianocore-wiki.github.io/development/coding-standards/edk_ii_code_formatting.html
