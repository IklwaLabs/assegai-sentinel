<#
.SYNOPSIS
  Builds a stub wpcap.dll so Windows test binaries can start without Npcap installed.

.DESCRIPTION
  The `pcap` crate declares its native bindings with `#[link(name = "wpcap")]`
  (pcap-1.3.0/src/raw.rs, module ffi_windows). That is a *static* import: the MSVC linker
  writes wpcap.dll into the test binary's import table and Windows resolves every named
  function during process startup, before main() runs. So a test binary that links
  sentinel-capture needs a wpcap.dll that exports the functions it imports -- even though
  not one of the 292 tests calls a single pcap function. They all run through generated
  frames and the offline reader.

  Installing the real DLL means running the Npcap installer, which does not work unattended.
  Npcap's own tracker says so:

    "Since the npcap installer has no silent mode, it can not be used to set up npcap in the
     CI setup of the rust pcap bindings."  -- nmap/npcap#227

  The silent installer is an OEM-only feature. Given /S, the free installer completes its work
  and then leaves a resident process behind; waiting on it hung the Windows job for 35
  minutes.

  So this builds an empty DLL instead, exporting every name from the Npcap SDK's wpcap.def so
  the loader's symbol resolution succeeds. Each export is a trap, not a no-op: if a test ever
  reaches a pcap function it aborts immediately with a clear message, instead of returning
  garbage into a caller.

  This is sound only for running tests, and only because of that. It must never end up on a
  developer's PATH: a capture build that silently resolved this stub would trap at the first
  pcap call. tools/check-for-stub-dll.py refuses to let one reach a release bundle.

.PARAMETER OutputDirectory
  Where to write wpcap.dll. Defaults to a directory under the runner temp.

.PARAMETER BinaryDirectory
  Directory holding the compiled test binaries to read import tables from. Their union of
  wpcap imports is exactly the set of symbols the loader will ask for.

.EXAMPLE
  pwsh -File tools/build-stub-wpcap-dll.ps1 -BinaryDirectory target/debug/deps
#>
[CmdletBinding()]
param(
    [string] $OutputDirectory = (Join-Path ([IO.Path]::GetTempPath()) 'iklwa-stub-wpcap'),
    [string] $BinaryDirectory = 'target\debug\deps'
)

$ErrorActionPreference = 'Stop'

# Set by Find-VisualStudioEnvironment; read by Get-RequiredExports and the link step.
$script:dumpbin = $null

function Find-VisualStudioEnvironment {
    <#
      Finds the batch file that puts cl.exe and link.exe on PATH, trying two routes because
      neither exists everywhere:

        1. vswhere.exe, the supported way in. Requiring the VC.Tools component matters: a
           machine with only the C# workload reports a valid installation path and then has
           no compiler at all.
        2. A direct search for vcvars64.bat. Build Tools installs do not ship vswhere.exe, so
           "has the toolchain but no vswhere" is a real configuration -- including the one
           this was developed on.

      Returns the batch file path, or $null.
    #>
    $vswhere = Join-Path ${env:ProgramFiles} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (Test-Path $vswhere) {
        $installPath = & $vswhere -latest -products * `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath 2>$null
        if ($installPath) {
            foreach ($relative in @('Common7\Tools\VsDevCmd.bat', 'VC\Auxiliary\Build\vcvars64.bat')) {
                $candidate = Join-Path $installPath $relative
                if (Test-Path $candidate) { return $candidate }
            }
        }
    }

    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio'),
        (Join-Path ${env:ProgramFiles} 'Microsoft Visual Studio')
    ) | Where-Object { $_ -and (Test-Path $_) }

    foreach ($root in $roots) {
        $found = Get-ChildItem -Path $root -Recurse -Filter 'vcvars64.bat' -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    return $null
}

function Find-Dumpbin {
    <#
      dumpbin lives beside cl.exe under Tools\MSVC, and is only on PATH after the developer
      environment is set up. Rather than shelling out to cmd once per binary, locate it once
      and call it directly.

      The MSVC root is found by walking *up* from the known batch file until Tools\MSVC
      appears, because the two batch files sit at different depths
      (VC\Auxiliary\Build\vcvars64.bat versus <edition>\Common7\Tools\VsDevCmd.bat) and
      counting parent directories to normalise that gets it wrong easily -- it did once.
    #>
    param([string] $VsDevCmd)

    $directory = Split-Path $VsDevCmd -Parent
    for ($depth = 0; $depth -lt 6 -and $directory; $depth++) {
        $tools = Join-Path $directory 'Tools\MSVC'
        if (Test-Path $tools) {
            $candidate = Get-ChildItem -Path $tools -Recurse -Filter 'dumpbin.exe' -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match 'Hostx64[\\/]x64' } |
                Sort-Object FullName -Descending |
                Select-Object -First 1
            if ($candidate) { return $candidate.FullName }
        }
        $parent = Split-Path $directory -Parent
        if ($parent -eq $directory) { break }
        $directory = $parent
    }

    throw "dumpbin.exe not found within 6 levels above $VsDevCmd."
}

function Get-RequiredExports {
    <#
      Reads the wpcap import table out of compiled binaries and returns the union of the
      symbols they import.

      This is derived from the binaries rather than from the Npcap SDK, and it has to be. Two
      sources that look authoritative are not:

        * The SDK ships no .def file. Its wpcap.lib contains only __IMPORT_DESCRIPTOR_wpcap;
          the function names live in the linked binary's .idata section, not in the library's
          symbol table, so `dumpbin /symbols` returns no __imp_ entries to work from.
        * Guessing the list from the pcap crate's source would rot the first time the crate
          added a call.

      The import table of the actual binaries cannot drift: it is literally the list the
      Windows loader will fail to resolve.
    #>
    param([string] $BinaryDirectory)

    if (-not (Test-Path $BinaryDirectory)) {
        throw "Binary directory not found: $BinaryDirectory. Compile the test binaries first."
    }

    $binaries = @(Get-ChildItem -Path $BinaryDirectory -Filter '*.exe' -File -ErrorAction SilentlyContinue)
    if ($binaries.Count -eq 0) {
        throw "No .exe files under $BinaryDirectory. Compile the test binaries first: cargo test --workspace --no-run"
    }

    $imports = [System.Collections.Generic.HashSet[string]]::new()
    $matched = 0

    foreach ($binary in $binaries) {
        $dump = & $dumpbin /imports $binary.FullName 2>$null
        if (-not $dump) { continue }

        $lines = @($dump)
        $index = 0
        while ($index -lt $lines.Count) {
            # The DLL name line is indented and ends in .dll. Imports for a module are the
            # symbol lines following it, up to the next module header or blank.
            if ($lines[$index] -match '^\s+(\S+\.dll)\s*$') {
                $module = $Matches[1]
                $cursor = $index + 1
                if ($module -ieq 'wpcap.dll') {
                    $matched++
                    while ($cursor -lt $lines.Count -and $lines[$cursor] -notmatch '^\s{4}\S') {
                        if ($lines[$cursor] -match '^\s+[0-9A-F]+\s+([A-Za-z_][A-Za-z0-9_@]*)\s*$') {
                            [void] $imports.Add($Matches[1])
                        }
                        $cursor++
                    }
                }
                $index = $cursor
            } else {
                $index++
            }
        }
    }

    if ($matched -eq 0) {
        throw "No binary under $BinaryDirectory imports wpcap.dll. Either the capture crate is no longer linked, or the binaries were built without it; nothing needs a stub in that case."
    }

    return @($imports | Sort-Object)
}

$devCmd = Find-VisualStudioEnvironment
if (-not $devCmd) {
    throw @'
No Visual Studio C++ toolchain found.

The stub DLL is compiled with cl.exe, which needs the MSVC build tools. On a GitHub
windows-latest runner they are present. On a developer machine, install "Desktop
development with C++" (Visual Studio) or the MSVC build tools.
'@
}
"Using toolchain environment: $devCmd"

$dumpbin = Find-Dumpbin -VsDevCmd $devCmd
$script:dumpbin = $dumpbin
"Using dumpbin: $dumpbin"

$exportNames = Get-RequiredExports -BinaryDirectory $BinaryDirectory
"Found $($exportNames.Count) wpcap symbol(s) across the compiled test binaries."

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

# A .def that maps every name to one shared trap. Aliasing 118 names to a single function
# keeps the generated source trivial and makes it obvious that none of them do anything real.
#
# pcap_findalldevs is excluded because wpcap_stub.c implements it properly: it is the one call
# that has a truthful answer on a machine with no driver, and Sentinel relies on that path.
$implemented = @('pcap_findalldevs')
$trap = 'pcap_stub_trap'
$aliased = $exportNames | Where-Object { $implemented -notcontains $_ }
$defBody = (($aliased | ForEach-Object { "  $_ = $trap" }) + ($implemented)) -join "`r`n"
@"
; Generated by tools/build-stub-wpcap-dll.ps1 from $definition.
;
; Every export forwards to a single function that terminates the process. The loader needs
; the names to exist; nothing in the test suite may call through them. If one is ever called,
; the run dies here with an unmistakable message instead of returning garbage into a caller.
LIBRARY wpcap
EXPORTS
$defBody
"@ | Set-Content -Path (Join-Path $OutputDirectory 'wpcap_stub.def') -Encoding ascii

$source = Join-Path $OutputDirectory 'wpcap_stub.c'
@'
/*
 * A stand-in for wpcap.dll on a machine with no capture driver.
 *
 * Almost every export forwards to pcap_stub_trap, which terminates the process with an
 * explanation. Reaching one means a test tried to capture for real, and any result it would
 * have produced here would be fabricated, so failing loudly is the honest outcome.
 *
 * The exception is pcap_findalldevs. Sentinel treats "no driver installed" as a supported
 * environment and reports it as a typed error rather than a crash, and a test asserts exactly
 * that. So this implements the one call that has a correct answer without a driver: it fails,
 * with the same wording libpcap uses when Npcap is absent. The test then exercises the real
 * no-driver path rather than being skipped or faked into passing.
 *
 * Uses only kernel32. The DLL is linked with /NODEFAULTLIB so it pulls in no C runtime, which
 * keeps it from failing to load over a redistributable unrelated to what it is for.
 */
#include <windows.h>

/* PCAP_ERRBUF_SIZE from pcap/pcap.h. The buffer is caller-owned and this size is the ABI
 * contract; writing past it would corrupt the caller's stack. */
#define IKLWA_PCAP_ERRBUF_SIZE 256

__declspec(dllexport) void pcap_stub_trap(void) {
    static const wchar_t message[] =
        L"\r\n"
        L"Sentinel: a test called into the CI stub wpcap.dll.\r\n"
        L"The stub stands in for a machine with no capture driver. It implements interface\r\n"
        L"enumeration and nothing else, so this test tried to capture for real and any result\r\n"
        L"it produced here would be fabricated. Run it on a machine with Npcap installed.\r\n";
    HANDLE stderr_handle = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written = 0;
    WriteConsoleW(stderr_handle, message, (DWORD)(sizeof(message) / sizeof(message[0])) - 1, &written, NULL);
    /* ExitProcess rather than abort: no CRT is linked, and this skips atexit handlers that
     * belong to the test process rather than to the stub. */
    ExitProcess(3);
}

/*
 * pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf) -> int
 *
 * Returns -1 and fills errbuf, which is what libpcap does when Npcap is not installed. The
 * device list is left untouched on failure; writing NULL is harmless and makes the intent
 * explicit.
 */
__declspec(dllexport) int pcap_findalldevs(void **alldevsp, char *errbuf) {
    static const char message[] =
        "No capture driver is available: this build links a stub wpcap.dll used only by CI.";
    char *cursor;
    int index;

    if (alldevsp != 0) {
        *alldevsp = 0;
    }
    if (errbuf == 0) {
        return -1;
    }

    cursor = errbuf;
    for (index = 0; message[index] != '\0' && index < IKLWA_PCAP_ERRBUF_SIZE - 1; index++) {
        cursor[index] = message[index];
    }
    cursor[index] = '\0';
    return -1;
}
'@ | Set-Content -Path $source -Encoding ascii

$obj = Join-Path $OutputDirectory 'wpcap_stub.obj'
$dll = Join-Path $OutputDirectory 'wpcap.dll'

# VsDevCmd.bat takes -arch/-host_arch; vcvars64.bat takes a bare positional amd64. Passing
# -arch=x64 to vcvars64 prints usage and exits 0 without setting anything, so cl.exe is then
# simply absent and the build fails later with a misleading error.
$archArguments = if ($devCmd -like '*vcvars*') { 'amd64' } else { '-arch=x64 -host_arch=x64' }

# /NODEFAULTLIB is deliberate: it keeps the stub free of the C runtime, so it cannot fail to
# load over a redistributable that has nothing to do with what it is for. The cost is that
# kernel32 must be named explicitly -- otherwise ExitProcess and WriteConsoleW are unresolved
# and the link fails on symbols that look like they should be free.

# Written to a file rather than passed to `cmd /C`, because a multi-line command string is
# not reliably executed by cmd.exe.
$batch = Join-Path $OutputDirectory 'build-stub.bat'
@"
@echo off
call "$devCmd" $archArguments >nul
if errorlevel 1 exit /b 1
cl.exe /nologo /c /O2 /Fo"$obj" "$source"
if errorlevel 1 exit /b 2
link.exe /nologo /DLL /NOENTRY /NODEFAULTLIB kernel32.lib /DEF:"$OutputDirectory\wpcap_stub.def" /OUT:"$dll" "$obj"
if errorlevel 1 exit /b 3
exit /b 0
"@ | Set-Content -Path $batch -Encoding ascii

& cmd.exe /C "`"$batch`""
if ($LASTEXITCODE -ne 0) {
    throw "Building the stub wpcap.dll failed with exit code $LASTEXITCODE. cl.exe exits 2, link.exe 3."
}

if (-not (Test-Path $dll)) {
    throw "link.exe reported success but produced no $dll."
}

Remove-Item (Join-Path $OutputDirectory 'wpcap_stub.lib') -ErrorAction SilentlyContinue
Remove-Item (Join-Path $OutputDirectory 'wpcap_stub.exp') -ErrorAction SilentlyContinue

"Built stub wpcap.dll ($((Get-Item $dll).Length) bytes, $($exportNames.Count) exports) at $dll"
"Put it on PATH only for the step that runs tests. Every export traps, and it must not ship."