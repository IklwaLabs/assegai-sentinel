# Generates an MSVC import library (wpcap.lib) from the installed wpcap.dll.
#
# Why this exists: the `pcap` crate links `wpcap.lib`, which ships in the **Npcap SDK**. This
# machine has the Npcap *runtime* (wpcap.dll in System32) but not the SDK, so cargo cannot link.
# npcap.com is unreachable from this environment, so the import library is synthesised from the
# DLL's PE export table instead.
#
# This is a local build aid only. It is NOT part of the Sentinel repository: the repository
# expects the real Npcap SDK, and its build script reports a clear actionable error when the
# import library is missing.
#
# Usage:  powershell -File make-wpcap-lib.ps1
# Output: %LOCALAPPDATA%\IklwaDevTools\pcap\wpcap.lib
# Then:   set IKLWA_PCAP_LIB=%LOCALAPPDATA%\IklwaDevTools\pcap

param(
    [string]$Dll = "$env:SystemRoot\System32\wpcap.dll",
    [string]$OutDir = "$env:LOCALAPPDATA\IklwaDevTools\pcap",
    [string]$VsRoot = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"
)

$ErrorActionPreference = 'Stop'

function Get-PeExports([string]$path) {
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
    if ([BitConverter]::ToUInt32($bytes, $peOffset) -ne 0x00004550) { throw "Not a PE file: $path" }

    $coff = $peOffset + 4
    $sectionCount = [BitConverter]::ToUInt16($bytes, $coff + 2)
    $optionalSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
    $optional = $coff + 20
    $magic = [BitConverter]::ToUInt16($bytes, $optional)
    if ($magic -ne 0x20b) { throw "Expected a 64-bit PE (magic 0x20b), found 0x$('{0:X}' -f $magic)" }

    $dataDirOffset = $optional + 112
    $exportRva = [BitConverter]::ToUInt32($bytes, $dataDirOffset)
    if ($exportRva -eq 0) { throw "No export directory" }

    $sections = @()
    $sectionTable = $optional + $optionalSize
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $s = $sectionTable + 40 * $i
        $sections += [pscustomobject]@{
            VirtualAddress = [BitConverter]::ToUInt32($bytes, $s + 12)
            VirtualSize    = [BitConverter]::ToUInt32($bytes, $s + 8)
            RawAddress     = [BitConverter]::ToUInt32($bytes, $s + 20)
            RawSize        = [BitConverter]::ToUInt32($bytes, $s + 16)
        }
    }

    $convert = {
        param([uint32]$rva)
        foreach ($section in $sections) {
            $span = [Math]::Max($section.VirtualSize, $section.RawSize)
            if ($rva -ge $section.VirtualAddress -and $rva -lt ($section.VirtualAddress + $span)) {
                return [int]($section.RawAddress + ($rva - $section.VirtualAddress))
            }
        }
        throw "RVA 0x$('{0:X}' -f $rva) lies outside every section"
    }

    $exportDir = & $convert $exportRva
    $nameCount = [BitConverter]::ToUInt32($bytes, $exportDir + 24)
    $namesRva = [BitConverter]::ToUInt32($bytes, $exportDir + 32)
    if ($nameCount -eq 0 -or $namesRva -eq 0) { throw "Export directory lists no names" }

    $namesTable = & $convert $namesRva
    $names = @()
    for ($i = 0; $i -lt $nameCount; $i++) {
        $nameOffset = & $convert ([BitConverter]::ToUInt32($bytes, $namesTable + 4 * $i))
        $end = $nameOffset
        while ($bytes[$end] -ne 0) { $end++ }
        $names += [System.Text.Encoding]::ASCII.GetString($bytes, $nameOffset, $end - $nameOffset)
    }
    return $names
}

if (-not (Test-Path $Dll)) {
    throw "wpcap.dll not found at $Dll. Install the Npcap runtime from https://npcap.com first."
}

$names = Get-PeExports $Dll
if ($names.Count -lt 50) { throw "Only $($names.Count) exports found; expected the full libpcap API" }
if (-not ($names -contains 'pcap_open_live')) { throw "pcap_open_live is missing; $Dll is not a libpcap DLL" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$defPath = Join-Path $OutDir 'wpcap.def'
$libPath = Join-Path $OutDir 'wpcap.lib'

$sb = [System.Text.StringBuilder]::new()
[void]$sb.AppendLine('LIBRARY wpcap.dll')
[void]$sb.AppendLine('EXPORTS')
foreach ($name in ($names | Sort-Object -Unique)) {
    if ($name -match '^[A-Za-z_][A-Za-z0-9_]*$') { [void]$sb.AppendLine("  $name") }
}
[System.IO.File]::WriteAllText($defPath, $sb.ToString())

$vcvars = Join-Path $VsRoot 'VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vcvars)) { throw "vcvars64.bat not found at $vcvars" }

& cmd.exe /c "call `"$vcvars`" >nul 2>&1 && lib.exe /nologo /def:`"$defPath`" /out:`"$libPath`" /machine:x64" | Out-String | Write-Host
if (-not (Test-Path $libPath)) { throw "lib.exe did not produce $libPath" }

"Created $libPath from $($names.Count) exports."
"Set IKLWA_PCAP_LIB to: $OutDir"
