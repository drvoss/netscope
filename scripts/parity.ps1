<#
.SYNOPSIS
    Verifies Go/C++ observable parity by byte-comparing canonical snapshots.

.DESCRIPTION
    Both binaries support `--replay <scenario.json> --emit-snapshot`, which drives
    the engine from a fixed ProbeResult stream and a virtual monotonic clock, then
    prints a canonical JSON snapshot. No sockets are opened and no real clock is
    read, so the output is fully deterministic and can be compared byte for byte.

    This is the parity mechanism docs/netscope-spec.md §9 requires. Mirroring
    directory names between the two implementations proves nothing; identical bytes
    out of identical input proves the measurement semantics agree.

.PARAMETER Scenario
    Run only the named scenario (without .json). Default: all of them.

.PARAMETER ShowDiff
    Print the differing lines for any scenario that fails.
#>
[CmdletBinding()]
param(
    [string]$Scenario,
    [switch]$ShowDiff
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$goBin = Join-Path $repoRoot 'netscope-go\netscope.exe'
$cppBin = Join-Path $repoRoot 'netscope-cpp\build\windows-release\nscope.exe'
$scenarioDir = Join-Path $repoRoot 'testdata\scenarios'

foreach ($b in @($goBin, $cppBin)) {
    if (-not (Test-Path $b)) {
        throw "missing binary: $b  (build both implementations first)"
    }
}

$files = if ($Scenario) {
    @(Join-Path $scenarioDir "$Scenario.json")
} else {
    Get-ChildItem -Path $scenarioDir -Filter '*.json' | Sort-Object Name | ForEach-Object { $_.FullName }
}

$pass = 0
$fail = 0

foreach ($file in $files) {
    $name = [System.IO.Path]::GetFileNameWithoutExtension($file)

    $goOut = & $goBin --replay $file --emit-snapshot 2>&1 | Out-String
    $goExit = $LASTEXITCODE
    $cppOut = & $cppBin --replay $file --emit-snapshot 2>&1 | Out-String
    $cppExit = $LASTEXITCODE

    if ($goExit -ne 0 -or $cppExit -ne 0) {
        Write-Host ("FAIL  {0,-22} replay exited go={1} cpp={2}" -f $name, $goExit, $cppExit) -ForegroundColor Red
        if ($ShowDiff) {
            Write-Host "--- go ---";  Write-Host $goOut
            Write-Host "--- cpp ---"; Write-Host $cppOut
        }
        $fail++
        continue
    }

    # Normalize line endings only. Everything else -- field order, float format,
    # spacing -- is part of the contract and must already match.
    $g = $goOut -replace "`r`n", "`n"
    $c = $cppOut -replace "`r`n", "`n"

    if ($g -ceq $c) {
        Write-Host ("PASS  {0,-22} {1} bytes identical" -f $name, $g.Length) -ForegroundColor Green
        $pass++
    } else {
        Write-Host ("FAIL  {0,-22} snapshots differ" -f $name) -ForegroundColor Red
        $fail++
        if ($ShowDiff) {
            $gl = $g -split "`n"
            $cl = $c -split "`n"
            $max = [Math]::Max($gl.Count, $cl.Count)
            $shown = 0
            for ($i = 0; $i -lt $max -and $shown -lt 30; $i++) {
                $a = if ($i -lt $gl.Count) { $gl[$i] } else { '<missing>' }
                $b = if ($i -lt $cl.Count) { $cl[$i] } else { '<missing>' }
                if ($a -cne $b) {
                    Write-Host ("  line {0}" -f ($i + 1)) -ForegroundColor Yellow
                    Write-Host ("    go : {0}" -f $a)
                    Write-Host ("    cpp: {0}" -f $b)
                    $shown++
                }
            }
        }
    }
}

Write-Host ""
Write-Host ("parity: {0} passed, {1} failed" -f $pass, $fail)
if ($fail -gt 0) { exit 1 }
exit 0
