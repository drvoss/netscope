<#
.SYNOPSIS
    Configures and builds netscope-cpp (binary nscope) with MSVC + vcpkg + Ninja.

.DESCRIPTION
    Wraps the Visual Studio developer environment so the build works from a plain
    shell. Three things need setting up that are not on PATH by default:

      * vcvars64.bat, for cl.exe and the Windows SDK
      * the CMake and Ninja bundled with Visual Studio (no standalone install)
      * VCPKG_ROOT, which CMakePresets.json expands into the toolchain file path

    Visual Studio 18.x uses the compatibility overlay in vcpkg-triplets-vs18/
    to pin the working MSVC toolset version. Visual Studio 2022 and GitHub CI
    use the standard x64-windows triplet.

.PARAMETER Preset
    A configurePreset from CMakePresets.json. Default windows-release.

.PARAMETER Test
    Run ctest after building.

.PARAMETER Clean
    Delete the build directory first.
#>
[CmdletBinding()]
param(
    [string]$Preset = 'windows-release',
    [switch]$Test,
    [switch]$Clean
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$cppDir = Join-Path $repoRoot 'netscope-cpp'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer (vswhere.exe) was not found'
}
$vsRoot = (& $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath).Trim()
$vsVersion = (& $vswhere -latest -products * `
    -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationVersion).Trim()
if (-not $vsRoot) {
    throw 'Visual Studio with the Desktop development with C++ workload was not found'
}
$vcvars = Join-Path $vsRoot 'VC\Auxiliary\Build\vcvars64.bat'
$vsCMake = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
$vsNinja = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja'

foreach ($p in @($vcvars, $vsCMake, $vsNinja)) {
    if (-not (Test-Path $p)) { throw "not found: $p" }
}

$vcpkgRoot = $env:VCPKG_ROOT
if (-not $vcpkgRoot) {
    throw 'Set VCPKG_ROOT to a vcpkg checkout before running this script'
}
if (-not (Test-Path (Join-Path $vcpkgRoot 'scripts\buildsystems\vcpkg.cmake'))) {
    throw "VCPKG_ROOT does not look like a vcpkg checkout: $vcpkgRoot"
}

if ($Clean) {
    $buildDir = Join-Path $cppDir "build\$Preset"
    if (Test-Path $buildDir) { Remove-Item -Recurse -Force $buildDir }
}

$cmakeExe = Join-Path $vsCMake 'cmake.exe'
$ctestExe = Join-Path $vsCMake 'ctest.exe'
$ninjaExe = Join-Path $vsNinja 'ninja.exe'

# CMake and Ninja are reached by absolute path rather than by extending PATH.
# cmd expands %PATH% while PARSING the whole command line, i.e. before
# vcvars64.bat has run, so `set "PATH=...;%PATH%"` in this same line would splice
# in the PRE-vcvars PATH and silently discard every directory vcvars just added --
# including the one holding cl.exe. Absolute paths avoid the whole trap.
$configure = "`"$cmakeExe`" --preset $Preset -D CMAKE_MAKE_PROGRAM=`"$ninjaExe`""
if ($vsVersion -like '18.*') {
    $overlay = Join-Path $cppDir 'vcpkg-triplets-vs18'
    $configure += " -D VCPKG_OVERLAY_TRIPLETS=`"$overlay`""
}

$steps = @(
    $configure,
    "`"$cmakeExe`" --build --preset $Preset"
)
if ($Test) { $steps += "`"$ctestExe`" --preset $Preset" }

# Note the quoting on `set`: `set VCPKG_ROOT=x && ...` would put a trailing space
# into the value and CMake would then look for "x /scripts/...".
$inner = @(
    "`"$vcvars`" >nul 2>&1",
    "set `"VCPKG_ROOT=$vcpkgRoot`"",
    "cd /d `"$cppDir`""
) + $steps

$command = $inner -join ' && '
& cmd /c $command
exit $LASTEXITCODE
