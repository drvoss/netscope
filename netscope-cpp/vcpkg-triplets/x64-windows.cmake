# Overlay triplet: standard x64-windows, but pins the MSVC toolset version.
#
# Why: on Visual Studio 2026 (18.x) this machine has two MSVC toolsets installed
# (14.51.36231 and 14.52.36418), but `vcvarsall.bat x64 -vcvars_ver=14.52.36418`
# fails to put cl.exe on PATH, so vcpkg's compiler detection dies with
# "No CMAKE_C_COMPILER could be found" while VSCMD_VER is already set.
# Verified on this host:
#   vcvarsall.bat x64                        -> cl.exe 14.51.36231   OK
#   vcvarsall.bat x64 -vcvars_ver=14.51      -> cl.exe 14.51.36231   OK
#   vcvarsall.bat x64 -vcvars_ver=14.5       -> FAIL
#   vcvarsall.bat x64 -vcvars_ver=14.52.36418-> FAIL
# Pinning to the toolset that actually activates makes vcpkg work again.
#
# Activated via VCPKG_OVERLAY_TRIPLETS (see CMakePresets.json / README).
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_PLATFORM_TOOLSET_VERSION 14.51)
