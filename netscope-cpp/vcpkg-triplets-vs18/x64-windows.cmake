# Visual Studio 2026 (18.x) compatibility overlay.
#
# Some VS 18 installations contain multiple 14.5x toolsets while vcpkg's
# compiler detection cannot activate the newest one. The repository's Windows
# helper applies this overlay only when vswhere reports VS 18.x. Visual Studio
# 2022 and GitHub-hosted runners use the standard x64-windows triplet.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_PLATFORM_TOOLSET_VERSION 14.51)
