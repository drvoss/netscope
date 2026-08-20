#!/usr/bin/env bash
# Full Linux verification: build both implementations natively, run both test
# suites, run the parity comparison, then take a real measurement.
#
# This is the script that closed the "POSIX runtime unverified" gap recorded in
# README; it ran green on 2026-07-30 under WSL 1. Run it inside WSL, a container,
# or on a real Linux host.
#
# It does NOT close the one branch still open: on a kernel where
# net.ipv4.ping_group_range permits the unprivileged ICMP datagram socket, both
# backends take that socket in preference to SOCK_RAW. WSL 1 has no
# ping_group_range at all, so this script always exercises the SOCK_RAW fallback.
# See docs/parity-checklist.md C4.
#
# usage: scripts/verify-linux.sh [target-host]
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${1:-1.1.1.1}"

step() { printf '\n=== %s ===\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Extract a .tar.gz, trying more than one extractor.
#
# GNU tar 1.35 as shipped by Ubuntu 26.04 dies under WSL1 with
# "Cannot mkdir: Function not implemented" (ENOSYS) -- it reaches for a syscall the
# WSL1 translation layer does not implement, even though plain mkdir(2) works fine.
# libarchive's bsdtar and Python's tarfile use ordinary mkdir/open and both succeed,
# so fall through to them. On a real kernel the first attempt just wins.
#
# Each attempt unpacks into a fresh staging dir: a half-finished extraction would
# otherwise leave debris that makes the next extractor look like it failed too.
extract_tgz() {
    local archive="$1" dest="$2" stage rc method
    mkdir -p "$dest" || return 1
    stage="$dest/.extract.$$"
    for method in tar bsdtar python3; do
        have "$method" || continue
        rm -rf "$stage"
        mkdir -p "$stage" || return 1
        case "$method" in
        tar)    tar -C "$stage" -xzf "$archive" >/dev/null 2>&1; rc=$? ;;
        bsdtar) bsdtar -C "$stage" -xzf "$archive" >/dev/null 2>&1; rc=$? ;;
        python3)
            python3 -c 'import sys, tarfile; tarfile.open(sys.argv[1]).extractall(sys.argv[2])' \
                "$archive" "$stage" >/dev/null 2>&1; rc=$? ;;
        esac
        if ((rc == 0)); then
            echo "extracted $(basename "$archive") with $method"
            if mv "$stage"/* "$dest"/; then rm -rf "$stage"; return 0; fi
            rm -rf "$stage"; return 1
        fi
        echo "$method could not extract $archive (exit $rc); trying the next extractor" >&2
    done
    rm -rf "$stage"
    echo "no working extractor for $archive (tried tar, bsdtar, python3)" >&2
    return 1
}

missing=()
for tool in cmake ninja g++ git curl; do
    have "$tool" || missing+=("$tool")
done
if ((${#missing[@]})); then
    echo "missing tools: ${missing[*]}" >&2
    echo "on Debian/Ubuntu: sudo apt-get install -y build-essential cmake ninja-build git curl" >&2
    exit 1
fi

# go.mod declares go 1.25.0, which is what the current golang.org/x/net, x/sys and
# x/text releases require. Distro Go is often older (Ubuntu 24.04 ships 1.22), so
# fetch a matching toolchain rather than fighting the package manager. Go's own
# GOTOOLCHAIN=auto would also handle it, but only with network access at build time
# and it leaves the "go" on PATH misleading.
GO_MIN=1.25.0
need_go=1
if have go; then
    current="$(go env GOVERSION 2>/dev/null | sed 's/^go//')"
    if [[ -n "$current" ]] && printf '%s\n%s\n' "$GO_MIN" "$current" | sort -V -C; then
        need_go=0
        echo "using existing go $current"
    else
        echo "existing go ${current:-unknown} is older than $GO_MIN"
    fi
fi
if ((need_go)); then
    goroot="$repo_root/.toolchain/go"
    if [[ ! -x "$goroot/bin/go" ]]; then
        arch="$(uname -m)"
        case "$arch" in
            x86_64) goarch=amd64 ;;
            aarch64 | arm64) goarch=arm64 ;;
            *) echo "unsupported arch for the Go tarball: $arch" >&2; exit 1 ;;
        esac
        tarball="go${GO_MIN}.linux-${goarch}.tar.gz"
        cache="/tmp/$tarball"
        mkdir -p "$repo_root/.toolchain"

        # Integrity-check the cache, and retry the fetch. A truncated download used to
        # be doubly opaque: `curl -fsSL` is silent, so `|| exit 1` aborted the whole
        # verification with no message whatsoever, and if curl did return 0 the partial
        # file surfaced later as "Truncated tar archive" from the extractor instead.
        if [[ -f "$cache" ]] && ! gzip -t "$cache" 2>/dev/null; then
            echo "cached $cache is truncated or corrupt; refetching"
            rm -f "$cache"
        fi
        if [[ -f "$cache" ]]; then
            echo "reusing cached $cache"
        else
            echo "downloading $tarball into $goroot"
            if ! curl -fL --no-progress-meter --retry 3 --retry-delay 2 \
                      --retry-connrefused -o "$cache" "https://go.dev/dl/$tarball"; then
                echo "failed to download https://go.dev/dl/$tarball" >&2
                rm -f "$cache"
                exit 1
            fi
        fi
        if ! gzip -t "$cache"; then
            echo "$cache is corrupt after downloading; aborting" >&2
            exit 1
        fi

        rm -rf "$goroot"
        extract_tgz "$cache" "$repo_root/.toolchain" || exit 1
    fi
    export PATH="$goroot/bin:$PATH"
    echo "using downloaded go $(go env GOVERSION)"
fi

# ---------------------------------------------------------------- Go
step "Go: build, vet, test"
cd "$repo_root/netscope-go"
mkdir -p build/linux
go build -o build/linux/netscope . || exit 1
go vet ./... || exit 1
# -count=1 disables the test cache. This script exists to prove the suite passes on
# THIS kernel; a re-run that prints "(cached)" proves only that it passed somewhere.
go test -count=1 ./... || exit 1

# ------------------------------------------------------- CMake new enough for vcpkg
# vcpkg's scripts/cmake/z_vcpkg_spdx.cmake calls string(JSON ... STRING_ENCODE), a mode
# that only exists in CMake 4.4+. With anything older every port dies at configure time
# with "string sub-command JSON got an invalid mode 'STRING_ENCODE'" -- which looks like
# a broken port rather than a too-old CMake. vcpkg normally avoids this by fetching its
# own CMake, but it unpacks that with the system tar, which fails under WSL1, so fetch
# it here and let extract_tgz handle the unpacking.
CMAKE_MIN=4.4.0
cur_cmake="$(cmake --version | head -1 | awk '{print $3}')"
if printf '%s\n%s\n' "$CMAKE_MIN" "$cur_cmake" | sort -V -C; then
    echo "using existing cmake $cur_cmake (>= $CMAKE_MIN)"
else
    echo "cmake $cur_cmake is older than the $CMAKE_MIN that vcpkg's port scripts need"
    cmake_root="$repo_root/.toolchain/cmake"
    if [[ ! -x "$cmake_root/bin/cmake" ]]; then
        case "$(uname -m)" in
            x86_64)        cm_arch=linux-x86_64 ;;
            aarch64|arm64) cm_arch=linux-aarch64 ;;
            *) echo "unsupported arch for the CMake tarball: $(uname -m)" >&2; exit 1 ;;
        esac
        cm_tar="cmake-${CMAKE_MIN}-${cm_arch}.tar.gz"
        cm_cache="/tmp/$cm_tar"
        if [[ -f "$cm_cache" ]] && ! gzip -t "$cm_cache" 2>/dev/null; then
            echo "cached $cm_cache is corrupt; refetching"
            rm -f "$cm_cache"
        fi
        if [[ ! -f "$cm_cache" ]]; then
            echo "downloading $cm_tar"
            if ! curl -fL --no-progress-meter --retry 3 --retry-delay 2 --retry-connrefused \
                      -o "$cm_cache" \
                      "https://github.com/Kitware/CMake/releases/download/v${CMAKE_MIN}/$cm_tar"; then
                echo "failed to download $cm_tar" >&2
                rm -f "$cm_cache"
                exit 1
            fi
        fi
        gzip -t "$cm_cache" || { echo "$cm_cache is corrupt after download" >&2; exit 1; }
        mkdir -p "$repo_root/.toolchain"
        rm -rf "$cmake_root" "$repo_root/.toolchain/cmake-${CMAKE_MIN}-${cm_arch}"
        extract_tgz "$cm_cache" "$repo_root/.toolchain" || exit 1
        mv "$repo_root/.toolchain/cmake-${CMAKE_MIN}-${cm_arch}" "$cmake_root" || exit 1
    fi
    export PATH="$cmake_root/bin:$PATH"
    echo "using downloaded cmake $(cmake --version | head -1 | awk '{print $3}')"
fi

# ---------------------------------------------------------------- C++
step "C++: configure, build, test"
cd "$repo_root/netscope-cpp"

# vcpkg supplies ftxui/asio/doctest. VCPKG_ROOT may already point at a checkout;
# otherwise clone one next to the repo so this script is self-contained.
if [[ -z "${VCPKG_ROOT:-}" || ! -f "$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" ]]; then
    export VCPKG_ROOT="$repo_root/.toolchain/vcpkg"
    if [[ ! -d "$VCPKG_ROOT" ]]; then
        echo "cloning vcpkg into $VCPKG_ROOT"
        git clone --depth 1 https://github.com/microsoft/vcpkg "$VCPKG_ROOT" || exit 1
    fi
    # Gate the bootstrap on the binary, not on the directory. The clone succeeds long
    # before the bootstrap does, so a bootstrap that fails (missing zip/unzip, say)
    # used to leave a directory that looked complete, and every later run skipped the
    # bootstrap and failed further along with a much less obvious error.
    if [[ ! -x "$VCPKG_ROOT/vcpkg" ]]; then
        echo "bootstrapping vcpkg"
        "$VCPKG_ROOT/bootstrap-vcpkg.sh" -disableMetrics || exit 1
    fi
fi
echo "VCPKG_ROOT=$VCPKG_ROOT"

# Left to itself vcpkg downloads its own CMake and Ninja and unpacks them with the
# system tar -- which is exactly what fails under WSL1 (ENOSYS; see extract_tgz).
# The half-extracted CMake then produced a thoroughly misleading pair of errors,
# "unable to find a build program corresponding to Ninja" and "CMAKE_CXX_COMPILER
# not set". The prerequisite check at the top already guarantees cmake and ninja are
# on PATH, so tell vcpkg to use those and skip the downloads entirely.
export VCPKG_FORCE_SYSTEM_BINARIES=1
echo "VCPKG_FORCE_SYSTEM_BINARIES=1 (using system cmake $(cmake --version | head -1 | awk '{print $3}') and ninja $(ninja --version))"

# The Windows overlay triplet pins an MSVC toolset and is irrelevant here, so the
# Linux preset does not use it.
cmake --preset linux-release || exit 1
cmake --build --preset linux-release || exit 1
ctest --preset linux-release || exit 1

# ---------------------------------------------------------------- parity
step "parity (7 scenarios, byte comparison)"
cd "$repo_root"
./scripts/parity.sh \
    "$repo_root/netscope-go/build/linux/netscope" \
    "$repo_root/netscope-cpp/build/linux-release/nscope" || exit 1

# ---------------------------------------------------------------- socket evidence
# Which ICMP socket the backend can take is decided by this sysctl, and a run that
# does not record it cannot be re-read later: "mode": "raw" is printed for BOTH the
# datagram socket and SOCK_RAW. The 2026-07-30 run left no such evidence, which a
# cross-review correctly flagged. See docs/parity-checklist.md C4.
step "ICMP socket preconditions"
pgr=/proc/sys/net/ipv4/ping_group_range
if [[ -r $pgr ]]; then
    printf '  %s = %s\n' "$pgr" "$(cat "$pgr")"
    echo "  -> the unprivileged ICMP datagram socket may be reachable for gids in that range;"
    echo "     if it is taken, mode still prints \"raw\" but intermediate responders are expected"
    echo "     to go unobserved on Linux (no IP_RECVERR in either implementation)."
else
    echo "  $pgr absent -> no ICMP datagram socket on this kernel (WSL 1 behaves this way);"
    echo "  the raw backend can only be the SOCK_RAW fallback."
fi
printf '  euid=%s groups=%s\n' "$EUID" "$(id -G 2>/dev/null | tr ' ' ',')"

# ---------------------------------------------------------------- real measurement
step "real measurement against $target"
go_bin="$repo_root/netscope-go/build/linux/netscope"
cpp_bin="$repo_root/netscope-cpp/build/linux-release/nscope"

# SOCK_RAW needs root or cap_net_raw. Where net.ipv4.ping_group_range covers the
# calling gid the datagram socket is taken first and no capability is involved at
# all -- on such a kernel an unprivileged run reports "raw" too, so the message
# below describes this host (WSL 1, no ping_group_range), not Linux in general.
if have setcap && [[ $EUID -eq 0 ]]; then
    setcap cap_net_raw+ep "$go_bin" || true
    setcap cap_net_raw+ep "$cpp_bin" || true
    echo "granted cap_net_raw to both binaries"
else
    echo "not root: without cap_net_raw and without an open ping_group_range, expect the degraded command fallback"
fi

for b in "$go_bin" "$cpp_bin"; do
    printf '\n--- %s ---\n' "$(basename "$b")"
    if [[ "$b" == "$go_bin" ]]; then
        out="$("$b" --headless 15s --no-public-ip "$target" 2>&1)"
    else
        out="$("$b" --headless 15 --no-public-ip "$target" 2>&1)"
    fi
    echo "$out" | grep -E '"(mode|degraded)"' | sed 's/^/  /'
    printf '  hop rows: %s, responding: %s\n' \
        "$(echo "$out" | grep -c '"ttl":')" \
        "$(echo "$out" | grep -c '"status": "RESPONDING"')"
done

step "also exercise the degraded fallback explicitly"
"$go_bin" --headless 40s --no-public-ip --force-command "$target" 2>&1 |
    grep -E '"(mode|degraded)"|"jitterMs"' | head -6 | sed 's/^/  go:  /'
"$cpp_bin" --headless 40 --no-public-ip --force-command "$target" 2>&1 |
    grep -E '"(mode|degraded)"|"jitterMs"' | head -6 | sed 's/^/  cpp: /'

step "done"
