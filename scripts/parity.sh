#!/usr/bin/env bash
# Verifies Go/C++ observable parity on Linux by byte-comparing canonical snapshots.
#
# The POSIX counterpart of scripts/parity.ps1. Both binaries support
# `--replay <scenario.json> --emit-snapshot`, which drives the engine from a fixed
# ProbeResult stream and a virtual monotonic clock and prints a canonical JSON
# snapshot. No sockets are opened and no real clock is read, so the output is fully
# deterministic and can be compared byte for byte (docs/netscope-spec.md §9).
#
# usage: scripts/parity.sh [go-binary] [cpp-binary]
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

go_bin="${1:-$repo_root/netscope-go/build/linux/netscope}"
cpp_bin="${2:-$repo_root/netscope-cpp/build/linux/nscope-x86_64-linux-gnu}"
scenario_dir="$repo_root/testdata/scenarios"

for b in "$go_bin" "$cpp_bin"; do
    if [[ ! -x "$b" ]]; then
        echo "missing or non-executable binary: $b" >&2
        echo "build both implementations for Linux first (see README)" >&2
        exit 1
    fi
done

pass=0
fail=0

for file in "$scenario_dir"/*.json; do
    name="$(basename "$file" .json)"

    if ! go_out="$("$go_bin" --replay "$file" --emit-snapshot 2>&1)"; then
        printf 'FAIL  %-22s go replay failed\n' "$name"
        echo "$go_out" | head -20
        fail=$((fail + 1))
        continue
    fi
    if ! cpp_out="$("$cpp_bin" --replay "$file" --emit-snapshot 2>&1)"; then
        printf 'FAIL  %-22s cpp replay failed\n' "$name"
        echo "$cpp_out" | head -20
        fail=$((fail + 1))
        continue
    fi

    if [[ "$go_out" == "$cpp_out" ]]; then
        printf 'PASS  %-22s %s bytes identical\n' "$name" "${#go_out}"
        pass=$((pass + 1))
    else
        printf 'FAIL  %-22s snapshots differ\n' "$name"
        diff <(printf '%s\n' "$go_out") <(printf '%s\n' "$cpp_out") | head -30
        fail=$((fail + 1))
    fi
done

echo
echo "parity: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
