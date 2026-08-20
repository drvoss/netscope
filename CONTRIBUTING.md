# Contributing to NetScope

Thanks for helping improve NetScope. Small, focused changes are easiest to
review.

## Before opening a change

- Open an issue first for behavior changes or new features.
- Do not include captured traffic, public IP addresses, credentials, or private
  hostnames in reports or fixtures.
- Keep observable behavior aligned between the Go and C++ implementations.

## Local checks

For Go:

```sh
cd netscope-go
gofmt -w .
go vet ./...
go test ./...
```

For C++ (with CMake, Ninja, and `VCPKG_ROOT` configured):

```sh
cd netscope-cpp
cmake --preset linux-release       # use windows-release on Windows
cmake --build --preset linux-release
ctest --preset linux-release
```

Run `scripts/parity.sh` on Linux or `scripts/parity.ps1` on Windows after a
change that can affect snapshots.

## Pull requests

Explain the problem, the chosen approach, platforms tested, and any remaining
limitations. Add or update tests for behavior changes. By contributing, you
agree that your contribution is licensed under the MIT License.
