# NetScope validation matrix

NetScope has two implementations. Replay parity is the compatibility gate, but
it is only one layer of validation.

## Automated checks

| Area | Go | C++ | Shared parity |
|---|:---:|:---:|:---:|
| Statistics and rolling windows | Yes | Yes | Yes |
| Windows/Linux command-output parsing | Yes | Yes | Shared fixtures |
| Backend selection and fallback | Yes | Yes | Replay labels |
| ECMP responder separation | Yes | Yes | Replay scenarios |
| Layout behavior | Yes | Yes | Canonical snapshot fields |
| Canonical JSON | Yes | Yes | Byte comparison |

The shared scenarios in `testdata/scenarios/` cover a basic path, ICMP blocking,
ECMP segregation and route changes, hysteresis, a silent tail, and rolling-window
boundaries.

## Commands

```sh
cd netscope-go && go vet ./... && go test ./...
```

```sh
cd netscope-cpp
cmake --preset linux-release
cmake --build --preset linux-release
ctest --preset linux-release
```

Use `windows-release` on Windows. From the repository root, run
`scripts/parity.sh` on Linux or `scripts/parity.ps1` on Windows.

## Important boundary

Replay injects `ProbeResult` values and does not open sockets. It detects drift
between implementations, but it cannot validate kernel ICMP delivery, platform
permissions, OS command behavior, scheduler cadence, or interactive terminal
input. Those areas require native platform testing.

## Current native coverage

- Windows: IP Helper IPv4 path and command fallback exercised.
- Linux: `SOCK_RAW` and command fallback exercised; capability downgrade and
  recovery checked.
- ICMP datagram selection is protected by injected backend tests, but still
  needs broader real-kernel coverage.
- Windows IPv6 intentionally uses the degraded command backend.

When adding native coverage, record the OS, kernel, architecture, privilege
model, backend label, and whether the test used real traffic or replay.
