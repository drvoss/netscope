# NetScope

**한국어 문서: [README.ko.md](README.ko.md)**

NetScope is a terminal dashboard that combines ping and traceroute observations
with DNS, interface, route, TCP health, and ASN context. It has independent Go
and C++ implementations whose replay output is checked byte for byte.

> NetScope is pre-1.0 diagnostic software. It makes active network probes. Use
> it only on systems and networks you own or are authorized to test.

| Implementation | Directory | Command | Stack |
|---|---|---|---|
| Go reference | [`netscope-go/`](netscope-go/) | `netscope` | Go, Bubble Tea, `x/net/icmp` |
| C++ | [`netscope-cpp/`](netscope-cpp/) | `nscope` | C++20, FTXUI, standalone Asio |

## What it shows

- Destination latency, loss, jitter, and TCP health
- TTL-limited path observations with per-responder ECMP statistics
- Local interface, gateway, DNS, public-IP, and ASN context
- Honest degraded-mode labels when native probes are unavailable
- Interactive TUI, timed headless JSON output, and deterministic replay

Silence is not labelled as filtering, and loss is not attributed to an
intermediate router unless it persists downstream. These constraints are part
of the shared [behavior contract](docs/netscope-spec.md).

## Build

### Go

Requires Go 1.26.6 or newer. This minimum includes standard-library security
fixes used by the network and TLS code paths.

Install the Go implementation directly:

```sh
go install github.com/drvoss/netscope/netscope-go@latest
```

Or build it from a local clone:

```sh
cd netscope-go
go test ./...
go build -o netscope .
```

On Windows, use `go build -o netscope.exe .`.

### C++

Requires CMake 3.21+, Ninja, a C++20 compiler, and
[vcpkg](https://github.com/microsoft/vcpkg). Set `VCPKG_ROOT` to the vcpkg
checkout.

```sh
cd netscope-cpp
cmake --preset linux-release
cmake --build --preset linux-release
ctest --preset linux-release
```

Using the `windows-release` preset directly requires an MSVC developer shell.
The PowerShell helper uses `vswhere` to find Visual Studio, prepares the MSVC
environment, and runs the build and tests. It applies the Visual Studio 18.x
compatibility triplet only when that host-specific workaround is needed;
Visual Studio 2022 and GitHub-hosted runners use the standard `x64-windows`
triplet.

```powershell
./scripts/build-cpp.ps1 -Test
```

## Quick start

```text
netscope [flags] <hostname|ip>     # Go
nscope   [flags] <hostname|ip>     # C++
```

```sh
netscope example.com
netscope --headless 10s --no-public-ip example.com
```

Common flags:

| Flag | Purpose |
|---|---|
| `--port <n>` | TCP health-check port; default `443` |
| `--no-public-ip` | Skip the external public-IP reflector lookup |
| `--force-command` | Force the degraded OS-command backend |
| `--headless <duration>` | Probe without the TUI, then emit canonical JSON |
| `--replay <file> --emit-snapshot` | Replay a fixture and emit canonical JSON |
| `--version` | Print the version and exit |

TUI keys: `q` quit, `p` pause, arrow keys or `j`/`k` select a hop, `r`
re-probe, `Tab` change focus, `d` refresh DNS, `w` refresh ASN, and `/` change
the target.

## Privileges and fallbacks

- Windows uses the IP Helper API and does not require administrator rights.
- Linux prefers a verified ICMP datagram socket, then `SOCK_RAW`, then the OS
  `ping`/`traceroute` commands. Raw sockets may require root or
  `cap_net_raw`. Command fallback is visibly marked as degraded.
- Windows IPv6 currently uses the degraded command backend.

Network and platform policy can change what is observable. A timeout alone
cannot distinguish an ACL, ICMP rate limiting, router load, or packet loss.

## Go/C++ parity

The replay harness injects the same probe stream and virtual monotonic clock
into both implementations, then compares canonical JSON snapshots byte for
byte. It does not open sockets, so it is deterministic and safe for CI.

```powershell
./scripts/parity.ps1
./scripts/parity.ps1 -ShowDiff
```

```sh
./scripts/parity.sh
```

Replay parity proves that both implementations agree; it does not prove that a
kernel backend is correct. Native backend tests and platform testing are still
required.

## Project status and limitations

Current version: **v0.3.0, pre-1.0**.

- Linux native runtime testing has covered the `SOCK_RAW` and command fallback
  paths. The unprivileged ICMP datagram path needs broader kernel coverage.
- Scheduler cadence and interactive key input are not end-to-end automated.
- The OS-command sweep cannot enforce the same packet-rate budget as the native
  backend.
- Public-IP and ASN enrichment can depend on external services; measurement
  continues with an explicit unavailable value when enrichment fails.
- Go and C++ use different executable names so they can be installed together.

See the [parity checklist](docs/parity-checklist.md) for the detailed validation
matrix.

## Development

Repository layout:

```text
netscope-go/     Go reference implementation
netscope-cpp/    C++ implementation
testdata/        shared parser fixtures and replay scenarios
scripts/         portable build and parity helpers
docs/            public behavior and validation documentation
```

Run the checks described in [CONTRIBUTING.md](CONTRIBUTING.md) before opening a
pull request. Third-party licenses are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Report security issues
according to [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
