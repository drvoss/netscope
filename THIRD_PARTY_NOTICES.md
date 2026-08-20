# Third-party dependencies

NetScope does not vendor or redistribute these libraries in the source tree.
They are resolved by Go modules or vcpkg when building.

## Go implementation

Direct dependencies include Bubble Tea, Bubbles, Lip Gloss, `go-runewidth`, and
`golang.org/x/net` / `x/sys`. See `netscope-go/go.mod` and `go.sum` for the
complete dependency graph and exact versions. Each dependency remains under
its own license.

## C++ implementation

| Dependency | Purpose | Declared license in the pinned vcpkg baseline |
|---|---|---|
| FTXUI | Terminal UI | MIT |
| standalone Asio | Networking | BSL-1.0 |
| doctest | Tests only | MIT |

The vcpkg registry is pinned in `netscope-cpp/vcpkg.json`. Review the license
files installed by vcpkg when preparing binary distributions. NetScope's MIT
license does not replace third-party license terms.
