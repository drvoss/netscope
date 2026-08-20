// nscope is the C++20 implementation of NetScope: a single-screen TUI that fuses
// ping and traceroute.
//
// See docs/netscope-spec.md for the cross-language behavioural contract that
// keeps this binary and the Go netscope binary observably equivalent.
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include "health.h"
#include "json.h"
#include "probe.h"
#include "replay.h"
#include "resolve.h"
#include "runner.h"
#include "ui.h"

namespace {

constexpr const char* kVersion = "0.3.0";

void usage() {
    std::fprintf(stderr,
                 "nscope %s - ping x traceroute dashboard\n"
                 "\n"
                 "usage:\n"
                 "  nscope [flags] <hostname|ip>\n"
                 "  nscope --replay <scenario.json> --emit-snapshot\n"
                 "\n"
                 "flags:\n"
                 "  --port <n>           TCP port for the health check (default 443)\n"
                 "  --no-public-ip       skip the public-IP reflector lookup\n"
                 "  --force-command      force the degraded command fallback backend\n"
                 "  --headless <seconds> probe with no TUI, then print the snapshot\n"
                 "  --replay <file>      replay a scenario file instead of probing\n"
                 "  --emit-snapshot      print the canonical JSON snapshot and exit\n"
                 "  --version            print version and exit\n",
                 kVersion);
}

int runReplay(const std::string& path, bool emit) {
    std::string err;
    auto snap = netscope::replayFile(path, err);
    if (!snap) {
        std::fprintf(stderr, "nscope: %s\n", err.c_str());
        return 1;
    }
    if (emit) {
        std::fputs(netscope::canonicalJson(*snap).c_str(), stdout);
        return 0;
    }
    std::printf("replayed %s: %zu hops, revision %llu\n", path.c_str(), snap->hops.size(),
                static_cast<unsigned long long>(snap->revision));
    return 0;
}

// Resolves the target and selects a backend, shared by the TUI and headless paths.
bool setup(const std::string& target, netscope::Options opts,
           std::unique_ptr<netscope::Runner>& out) {
    netscope::setStartInstant();

    netscope::Target t;
    std::string err;
    if (!netscope::resolveTarget(target, t, err)) {
        // A name that does not resolve is a normal user error, not a crash
        // (DoD: graceful failure paths).
        std::fprintf(stderr, "nscope: cannot resolve %s: %s\n", target.c_str(), err.c_str());
        return false;
    }

    auto choice = netscope::selectBackend(t.ip, t.family, opts.forceCommand);
    if (!choice.backend) {
        std::fprintf(stderr, "nscope: no usable probe backend\n");
        return false;
    }

    out = std::make_unique<netscope::Runner>(t, std::move(choice.backend), opts, choice.note);
    return true;
}

// Probes for a fixed duration with no terminal attached, then prints the canonical
// snapshot. This is how real-environment behaviour is verified in CI and over a
// pipe, where the TUI cannot run.
int runHeadless(const std::string& target, netscope::Options opts, double seconds) {
    std::unique_ptr<netscope::Runner> runner;
    if (!setup(target, opts, runner)) return 1;

    runner->start();

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(static_cast<long long>(seconds * 1000));
    while (std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    auto snap = runner->latest();
    runner->shutdown();

    if (!snap) {
        std::fprintf(stderr, "nscope: no snapshot produced in %.1fs\n", seconds);
        return 1;
    }
    std::fputs(netscope::canonicalJson(*snap).c_str(), stdout);
    return 0;
}

int runInteractive(const std::string& target, netscope::Options opts) {
    std::unique_ptr<netscope::Runner> runner;
    if (!setup(target, opts, runner)) return 1;

    runner->start();
    const int rc = netscope::runUI(*runner);

    // Ordered teardown: commands refused, workers stopped, sockets closed, wake-up
    // gate closed, threads joined (spec §3.3).
    runner->shutdown();
    return rc;
}

}  // namespace

int main(int argc, char** argv) {
    netscope::Options opts;
    std::string target;
    std::string replayPath;
    bool emitSnapshot = false;
    double headlessSeconds = 0;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto next = [&](const char* what) -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "nscope: %s needs a value\n", what);
                std::exit(2);
            }
            return argv[++i];
        };

        if (arg == "--version") {
            std::printf("nscope %s\n", kVersion);
            return 0;
        }
        if (arg == "--help" || arg == "-h") {
            usage();
            return 0;
        }
        if (arg == "--port") {
            opts.port = std::atoi(next("--port"));
            continue;
        }
        if (arg == "--no-public-ip") {
            opts.wantPublicIp = false;
            continue;
        }
        if (arg == "--force-command") {
            opts.forceCommand = true;
            continue;
        }
        if (arg == "--headless") {
            headlessSeconds = std::atof(next("--headless"));
            continue;
        }
        if (arg == "--replay") {
            replayPath = next("--replay");
            continue;
        }
        if (arg == "--emit-snapshot") {
            emitSnapshot = true;
            continue;
        }
        if (!arg.empty() && arg[0] == '-') {
            std::fprintf(stderr, "nscope: unknown flag %s\n", arg.c_str());
            usage();
            return 2;
        }
        if (!target.empty()) {
            std::fprintf(stderr, "nscope: more than one target given\n");
            return 2;
        }
        target = arg;
    }

    // Deterministic replay: no sockets, no wall clock, byte-comparable output. This
    // is the parity harness both implementations share (spec §9).
    if (!replayPath.empty()) return runReplay(replayPath, emitSnapshot);

    if (target.empty()) {
        usage();
        return 2;
    }
    if (opts.port <= 0 || opts.port > 65535) {
        std::fprintf(stderr, "nscope: --port must be 1..65535\n");
        return 2;
    }

    if (headlessSeconds > 0) return runHeadless(target, opts, headlessSeconds);
    return runInteractive(target, opts);
}
