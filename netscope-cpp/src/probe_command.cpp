// The unprivileged command fallback (plan §5.3, spec §6.2 rank 3).
//
// It shells out to the system tracert/traceroute for the path and to ping for the
// destination, then parses the output. This backend is DEGRADED by construction
// and the engine suppresses the metrics it cannot honestly support -- jitter,
// stdev, the TRANSIT_ONLY inference and ECMP responder tracking (spec §6.4).
// agy argued for refusing to run at all without raw sockets; the plan explicitly
// requires this fallback, so it stays, clearly labelled, with its weak metrics
// switched off (cross-review R1-4).
#include <array>
#include <atomic>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "child_process.h"
#include "probe.h"
#include "probe_parse.h"
#include "stats.h"

namespace netscope {
namespace {

// Argument vectors rather than shell strings: no quoting hazards, and the child is
// the tool itself rather than a shell wrapping it, so terminating it actually
// terminates the tool.
std::vector<std::string> traceArgv(const std::string& targetIp, int maxTTL) {
#ifdef _WIN32
    // -d skips reverse DNS (enrichment does that off the probe path).
    return {"tracert", "-d", "-w", "1500", "-h", std::to_string(maxTTL), targetIp};
#else
    // ICMP mode (-I) is deliberately NOT requested: it needs privileges, and if we
    // had them we would be using the raw backend. The default UDP probes mean the
    // observed path can differ from the raw backend's ICMP path -- one more reason
    // this mode is labelled degraded (spec §6.4).
    return {"traceroute", "-n", "-q", "3", "-w", "2", "-m", std::to_string(maxTTL), targetIp};
#endif
}

std::vector<std::string> pingArgv(const std::string& targetIp) {
#ifdef _WIN32
    return {"ping", "-n", "1", "-w", "1500", targetIp};
#else
    return {"ping", "-c", "1", "-W", "2", "-n", targetIp};
#endif
}

// LC_ALL=C forces stable numeric formatting and message text on POSIX (spec §6.4).
// On Windows the display language cannot be forced this way, so the parsers are
// locale-agnostic instead (see probe_parse.h).
std::vector<std::string> stableLocaleEnv() {
#ifdef _WIN32
    return {};
#else
    return {"LC_ALL=C", "LANG=C"};
#endif
}

Family familyOf(const std::string& ip) {
    return ip.find(':') != std::string::npos ? Family::IP6 : Family::IP4;
}

class CommandBackend final : public Backend {
public:
    explicit CommandBackend(std::string targetIp) : targetIp_(std::move(targetIp)) {}

    ProbeMode mode() const override { return ProbeMode::Command; }

    // False: a single TTL-limited measurement with an accurate RTT is not
    // obtainable from the system ping on Windows (it reports "TTL expired in
    // transit" with no time), so the scheduler must use whole sweeps instead.
    bool supportsPerTTL() const override { return false; }

    // Terminates any running child so shutdown is bounded. A flag alone could not
    // interrupt a read on a tracert that has minutes of work left (codex HIGH
    // finding).
    void close() override {
        closed_.store(true);
        std::lock_guard<std::mutex> lk(childMu_);
        if (child_) child_->kill();
    }

    // Measures the destination only. The scheduler calls this for the destination
    // TTL at the destination cadence.
    ProbeResult probe(const ProbeID& id, std::stop_token stop) override {
        ProbeResult res;
        res.id = id;
        res.sentAt = elapsedSinceStart();

        if (closed_.load() || stop.stop_requested()) {
            res.outcome = Outcome::Timeout;
            res.note = "cancelled";
            res.recvAt = res.sentAt;
            return res;
        }

        std::string out;
        if (!run(pingArgv(targetIp_), out)) {
            res.outcome = Outcome::BackendError;
            res.note = "cannot start ping (not on PATH?)";
            res.recvAt = elapsedSinceStart();
            return res;
        }
        res.recvAt = elapsedSinceStart();
        if (closed_.load() || stop.stop_requested()) {
            res.outcome = Outcome::Timeout;
            res.note = "cancelled";
            return res;
        }

        auto rtt = parsePingRTT(out);
        if (!rtt) {
            // ping exits non-zero on loss; no parsed time means no answer.
            res.outcome = Outcome::Timeout;
            res.recvAt = res.sentAt + kProbeTimeout;
            return res;
        }
        res.outcome = Outcome::Reply;
        res.responder = targetIp_;
        res.rtt = fromMs(*rtt);
        res.recvAt = res.sentAt + res.rtt;
        return res;
    }

    // Runs one full sweep and converts every parsed probe into a result.
    //
    // Send timestamps are synthesized as evenly spaced offsets from the moment the
    // command was launched: the OS tool does not tell us when each individual probe
    // left. Order is preserved, which is all the time-based window needs, and
    // jitter -- the one metric that would be misled by fake spacing -- is disabled
    // in this mode anyway.
    std::vector<ProbeResult> traceRound(std::uint64_t generation, int maxTTL,
                                        std::stop_token stop) override {
        std::vector<ProbeResult> results;
        if (closed_.load() || stop.stop_requested()) return results;

        const Dur base = elapsedSinceStart();

        std::string out;
        if (!run(traceArgv(targetIp_, maxTTL), out)) {
            ProbeResult err;
            err.id.generation = generation;
            err.id.ttl = 1;
            err.outcome = Outcome::BackendError;
            err.sentAt = base;
            err.recvAt = elapsedSinceStart();
            // The tool being absent is a normal condition on a stripped container,
            // not a crash: it is reported and the UI keeps running.
            err.note = "cannot start traceroute (not on PATH?)";
            results.push_back(std::move(err));
            return results;
        }
        if (stop.stop_requested() || closed_.load()) return results;

        const auto samples = parseTraceOutput(out);
        if (samples.empty()) {
            ProbeResult err;
            err.id.generation = generation;
            err.id.ttl = 1;
            err.outcome = Outcome::BackendError;
            err.sentAt = base;
            err.recvAt = elapsedSinceStart();
            err.note = "no hops parsed from traceroute output";
            results.push_back(std::move(err));
            return results;
        }

        results.reserve(samples.size());
        for (std::size_t i = 0; i < samples.size(); ++i) {
            const TraceSample& s = samples[i];
            ProbeResult r;
            r.id.generation = generation;
            r.id.family = familyOf(targetIp_);
            r.id.ttl = s.ttl;
            r.id.attempt = ++attempt_;
            r.sentAt = base + std::chrono::milliseconds(10) * static_cast<long long>(i);

            if (!s.ok) {
                r.outcome = Outcome::Timeout;
                r.recvAt = r.sentAt + kProbeTimeout;
            } else if (s.unreachable) {
                r.outcome = Outcome::Unreachable;
                r.responder = s.responder;
                r.note = s.note;
                r.rtt = fromMs(s.rttMs);
                r.recvAt = r.sentAt + r.rtt;
            } else {
                r.responder = s.responder;
                r.rtt = fromMs(s.rttMs);
                r.recvAt = r.sentAt + r.rtt;
                r.outcome = (s.responder == targetIp_) ? Outcome::Reply : Outcome::TTLExpired;
            }
            results.push_back(std::move(r));
        }
        return results;
    }

private:
    // Runs a tool and captures its combined output. The child is published to
    // child_ first so close() can terminate it mid-run.
    bool run(const std::vector<std::string>& argv, std::string& out) {
        out.clear();
        auto child = std::make_shared<ChildProcess>();
        {
            std::lock_guard<std::mutex> lk(childMu_);
            if (closed_.load()) return false;
            child_ = child;
        }
        const bool started = child->start(argv, stableLocaleEnv());
        if (started) {
            child->readAll(out);
            child->wait();
        }
        {
            std::lock_guard<std::mutex> lk(childMu_);
            if (child_ == child) child_.reset();
        }
        return started;
    }

    std::string targetIp_;
    std::atomic<bool> closed_{false};
    std::uint64_t attempt_ = 0;

    std::mutex childMu_;
    std::shared_ptr<ChildProcess> child_;
};

}  // namespace

std::unique_ptr<Backend> makeCommandBackend(const std::string& targetIp) {
    return std::make_unique<CommandBackend>(targetIp);
}

}  // namespace netscope
