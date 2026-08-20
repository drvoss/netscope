// The single writer of all measurement state.
//
// Probe workers, enrichment workers and the UI all communicate with it by passing
// immutable values in; nothing else mutates hop statistics or route state
// (spec §3.1). The pure part -- ingest() and snapshot() -- opens no sockets and
// reads no clock of its own, which is what makes the deterministic replay parity
// harness possible (spec §9).
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "model.h"
#include "stats.h"

namespace netscope {

// Hysteresis constants (spec §5.2). Shared with the Go implementation.
inline constexpr std::uint64_t kMinSamples = 3;
inline constexpr int kLossStreak = 4;
inline constexpr int kRecoverStreak = 2;

// The probe schedule contract from spec §4.4.
Cadence defaultCadence();

// Mutable per-responder record. Only the engine touches it.
struct RespState {
    std::string ip;
    std::uint64_t seen = 0;
    Dur firstSeenAt{};
    Dur lastSeenAt{};
};

// Mutable per-TTL record.
//
// A single window per TTL, with every sample tagged by the responder that
// answered. A responder switch therefore already breaks jitter pairing and keeps
// each router's RTTs separate, without parallel windows that could drift out of
// sync (spec §4.3, §5.3). Samples from a responder that stopped answering simply
// age out of the 120s window.
struct HopState {
    int ttl = 0;
    Window win;
    std::uint64_t sent = 0;
    std::uint64_t replied = 0;
    bool everReplied = false;
    int timeoutStreak = 0;
    int replyStreak = 0;
    HopStatus status = HopStatus::Unknown;
    std::map<std::string, RespState> responders;
    bool isDestination = false;

    void record(const ProbeResult& r);
    std::vector<std::string> responderSet() const { return win.responders(); }
    std::string primary() const;
};

// Maps hop state onto the five-state enum from spec §5.1.
//
// The FILTERED/LOSS split the plan originally called for was rejected in
// cross-review: silence cannot distinguish an ACL from ICMP rate limiting, a busy
// control plane, MPLS, or an unobserved ECMP branch. TransitOnly states only the
// observed fact -- traffic gets through, probes go unanswered.
HopStatus classify(const HopState& h, bool anyGreaterReplied, bool degraded);

class Engine {
public:
    Engine(Target target, ProbeMode mode);

    std::uint64_t generation() const { return generation_; }
    Cadence cadence() const { return cadence_; }
    ProbeMode mode() const { return mode_; }
    bool paused() const { return paused_; }
    const Target& target() const { return target_; }
    int destTTL() const { return destTTL_; }
    int maxTTL() const { return maxTTL_; }

    void setLocal(LocalInfo l) { local_ = std::move(l); }
    void setHealth(Health h) { health_ = std::move(h); }
    void setRecords(Records r) { records_ = std::move(r); }
    const Records& records() const { return records_; }

    // Records the schedule actually applied after dilution, so the UI shows the
    // real numbers rather than the nominal ones (spec §4.4).
    void setCadence(int destMs, int midMs);

    void setMode(ProbeMode m, Dur at);

    void addEvent(Dur at, EventKind kind, std::optional<int> ttl, std::string text);

    // Folds one probe result into state. The only path by which measurements
    // enter the engine.
    void ingest(const ProbeResult& r);

    // Records rDNS / ASN / org for an IP. Enrichment runs off the probe path and
    // its failures never block measurement (spec §7).
    void applyEnrich(const std::string& ip, const std::string& rdns, const std::string& asn,
                     const std::string& org);

    // Runs the debounced route-change comparison (spec §5.3).
    void endTraceRound(Dur now);

    void reprobe(Dur now);
    void setTarget(Target t, Dur now);
    void togglePause(Dur now);

    // Builds the immutable view the UI renders, finalizing hop classification.
    std::shared_ptr<const Snapshot> snapshot(Dur now);

private:
    struct EnrichRec {
        std::string rdns;
        std::string asn;
        std::string org;
    };

    int visibleTTL() const;
    RttStats statsFor(const HopState& h, const std::string& responder) const;

    Cadence cadence_;
    ProbeMode mode_;
    bool degraded_;
    Target target_;

    std::uint64_t generation_ = 1;
    std::uint64_t revision_ = 0;
    bool paused_ = false;

    std::map<int, HopState> hops_;
    int maxTTL_ = 0;
    // Lowest TTL that produced an Echo Reply. 0 while unknown.
    int destTTL_ = 0;

    std::vector<Event> events_;
    LocalInfo local_;
    Health health_;
    Records records_;

    std::map<std::string, EnrichRec> enrich_;

    std::map<int, std::vector<std::string>> lastRoundSet_;
    std::map<int, int> changeStreak_;
    int lastRoundLen_ = 0;

    // Where sustained loss appears to begin, plus its debounce state. Loss is
    // never attributed to a single hop (spec §5.1); we only say where it seems to
    // start, and only once it has persisted.
    void checkLossOnset(Dur now, int visible);
    int lossOnsetTTL_ = 0;
    int lossOnsetStreak_ = 0;
    int lossOnsetLogged_ = 0;
};

// The per-hop loss level that counts as elevated when looking for where sustained
// loss begins.
inline constexpr double kElevatedLossPct = 10.0;

}  // namespace netscope
