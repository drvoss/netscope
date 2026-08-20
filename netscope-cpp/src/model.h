// Data types shared by every other translation unit.
//
// Field names and semantics are fixed by docs/netscope-spec.md and must stay
// identical to the Go implementation's internal/model/model.go. Changing one side
// only is a bug.
#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace netscope {

// Dur is the monotonic offset type. Nanosecond resolution matches Go's
// time.Duration so the two implementations round identically.
using Dur = std::chrono::nanoseconds;

inline constexpr Dur ms(long long v) { return std::chrono::milliseconds(v); }

inline double toMs(Dur d) {
    return std::chrono::duration<double, std::milli>(d).count();
}

inline Dur fromMs(double v) {
    return std::chrono::duration_cast<Dur>(std::chrono::duration<double, std::milli>(v));
}

// Address family a target resolved to.
enum class Family { IP4, IP6 };
const char* familyName(Family f);
Family familyFromName(std::string_view s);

// Measurement backend in use (spec §6.2).
enum class ProbeMode {
    Raw,     // raw / datagram ICMP socket: full control of TTL and id/seq
    Helper,  // Windows IP Helper API
    Command  // parses ping/tracert output. Degraded.
};
const char* modeName(ProbeMode m);
ProbeMode modeFromName(std::string_view s);

// Normalized single-probe result (spec §6.1). Backends produce these; only the
// engine interprets them.
enum class Outcome {
    Reply,             // Echo Reply: the destination answered
    TTLExpired,        // Time Exceeded: an intermediate router answered
    Unreachable,       // ICMP type 3. A response, not a loss.
    Timeout,           // no answer within probeTimeout
    PermissionDenied,  // backend cannot run at all
    BackendError       // parse failure, spawn failure, ...
};
const char* outcomeName(Outcome o);
Outcome outcomeFromName(std::string_view s);

// Only Timeout counts as loss (spec §4.2).
inline bool answered(Outcome o) {
    return o == Outcome::Reply || o == Outcome::TTLExpired || o == Outcome::Unreachable;
}

// Hop classification. The binary FILTERED/LOSS split was discarded during
// cross-review: silence does not prove filtering (spec §5.1).
enum class HopStatus {
    Unknown,      // fewer than minSamples probes sent
    Responding,   // at least one reply inside the window
    Silent,       // never answered, and nothing beyond it answers either
    TransitOnly,  // never answered, but a greater TTL does answer
    Degraded      // answered before, now on a timeout streak
};
const char* statusName(HopStatus s);

// Log timeline entry kinds (spec §5.4).
enum class EventKind {
    Start,
    Resolved,
    TraceRound,
    RouteChange,
    ResponderChange,
    Unreachable,
    TimeoutStreak,
    DegradedMode,
    Permission,
    TargetChange,
    Paused,
    Resumed,
    Enrich,
    Health,
    Error
};
const char* eventKindName(EventKind k);
EventKind eventKindFromName(std::string_view s);

// Identifies one attempt. Correlation uses these internal fields, never
// wire-level id/seq recovered across backends (spec §6.3).
struct ProbeID {
    std::uint64_t generation = 0;
    Family family = Family::IP4;
    int ttl = 0;
    std::uint64_t attempt = 0;
};

// What a backend hands back. Immutable by convention: workers never mutate engine
// state, they only produce these (spec §3.1).
struct ProbeResult {
    ProbeID id{};
    Outcome outcome = Outcome::Timeout;
    std::string responder;  // observed responder IP, empty when none
    Dur rtt{};              // valid only when answered(outcome)
    Dur sentAt{};           // monotonic offset from engine start
    Dur recvAt{};
    std::string note;
};

// The destination every probe is sent to. Only the TTL varies.
struct Target {
    std::string input;
    std::string ip;
    Family family = Family::IP4;
    Dur resolvedAt{};
};

// Window-derived summary. std::nullopt means undefined; the UI renders it as
// "-" / "—" rather than inventing a zero (spec §8.3).
struct RttStats {
    int samples = 0;
    std::optional<double> lastMs;
    std::optional<double> bestMs;
    std::optional<double> avgMs;
    std::optional<double> worstMs;
    std::optional<double> jitterMs;  // mean absolute successive difference (spec §4.3)
    std::optional<double> stdevMs;   // sample standard deviation, n-1
    std::vector<double> spark;
};

// An IP observed answering at some TTL. ECMP means a single TTL can have several;
// each keeps independent statistics so their RTTs are never mixed into one
// meaningless average (spec §5.3).
struct Responder {
    std::string ip;
    std::string rdns;  // empty: not looked up yet. "-": looked up and absent.
    std::string asn;   // "AS15133" form
    std::string org;
    std::uint64_t seen = 0;
    Dur firstSeenAt{};
    Dur lastSeenAt{};
    RttStats stats;
};

// One TTL bucket. Deliberately not called "Hop": a TTL is a position on the path,
// not necessarily a single router (spec §6.5).
struct HopPosition {
    int ttl = 0;
    HopStatus status = HopStatus::Unknown;
    std::uint64_t sent = 0;
    std::uint64_t replied = 0;
    std::optional<double> lossPct;
    std::vector<Responder> responders;
    std::string primary;
    RttStats stats;  // primary responder's stats
    bool isDestination = false;
};

struct LocalInfo {
    std::string interfaceName;
    std::string address;  // CIDR form
    std::string gateway;
    std::vector<std::string> dnsServers;
    std::string defaultRoute;
    std::string publicIp;
    std::string note;  // "unsupported" etc. rather than a silently blank panel
};

// L7 / port state for the mid bar. Deliberately independent of hop
// classification: ICMP can be blocked end to end while HTTP works.
struct Health {
    int httpStatus = 0;
    std::optional<double> httpLatencyMs;
    std::string httpNote;
    int tcpPort = 0;
    bool tcpOpen = false;
    std::string tcpNote;
    Dur checkedAt{};
};

struct Event {
    Dur at{};
    EventKind kind = EventKind::Start;
    std::optional<int> ttl;
    std::string text;
};

// The probe schedule actually in force, so both binaries can display the same
// numbers and be compared (spec §4.4).
struct Cadence {
    int destIntervalMs = 0;
    int midIntervalMs = 0;
    int globalCapPps = 0;
    int windowDurationMs = 0;
    int probeTimeoutMs = 0;
};

// DNS records for the RESOLVE panel.
struct Records {
    std::vector<std::string> a;
    std::vector<std::string> aaaa;
    std::string ptr;
    std::string note;
};

// The immutable view the UI renders. The engine loop is its only producer
// (spec §3.1).
struct Snapshot {
    std::uint64_t revision = 0;
    std::uint64_t generation = 0;
    Target target;
    Dur now{};
    ProbeMode mode = ProbeMode::Raw;
    bool degraded = false;
    bool paused = false;
    std::vector<HopPosition> hops;
    LocalInfo local;
    Health health;
    std::vector<Event> events;  // newest first
    Cadence cadence;
};

// Bounds the retained log (spec §2).
inline constexpr std::size_t kMaxEvents = 200;

// UI-to-engine message. The UI never touches engine state directly.
enum class CommandKind {
    Quit,
    TogglePause,
    Reprobe,
    SetTarget,
    RefreshDNS,
    RefreshASN,
    SelectHop
};

struct Command {
    CommandKind kind = CommandKind::Quit;
    std::string target;
    int ttl = 0;
    std::string selectedIp;
};

}  // namespace netscope
