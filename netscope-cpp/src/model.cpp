#include "model.h"

#include <string_view>

namespace netscope {

// The string forms are part of the cross-language contract: they appear in the
// canonical JSON that the parity harness diffs, so they must match the Go
// constants exactly (spec §9).

const char* familyName(Family f) { return f == Family::IP4 ? "ip4" : "ip6"; }

Family familyFromName(std::string_view s) {
    return s == "ip6" ? Family::IP6 : Family::IP4;
}

const char* modeName(ProbeMode m) {
    switch (m) {
        case ProbeMode::Raw: return "raw";
        case ProbeMode::Helper: return "helper";
        case ProbeMode::Command: return "command";
    }
    return "raw";
}

ProbeMode modeFromName(std::string_view s) {
    if (s == "helper") return ProbeMode::Helper;
    if (s == "command") return ProbeMode::Command;
    return ProbeMode::Raw;
}

const char* outcomeName(Outcome o) {
    switch (o) {
        case Outcome::Reply: return "Reply";
        case Outcome::TTLExpired: return "TTLExpired";
        case Outcome::Unreachable: return "Unreachable";
        case Outcome::Timeout: return "Timeout";
        case Outcome::PermissionDenied: return "PermissionDenied";
        case Outcome::BackendError: return "BackendError";
    }
    return "Timeout";
}

Outcome outcomeFromName(std::string_view s) {
    if (s == "Reply") return Outcome::Reply;
    if (s == "TTLExpired") return Outcome::TTLExpired;
    if (s == "Unreachable") return Outcome::Unreachable;
    if (s == "PermissionDenied") return Outcome::PermissionDenied;
    if (s == "BackendError") return Outcome::BackendError;
    return Outcome::Timeout;
}

const char* statusName(HopStatus s) {
    switch (s) {
        case HopStatus::Unknown: return "UNKNOWN";
        case HopStatus::Responding: return "RESPONDING";
        case HopStatus::Silent: return "SILENT";
        case HopStatus::TransitOnly: return "TRANSIT_ONLY";
        case HopStatus::Degraded: return "DEGRADED";
    }
    return "UNKNOWN";
}

const char* eventKindName(EventKind k) {
    switch (k) {
        case EventKind::Start: return "start";
        case EventKind::Resolved: return "resolved";
        case EventKind::TraceRound: return "trace-round";
        case EventKind::RouteChange: return "route-change";
        case EventKind::ResponderChange: return "responder-change";
        case EventKind::Unreachable: return "unreachable";
        case EventKind::TimeoutStreak: return "timeout-streak";
        case EventKind::DegradedMode: return "degraded-mode";
        case EventKind::Permission: return "permission";
        case EventKind::TargetChange: return "target-change";
        case EventKind::Paused: return "paused";
        case EventKind::Resumed: return "resumed";
        case EventKind::Enrich: return "enrich";
        case EventKind::Health: return "health";
        case EventKind::Error: return "error";
    }
    return "start";
}

EventKind eventKindFromName(std::string_view s) {
    if (s == "resolved") return EventKind::Resolved;
    if (s == "trace-round") return EventKind::TraceRound;
    if (s == "route-change") return EventKind::RouteChange;
    if (s == "responder-change") return EventKind::ResponderChange;
    if (s == "unreachable") return EventKind::Unreachable;
    if (s == "timeout-streak") return EventKind::TimeoutStreak;
    if (s == "degraded-mode") return EventKind::DegradedMode;
    if (s == "permission") return EventKind::Permission;
    if (s == "target-change") return EventKind::TargetChange;
    if (s == "paused") return EventKind::Paused;
    if (s == "resumed") return EventKind::Resumed;
    if (s == "enrich") return EventKind::Enrich;
    if (s == "health") return EventKind::Health;
    if (s == "error") return EventKind::Error;
    return EventKind::Start;
}

}  // namespace netscope
