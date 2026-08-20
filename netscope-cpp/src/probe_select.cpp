#include <chrono>
#include <stop_token>
#include <string>
#include <vector>

#include "probe.h"

namespace netscope {
namespace {

// Process start instant for the monotonic clock. steady_clock, never
// system_clock: RTT must not be affected by NTP steps or DST (spec §4.1).
std::chrono::steady_clock::time_point& startInstant() {
    static std::chrono::steady_clock::time_point t = std::chrono::steady_clock::now();
    return t;
}

std::string joinNotes(const std::vector<std::string>& notes) {
    std::string out;
    for (std::size_t i = 0; i < notes.size(); ++i) {
        if (i > 0) out += "; ";
        out += notes[i];
    }
    return out;
}

}  // namespace

// Contract documented in probe.h. Keep this byte-for-byte equivalent to Go's
// verify() in internal/probe/select.go -- it decides which backend a host uses,
// so a difference here is a difference in every measurement that follows.
bool verifyBackend(Backend& b, Family family, bool requireReply, std::string& why) {
    if (!b.supportsPerTTL()) return true;

    std::stop_source src;
    const int maxTTL = requireReply ? kVerifyMaxTTL : 1;

    for (int ttl = 1; ttl <= maxTTL; ++ttl) {
        ProbeID id;
        // Generation 0 is never the engine's live generation, so this probe's result
        // could not be mistaken for a measurement even if it leaked.
        id.generation = 0;
        id.family = family;
        id.ttl = ttl;

        const ProbeResult res = b.probe(id, src.get_token());
        if (res.outcome == Outcome::PermissionDenied || res.outcome == Outcome::BackendError) {
            why = res.note;
            return false;
        }
        // Without requireReply the send alone is the evidence, so stop at the first.
        if (!requireReply) return true;
        // Any observed reply proves the receive path: TTLExpired and Unreachable both
        // arrive by the same mechanism that a datagram socket cannot deliver, and Reply
        // means the target is within reach of this TTL, which also came back through
        // the socket. Only Timeout keeps the loop going.
        if (answered(res.outcome)) return true;
    }

    // Deliberately "may not": silence across these TTLs is consistent with a socket
    // that cannot see Time Exceeded, but it is also consistent with a genuinely quiet
    // near path. The log must not claim to have distinguished them (codex R5).
    why = "sent, but nothing observed at ttl 1.." + std::to_string(maxTTL) +
          " -- this socket may not be able to see Time Exceeded (no IP_RECVERR), "
          "so the next candidate is tried instead";
    return false;
}

#ifndef _WIN32
// Two candidates, not one factory that chooses internally. The unprivileged
// datagram socket is still preferred -- it needs no capability, so an ordinary user
// gets real per-hop measurement wherever the kernel allows it -- but it must PROVE
// it can observe a reply before it is accepted, because on Linux it can send
// TTL-limited probes and never see a single Time Exceeded (spec §6.2,
// cross-review R4). SOCK_RAW keeps the ordinary bar: its ability to receive TTL
// expiry was verified in a real environment on 2026-07-30.
const std::vector<PosixCandidate>& posixCandidates() {
    static const std::vector<PosixCandidate> list = {
        {RawSocketKind::Datagram, "raw ICMP (datagram socket)", true},
        {RawSocketKind::Raw, "raw ICMP (SOCK_RAW)", false},
    };
    return list;
}
#endif

void setStartInstant() { startInstant() = std::chrono::steady_clock::now(); }

Dur elapsedSinceStart() {
    return std::chrono::duration_cast<Dur>(std::chrono::steady_clock::now() - startInstant());
}

BackendChoice selectBackend(const std::string& targetIp, Family family, bool forceCommand) {
    std::vector<std::string> notes;

    if (forceCommand) {
        return BackendChoice{makeCommandBackend(targetIp),
                             "command fallback forced by --force-command (degraded metrics)"};
    }

#ifdef _WIN32
    // The IP Helper backend comes FIRST on Windows, ahead of a raw socket, which is
    // a deliberate deviation from the generic "raw is best" ranking. Verified while
    // building the Go implementation on this host: a raw ICMP socket receives Echo
    // Replies but NOT the Time Exceeded messages from intermediate routers, so raw
    // mode reports every intermediate hop as silent and only the destination as
    // responding -- useless for a path table. IcmpSendEcho reports TTL expiry
    // explicitly, with the responding router's address.
    {
        std::string err;
        auto helper = makeHelperBackend(targetIp, err);
        if (helper) {
            std::string why;
            if (verifyBackend(*helper, family, false, why)) {
                notes.insert(notes.begin(), "helper (IcmpSendEcho) backend active");
                return BackendChoice{std::move(helper), joinNotes(notes)};
            }
            helper->close();
            notes.push_back("helper opened but unusable (" + why + ")");
        } else {
            notes.push_back("helper unavailable (" + err + ")");
        }
    }
#else
    {
        for (const auto& c : posixCandidates()) {
            std::string err;
            auto raw = makeRawBackend(targetIp, c.kind, err);
            if (!raw) {
                notes.push_back(std::string(c.label) + " unavailable (" + err + ")");
                continue;
            }
            std::string why;
            if (verifyBackend(*raw, family, c.requireReply, why)) {
                notes.insert(notes.begin(), std::string(c.label) + " backend active");
                return BackendChoice{std::move(raw), joinNotes(notes)};
            }
            raw->close();
            notes.push_back(std::string(c.label) + " opened but unusable (" + why + ")");
        }
    }
#endif

    notes.push_back("using command fallback (degraded metrics)");
    return BackendChoice{makeCommandBackend(targetIp), joinNotes(notes)};
}

}  // namespace netscope
