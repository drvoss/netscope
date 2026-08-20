// Measurement backends.
//
// Every backend produces normalized ProbeResult values and nothing else;
// classification and aggregation belong to the engine (spec §6.1). A probe's
// destination is ALWAYS the final target -- only the TTL varies. Pinging a
// router's own interface address would measure a different forward/reverse path
// and a different control-plane policy (spec §1, cross-review R1-2).
#pragma once

#include <memory>
#include <stop_token>
#include <string>
#include <vector>

#include "model.h"

namespace netscope {

class Backend {
public:
    virtual ~Backend() = default;

    virtual ProbeMode mode() const = 0;

    // Whether the scheduler may issue individual TTL-limited probes. Backends
    // that can only run a whole sweep (the command fallback) return false and
    // implement traceRound instead.
    virtual bool supportsPerTTL() const = 0;

    // Sends one TTL-limited probe toward the target and blocks until a reply
    // arrives, the probe times out, or stop is requested. Never throws: failures
    // are expressed as outcomes so the engine can log them without
    // special-casing (spec §6.1).
    virtual ProbeResult probe(const ProbeID& id, std::stop_token stop) = 0;

    // Performs a batch sweep. Returns an empty vector when unsupported.
    virtual std::vector<ProbeResult> traceRound(std::uint64_t generation, int maxTTL,
                                                std::stop_token stop) = 0;

    // Releases sockets and handles. Must be called before workers are joined so
    // blocking reads are interrupted: a stop request alone does not interrupt a
    // blocking syscall (spec §3.3 step 3).
    virtual void close() = 0;
};

// Result of capability detection.
struct BackendChoice {
    std::unique_ptr<Backend> backend;
    std::string note;  // for the event log
};

// Selects the best working backend for targetIp (spec §6.2). Detection sends one
// real probe rather than merely opening the handle: on Windows a raw ICMP socket
// opens successfully and then rejects every send, so "the constructor succeeded"
// is not evidence that a backend works.
//
// forceCommand pins the degraded fallback, so that path can be exercised on a
// machine where a better backend is available (--force-command). Without it the
// fallback is only reachable on a host that cannot do better, which makes it the
// least-tested code in the program.
BackendChoice selectBackend(const std::string& targetIp, Family family,
                            bool forceCommand = false);

// Factories, defined in the platform translation units.
std::unique_ptr<Backend> makeCommandBackend(const std::string& targetIp);
#ifdef _WIN32
std::unique_ptr<Backend> makeHelperBackend(const std::string& targetIp, std::string& err);
#else
// Which POSIX ICMP socket to open. These are two SEPARATE candidates rather than
// one factory that picks internally, because detection has to hold them to
// different bars -- see verifyBackend and spec §6.2.
enum class RawSocketKind {
    Datagram,  // SOCK_DGRAM + IPPROTO_ICMP: unprivileged, needs ping_group_range
    Raw,       // SOCK_RAW: needs root or cap_net_raw
};

std::unique_ptr<Backend> makeRawBackend(const std::string& targetIp, RawSocketKind kind,
                                        std::string& err);

// One entry of the POSIX candidate list, in preference order.
struct PosixCandidate {
    RawSocketKind kind;
    const char* label;
    bool requireReply;
};

// The POSIX candidate list itself, exposed so a test can pin it. Mirrors
// posixCandidates in netscope-go/internal/probe/select_unix.go: same order, same
// labels, same bars. Flipping a requireReply here silently re-opens the defect that
// cross-review R4 found, and no other test would notice.
const std::vector<PosixCandidate>& posixCandidates();
#endif

// How many TTLs a requireReply detection may try before giving up. Must equal Go's
// verifyMaxTTL in internal/probe/select.go (spec §6.2).
//
// More than one because a first hop that does not answer is ordinary -- plenty of
// home routers and clouds suppress Time Exceeded at TTL 1 -- and rejecting on that
// alone would demote a socket that works. A backend that cannot see TTL expiry AT
// ALL fails every one of them, so the discrimination survives. Retrying the same
// TTL would not help: the question is not whether one packet was lost, it is
// whether this socket can ever observe an expiry.
inline constexpr int kVerifyMaxTTL = 3;

// Detection predicate, exposed for unit tests.
//
// Sends TTL-limited probes to confirm the backend actually works. Ordinarily one
// probe is sent and a Timeout counts as success: it proves the packet went out, and
// says only that this hop stayed quiet.
//
// requireReply flips that. A Linux ICMP datagram socket sends TTL-limited packets
// perfectly well but never delivers the routers' Time Exceeded messages, because
// those go to the socket error queue (IP_RECVERR / MSG_ERRQUEUE) which this program
// does not read. Such a socket passes the ordinary bar and then reports every
// intermediate hop as silent while still calling itself "raw". So for that candidate
// something must be OBSERVED -- any reply at all, TTLExpired / Reply / Unreachable --
// across TTL 1..kVerifyMaxTTL, and silence throughout rejects it (cross-review R4).
bool verifyBackend(Backend& b, Family family, bool requireReply, std::string& why);

// Monotonic offset from process start, used for every RTT measurement. Never the
// wall clock (spec §4.1).
Dur elapsedSinceStart();

// Sets the process start instant. Called once from main.
void setStartInstant();

}  // namespace netscope
