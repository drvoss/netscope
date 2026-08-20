// Mirrors netscope-go/internal/probe/select_test.go and select_unix_test.go.
#include <cstddef>
#include <string>
#include <vector>

#include <doctest/doctest.h>

#include "probe.h"

using namespace netscope;

namespace {

// Returns canned outcomes for the detection probes, one per TTL, repeating the last
// entry once they run out. It exists so the detection RULE can be tested without a
// kernel: the case that matters -- an ICMP datagram socket that sends fine but can
// never observe a Time Exceeded -- cannot be produced on the host this project is
// developed on.
class FakeBackend : public Backend {
public:
    FakeBackend(std::vector<Outcome> outcomes, bool perTTL)
        : outcomes_(std::move(outcomes)), perTTL_(perTTL) {}

    ProbeMode mode() const override { return ProbeMode::Raw; }
    bool supportsPerTTL() const override { return perTTL_; }

    ProbeResult probe(const ProbeID& id, std::stop_token) override {
        seen_.push_back(id);
        const std::size_t i = seen_.size() - 1;
        ProbeResult r;
        r.id = id;
        r.outcome = (i < outcomes_.size()) ? outcomes_[i] : outcomes_.back();
        r.note = "canned";
        return r;
    }

    std::vector<ProbeResult> traceRound(std::uint64_t, int, std::stop_token) override {
        return {};
    }

    void close() override { ++closed_; }

    std::size_t probes() const { return seen_.size(); }
    int closed() const { return closed_; }

    // Detection must never let its own probe be mistaken for a measurement, and must
    // walk TTLs upward from 1. Both facts were previously protected only by a comment.
    void checkIDs(Family wantFamily) const {
        for (std::size_t i = 0; i < seen_.size(); ++i) {
            CAPTURE(i);
            CHECK(seen_[i].generation == 0u);
            CHECK(seen_[i].ttl == static_cast<int>(i) + 1);
            CHECK(seen_[i].family == wantFamily);
        }
    }

private:
    std::vector<Outcome> outcomes_;
    bool perTTL_;
    std::vector<ProbeID> seen_;
    int closed_ = 0;
};

}  // namespace

// The rule, per spec §6.2. Mirrored by the Go suite in internal/probe/select_test.go
// -- these two must agree case for case, because this decides which backend a host
// uses and therefore every measurement that follows.
TEST_CASE("verifyBackend: requireReply rejects only sustained silence") {
    struct Case {
        const char* name;
        std::vector<Outcome> outcomes;
        bool requireReply;
        bool wantOk;
        std::size_t wantProbes;
    };

    const std::vector<Case> cases = {
        // The defect this rule exists to catch: sent successfully, nothing observed
        // at any TTL it is willing to try.
        {"silence throughout rejects when a reply is required",
         {Outcome::Timeout}, true, false, static_cast<std::size_t>(kVerifyMaxTTL)},

        // A quiet FIRST hop is ordinary and must not demote a working socket. This is
        // why detection sweeps TTLs instead of retrying TTL 1 (codex/claude R1).
        {"a silent first hop is tolerated when a later one answers",
         {Outcome::Timeout, Outcome::TTLExpired}, true, true, 2},
        {"silent until the last TTL still passes",
         {Outcome::Timeout, Outcome::Timeout, Outcome::TTLExpired}, true, true, 3},

        // The lenient bar sends exactly one probe and accepts the send as evidence.
        {"timeout accepted when no reply is required", {Outcome::Timeout}, false, true, 1},

        // Any observed reply proves the receive path, and stops the sweep early.
        {"ttl expired proves the receive path", {Outcome::TTLExpired}, true, true, 1},
        {"reply proves the receive path", {Outcome::Reply}, true, true, 1},
        {"unreachable proves the receive path", {Outcome::Unreachable}, true, true, 1},

        // Hard failures reject at either bar, and abandon the sweep immediately.
        {"permission denied rejects, strict", {Outcome::PermissionDenied}, true, false, 1},
        {"permission denied rejects, lenient", {Outcome::PermissionDenied}, false, false, 1},
        {"backend error rejects, strict", {Outcome::BackendError}, true, false, 1},
        {"backend error rejects, lenient", {Outcome::BackendError}, false, false, 1},
    };

    for (const auto& c : cases) {
        CAPTURE(c.name);
        FakeBackend b(c.outcomes, true);
        std::string why;
        const bool ok = verifyBackend(b, Family::IP4, c.requireReply, why);
        CHECK(ok == c.wantOk);
        if (!ok) {
            // A rejection with no reason would leave the event log saying nothing.
            CHECK_FALSE(why.empty());
        }
        CHECK(b.probes() == c.wantProbes);
        b.checkIDs(Family::IP4);
    }
}

// The rejection reason must not claim more than was observed: silence is also what
// a genuinely quiet near path looks like (codex R4).
TEST_CASE("verifyBackend: the rejection reason does not overclaim") {
    FakeBackend b({Outcome::Timeout}, true);
    std::string why;
    verifyBackend(b, Family::IP4, true, why);
    CHECK(why.find("cannot see") == std::string::npos);
    CHECK(why.find("may not") != std::string::npos);
}

TEST_CASE("verifyBackend: the detection probe carries the target's family") {
    FakeBackend b({Outcome::Reply}, true);
    std::string why;
    verifyBackend(b, Family::IP6, true, why);
    b.checkIDs(Family::IP6);
}

// A sweep-only backend cannot answer a single TTL-limited probe, so it must be
// accepted without one. Otherwise requireReply would also reject the command
// fallback and the program would be left with no backend at all.
TEST_CASE("verifyBackend: a sweep-only backend is accepted without probing") {
    FakeBackend b({Outcome::Timeout}, false);
    std::string why;
    CHECK(verifyBackend(b, Family::IP4, true, why));
    CHECK(b.probes() == 0);
}

#ifndef _WIN32
// The POSIX candidate list must offer the datagram socket first and hold it to the
// strict bar, then SOCK_RAW at the ordinary one. Getting either flag backwards
// re-opens the defect that cross-review R4 found, and no other test would notice.
// Must stay identical to posixCandidates in netscope-go/internal/probe/select_unix.go.
TEST_CASE("posixCandidates: order and bars are pinned") {
    const auto& got = posixCandidates();
    REQUIRE(got.size() == 2u);

    CHECK(got[0].kind == RawSocketKind::Datagram);
    CHECK(std::string(got[0].label) == "raw ICMP (datagram socket)");
    CHECK(got[0].requireReply == true);

    CHECK(got[1].kind == RawSocketKind::Raw);
    CHECK(std::string(got[1].label) == "raw ICMP (SOCK_RAW)");
    CHECK(got[1].requireReply == false);
}
#endif
