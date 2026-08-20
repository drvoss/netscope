// Mirrors netscope-go/internal/engine/engine_test.go.
#include <string>

#include <doctest/doctest.h>

#include "engine.h"
#include "resolve.h"

using namespace netscope;

namespace {

Engine makeEngine(ProbeMode mode) {
    Target t;
    t.input = "example.com";
    t.ip = "93.184.216.34";
    t.family = Family::IP4;
    return Engine(t, mode);
}

void feed(Engine& e, int ttl, std::uint64_t attempt, long long atMs, Outcome out,
          const std::string& responder, double rttMs) {
    ProbeResult r;
    r.id.generation = e.generation();
    r.id.family = Family::IP4;
    r.id.ttl = ttl;
    r.id.attempt = attempt;
    r.outcome = out;
    r.responder = responder;
    r.sentAt = ms(atMs);
    if (answered(out)) {
        r.rtt = fromMs(rttMs);
        r.recvAt = r.sentAt + r.rtt;
    } else {
        r.recvAt = r.sentAt + ms(1500);
    }
    e.ingest(r);
}

const HopPosition* hop(const Snapshot& s, int ttl) {
    for (const auto& h : s.hops) {
        if (h.ttl == ttl) return &h;
    }
    return nullptr;
}

int countEvents(const Snapshot& s, EventKind kind) {
    int n = 0;
    for (const auto& e : s.events) {
        if (e.kind == kind) ++n;
    }
    return n;
}

std::string responderFor(Outcome out) { return answered(out) ? "10.0.0.1" : ""; }

}  // namespace

TEST_CASE("a hop is UNKNOWN until minSamples probes have been sent") {
    Engine e = makeEngine(ProbeMode::Raw);
    feed(e, 1, 1, 0, Outcome::Timeout, "", 0);
    feed(e, 1, 2, 1000, Outcome::Timeout, "", 0);
    auto s = e.snapshot(ms(2000));
    REQUIRE(hop(*s, 1) != nullptr);
    CHECK(hop(*s, 1)->status == HopStatus::Unknown);

    feed(e, 1, 3, 2000, Outcome::Timeout, "", 0);
    s = e.snapshot(ms(3000));
    CHECK(hop(*s, 1)->status == HopStatus::Silent);
}

TEST_CASE("TRANSIT_ONLY requires a greater TTL to be answering") {
    Engine e = makeEngine(ProbeMode::Raw);
    for (int i = 1; i <= 3; ++i) feed(e, 2, static_cast<std::uint64_t>(i), i * 1000, Outcome::Timeout, "", 0);
    auto s = e.snapshot(ms(4000));
    CHECK(hop(*s, 2)->status == HopStatus::Silent);

    // now hop 3 answers -> hop 2 forwards traffic but does not answer probes
    feed(e, 3, 1, 5000, Outcome::TTLExpired, "10.0.0.3", 20);
    s = e.snapshot(ms(6000));
    CHECK(hop(*s, 2)->status == HopStatus::TransitOnly);
}

TEST_CASE("the degraded backend never infers TRANSIT_ONLY") {
    // The command backend cannot support the inference (spec §6.4).
    Engine e = makeEngine(ProbeMode::Command);
    for (int i = 1; i <= 3; ++i) feed(e, 2, static_cast<std::uint64_t>(i), i * 1000, Outcome::Timeout, "", 0);
    feed(e, 3, 1, 5000, Outcome::TTLExpired, "10.0.0.3", 20);
    auto s = e.snapshot(ms(6000));
    CHECK(hop(*s, 2)->status == HopStatus::Silent);
}

TEST_CASE("the degraded backend suppresses jitter and stdev") {
    Engine e = makeEngine(ProbeMode::Command);
    for (int i = 0; i < 5; ++i) {
        feed(e, 1, static_cast<std::uint64_t>(i + 1), i * 1000, Outcome::TTLExpired, "10.0.0.1",
             10.0 + i);
    }
    auto s = e.snapshot(ms(6000));
    const HopPosition* h = hop(*s, 1);
    REQUIRE(h != nullptr);
    CHECK_FALSE(h->stats.jitterMs.has_value());
    CHECK_FALSE(h->stats.stdevMs.has_value());
    CHECK(h->stats.avgMs.has_value());  // avg is still honest
}

TEST_CASE("hysteresis moves RESPONDING to DEGRADED and back") {
    Engine e = makeEngine(ProbeMode::Raw);
    long long at = 0;
    auto send = [&](Outcome out) {
        at += 1000;
        feed(e, 1, static_cast<std::uint64_t>(at / 1000), at, out, responderFor(out), 10);
        e.snapshot(ms(at + 100));
    };

    for (int i = 0; i < 3; ++i) send(Outcome::TTLExpired);
    CHECK(hop(*e.snapshot(ms(at + 200)), 1)->status == HopStatus::Responding);

    // 3 timeouts is below LossStreak=4, must not flap
    for (int i = 0; i < 3; ++i) send(Outcome::Timeout);
    CHECK(hop(*e.snapshot(ms(at + 200)), 1)->status == HopStatus::Responding);

    send(Outcome::Timeout);  // 4th
    CHECK(hop(*e.snapshot(ms(at + 200)), 1)->status == HopStatus::Degraded);

    send(Outcome::TTLExpired);  // one reply is not enough to recover
    CHECK(hop(*e.snapshot(ms(at + 200)), 1)->status == HopStatus::Degraded);

    send(Outcome::TTLExpired);
    CHECK(hop(*e.snapshot(ms(at + 200)), 1)->status == HopStatus::Responding);
}

TEST_CASE("Unreachable counts as an answer, not a loss") {
    Engine e = makeEngine(ProbeMode::Raw);
    feed(e, 4, 1, 0, Outcome::Unreachable, "10.0.0.4", 30);
    feed(e, 4, 2, 1000, Outcome::Unreachable, "10.0.0.4", 31);
    auto s = e.snapshot(ms(2000));
    const HopPosition* h = hop(*s, 4);
    REQUIRE(h != nullptr);
    REQUIRE(h->lossPct.has_value());
    CHECK(*h->lossPct == doctest::Approx(0));
    CHECK(h->replied == 2);
}

TEST_CASE("results from a stale generation are discarded") {
    Engine e = makeEngine(ProbeMode::Raw);
    feed(e, 1, 1, 0, Outcome::TTLExpired, "10.0.0.1", 10);
    e.reprobe(ms(1000));

    ProbeResult late;
    late.id.generation = 1;  // the previous generation
    late.id.ttl = 1;
    late.id.attempt = 2;
    late.outcome = Outcome::TTLExpired;
    late.responder = "10.0.0.1";
    late.rtt = ms(10);
    late.sentAt = ms(500);
    late.recvAt = ms(510);
    e.ingest(late);

    auto s = e.snapshot(ms(2000));
    CHECK(s->hops.empty());
    CHECK(s->generation == 2);
}

TEST_CASE("a reply arriving after the timeout is discarded") {
    Engine e = makeEngine(ProbeMode::Raw);
    // 1600ms > probeTimeout 1500ms: we already gave up, counting it would pollute
    // avg and jitter.
    feed(e, 1, 1, 0, Outcome::TTLExpired, "10.0.0.1", 1600);
    auto s = e.snapshot(ms(2000));
    CHECK(s->hops.empty());
}

TEST_CASE("ECMP responders keep separate statistics") {
    Engine e = makeEngine(ProbeMode::Raw);
    feed(e, 3, 1, 0, Outcome::TTLExpired, "10.0.0.9", 10);
    feed(e, 3, 2, 1000, Outcome::TTLExpired, "10.0.0.8", 90);
    feed(e, 3, 3, 2000, Outcome::TTLExpired, "10.0.0.9", 12);

    auto s = e.snapshot(ms(3000));
    const HopPosition* h = hop(*s, 3);
    REQUIRE(h != nullptr);
    REQUIRE(h->responders.size() == 2);
    CHECK(h->primary == "10.0.0.9");
    // The two routers' RTTs must not be averaged together into 37.3ms.
    REQUIRE(h->stats.avgMs.has_value());
    CHECK(*h->stats.avgMs == doctest::Approx(11));
    for (const auto& r : h->responders) {
        if (r.ip == "10.0.0.8") {
            REQUIRE(r.stats.avgMs.has_value());
            CHECK(*r.stats.avgMs == doctest::Approx(90));
        }
    }
}

TEST_CASE("a route change is only reported after two rounds") {
    Engine e = makeEngine(ProbeMode::Raw);
    feed(e, 1, 1, 0, Outcome::TTLExpired, "10.0.0.1", 5);
    feed(e, 2, 1, 100, Outcome::Reply, "93.184.216.34", 40);
    e.snapshot(ms(200));
    e.endTraceRound(ms(300));  // establishes the baseline

    feed(e, 1, 2, 1000, Outcome::TTLExpired, "10.0.0.2", 6);
    e.snapshot(ms(1100));
    e.endTraceRound(ms(1200));
    CHECK(countEvents(*e.snapshot(ms(1300)), EventKind::RouteChange) == 0);

    feed(e, 1, 3, 2000, Outcome::TTLExpired, "10.0.0.2", 6);
    e.snapshot(ms(2100));
    e.endTraceRound(ms(2200));
    CHECK(countEvents(*e.snapshot(ms(2300)), EventKind::RouteChange) > 0);
}

TEST_CASE("temporary silence is not a route change") {
    Engine e = makeEngine(ProbeMode::Raw);
    feed(e, 1, 1, 0, Outcome::TTLExpired, "10.0.0.1", 5);
    feed(e, 2, 1, 100, Outcome::Reply, "93.184.216.34", 40);
    e.snapshot(ms(200));
    e.endTraceRound(ms(300));

    for (int round = 0; round < 3; ++round) {
        const long long at = 200000 + round * 1000;
        feed(e, 1, static_cast<std::uint64_t>(round + 2), at, Outcome::Timeout, "", 0);
        e.snapshot(ms(at + 100));
        e.endTraceRound(ms(at + 200));
    }
    CHECK(countEvents(*e.snapshot(ms(210000)), EventKind::RouteChange) == 0);
}

TEST_CASE("PermissionDenied is a graceful event, not a hop row") {
    Engine e = makeEngine(ProbeMode::Raw);
    ProbeResult r;
    r.id.generation = 1;
    r.id.ttl = 1;
    r.outcome = Outcome::PermissionDenied;
    r.note = "socket: operation not permitted";
    r.recvAt = ms(10);
    e.ingest(r);

    auto s = e.snapshot(ms(20));
    CHECK(s->hops.empty());
    bool found = false;
    for (const auto& ev : s->events) {
        if (ev.kind == EventKind::Permission &&
            ev.text.find("not permitted") != std::string::npos) {
            found = true;
        }
    }
    CHECK(found);
}

TEST_CASE("hops are gap-free and ascending") {
    Engine e = makeEngine(ProbeMode::Raw);
    feed(e, 1, 1, 0, Outcome::TTLExpired, "10.0.0.1", 5);
    feed(e, 4, 1, 100, Outcome::Reply, "93.184.216.34", 40);
    auto s = e.snapshot(ms(200));
    REQUIRE(s->hops.size() == 4);
    for (std::size_t i = 0; i < s->hops.size(); ++i) {
        CHECK(s->hops[i].ttl == static_cast<int>(i) + 1);
    }
    // The filler rows must be UNKNOWN with no invented statistics, not a
    // zero-valued RESPONDING row.
    for (int ttl : {2, 3}) {
        const HopPosition* h = hop(*s, ttl);
        REQUIRE(h != nullptr);
        CHECK(h->status == HopStatus::Unknown);
        CHECK_FALSE(h->lossPct.has_value());
        CHECK_FALSE(h->stats.avgMs.has_value());
        CHECK(h->sent == 0);
    }
}

TEST_CASE("ECMP jitter is not paired across responders") {
    // The avg-only assertion above would still pass if jitter mixed the two
    // routers, so check jitter explicitly.
    Engine e = makeEngine(ProbeMode::Raw);
    feed(e, 2, 1, 0, Outcome::TTLExpired, "10.0.0.9", 10);
    feed(e, 2, 2, 1000, Outcome::TTLExpired, "10.0.0.8", 90);
    feed(e, 2, 3, 2000, Outcome::TTLExpired, "10.0.0.9", 12);
    feed(e, 2, 4, 3000, Outcome::TTLExpired, "10.0.0.8", 95);
    auto s = e.snapshot(ms(4000));
    const HopPosition* h = hop(*s, 2);
    REQUIRE(h != nullptr);
    for (const auto& r : h->responders) {
        CHECK_FALSE(r.stats.jitterMs.has_value());
    }
}

TEST_CASE("degraded mode reports only the primary responder") {
    // The command backend runs one sweep at a time and cannot tell a real ECMP
    // split from two sweeps taking different paths (spec §6.4).
    Engine e = makeEngine(ProbeMode::Command);
    feed(e, 2, 1, 0, Outcome::TTLExpired, "10.0.0.9", 10);
    feed(e, 2, 2, 1000, Outcome::TTLExpired, "10.0.0.8", 90);
    feed(e, 2, 3, 2000, Outcome::TTLExpired, "10.0.0.9", 12);
    auto s = e.snapshot(ms(3000));
    const HopPosition* h = hop(*s, 2);
    REQUIRE(h != nullptr);
    REQUIRE(h->responders.size() == 1);
    CHECK(h->responders.front().ip == "10.0.0.9");

    // A raw-mode engine with the same input must still show both.
    Engine raw = makeEngine(ProbeMode::Raw);
    feed(raw, 2, 1, 0, Outcome::TTLExpired, "10.0.0.9", 10);
    feed(raw, 2, 2, 1000, Outcome::TTLExpired, "10.0.0.8", 90);
    feed(raw, 2, 3, 2000, Outcome::TTLExpired, "10.0.0.9", 12);
    auto rawSnap = raw.snapshot(ms(3000));
    CHECK(hop(*rawSnap, 2)->responders.size() == 2);
}

TEST_CASE("loss onset is reported after two rounds and never blames a hop") {
    Engine e = makeEngine(ProbeMode::Raw);
    long long at = 0;

    auto round = [&] {
        for (int i = 0; i < 5; ++i) {
            at += 100;
            feed(e, 1, static_cast<std::uint64_t>(at), at, Outcome::TTLExpired, "10.0.0.1", 5);
            at += 100;
            feed(e, 2, static_cast<std::uint64_t>(at), at, Outcome::TTLExpired, "10.0.0.2", 10);
            at += 100;
            const Outcome out = (i >= 3) ? Outcome::TTLExpired : Outcome::Timeout;
            feed(e, 3, static_cast<std::uint64_t>(at), at, out, responderFor(out), 20);
            at += 100;
            const Outcome outD = (i >= 3) ? Outcome::Reply : Outcome::Timeout;
            feed(e, 4, static_cast<std::uint64_t>(at), at, outD, "93.184.216.34", 40);
        }
        e.snapshot(ms(at + 50));
        e.endTraceRound(ms(at + 60));
    };

    auto countOnset = [](const Snapshot& s) {
        int n = 0;
        for (const auto& ev : s.events) {
            if (ev.text.find("possible loss beginning after hop") != std::string::npos) ++n;
        }
        return n;
    };

    round();
    CHECK(countOnset(*e.snapshot(ms(at + 100))) == 0);
    round();

    auto s = e.snapshot(ms(at + 100));
    CHECK(countOnset(*s) == 1);
    for (const auto& ev : s->events) {
        if (ev.text.find("possible loss beginning after hop") != std::string::npos) {
            // Never accuse a hop of causing the loss; only say where it starts.
            CHECK(ev.text.find("beginning after hop 2") != std::string::npos);
        }
    }
}

TEST_CASE("resolveTarget fails gracefully and handles literals without DNS") {
    Target t;
    std::string err;
    CHECK_FALSE(resolveTarget("this-name-should-not-exist.invalid", t, err));
    CHECK_FALSE(err.empty());

    REQUIRE(resolveTarget("192.0.2.1", t, err));
    CHECK(t.ip == "192.0.2.1");
    CHECK(t.family == Family::IP4);

    REQUIRE(resolveTarget("2001:db8::1", t, err));
    CHECK(t.family == Family::IP6);
}

TEST_CASE("events are newest first") {
    Engine e = makeEngine(ProbeMode::Raw);
    e.addEvent(ms(100), EventKind::Start, std::nullopt, "first");
    e.addEvent(ms(200), EventKind::Start, std::nullopt, "second");
    auto s = e.snapshot(ms(300));
    REQUIRE_FALSE(s->events.empty());
    CHECK(s->events.front().text == "second");
}

TEST_CASE("pause toggles") {
    Engine e = makeEngine(ProbeMode::Raw);
    CHECK_FALSE(e.paused());
    e.togglePause(ms(10));
    CHECK(e.paused());
    CHECK(e.snapshot(ms(20))->paused);
    e.togglePause(ms(30));
    CHECK_FALSE(e.paused());
}

TEST_CASE("the destination TTL unlatches when the path grows") {
    Engine e = makeEngine(ProbeMode::Raw);
    feed(e, 1, 1, 0, Outcome::TTLExpired, "10.0.0.1", 5);
    feed(e, 2, 1, 100, Outcome::Reply, "93.184.216.34", 40);
    CHECK(e.destTTL() == 2);
    // A router now answers at TTL 2, so the destination moved further away.
    feed(e, 2, 2, 1000, Outcome::TTLExpired, "10.0.0.2", 6);
    CHECK(e.destTTL() == 0);
}
