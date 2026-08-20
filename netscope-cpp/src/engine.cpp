#include "engine.h"

#include <algorithm>
#include <sstream>

namespace netscope {

Cadence defaultCadence() {
    Cadence c;
    c.destIntervalMs = 1000;
    c.midIntervalMs = 4000;
    c.globalCapPps = 10;
    c.windowDurationMs =
        static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(kWindowDuration).count());
    c.probeTimeoutMs =
        static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(kProbeTimeout).count());
    return c;
}

void HopState::record(const ProbeResult& r) {
    ++sent;
    if (answered(r.outcome)) {
        ++replied;
        everReplied = true;
        timeoutStreak = 0;
        ++replyStreak;
        if (!r.responder.empty()) {
            auto it = responders.find(r.responder);
            if (it == responders.end()) {
                RespState rs;
                rs.ip = r.responder;
                rs.firstSeenAt = r.recvAt;
                it = responders.emplace(r.responder, rs).first;
            }
            ++it->second.seen;
            it->second.lastSeenAt = r.recvAt;
        }
        if (r.outcome == Outcome::Reply) isDestination = true;

        Sample s;
        s.sentAt = r.sentAt;
        s.rtt = r.rtt;
        s.ok = true;
        s.responder = r.responder;
        win.add(s);
        return;
    }
    // Timeout. PermissionDenied / BackendError are filtered out before here.
    replyStreak = 0;
    ++timeoutStreak;
    Sample s;
    s.sentAt = r.sentAt;
    s.ok = false;
    win.add(s);
}

std::string HopState::primary() const {
    auto rs = win.responders();
    if (!rs.empty()) return rs.front();
    // Fall back to cumulative observations so a briefly silent hop keeps its label.
    std::string best;
    std::uint64_t bestSeen = 0;
    for (const auto& kv : responders) {  // std::map iterates in IP order already
        if (kv.second.seen > bestSeen) {
            best = kv.first;
            bestSeen = kv.second.seen;
        }
    }
    return best;
}

HopStatus classify(const HopState& h, bool anyGreaterReplied, bool degraded) {
    if (!h.everReplied) {
        if (h.sent < kMinSamples) return HopStatus::Unknown;
        if (anyGreaterReplied && !degraded) return HopStatus::TransitOnly;
        return HopStatus::Silent;
    }

    // Has answered at some point. Hysteresis keeps a single lost probe from
    // flapping the row, and requires sustained replies to come back.
    if (h.status == HopStatus::Degraded) {
        if (h.replyStreak >= kRecoverStreak) return HopStatus::Responding;
        return HopStatus::Degraded;
    }
    if (h.timeoutStreak >= kLossStreak) return HopStatus::Degraded;
    return HopStatus::Responding;
}

Engine::Engine(Target target, ProbeMode mode)
    : cadence_(defaultCadence()),
      mode_(mode),
      degraded_(mode == ProbeMode::Command),
      target_(std::move(target)) {}

void Engine::setCadence(int destMs, int midMs) {
    cadence_.destIntervalMs = destMs;
    cadence_.midIntervalMs = midMs;
}

void Engine::setMode(ProbeMode m, Dur at) {
    if (mode_ == m) return;
    mode_ = m;
    degraded_ = (m == ProbeMode::Command);
    if (degraded_) {
        addEvent(at, EventKind::DegradedMode, std::nullopt,
                 "backend downgraded to command parsing (degraded metrics)");
    }
}

void Engine::addEvent(Dur at, EventKind kind, std::optional<int> ttl, std::string text) {
    Event e;
    e.at = at;
    e.kind = kind;
    e.ttl = ttl;
    e.text = std::move(text);
    events_.push_back(std::move(e));
    if (events_.size() > kMaxEvents) {
        events_.erase(events_.begin(),
                      events_.begin() + static_cast<std::ptrdiff_t>(events_.size() - kMaxEvents));
    }
}

void Engine::ingest(const ProbeResult& r) {
    // Stale generation: the target changed or the user re-probed (spec §3.1).
    if (r.id.generation != generation_) return;

    if (r.outcome == Outcome::PermissionDenied) {
        addEvent(r.recvAt, EventKind::Permission, r.id.ttl,
                 "raw ICMP not permitted: " + r.note);
        return;
    }
    if (r.outcome == Outcome::BackendError) {
        addEvent(r.recvAt, EventKind::Error, r.id.ttl, "probe backend: " + r.note);
        return;
    }

    // Late reply: arrived after we had already given up on this attempt. Counting
    // it would pollute avg and jitter (spec §6.3).
    if (answered(r.outcome) && r.rtt > kProbeTimeout) return;
    if (r.id.ttl < 1) return;

    auto it = hops_.find(r.id.ttl);
    if (it == hops_.end()) {
        HopState h;
        h.ttl = r.id.ttl;
        it = hops_.emplace(r.id.ttl, std::move(h)).first;
    }
    HopState& h = it->second;
    if (r.id.ttl > maxTTL_) maxTTL_ = r.id.ttl;

    const std::size_t prevResponders = h.responders.size();
    h.record(r);

    if (r.outcome == Outcome::Reply) {
        if (destTTL_ == 0 || r.id.ttl < destTTL_) destTTL_ = r.id.ttl;
    }
    // The destination used to answer at this TTL and now a router does instead:
    // the path grew longer. Unlatch so the sweep can find the new position,
    // otherwise a lengthened path would be permanently truncated in the table.
    if (r.outcome == Outcome::TTLExpired && destTTL_ != 0 && r.id.ttl >= destTTL_) {
        destTTL_ = 0;
    }

    if (r.outcome == Outcome::Unreachable) {
        std::ostringstream os;
        os << "hop" << r.id.ttl << " " << r.responder << " unreachable: " << r.note;
        addEvent(r.recvAt, EventKind::Unreachable, r.id.ttl, os.str());
    }
    // A brand-new responder at an already-known TTL is worth logging immediately;
    // the debounced route-change check runs per trace round.
    if (!degraded_ && prevResponders > 0 && h.responders.size() > prevResponders) {
        std::ostringstream os;
        os << "hop" << r.id.ttl << " new responder " << r.responder << " ("
           << h.responders.size() << " seen at this TTL)";
        addEvent(r.recvAt, EventKind::ResponderChange, r.id.ttl, os.str());
    }
    if (h.timeoutStreak == kLossStreak) {
        std::ostringstream os;
        os << "hop" << r.id.ttl << " " << kLossStreak << " consecutive timeouts";
        addEvent(r.recvAt, EventKind::TimeoutStreak, r.id.ttl, os.str());
    }
}

void Engine::applyEnrich(const std::string& ip, const std::string& rdns, const std::string& asn,
                         const std::string& org) {
    if (ip.empty()) return;
    EnrichRec& rec = enrich_[ip];
    if (!rdns.empty()) rec.rdns = rdns;
    if (!asn.empty()) rec.asn = asn;
    if (!org.empty()) rec.org = org;
}

namespace {

bool sameSet(std::vector<std::string> a, std::vector<std::string> b) {
    if (a.size() != b.size()) return false;
    std::sort(a.begin(), a.end());
    std::sort(b.begin(), b.end());
    return a == b;
}

std::string joinOrDash(const std::vector<std::string>& v) {
    if (v.empty()) return "*";
    std::string out = v.front();
    for (std::size_t i = 1; i < v.size(); ++i) {
        out += ",";
        out += v[i];
    }
    return out;
}

}  // namespace

void Engine::endTraceRound(Dur now) {
    const int visible = visibleTTL();
    for (int ttl = 1; ttl <= visible; ++ttl) {
        auto it = hops_.find(ttl);
        if (it == hops_.end()) continue;
        auto cur = it->second.responderSet();

        auto prevIt = lastRoundSet_.find(ttl);
        if (prevIt == lastRoundSet_.end()) {
            lastRoundSet_[ttl] = cur;
            continue;
        }
        if (sameSet(prevIt->second, cur)) {
            changeStreak_[ttl] = 0;
            continue;
        }
        // Temporary silence is not a route change (spec §5.3).
        if (cur.empty()) {
            changeStreak_[ttl] = 0;
            continue;
        }
        if (++changeStreak_[ttl] >= 2) {
            std::ostringstream os;
            os << "route changed @hop" << ttl << " " << joinOrDash(prevIt->second) << " -> "
               << joinOrDash(cur);
            addEvent(now, EventKind::RouteChange, ttl, os.str());
            prevIt->second = cur;
            changeStreak_[ttl] = 0;
        }
    }

    if (lastRoundLen_ != 0 && visible != 0 && visible != lastRoundLen_) {
        std::ostringstream os;
        os << "path length changed " << lastRoundLen_ << " -> " << visible << " hops";
        addEvent(now, EventKind::RouteChange, std::nullopt, os.str());
    }
    if (visible != 0) lastRoundLen_ = visible;

    checkLossOnset(now, visible);

    std::ostringstream os;
    os << "trace round complete (" << visible << " hops)";
    addEvent(now, EventKind::TraceRound, std::nullopt, os.str());
}

namespace {

bool elevated(const std::optional<double>& loss) {
    return loss.has_value() && *loss >= kElevatedLossPct;
}

}  // namespace

// Reports where sustained loss appears to begin.
//
// Forwarding loss is never attributed to the hop that stopped answering: a router
// may simply rate-limit its own ICMP replies while forwarding perfectly. The only
// defensible statement is "loss is elevated from this point onward, including at
// the destination", so that is what gets logged -- and only after it has persisted
// across two trace rounds (spec §5.1).
void Engine::checkLossOnset(Dur now, int visible) {
    int onset = 0;
    if (visible >= 1) {
        auto destIt = hops_.find(visible);
        const bool destElevated = destIt != hops_.end() && elevated(destIt->second.win.lossPct());
        if (destElevated) {
            // Scan down from the destination and stop at the first hop that is NOT
            // elevated; loss appears to begin after it. Because the scan stops
            // there, every hop above it is elevated by construction.
            for (int ttl = visible; ttl >= 1; --ttl) {
                auto it = hops_.find(ttl);
                if (it == hops_.end() || it->second.status == HopStatus::Silent ||
                    it->second.status == HopStatus::TransitOnly) {
                    // A hop that never answers tells us nothing about forwarding
                    // loss, so it neither confirms nor breaks the run.
                    continue;
                }
                if (elevated(it->second.win.lossPct())) continue;
                onset = ttl;
                break;
            }
            // onset == 0 means even the first hop is lossy, which points at the
            // local link rather than at a place on the path, so nothing is claimed.
        }
    }

    if (onset != lossOnsetTTL_) {
        lossOnsetTTL_ = onset;
        // This round counts as the first observation, so the second consecutive
        // round is what trips the report -- "persisted across two rounds".
        lossOnsetStreak_ = 1;
        return;
    }
    if (onset == 0) {
        lossOnsetLogged_ = 0;
        return;
    }
    ++lossOnsetStreak_;
    if (lossOnsetStreak_ >= 2 && lossOnsetLogged_ != onset) {
        lossOnsetLogged_ = onset;
        std::ostringstream os;
        os << "possible loss beginning after hop " << onset
           << " (elevated through the destination)";
        addEvent(now, EventKind::TimeoutStreak, onset, os.str());
    }
}

void Engine::reprobe(Dur now) {
    ++generation_;
    hops_.clear();
    maxTTL_ = 0;
    destTTL_ = 0;
    lastRoundSet_.clear();
    changeStreak_.clear();
    lastRoundLen_ = 0;
    addEvent(now, EventKind::TraceRound, std::nullopt, "re-probe requested, statistics reset");
}

void Engine::setTarget(Target t, Dur now) {
    target_ = std::move(t);
    addEvent(now, EventKind::TargetChange, std::nullopt,
             "target changed to " + target_.input + " (" + target_.ip + ")");
    reprobe(now);
}

void Engine::togglePause(Dur now) {
    paused_ = !paused_;
    if (paused_) {
        addEvent(now, EventKind::Paused, std::nullopt, "paused");
    } else {
        addEvent(now, EventKind::Resumed, std::nullopt, "resumed");
    }
}

int Engine::visibleTTL() const { return destTTL_ > 0 ? destTTL_ : maxTTL_; }

RttStats Engine::statsFor(const HopState& h, const std::string& responder) const {
    RttStats st = h.win.statsFor(responder);
    if (degraded_) {
        // The command backend cannot support these honestly (spec §6.4).
        st.jitterMs.reset();
        st.stdevMs.reset();
    }
    return st;
}

std::shared_ptr<const Snapshot> Engine::snapshot(Dur now) {
    ++revision_;

    const int visible = visibleTTL();

    // Walk TTLs from the far end so "does any greater TTL answer?" is a running
    // flag rather than a nested scan (spec §5.1 TRANSIT_ONLY).
    std::vector<char> anyGreater(static_cast<std::size_t>(visible) + 2, 0);
    for (int ttl = visible; ttl >= 1; --ttl) {
        bool greater = anyGreater[static_cast<std::size_t>(ttl) + 1] != 0;
        auto it = hops_.find(ttl + 1);
        if (it != hops_.end() && it->second.everReplied) greater = true;
        anyGreater[static_cast<std::size_t>(ttl)] = greater ? 1 : 0;
    }

    auto snap = std::make_shared<Snapshot>();
    snap->revision = revision_;
    snap->generation = generation_;
    snap->target = target_;
    snap->now = now;
    snap->mode = mode_;
    snap->degraded = degraded_;
    snap->paused = paused_;
    snap->local = local_;
    snap->health = health_;
    snap->cadence = cadence_;

    snap->hops.reserve(static_cast<std::size_t>(std::max(visible, 0)));
    for (int ttl = 1; ttl <= visible; ++ttl) {
        auto it = hops_.find(ttl);
        if (it == hops_.end()) {
            // Keep the list gap-free so both implementations render the same rows.
            HopPosition hp;
            hp.ttl = ttl;
            hp.status = HopStatus::Unknown;
            snap->hops.push_back(std::move(hp));
            continue;
        }
        HopState& h = it->second;
        h.win.prune(now);
        h.status = classify(h, anyGreater[static_cast<std::size_t>(ttl)] != 0, degraded_);

        const std::string primary = h.primary();

        HopPosition hp;
        hp.ttl = ttl;
        hp.status = h.status;
        hp.sent = h.sent;
        hp.replied = h.replied;
        hp.lossPct = h.win.lossPct();
        hp.primary = primary;
        hp.isDestination = h.isDestination;
        hp.stats = statsFor(h, primary);

        // Responders ordered by observation count, then IP, so the table is stable
        // and identical across implementations.
        std::vector<const RespState*> ordered;
        ordered.reserve(h.responders.size());
        for (const auto& kv : h.responders) ordered.push_back(&kv.second);
        std::sort(ordered.begin(), ordered.end(), [](const RespState* a, const RespState* b) {
            if (a->seen != b->seen) return a->seen > b->seen;
            return a->ip < b->ip;
        });
        // The command backend runs one sweep at a time and cannot distinguish a
        // genuine ECMP split from consecutive sweeps taking different paths, so it
        // reports only the primary responder (spec §6.4, agy QA finding).
        if (degraded_ && ordered.size() > 1) ordered.resize(1);

        for (const RespState* rs : ordered) {
            Responder r;
            r.ip = rs->ip;
            auto en = enrich_.find(rs->ip);
            if (en != enrich_.end()) {
                r.rdns = en->second.rdns;
                r.asn = en->second.asn;
                r.org = en->second.org;
            }
            r.seen = rs->seen;
            r.firstSeenAt = rs->firstSeenAt;
            r.lastSeenAt = rs->lastSeenAt;
            r.stats = statsFor(h, rs->ip);
            hp.responders.push_back(std::move(r));
        }
        snap->hops.push_back(std::move(hp));
    }

    // Events newest first for display.
    snap->events.reserve(events_.size());
    for (auto it = events_.rbegin(); it != events_.rend(); ++it) snap->events.push_back(*it);

    return snap;
}

}  // namespace netscope
