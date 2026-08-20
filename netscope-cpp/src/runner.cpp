#include "runner.h"

#include <algorithm>
#include <map>

#include "health.h"
#include "sysinfo.h"

namespace netscope {
namespace {

// Dilutes the intermediate-hop interval when the hop count would push the global
// packet rate over the cap. The destination keeps priority (spec §4.4).
void effectiveCadence(int destTTL, int maxTTL, Dur& dest, Dur& mid) {
    const Cadence c = defaultCadence();
    dest = std::chrono::milliseconds(c.destIntervalMs);
    mid = std::chrono::milliseconds(c.midIntervalMs);

    const int n = destTTL > 0 ? destTTL : maxTTL;
    if (n <= 1) return;

    const double destSeconds = std::chrono::duration<double>(dest).count();
    const double midSeconds = std::chrono::duration<double>(mid).count();
    const double destPps = 1.0 / destSeconds;
    const double budget = static_cast<double>(c.globalCapPps) - destPps;
    if (budget <= 0) return;

    const double needed = static_cast<double>(n - 1) / midSeconds;
    if (needed <= budget) return;

    mid = std::chrono::duration_cast<Dur>(
        std::chrono::duration<double>(static_cast<double>(n - 1) / budget));
}

void destAndMax(const Snapshot& s, int& destTTL, int& maxTTL) {
    destTTL = 0;
    maxTTL = 0;
    for (const auto& h : s.hops) {
        maxTTL = std::max(maxTTL, h.ttl);
        if (h.isDestination && destTTL == 0) destTTL = h.ttl;
    }
}

}  // namespace

Runner::Runner(Target target, std::unique_ptr<Backend> backend, Options opts,
               const std::string& backendNote)
    : engine_(std::move(target), backend->mode()), backend_(std::move(backend)), opts_(opts) {
    const Target& t = engine_.target();
    engine_.addEvent(Dur::zero(), EventKind::Start, std::nullopt,
                     "start probing " + t.input + " (" + t.ip + ")");
    engine_.addEvent(Dur::zero(), EventKind::Resolved, std::nullopt,
                     "resolved " + t.input + " -> " + t.ip);
    if (!backendNote.empty()) {
        engine_.addEvent(Dur::zero(),
                         engine_.mode() == ProbeMode::Command ? EventKind::DegradedMode
                                                             : EventKind::Start,
                         std::nullopt, backendNote);
    }
    // latest_ starts null; the engine loop publishes the first snapshot.
    setTargetRefs(t);
}

Runner::~Runner() { shutdown(); }

std::shared_ptr<Backend> Runner::currentBackend() const {
    std::lock_guard<std::mutex> lk(backendMu_);
    return backend_;
}

// Swaps in a backend for a new destination and closes the old one. Results still in
// flight for the old destination carry the previous generation and are discarded by
// Engine::ingest.
void Runner::rebindBackend(const Target& t, Dur now) {
    auto choice = selectBackend(t.ip, t.family, opts_.forceCommand);
    if (!choice.backend) {
        engine_.addEvent(now, EventKind::Error, std::nullopt,
                         "no usable probe backend for " + t.ip);
        return;
    }
    std::shared_ptr<Backend> next(choice.backend.release());

    std::shared_ptr<Backend> old;
    {
        std::lock_guard<std::mutex> lk(backendMu_);
        old = backend_;
        backend_ = next;
    }
    if (old) old->close();

    engine_.setMode(next->mode(), now);
    engine_.addEvent(now, EventKind::Start, std::nullopt, "probe backend rebound: " + choice.note);
}

void Runner::setTargetRefs(const Target& t) {
    std::lock_guard<std::mutex> lk(targetMu_);
    targetIp_ = t.ip;
    targetInput_ = t.input;
}

void Runner::currentTarget(std::string& ip, std::string& input) const {
    std::lock_guard<std::mutex> lk(targetMu_);
    ip = targetIp_;
    input = targetInput_;
}

void Runner::setWakeup(std::function<void()> fn) {
    std::lock_guard<std::mutex> lk(wakeupMu_);
    wakeup_ = std::move(fn);
}

void Runner::disableWakeup() {
    std::lock_guard<std::mutex> lk(wakeupMu_);
    wakeup_ = nullptr;
}

void Runner::send(Command c) {
    if (!acceptCommands_.load()) return;
    commands_.push(std::move(c));
}

std::shared_ptr<const Snapshot> Runner::latest() const {
    std::lock_guard<std::mutex> lk(latestMu_);
    return latest_;
}

Records Runner::records() const {
    std::lock_guard<std::mutex> lk(recordsMu_);
    return records_;
}

double Runner::jitterFactor() {
    // xorshift* rather than <random>: no global state, deterministic per instance,
    // and the quality demanded of a +/-20% schedule jitter is nil (spec §4.4).
    std::lock_guard<std::mutex> lk(rngMu_);
    rngState_ ^= rngState_ >> 12;
    rngState_ ^= rngState_ << 25;
    rngState_ ^= rngState_ >> 27;
    const std::uint64_t v = rngState_ * 0x2545F4914F6CDD1DULL;
    const double unit = static_cast<double>(v >> 11) / static_cast<double>(1ULL << 53);
    return 0.8 + 0.4 * unit;
}

void Runner::start() {
    auto token = stopSource_.get_token();

    threads_.emplace_back([this, token] { engineLoop(token); });

    if (currentBackend()->supportsPerTTL()) {
        threads_.emplace_back([this, token] { schedulerLoop(token); });
        for (int i = 0; i < kProbeWorkers; ++i) {
            threads_.emplace_back([this, token] { probeWorkerLoop(token); });
        }
    } else {
        threads_.emplace_back([this, token] { sweepSchedulerLoop(token); });
    }

    threads_.emplace_back([this, token] { enrichLoop(token); });
    threads_.emplace_back([this, token] { auxLoop(token); });
}

void Runner::shutdown() {
    bool expected = false;
    if (!shutdownDone_.compare_exchange_strong(expected, true)) return;

    // 1. stop accepting UI commands
    acceptCommands_.store(false);

    // 2. request worker stop
    stopSource_.request_stop();

    // 3. close sockets, handles and child processes. A stop request alone does not
    //    interrupt a blocking recv or a running tracert.
    if (auto b = currentBackend()) b->close();

    // 4. wake every queue so bounded waits return immediately
    results_.stop();
    commands_.stop();
    enriched_.stop();
    healths_.stop();
    locals_.stop();
    recordsQueue_.stop();
    probeRequests_.stop();

    // 5. close the UI wake-up gate before the screen can be destroyed
    disableWakeup();

    // 6. join. Every worker wait is bounded, so this terminates; the grace period
    //    from spec §3.3 is enforced by those bounds rather than by a join timeout.
    for (auto& t : threads_) {
        if (t.joinable()) t.join();
    }
    threads_.clear();

    // 7. engine state is released with this object
}

void Runner::publish(std::shared_ptr<const Snapshot> snap) {
    {
        std::lock_guard<std::mutex> lk(latestMu_);
        latest_ = snap;
    }
    std::lock_guard<std::mutex> lk(wakeupMu_);
    if (wakeup_) wakeup_();
}

std::shared_ptr<const Snapshot> Runner::buildSnapshot() {
    Dur dest{};
    Dur mid{};
    effectiveCadence(engine_.destTTL(), engine_.maxTTL(), dest, mid);
    engine_.setCadence(
        static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(dest).count()),
        static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(mid).count()));
    return engine_.snapshot(elapsedSinceStart());
}

void Runner::engineLoop(std::stop_token stop) {
    publish(buildSnapshot());

    auto nextSnapshot = std::chrono::steady_clock::now() + kSnapshotInterval;
    auto nextTraceRound = std::chrono::steady_clock::now() + kTraceRoundMinGap;

    while (!stop.stop_requested()) {
        // Drain whatever is ready, with a short bounded wait so the loop stays
        // responsive to stop requests.
        ProbeResult res;
        while (results_.popFor(res, std::chrono::milliseconds(5))) {
            engine_.ingest(res);
            if (stop.stop_requested()) break;
        }

        EnrichResult en;
        while (enriched_.popFor(en, std::chrono::milliseconds(0))) {
            engine_.applyEnrich(en.ip, en.rdns, en.asn, en.org);
        }

        Health h;
        while (healths_.popFor(h, std::chrono::milliseconds(0))) engine_.setHealth(h);

        LocalInfo l;
        while (locals_.popFor(l, std::chrono::milliseconds(0))) engine_.setLocal(l);

        Records rec;
        while (recordsQueue_.popFor(rec, std::chrono::milliseconds(0))) {
            engine_.setRecords(rec);
            std::lock_guard<std::mutex> lk(recordsMu_);
            records_ = rec;
        }

        Command cmd;
        while (commands_.popFor(cmd, std::chrono::milliseconds(0))) {
            if (apply(cmd)) return;
        }

        const auto nowWall = std::chrono::steady_clock::now();
        if (nowWall >= nextTraceRound) {
            engine_.endTraceRound(elapsedSinceStart());
            nextTraceRound = nowWall + kTraceRoundMinGap;
        }
        if (nowWall >= nextSnapshot) {
            publish(buildSnapshot());
            nextSnapshot = nowWall + kSnapshotInterval;
        }
    }
}

bool Runner::apply(const Command& c) {
    const Dur now = elapsedSinceStart();
    switch (c.kind) {
        case CommandKind::Quit:
            quit_.store(true);
            return true;

        case CommandKind::TogglePause:
            engine_.togglePause(now);
            break;

        case CommandKind::Reprobe:
            engine_.reprobe(now);
            break;

        case CommandKind::SelectHop:
            selected_.store(c.ttl);
            break;

        case CommandKind::SetTarget: {
            Target t;
            std::string err;
            if (!resolveTarget(c.target, t, err)) {
                engine_.addEvent(now, EventKind::Error, std::nullopt,
                                 "cannot resolve " + c.target + ": " + err);
                break;
            }
            t.resolvedAt = now;
            // Order matters: bump the generation first so results still in flight
            // for the old destination are discarded, then rebind the backend.
            engine_.setTarget(t, now);
            setTargetRefs(t);
            rebindBackend(t, now);
            break;
        }

        case CommandKind::RefreshDNS:
            if (!c.selectedIp.empty()) {
                cache_.invalidate(c.selectedIp, true, false);
                engine_.addEvent(now, EventKind::Enrich, c.ttl,
                                 "rDNS refresh queued for " + c.selectedIp);
            }
            break;

        case CommandKind::RefreshASN:
            if (!c.selectedIp.empty()) {
                cache_.invalidate(c.selectedIp, false, true);
                engine_.addEvent(now, EventKind::Enrich, c.ttl,
                                 "ASN refresh queued for " + c.selectedIp);
            }
            break;
    }
    publish(buildSnapshot());
    return false;
}

int Runner::pickTTL(const Snapshot& snap, int destTTL, int maxTTL, Dur now, Dur destInterval,
                    Dur midInterval) {
    (void)snap;
    (void)destInterval;
    (void)midInterval;

    std::lock_guard<std::mutex> lk(sched_.mu);

    int countOutstanding = 0;
    for (const auto& kv : sched_.outstanding) {
        if (kv.second != 0) ++countOutstanding;
    }

    // Sweep phase: extend the path while the destination is unknown.
    if (destTTL == 0 && maxTTL < kMaxHops && countOutstanding < kSweepConcurrency) {
        for (int ttl = 1; ttl <= kMaxHops; ++ttl) {
            if (sched_.nextDue.count(ttl) != 0) continue;
            auto it = sched_.outstanding.find(ttl);
            if (it != sched_.outstanding.end() && it->second != 0) continue;
            return ttl;
        }
    }

    // Steady state: one outstanding probe per TTL (spec §4.4).
    int last = destTTL > 0 ? destTTL : maxTTL;
    if (last == 0) last = 1;

    int best = 0;
    Dur bestOverdue = Dur::min();
    for (int ttl = 1; ttl <= last; ++ttl) {
        auto out = sched_.outstanding.find(ttl);
        if (out != sched_.outstanding.end() && out->second != 0) continue;
        auto due = sched_.nextDue.find(ttl);
        if (due == sched_.nextDue.end()) return ttl;
        if (now < due->second) continue;
        const Dur over = now - due->second;
        if (over > bestOverdue) {
            best = ttl;
            bestOverdue = over;
        }
    }
    return best;
}

void Runner::schedulerLoop(std::stop_token stop) {
    const Dur minGap = std::chrono::duration_cast<Dur>(
        std::chrono::seconds(1) / defaultCadence().globalCapPps);

    while (!stop.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        if (stop.stop_requested()) return;

        auto snap = latest();
        if (!snap || snap->paused) continue;

        {
            std::lock_guard<std::mutex> lk(sched_.mu);
            if (snap->generation != sched_.generation) {
                // New generation: forget the old schedule entirely.
                sched_.outstanding.clear();
                sched_.nextDue.clear();
                sched_.generation = snap->generation;
            }
        }

        const Dur now = elapsedSinceStart();
        {
            std::lock_guard<std::mutex> lk(sched_.mu);
            if (now - sched_.lastSend < minGap) continue;
        }

        int destTTL = 0;
        int maxTTL = 0;
        destAndMax(*snap, destTTL, maxTTL);

        Dur dest{};
        Dur mid{};
        effectiveCadence(destTTL, maxTTL, dest, mid);

        const int ttl = pickTTL(*snap, destTTL, maxTTL, now, dest, mid);
        if (ttl == 0) continue;

        ProbeID id;
        {
            std::lock_guard<std::mutex> lk(sched_.mu);
            sched_.outstanding[ttl] = snap->generation;
            sched_.lastSend = now;
            id.generation = snap->generation;
            id.family = snap->target.family;
            id.ttl = ttl;
            id.attempt = ++sched_.attempt;

            const Dur interval = (destTTL != 0 && ttl >= destTTL) ? dest : mid;
            const Dur jittered = std::chrono::duration_cast<Dur>(
                std::chrono::duration<double, std::nano>(
                    static_cast<double>(interval.count()) * jitterFactor()));
            sched_.nextDue[ttl] = now + jittered;
        }
        probeRequests_.push(id);
    }
}

void Runner::probeWorkerLoop(std::stop_token stop) {
    while (!stop.stop_requested()) {
        ProbeID id;
        if (!probeRequests_.popFor(id, std::chrono::milliseconds(50))) continue;

        ProbeResult res = currentBackend()->probe(id, stop);

        {
            // Only release the slot if it still belongs to this probe's generation.
            std::lock_guard<std::mutex> lk(sched_.mu);
            auto it = sched_.outstanding.find(id.ttl);
            if (it != sched_.outstanding.end() && it->second == id.generation) {
                it->second = 0;
            }
        }
        results_.push(std::move(res));
    }
}

void Runner::sweepSchedulerLoop(std::stop_token stop) {
    auto runSweep = [&] {
        auto snap = latest();
        // Pause must stop sweeps too, not only the destination ping: a sweep is by
        // far the larger share of the traffic (codex MEDIUM finding).
        if (!snap || snap->paused) return;
        for (auto& res : currentBackend()->traceRound(snap->generation, kMaxHops, stop)) {
            if (stop.stop_requested()) return;
            results_.push(std::move(res));
        }
    };

    runSweep();

    auto nextSweep = std::chrono::steady_clock::now() + kTraceRoundMinGap;
    auto nextPing = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(defaultCadence().destIntervalMs);
    std::uint64_t attempt = 0;

    while (!stop.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (stop.stop_requested()) return;

        const auto nowWall = std::chrono::steady_clock::now();
        if (nowWall >= nextSweep) {
            runSweep();
            nextSweep = std::chrono::steady_clock::now() + kTraceRoundMinGap;
        }
        if (nowWall >= nextPing) {
            nextPing = nowWall + std::chrono::milliseconds(defaultCadence().destIntervalMs);
            auto snap = latest();
            if (!snap || snap->paused) continue;
            int destTTL = 0;
            int maxTTL = 0;
            destAndMax(*snap, destTTL, maxTTL);
            if (destTTL == 0) continue;

            ProbeID id;
            id.generation = snap->generation;
            id.family = snap->target.family;
            id.ttl = destTTL;
            id.attempt = ++attempt;
            results_.push(currentBackend()->probe(id, stop));
        }
    }
}

void Runner::enrichLoop(std::stop_token stop) {
    auto nextDebounce = std::chrono::steady_clock::now() + kEnrichDebounce;
    auto nextBackground = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    int lastSelected = -1;
    std::map<std::string, bool> done;

    auto lookup = [&](const std::string& ip) {
        if (ip.empty() || stop.stop_requested()) return;
        enriched_.push(cache_.lookup(ip));
    };

    while (!stop.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        if (stop.stop_requested()) return;

        const auto nowWall = std::chrono::steady_clock::now();

        if (nowWall >= nextDebounce) {
            nextDebounce = nowWall + kEnrichDebounce;
            const int sel = selected_.load();
            if (sel != lastSelected) {
                lastSelected = sel;
                if (auto snap = latest()) {
                    for (const auto& h : snap->hops) {
                        if (h.ttl == sel) lookup(h.primary);
                    }
                }
            }
        }

        if (nowWall >= nextBackground) {
            nextBackground = nowWall + std::chrono::seconds(2);
            if (auto snap = latest()) {
                for (const auto& h : snap->hops) {
                    if (h.responders.empty()) continue;
                    const std::string& ip = h.responders.front().ip;
                    if (ip.empty() || done[ip]) continue;
                    done[ip] = true;
                    lookup(ip);
                    break;  // one lookup per tick keeps the resolver load gentle
                }
            }
        }
    }
}

void Runner::auxLoop(std::stop_token stop) {
    auto refreshLocal = [&] {
        std::string ip;
        std::string input;
        currentTarget(ip, input);
        locals_.push(gatherSysinfo(ip, opts_.wantPublicIp));
    };
    auto refreshRecords = [&] {
        std::string ip;
        std::string input;
        currentTarget(ip, input);
        if (input.empty()) return;
        recordsQueue_.push(cache_.lookupRecords(input));
    };
    auto refreshHealth = [&] {
        std::string ip;
        std::string input;
        currentTarget(ip, input);
        if (ip.empty()) return;
        healths_.push(checkHealth(input, ip, opts_.port, elapsedSinceStart()));
    };

    refreshLocal();
    if (stop.stop_requested()) return;
    refreshRecords();
    if (stop.stop_requested()) return;
    refreshHealth();

    auto nextLocal = std::chrono::steady_clock::now() + kLocalInfoInterval;
    auto nextHealth = std::chrono::steady_clock::now() + kHealthInterval;

    while (!stop.stop_requested()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (stop.stop_requested()) return;

        const auto nowWall = std::chrono::steady_clock::now();
        if (nowWall >= nextLocal) {
            nextLocal = nowWall + kLocalInfoInterval;
            refreshLocal();
            if (stop.stop_requested()) return;
            refreshRecords();
        }
        if (nowWall >= nextHealth) {
            nextHealth = nowWall + kHealthInterval;
            refreshHealth();
        }
    }
}

}  // namespace netscope
