// The live engine: the single-writer loop plus the worker threads that feed it
// (spec §3.1).
//
// Teardown is the highest-risk area in this program -- all three cross-review
// tools said so independently -- so the shutdown order in spec §3.3 is implemented
// literally in shutdown(), and every worker wait is bounded so joining cannot
// hang.
#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "engine.h"
#include "model.h"
#include "probe.h"
#include "resolve.h"

namespace netscope {

// Scheduling constants (spec §4.4).
inline constexpr int kMaxHops = 30;
inline constexpr int kSweepConcurrency = 4;
inline constexpr auto kTraceRoundMinGap = std::chrono::seconds(30);
inline constexpr auto kSnapshotInterval = std::chrono::milliseconds(100);  // 10 Hz (spec §3.2)
inline constexpr auto kEnrichDebounce = std::chrono::milliseconds(300);    // spec §7
inline constexpr auto kHealthInterval = std::chrono::seconds(15);
inline constexpr auto kLocalInfoInterval = std::chrono::seconds(60);
inline constexpr int kProbeWorkers = 6;

struct Options {
    int port = 443;
    bool wantPublicIp = true;
    // Keeps the degraded backend selected across a target change too, so
    // --force-command survives pressing "/".
    bool forceCommand = false;
};

// A bounded-wait queue. Every pop has a deadline so a stop request always takes
// effect promptly and join() cannot block indefinitely (spec §3.3 step 4).
template <typename T>
class Queue {
public:
    void push(T value) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (stopped_) return;
            items_.push_back(std::move(value));
        }
        cv_.notify_one();
    }

    bool popFor(T& out, std::chrono::milliseconds wait) {
        std::unique_lock<std::mutex> lk(mu_);
        if (!cv_.wait_for(lk, wait, [this] { return !items_.empty() || stopped_; })) return false;
        if (items_.empty()) return false;
        out = std::move(items_.front());
        items_.pop_front();
        return true;
    }

    void stop() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            stopped_ = true;
            items_.clear();
        }
        cv_.notify_all();
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<T> items_;
    bool stopped_ = false;
};

class Runner {
public:
    Runner(Target target, std::unique_ptr<Backend> backend, Options opts,
           const std::string& backendNote);
    ~Runner();

    Runner(const Runner&) = delete;
    Runner& operator=(const Runner&) = delete;

    void start();

    // Ordered teardown per spec §3.3. Idempotent.
    void shutdown();

    // Hands a command to the engine loop. Never blocks.
    void send(Command c);

    // The newest published snapshot. Lock-free pointer read; the UI only ever
    // reads snapshots, never engine state (spec §3.1).
    std::shared_ptr<const Snapshot> latest() const;

    Records records() const;

    bool quitRequested() const { return quit_.load(); }

    // Installs the UI wake-up callback. It is invoked from the engine thread and
    // is cleared before the screen is destroyed, so a post can never reach a dead
    // ScreenInteractive (spec §3.3 step 5).
    void setWakeup(std::function<void()> fn);
    void disableWakeup();

private:
    struct SchedState {
        std::mutex mu;
        // Maps a TTL to the GENERATION of the probe in flight on it, or 0 when
        // free. Storing the generation rather than a bare bool stops a completion
        // from a previous generation clearing the slot of a new one, which would let
        // the scheduler issue a second probe on a TTL that already had one in
        // flight (codex HIGH finding).
        std::map<int, std::uint64_t> outstanding;
        std::map<int, Dur> nextDue;
        std::uint64_t generation = 0;
        std::uint64_t attempt = 0;
        Dur lastSend{};
    };

    void engineLoop(std::stop_token stop);
    void schedulerLoop(std::stop_token stop);
    void sweepSchedulerLoop(std::stop_token stop);
    void probeWorkerLoop(std::stop_token stop);
    void enrichLoop(std::stop_token stop);
    void auxLoop(std::stop_token stop);

    bool apply(const Command& c);
    void setTargetRefs(const Target& t);
    void currentTarget(std::string& ip, std::string& input) const;
    std::shared_ptr<Backend> currentBackend() const;
    void rebindBackend(const Target& t, Dur now);
    void publish(std::shared_ptr<const Snapshot> snap);
    std::shared_ptr<const Snapshot> buildSnapshot();
    int pickTTL(const Snapshot& snap, int destTTL, int maxTTL, Dur now, Dur destInterval,
                Dur midInterval);
    double jitterFactor();

    Engine engine_;

    // A shared_ptr, and replaced when the target changes. A backend is bound to one
    // destination address at construction, so reusing it after a target change would
    // keep measuring the OLD address while labelling the results with the new target
    // -- silently wrong output rather than an error (codex CRITICAL finding). Shared
    // ownership keeps a backend alive while a probe is still inside it.
    mutable std::mutex backendMu_;
    std::shared_ptr<Backend> backend_;

    Options opts_;
    EnrichCache cache_;

    Queue<ProbeResult> results_;
    Queue<Command> commands_;
    Queue<EnrichResult> enriched_;
    Queue<Health> healths_;
    Queue<LocalInfo> locals_;
    Queue<Records> recordsQueue_;
    Queue<ProbeID> probeRequests_;

    // A mutex-guarded shared_ptr, NOT std::atomic<std::shared_ptr<...>>.
    //
    // The C++20 atomic<shared_ptr> specialization is implemented by MSVC's STL and
    // by libstdc++ 12+, but NOT by libc++ -- there it falls through to the primary
    // template and fails a static_assert about trivial copyability, so the whole
    // program stops compiling on any libc++-based Linux or macOS. Caught by the
    // Keep this branch warning-clean in the Linux CI build.
    //
    // The mutex costs nothing here: the critical section is a pointer copy, and the
    // publish rate is 10 Hz.
    mutable std::mutex latestMu_;
    std::shared_ptr<const Snapshot> latest_;
    std::atomic<int> selected_{1};
    std::atomic<bool> quit_{false};
    std::atomic<bool> acceptCommands_{true};

    mutable std::mutex recordsMu_;
    Records records_;

    // The target is kept here as well as in the engine so the aux and enrich
    // workers never have to wait for the first snapshot to be published. Reading it
    // from the snapshot raced at startup: whether the LOCAL IF panel was populated
    // depended on thread start order.
    mutable std::mutex targetMu_;
    std::string targetIp_;
    std::string targetInput_;

    std::mutex wakeupMu_;
    std::function<void()> wakeup_;

    SchedState sched_;

    std::stop_source stopSource_;
    std::vector<std::thread> threads_;
    std::atomic<bool> shutdownDone_{false};

    std::mutex rngMu_;
    std::uint64_t rngState_ = 0x9e3779b97f4a7c15ULL;
};

}  // namespace netscope
