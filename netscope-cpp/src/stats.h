// Moving window and derived RTT statistics.
//
// Every rule here is a cross-language contract from docs/netscope-spec.md §4 and
// must match the Go implementation's internal/stats/window.go exactly.
#pragma once

#include <string>
#include <vector>

#include "model.h"

namespace netscope {

// Contract constants (spec §4.1). Do not change one implementation only.
inline constexpr Dur kWindowDuration = std::chrono::seconds(120);
inline constexpr int kWindowMaxSamples = 120;
inline constexpr Dur kProbeTimeout = std::chrono::milliseconds(1500);
inline constexpr int kSparkMax = 120;

// One probe outcome recorded against a TTL bucket.
//
// There is exactly ONE window per TTL, with each sample tagged by the responder
// that answered it. That is what lets jitter pairing break both on a timeout and
// on an ECMP responder switch without keeping several parallel windows in sync
// (spec §4.3, §5.3).
struct Sample {
    Dur sentAt{};
    Dur rtt{};
    bool ok = false;  // false == Timeout; only timeouts count as loss (spec §4.2)
    std::string responder;
};

// A time-based moving window with a hard sample cap.
//
// Time-based, not count-based: cadence differs per TTL, so a fixed sample count
// would represent a different amount of wall time at each hop (spec §4.1).
class Window {
public:
    // Records a sample. Samples are expected in non-decreasing sentAt order;
    // out-of-order arrivals are inserted so the adjacency-sensitive jitter
    // computation still reflects real send order.
    void add(const Sample& s);

    // Drops samples that fell out of the time window.
    void prune(Dur now);

    // Clears the window.
    void reset() { samples_.clear(); }

    std::size_t size() const { return samples_.size(); }
    const std::vector<Sample>& samples() const { return samples_; }

    // Bucket loss rate: timeouts over probes sent inside the window. Returns
    // nullopt when nothing was sent, which the UI shows as "---" rather than 0%
    // (spec §4.2, §8.3).
    std::optional<double> lossPct() const;

    // Distinct responders seen, ordered by descending observation count then
    // ascending IP so both implementations agree.
    std::vector<std::string> responders() const;

    // Derives the summary for one responder (spec §4.3).
    RttStats statsFor(const std::string& responder) const;

private:
    std::vector<Sample> samples_;
};

}  // namespace netscope
