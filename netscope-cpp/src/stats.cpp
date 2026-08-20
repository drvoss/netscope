#include "stats.h"

#include <algorithm>
#include <cmath>
#include <map>

namespace netscope {

void Window::add(const Sample& s) {
    if (samples_.empty() || samples_.back().sentAt <= s.sentAt) {
        samples_.push_back(s);
    } else {
        auto it = std::upper_bound(samples_.begin(), samples_.end(), s.sentAt,
                                   [](Dur value, const Sample& e) { return value < e.sentAt; });
        samples_.insert(it, s);
    }
    if (samples_.size() > static_cast<std::size_t>(kWindowMaxSamples)) {
        samples_.erase(samples_.begin(),
                       samples_.begin() +
                           static_cast<std::ptrdiff_t>(samples_.size() - kWindowMaxSamples));
    }
}

void Window::prune(Dur now) {
    const Dur cut = now - kWindowDuration;
    auto it = samples_.begin();
    while (it != samples_.end() && it->sentAt <= cut) ++it;
    samples_.erase(samples_.begin(), it);
}

std::optional<double> Window::lossPct() const {
    if (samples_.empty()) return std::nullopt;
    std::size_t lost = 0;
    for (const auto& s : samples_) {
        if (!s.ok) ++lost;
    }
    return 100.0 * static_cast<double>(lost) / static_cast<double>(samples_.size());
}

std::vector<std::string> Window::responders() const {
    std::map<std::string, int> counts;
    for (const auto& s : samples_) {
        if (s.ok && !s.responder.empty()) ++counts[s.responder];
    }
    std::vector<std::string> out;
    out.reserve(counts.size());
    for (const auto& kv : counts) out.push_back(kv.first);
    std::sort(out.begin(), out.end(), [&](const std::string& a, const std::string& b) {
        if (counts.at(a) != counts.at(b)) return counts.at(a) > counts.at(b);
        return a < b;
    });
    return out;
}

RttStats Window::statsFor(const std::string& responder) const {
    RttStats st;
    if (responder.empty()) return st;

    std::vector<double> rtts;
    std::vector<double> diffs;
    rtts.reserve(samples_.size());

    for (std::size_t i = 0; i < samples_.size(); ++i) {
        const Sample& s = samples_[i];
        if (!s.ok || s.responder != responder) continue;
        const double v = toMs(s.rtt);
        rtts.push_back(v);
        if (i > 0) {
            const Sample& p = samples_[i - 1];
            // Adjacency in the bucket: a timeout OR a different responder between
            // two samples breaks the pair, so loss is never double-counted as
            // jitter and two routers' RTTs are never differenced (spec §4.3).
            if (p.ok && p.responder == responder) {
                diffs.push_back(std::fabs(v - toMs(p.rtt)));
            }
        }
    }

    st.samples = static_cast<int>(rtts.size());
    if (rtts.empty()) return st;

    double best = rtts.front();
    double worst = rtts.front();
    double sum = 0;
    for (double v : rtts) {
        best = std::min(best, v);
        worst = std::max(worst, v);
        sum += v;
    }
    const double avg = sum / static_cast<double>(rtts.size());

    st.lastMs = rtts.back();
    st.bestMs = best;
    st.worstMs = worst;
    st.avgMs = avg;

    // Jitter needs at least two successive-difference pairs (spec §4.3).
    if (diffs.size() >= 2) {
        double d = 0;
        for (double v : diffs) d += v;
        st.jitterMs = d / static_cast<double>(diffs.size());
    }

    // Sample standard deviation, n-1. Reported alongside jitter because the
    // cross-review disagreed on which is the right metric (R1-3).
    if (rtts.size() >= 2) {
        double ss = 0;
        for (double v : rtts) ss += (v - avg) * (v - avg);
        st.stdevMs = std::sqrt(ss / static_cast<double>(rtts.size() - 1));
    }

    if (rtts.size() > static_cast<std::size_t>(kSparkMax)) {
        st.spark.assign(rtts.end() - kSparkMax, rtts.end());
    } else {
        st.spark = rtts;
    }
    return st;
}

}  // namespace netscope
