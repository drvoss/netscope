#include "ui.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

namespace netscope {
namespace {

using namespace ftxui;

// ---------------------------------------------------------------- text helpers

// Display width, UTF-8 aware enough for our content: ASCII plus the box-drawing
// and block characters we emit, plus CJK when an rDNS name contains it.
int displayWidth(const std::string& s) {
    int w = 0;
    for (std::size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        std::size_t len = 1;
        unsigned int cp = c;
        if ((c & 0x80) == 0) {
            len = 1;
            cp = c;
        } else if ((c & 0xE0) == 0xC0) {
            len = 2;
            cp = c & 0x1Fu;
        } else if ((c & 0xF0) == 0xE0) {
            len = 3;
            cp = c & 0x0Fu;
        } else if ((c & 0xF8) == 0xF0) {
            len = 4;
            cp = c & 0x07u;
        }
        for (std::size_t k = 1; k < len && i + k < s.size(); ++k) {
            cp = (cp << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3Fu);
        }
        // Wide ranges: CJK, Hangul, fullwidth forms.
        const bool wide = (cp >= 0x1100 && cp <= 0x115F) || (cp >= 0x2E80 && cp <= 0xA4CF) ||
                          (cp >= 0xAC00 && cp <= 0xD7A3) || (cp >= 0xF900 && cp <= 0xFAFF) ||
                          (cp >= 0xFF00 && cp <= 0xFF60) || (cp >= 0xFFE0 && cp <= 0xFFE6);
        w += wide ? 2 : 1;
        i += len;
    }
    return w;
}

std::string truncateTo(const std::string& s, int width) {
    if (width <= 0) return "";
    if (displayWidth(s) <= width) return s;
    std::string out;
    int w = 0;
    for (std::size_t i = 0; i < s.size();) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        std::size_t len = 1;
        if ((c & 0xE0) == 0xC0) len = 2;
        else if ((c & 0xF0) == 0xE0) len = 3;
        else if ((c & 0xF8) == 0xF0) len = 4;
        const std::string ch = s.substr(i, len);
        const int cw = displayWidth(ch);
        if (w + cw > width - 1) break;
        out += ch;
        w += cw;
        i += len;
    }
    out += "\xE2\x80\xA6";  // U+2026 HORIZONTAL ELLIPSIS
    return out;
}

std::string padRight(const std::string& s, int width) {
    if (width <= 0) return "";
    const std::string t = truncateTo(s, width);
    const int d = width - displayWidth(t);
    return d > 0 ? t + std::string(static_cast<std::size_t>(d), ' ') : t;
}

std::string padLeft(const std::string& s, int width) {
    if (width <= 0) return "";
    const std::string t = truncateTo(s, width);
    const int d = width - displayWidth(t);
    return d > 0 ? std::string(static_cast<std::size_t>(d), ' ') + t : t;
}

std::string fmt1(double v) {
    std::array<char, 32> buf{};
    std::snprintf(buf.data(), buf.size(), "%.1f", v);
    return buf.data();
}

// Display rules from spec §8.3: a missing value is never rendered as zero.
std::string fmtLoss(const std::optional<double>& v) {
    if (!v) return "---";
    return fmt1(*v) + "%";
}
std::string fmtMs(const std::optional<double>& v) {
    if (!v) return "-";
    return fmt1(*v);
}
std::string fmtJitter(const std::optional<double>& v) {
    // Fewer than two adjacent successful probes: showing 0 would claim a perfectly
    // stable link (spec §4.3).
    if (!v) return "\xE2\x80\x94";  // U+2014 EM DASH
    return fmt1(*v);
}

std::string orDash(const std::string& s) { return s.empty() ? "-" : s; }

std::string fmtUptime(Dur d) {
    const long long total = std::chrono::duration_cast<std::chrono::seconds>(d).count();
    std::array<char, 32> buf{};
    std::snprintf(buf.data(), buf.size(), "%02lld:%02lld:%02lld", total / 3600,
                  (total % 3600) / 60, total % 60);
    return buf.data();
}

std::string joinComma(const std::vector<std::string>& v) {
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i > 0) out += ", ";
        out += v[i];
    }
    return out;
}

// ---------------------------------------------------------------- labels

// Careful never to claim a hop is "filtered": TransitOnly states only the observed
// fact that traffic passes but probes go unanswered (spec §5.1).
std::string hostLabel(const HopPosition& hp) {
    switch (hp.status) {
        case HopStatus::Unknown: return "\xC2\xB7\xC2\xB7\xC2\xB7";  // ···
        case HopStatus::Silent: return "* (no reply)";
        case HopStatus::TransitOnly:
            // "transit ok" read as ambiguous to a network operator in review: OK
            // how, the path or the ICMP? This says exactly what was observed.
            return "* (pass, no ICMP)";
        default: break;
    }
    std::string label = hp.primary.empty() ? "*" : hp.primary;
    // ECMP: several routers answered at this TTL, so a single-address label would
    // be a lie (spec §6.5). Labelled "ecmp" because "+2" alone was not
    // discoverable.
    if (hp.responders.size() > 1) {
        label += " +" + std::to_string(hp.responders.size() - 1) + " ecmp";
    }
    // DEGRADED must not be conveyed by row colour alone -- that is invisible to a
    // monochrome terminal and to a red/green colour-blind reader.
    if (hp.status == HopStatus::Degraded) label += " !loss";
    return label;
}

std::string rdnsLabel(const HopPosition& hp) {
    if (hp.responders.empty()) return "-";
    const Responder& r = hp.responders.front();
    const bool hasAsn = !r.asn.empty() && r.asn != "-";
    const bool hasOrg = !r.org.empty() && r.org != "-";
    const bool hasRdns = !r.rdns.empty() && r.rdns != "-";
    if (hasAsn && hasOrg) return r.asn + " " + r.org;
    if (hasRdns) return r.rdns;
    if (hasAsn) return r.asn;
    if (r.rdns == "-") return "-";
    return "\xE2\x80\xA6";  // still resolving
}

enum class Focus { Path, Resolve, Local };

// ---------------------------------------------------------------- view state

struct View {
    std::shared_ptr<const Snapshot> snap;
    Records records;
    int selected = 1;
    Focus focus = Focus::Path;
    bool inputMode = false;
    std::string inputBuffer;
    std::string toast;
    std::chrono::steady_clock::time_point toastExpiry{};
    std::chrono::system_clock::time_point startWall = std::chrono::system_clock::now();
};

const HopPosition* selectedHop(const View& v) {
    if (!v.snap) return nullptr;
    for (const auto& h : v.snap->hops) {
        if (h.ttl == v.selected) return &h;
    }
    return nullptr;
}

// ---------------------------------------------------------------- panels

// A bordered panel whose title is the FIRST CONTENT ROW, not part of the border.
//
// FTXUI's window() puts the title in the top border, which would give this build one
// more usable content row than the Go build at the same panel height and shift every
// row budget by one. Matching Go's structure keeps the two layouts row-for-row
// identical (spec §8.2).
Element boxed(const std::string& title, Element content) {
    return vbox({text(title) | bold, std::move(content)}) | borderRounded;
}

Element renderHeader(const View& v) {
    const Snapshot& s = *v.snap;

    Element mode = s.degraded ? text(std::string(modeName(s.mode)) + " (degraded)") | color(Color::Orange1)
                              : text(modeName(s.mode)) | color(Color::Green);

    std::string line1 = "  target " + s.target.input + " (" + s.target.ip + ")  up " +
                        fmtUptime(s.now) + "  pub-ip " + orDash(s.local.publicIp) + "  mode ";

    Elements first;
    first.push_back(text("NetScope") | bold | color(Color::SkyBlue1));
    first.push_back(text(line1));
    first.push_back(mode);
    if (s.paused) first.push_back(text(" PAUSED") | color(Color::Orange1));

    const std::string line2 = "gw " + orDash(s.local.gateway) + "  dns " +
                              truncateTo(orDash(joinComma(s.local.dnsServers)), 30) + "  probe " +
                              std::to_string(s.cadence.destIntervalMs) + "ms/" +
                              std::to_string(s.cadence.midIntervalMs) + "ms cap " +
                              std::to_string(s.cadence.globalCapPps) + "pps";

    Element third;
    if (v.inputMode) {
        third = text("target> " + v.inputBuffer + "_") | color(Color::SkyBlue1);
    } else if (!v.toast.empty()) {
        third = text(v.toast) | color(Color::Yellow1);
    } else {
        third = text("[q]uit [p]ause [\xE2\x86\x91\xE2\x86\x93]hop [r]eprobe [Tab]focus [d]ns "
                     "[w]asn [/]target") |
                dim;
    }

    return vbox({hbox(std::move(first)), text(line2) | dim, third}) | border;
}

Element renderPath(const View& v, int width, int height, bool withRDNS) {
    const int inner = std::max(width - 4, 20);

    constexpr int wMark = 2;
    constexpr int wTTL = 3;
    constexpr int wLoss = 7;
    constexpr int wAvg = 7;
    constexpr int wLast = 7;
    constexpr int wJit = 6;
    const int fixed = wMark + wTTL + wLoss + wAvg + wLast + wJit;
    const int wRDNS = withRDNS ? 22 : 0;
    const int wHost = std::max(inner - fixed - wRDNS, 12);

    std::string head = padRight("", wMark) + padRight("#", wTTL) + padRight("HOST/IP", wHost);
    if (withRDNS) head += padRight("rDNS/ASN", wRDNS);
    head += padLeft("LOSS", wLoss) + padLeft("AVG", wAvg) + padLeft("LAST", wLast) +
            padLeft("JIT", wJit);

    Elements rows;
    rows.push_back(text(head) | dim);

    const auto& hops = v.snap->hops;
    // A box of height h shows h-2 content rows; the title takes one and the column
    // header takes another, leaving h-4 for data rows.
    const int visible = std::max(height - 4, 1);

    // Scroll so the selection stays centred. The selection is a TTL, not a slice
    // index; they only coincide while the list starts at TTL 1 with no gaps.
    int selIdx = 0;
    for (std::size_t i = 0; i < hops.size(); ++i) {
        if (hops[i].ttl == v.selected) {
            selIdx = static_cast<int>(i);
            break;
        }
    }
    int start = 0;
    if (static_cast<int>(hops.size()) > visible) {
        start = selIdx - visible / 2;
        start = std::max(start, 0);
        start = std::min(start, static_cast<int>(hops.size()) - visible);
    }
    const int end = std::min(start + visible, static_cast<int>(hops.size()));

    for (int i = start; i < end; ++i) {
        const HopPosition& hp = hops[static_cast<std::size_t>(i)];
        const bool isSelected = hp.ttl == v.selected;

        // The marker is emitted verbatim rather than width-padded. U+25B6 has East
        // Asian Width "Ambiguous", so a width table would put it at 1 or 2 columns
        // depending on locale -- and the Go and C++ width tables do not agree on
        // it. Emitting identical bytes makes both implementations render
        // identically, whatever the terminal decides the glyph is worth.
        std::string row = std::string(isSelected ? "\xE2\x96\xB6 " : "  ") +
                          padRight(std::to_string(hp.ttl), wTTL) +
                          padRight(hostLabel(hp), wHost);
        static_cast<void>(wMark);
        if (withRDNS) row += padRight(rdnsLabel(hp), wRDNS);
        row += padLeft(fmtLoss(hp.lossPct), wLoss) + padLeft(fmtMs(hp.stats.avgMs), wAvg) +
               padLeft(fmtMs(hp.stats.lastMs), wLast) + padLeft(fmtJitter(hp.stats.jitterMs), wJit);

        Element e = text(row);
        if (isSelected) {
            e = e | bold | color(Color::SkyBlue1);
        } else if (hp.status == HopStatus::Silent || hp.status == HopStatus::TransitOnly) {
            e = e | dim;
        } else if (hp.status == HopStatus::Degraded) {
            e = e | color(Color::Red1);
        } else if (hp.lossPct && *hp.lossPct >= 10) {
            e = e | color(Color::Orange1);
        }
        rows.push_back(e);
    }
    if (hops.empty()) rows.push_back(text("  discovering path...") | dim);

    std::string title = "PATH \xC3\x97 PING";
    if (v.focus == Focus::Path) title += " \xE2\x97\x82";
    return boxed(title, vbox(std::move(rows)));
}

Element renderResolve(const View& v, int width) {
    Elements body;
    const int w = width - 6;

    body.push_back(text(padRight("A", 7) + truncateTo(orDash(joinComma(v.records.a)), w - 7)));
    body.push_back(text(padRight("AAAA", 7) + truncateTo(orDash(joinComma(v.records.aaaa)), w - 7)));
    body.push_back(text(padRight("PTR", 7) + truncateTo(orDash(v.records.ptr), w - 7)));
    if (!v.records.note.empty()) {
        body.push_back(text(truncateTo(v.records.note, w)) | color(Color::Orange1));
    }
    body.push_back(text(""));

    if (const HopPosition* hp = selectedHop(v)) {
        body.push_back(text("hop " + std::to_string(hp->ttl) + " selected") | dim);
        if (hp->responders.empty()) body.push_back(text("  no responder observed") | dim);
        for (std::size_t i = 0; i < hp->responders.size(); ++i) {
            if (i >= 3) {
                body.push_back(text("  +" + std::to_string(hp->responders.size() - 3) +
                                    " more responders") |
                               dim);
                break;
            }
            const Responder& r = hp->responders[i];
            body.push_back(text("  " + truncateTo(r.ip, w - 2)));
            body.push_back(text("   " + padRight("rDNS", 7) + truncateTo(orDash(r.rdns), w - 10)) | dim);
            body.push_back(text("   " + padRight("ASN", 7) + truncateTo(orDash(r.asn), w - 10)) | dim);
            body.push_back(text("   " + padRight("ORG", 7) + truncateTo(orDash(r.org), w - 10)) | dim);
            // StDev sits here rather than in the table: the cross-review split on
            // whether jitter or stdev is the right metric, so both are shown
            // (cross-review R1-3).
            body.push_back(text("   " + padRight("StDev", 7) + fmtMs(r.stats.stdevMs) + " ms") | dim);
        }
    }

    std::string title = "RESOLVE / ASN";
    if (v.focus == Focus::Resolve) title += " \xE2\x97\x82";
    return boxed(title, vbox(std::move(body)));
}

Element renderLocal(const View& v, int width) {
    const LocalInfo& l = v.snap->local;
    const int w = width - 6;
    Elements body;
    body.push_back(text(padRight("if", 7) +
                        truncateTo(orDash(l.interfaceName) + "  " + orDash(l.address), w - 7)));
    body.push_back(text(padRight("gw", 7) + truncateTo(orDash(l.gateway), w - 7)));
    body.push_back(text(padRight("route", 7) + truncateTo(orDash(l.defaultRoute), w - 7)));
    body.push_back(text(padRight("dns", 7) + truncateTo(orDash(joinComma(l.dnsServers)), w - 7)));
    body.push_back(text(padRight("pub", 7) + truncateTo(orDash(l.publicIp), w - 7)));
    if (!l.note.empty()) body.push_back(text(truncateTo(l.note, w)) | color(Color::Orange1));

    std::string title = "LOCAL IF / ROUTE";
    if (v.focus == Focus::Local) title += " \xE2\x97\x82";
    return boxed(title, vbox(std::move(body)));
}

Element renderMidBar(const View& v, int width) {
    const HopPosition* hp = selectedHop(v);

    std::string label = "RTT SPARKLINE (no hop selected)";
    std::string spark;
    std::string stat;
    if (hp != nullptr) {
        label = "RTT hop " + std::to_string(hp->ttl);
        int sparkW = std::clamp(width / 2, 10, 60);
        spark = sparkline(hp->stats.spark, sparkW);
        if (!hp->stats.spark.empty()) {
            const double lo = *std::min_element(hp->stats.spark.begin(), hp->stats.spark.end());
            const double hi = *std::max_element(hp->stats.spark.begin(), hp->stats.spark.end());
            stat = fmtMs(hp->stats.lastMs) + " ms  min " + fmt1(lo) + " max " + fmt1(hi) +
                   "  loss " + fmtLoss(hp->lossPct);
        } else {
            stat = "no samples  loss " + fmtLoss(hp->lossPct);
        }
    }

    const Health& h = v.snap->health;
    Element httpPart;
    if (h.httpStatus > 0) {
        const std::string s =
            "HTTP " + std::to_string(h.httpStatus) + " " + fmtMs(h.httpLatencyMs) + " ms";
        httpPart = h.httpStatus < 400 ? (text(s) | color(Color::Green))
                                      : (text(s) | color(Color::Orange1));
    } else if (!h.httpNote.empty()) {
        httpPart = text("HTTP " + h.httpNote) | dim;
    } else {
        httpPart = text("HTTP -") | dim;
    }

    Element tcpPart = text("TCP -") | dim;
    if (h.tcpPort > 0) {
        const std::string s = "TCP:" + std::to_string(h.tcpPort) + " " + orDash(h.tcpNote);
        tcpPart = h.tcpOpen ? (text(s) | color(Color::Green)) : (text(s) | color(Color::Red1));
    }

    // The health bar is deliberately independent of hop classification: ICMP can be
    // blocked end to end while HTTP works (spec §6.5).
    return vbox({
               hbox({text(label) | dim, text(" " + spark + "  "), text(stat)}),
               hbox({httpPart, text("  \xC2\xB7  "), tcpPart}),
           }) |
           border;
}

Element renderLog(const View& v, int width, int lines) {
    Elements body;
    int n = 0;
    for (const Event& e : v.snap->events) {
        if (n++ >= lines) break;
        const auto wall = v.startWall + std::chrono::duration_cast<std::chrono::system_clock::duration>(e.at);
        const std::time_t tt = std::chrono::system_clock::to_time_t(wall);
        std::tm tmv{};
#ifdef _WIN32
        localtime_s(&tmv, &tt);
#else
        localtime_r(&tt, &tmv);
#endif
        std::array<char, 16> ts{};
        std::snprintf(ts.data(), ts.size(), "%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);

        Element textEl = text(truncateTo(e.text, width - 16));
        switch (e.kind) {
            case EventKind::RouteChange:
            case EventKind::ResponderChange:
                textEl = textEl | color(Color::Orange1);
                break;
            case EventKind::Error:
            case EventKind::Permission:
            case EventKind::Unreachable:
            case EventKind::TimeoutStreak:
                textEl = textEl | color(Color::Red1);
                break;
            default: break;
        }
        body.push_back(hbox({text(std::string(ts.data()) + " ") | dim, textEl}));
    }
    if (body.empty()) body.push_back(text("no events yet") | dim);
    return boxed("LOG", vbox(std::move(body)));
}

}  // namespace

int Layout::totalHeight() const {
    int total = kHeaderHeight + bodyHeight + tabHeight;
    if (showMidBar) total += kMidBarHeight;
    if (logLines > 0) total += logLines + kLogChrome;
    return total;
}

Layout planLayout(int w, int h) {
    if (w < kMinWidth) w = kMinWidth;
    if (h < kMinHeight) h = kMinHeight;

    Layout l;
    l.narrow = w < kMediumMin;
    l.medium = w >= kMediumMin && w < kWideMin;
    l.withRDNS = !l.narrow && !l.medium;
    l.showMidBar = true;

    if (l.narrow) {
        l.rightWidth = 0;
        l.tabHeight = kTabHeightFull;
    } else if (l.medium) {
        l.rightWidth = 36;
    } else {
        l.rightWidth = 46;
    }

    l.logLines = 4;
    if (h < kShortRows) l.logLines = 3;  // spec §8.2: shrink the log, keep the sparkline

    const auto chrome = [&l] {
        int c = kHeaderHeight + l.tabHeight;
        if (l.showMidBar) c += kMidBarHeight;
        if (l.logLines > 0) c += l.logLines + kLogChrome;
        return c;
    };

    for (;;) {
        l.bodyHeight = h - chrome();
        if (l.bodyHeight >= kBodyPreferred) break;
        // Give up, in order of least value.
        if (l.logLines > 1) {
            --l.logLines;
            continue;
        }
        if (l.tabHeight > kTabHeightMin) {
            --l.tabHeight;
            continue;
        }
        if (l.tabHeight > 0) {
            l.tabHeight = 0;
            continue;
        }
        if (l.showMidBar) {
            // Reluctant: the sparkline is the reason for the bar. But a clipped
            // screen is worse than a missing panel.
            l.showMidBar = false;
            continue;
        }
        if (l.logLines > 0) {
            l.logLines = 0;
            continue;
        }
        break;
    }
    if (l.bodyHeight < kBodyFloor) l.bodyHeight = kBodyFloor;
    return l;
}

std::string sparkline(const std::vector<double>& values, int width) {
    static const char* runes[] = {"\xE2\x96\x81", "\xE2\x96\x82", "\xE2\x96\x83", "\xE2\x96\x84",
                                  "\xE2\x96\x85", "\xE2\x96\x86", "\xE2\x96\x87", "\xE2\x96\x88"};
    constexpr int kLevels = 8;

    if (width <= 0) return "";
    if (values.empty()) return std::string(static_cast<std::size_t>(width), ' ');

    std::vector<double> v = values;
    if (static_cast<int>(v.size()) > width) {
        v.erase(v.begin(), v.end() - width);
    }

    const double lo = *std::min_element(v.begin(), v.end());
    const double hi = *std::max_element(v.begin(), v.end());
    const double span = hi - lo;

    std::string out;
    for (double x : v) {
        int idx;
        if (span > 1e-9) {
            idx = static_cast<int>((x - lo) / span * (kLevels - 1));
        } else {
            // A perfectly flat series should read as a mid-level line, not as an
            // empty trough.
            idx = kLevels / 2;
        }
        idx = std::clamp(idx, 0, kLevels - 1);
        out += runes[idx];
    }
    if (const int pad = width - static_cast<int>(v.size()); pad > 0) {
        out += std::string(static_cast<std::size_t>(pad), ' ');
    }
    return out;
}

int runUI(Runner& runner) {
    // The using-directive in the anonymous namespace above does not reach here, so
    // reintroduce it. Note that unqualified `Event` still resolves to
    // netscope::Event -- the enclosing namespace wins over a using-directive -- so
    // every FTXUI event below is spelled ftxui::Event explicitly.
    using namespace ftxui;

    auto screen = ScreenInteractive::Fullscreen();
    View view;

    // The runner posts a custom event whenever a new snapshot is published. The
    // callback is cleared by Runner::shutdown() before this screen is destroyed, so
    // a post can never reach a dead ScreenInteractive (spec §3.3 step 5).
    runner.setWakeup([&screen] { screen.PostEvent(ftxui::Event::Custom); });

    auto renderer = Renderer([&] {
        view.snap = runner.latest();
        view.records = runner.records();
        if (!view.snap) return text("NetScope starting...") | center;

        // A re-probe or a target change can shorten the path; without this the
        // selection could fall outside the list and the mid-bar sparkline would go
        // blank with no way for the user to get it back.
        if (!view.snap->hops.empty()) {
            const int n = static_cast<int>(view.snap->hops.size());
            const int clamped = std::clamp(view.selected, 1, n);
            if (clamped != view.selected) {
                view.selected = clamped;
                Command c;
                c.kind = CommandKind::SelectHop;
                c.ttl = clamped;
                runner.send(c);
            }
        }

        if (!view.toast.empty() && std::chrono::steady_clock::now() > view.toastExpiry) {
            view.toast.clear();
        }

        const int w = std::max(screen.dimx(), kMinWidth);
        const int h = std::max(screen.dimy(), kMinHeight);
        const Layout l = planLayout(w, h);

        Elements parts;
        parts.push_back(renderHeader(view));

        if (l.narrow) {
            parts.push_back(renderPath(view, w, l.bodyHeight, false) |
                            size(HEIGHT, EQUAL, l.bodyHeight));
        } else {
            const int leftW = w - l.rightWidth;
            // Explicit heights rather than flex, so the scroll window the path
            // panel computed matches the rows FTXUI actually gives it, and so the
            // right column splits the same way the Go build does.
            const int resolveH = l.bodyHeight / 2;
            const int localH = l.bodyHeight - resolveH;
            parts.push_back(hbox({
                                renderPath(view, leftW, l.bodyHeight, l.withRDNS),
                                vbox({
                                    renderResolve(view, l.rightWidth) |
                                        size(HEIGHT, EQUAL, resolveH),
                                    renderLocal(view, l.rightWidth) |
                                        size(HEIGHT, EQUAL, localH),
                                }) | size(WIDTH, EQUAL, l.rightWidth),
                            }) |
                            size(HEIGHT, EQUAL, l.bodyHeight));
        }

        if (l.tabHeight > 0) {
            Element tab = (view.focus == Focus::Local) ? renderLocal(view, w)
                                                       : renderResolve(view, w);
            parts.push_back(tab | size(HEIGHT, EQUAL, l.tabHeight));
        }
        if (l.showMidBar) parts.push_back(renderMidBar(view, w));
        if (l.logLines > 0) parts.push_back(renderLog(view, w, l.logLines));
        return vbox(std::move(parts));
    });

    auto setToast = [&view](std::string s) {
        view.toast = std::move(s);
        view.toastExpiry = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    };

    auto moveSelection = [&](int delta) {
        auto snap = runner.latest();
        if (!snap || snap->hops.empty()) return;
        const int n = static_cast<int>(snap->hops.size());
        view.selected = std::clamp(view.selected + delta, 1, n);
        Command c;
        c.kind = CommandKind::SelectHop;
        c.ttl = view.selected;
        runner.send(c);
    };

    auto selectedIp = [&]() -> std::string {
        if (const HopPosition* hp = selectedHop(view)) return hp->primary;
        return "";
    };

    auto component = CatchEvent(renderer, [&](const ftxui::Event& event) {
        if (event == ftxui::Event::Custom) return true;  // repaint on a new snapshot

        if (view.inputMode) {
            if (event == ftxui::Event::Escape) {
                view.inputMode = false;
                view.inputBuffer.clear();
                return true;
            }
            if (event == ftxui::Event::Return) {
                if (!view.inputBuffer.empty()) {
                    Command c;
                    c.kind = CommandKind::SetTarget;
                    c.target = view.inputBuffer;
                    runner.send(c);
                }
                view.inputMode = false;
                view.inputBuffer.clear();
                return true;
            }
            if (event == ftxui::Event::Backspace) {
                if (!view.inputBuffer.empty()) view.inputBuffer.pop_back();
                return true;
            }
            if (event.is_character()) {
                if (view.inputBuffer.size() < 253) view.inputBuffer += event.character();
                return true;
            }
            return false;
        }

        if (event == ftxui::Event::Character('q') || event == ftxui::Event::CtrlC) {
            Command c;
            c.kind = CommandKind::Quit;
            runner.send(c);
            screen.Exit();
            return true;
        }
        if (event == ftxui::Event::Character('p')) {
            Command c;
            c.kind = CommandKind::TogglePause;
            runner.send(c);
            return true;
        }
        if (event == ftxui::Event::Character('r')) {
            Command c;
            c.kind = CommandKind::Reprobe;
            runner.send(c);
            // Without this the key felt dead: the log event only arrives on the
            // next engine tick.
            setToast("re-probing: path and statistics reset");
            return true;
        }
        if (event == ftxui::Event::ArrowUp || event == ftxui::Event::Character('k')) {
            moveSelection(-1);
            return true;
        }
        if (event == ftxui::Event::ArrowDown || event == ftxui::Event::Character('j')) {
            moveSelection(1);
            return true;
        }
        if (event == ftxui::Event::Tab) {
            // On a narrow terminal Tab is the tab switcher for the collapsed right
            // column, so it must cycle only the two panels that are actually shown.
            // Including Focus::Path there made one press in three look like a no-op.
            if (screen.dimx() < kMediumMin) {
                view.focus = (view.focus == Focus::Local) ? Focus::Resolve : Focus::Local;
            } else {
                view.focus = static_cast<Focus>((static_cast<int>(view.focus) + 1) % 3);
            }
            return true;
        }
        if (event == ftxui::Event::Character('d')) {
            Command c;
            c.kind = CommandKind::RefreshDNS;
            c.ttl = view.selected;
            c.selectedIp = selectedIp();
            runner.send(c);
            setToast("DNS refresh requested for hop " + std::to_string(view.selected));
            return true;
        }
        if (event == ftxui::Event::Character('w')) {
            Command c;
            c.kind = CommandKind::RefreshASN;
            c.ttl = view.selected;
            c.selectedIp = selectedIp();
            runner.send(c);
            setToast("ASN refresh requested for hop " + std::to_string(view.selected));
            return true;
        }
        if (event == ftxui::Event::Character('s') || event == ftxui::Event::Character('n')) {
            // Reserved. Cross-review agreed speedtest and port scanning are not
            // small extensions of the health check: they need scope, rate limits,
            // cancellation and a safety policy of their own (spec §8.1).
            setToast(std::string("'") + event.character() +
                     "' is reserved: not enabled in this build (v1.0)");
            return true;
        }
        if (event == ftxui::Event::Character('/')) {
            view.inputMode = true;
            view.inputBuffer.clear();
            return true;
        }
        return false;
    });

    screen.Loop(component);

    // Close the wake-up gate before this function's screen goes out of scope.
    runner.disableWakeup();
    return 0;
}

}  // namespace netscope
