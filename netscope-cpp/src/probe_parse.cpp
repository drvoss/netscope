#include "probe_parse.h"

#include <cctype>
#include <cstdlib>

#include "net_compat.h"

namespace netscope {
namespace {

bool isSpace(char c) { return c == ' ' || c == '\t' || c == '\v' || c == '\f'; }

std::vector<std::string_view> splitFields(std::string_view s) {
    std::vector<std::string_view> out;
    std::size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && isSpace(s[i])) ++i;
        if (i >= s.size()) break;
        std::size_t start = i;
        while (i < s.size() && !isSpace(s[i])) ++i;
        out.push_back(s.substr(start, i - start));
    }
    return out;
}

// Mirrors the Go regex `^\s*(\d{1,2})\s+(.*)$`, including its backtracking: at
// most two digits, and they must be followed by whitespace. "123 foo" therefore
// does NOT match, which is what keeps header lines out of the sample stream.
bool matchHopLine(std::string_view line, int& ttl, std::string_view& rest) {
    std::size_t i = 0;
    while (i < line.size() && isSpace(line[i])) ++i;

    std::size_t digitStart = i;
    std::size_t digits = 0;
    while (i < line.size() && digits < 2 && std::isdigit(static_cast<unsigned char>(line[i]))) {
        ++i;
        ++digits;
    }
    if (digits == 0) return false;

    // Try the longest match first, then back off to one digit.
    for (std::size_t take = digits; take >= 1; --take) {
        std::size_t after = digitStart + take;
        if (after >= line.size()) continue;
        if (!isSpace(line[after])) continue;
        std::size_t j = after;
        while (j < line.size() && isSpace(line[j])) ++j;
        ttl = std::atoi(std::string(line.substr(digitStart, take)).c_str());
        rest = line.substr(j);
        return true;
    }
    return false;
}

std::string unreachAnnotation(std::string_view f) {
    if (f == "!H") return "host unreachable";
    if (f == "!N") return "net unreachable";
    if (f == "!P") return "protocol unreachable";
    if (f == "!X" || f == "!A") return "administratively prohibited";
    return "unreachable " + std::string(f);
}

// Accepts a bare literal or a "host (1.2.3.4)" / "(1.2.3.4)" form.
std::string extractIP(std::string_view tok) {
    const std::string_view trimChars = "()[],:";
    while (!tok.empty() && trimChars.find(tok.front()) != std::string_view::npos) {
        tok.remove_prefix(1);
    }
    while (!tok.empty() && trimChars.find(tok.back()) != std::string_view::npos) {
        tok.remove_suffix(1);
    }
    if (tok.empty()) return "";
    return parseIPLiteral(tok);
}

std::vector<TraceSample> parseHopLine(int ttl, std::string_view rest) {
    std::vector<TraceSample> out;
    const auto fields = splitFields(rest);

    std::string current;            // responder the following times belong to
    std::vector<double> pending;    // times seen before any host (Windows layout)
    bool lastUnreachable = false;
    std::string note;

    auto flushPending = [&](const std::string& ip) {
        for (double v : pending) {
            TraceSample s;
            s.ttl = ttl;
            s.responder = ip;
            s.rttMs = v;
            s.ok = true;
            out.push_back(std::move(s));
        }
        pending.clear();
    };

    for (std::size_t i = 0; i < fields.size(); ++i) {
        std::string_view f = fields[i];

        if (f == "*") {
            TraceSample s;
            s.ttl = ttl;
            out.push_back(std::move(s));
            continue;
        }

        if (!f.empty() && f.front() == '!') {
            lastUnreachable = true;
            note = unreachAnnotation(f);
            continue;
        }

        // A bare number followed by a separate "ms" token (the tracert layout).
        if (i + 1 < fields.size() && fields[i + 1] == "ms") {
            if (auto v = parseMsToken(std::string(f) + " ms")) {
                if (current.empty()) {
                    pending.push_back(*v);
                } else {
                    TraceSample s;
                    s.ttl = ttl;
                    s.responder = current;
                    s.rttMs = *v;
                    s.ok = true;
                    out.push_back(std::move(s));
                }
                ++i;
                continue;
            }
        }
        if (auto v = parseMsToken(f)) {
            if (current.empty()) {
                pending.push_back(*v);
            } else {
                TraceSample s;
                s.ttl = ttl;
                s.responder = current;
                s.rttMs = *v;
                s.ok = true;
                out.push_back(std::move(s));
            }
            continue;
        }

        if (std::string ip = extractIP(f); !ip.empty()) {
            current = ip;
            flushPending(ip);
            continue;
        }
        // Anything else is prose (a localized "request timed out", an rDNS name we
        // did not ask for, "Trace complete") and is ignored.
    }

    // Times with no host at all: the hop answered but the address was
    // unparseable. Record them with an empty responder so loss is not overstated.
    flushPending("");

    if (lastUnreachable) {
        for (auto& s : out) {
            if (s.ok) {
                s.unreachable = true;
                s.note = note;
            }
        }
    }
    return out;
}

}  // namespace

std::optional<double> parseMsToken(std::string_view s) {
    // Grammar: optional '<', digits, optional '.' digits, optional spaces, "ms".
    std::size_t i = 0;
    bool less = false;
    if (i < s.size() && s[i] == '<') {
        less = true;
        ++i;
    }
    std::size_t numStart = i;
    bool any = false;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
        ++i;
        any = true;
    }
    if (i < s.size() && s[i] == '.') {
        ++i;
        bool frac = false;
        while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
            ++i;
            frac = true;
        }
        if (!frac) return std::nullopt;
    }
    if (!any) return std::nullopt;
    const std::string num(s.substr(numStart, i - numStart));

    while (i < s.size() && isSpace(s[i])) ++i;
    if (s.substr(i) != "ms") return std::nullopt;

    if (less) {
        // "<1 ms" is a Windows sub-millisecond report; 0.5 keeps it
        // distinguishable from a genuine zero.
        return 0.5;
    }
    return std::strtod(num.c_str(), nullptr);
}

std::vector<TraceSample> parseTraceOutput(std::string_view text) {
    std::vector<TraceSample> out;
    std::size_t pos = 0;
    while (pos <= text.size()) {
        std::size_t nl = text.find('\n', pos);
        std::string_view line =
            (nl == std::string_view::npos) ? text.substr(pos) : text.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);

        int ttl = 0;
        std::string_view rest;
        if (matchHopLine(line, ttl, rest) && ttl >= 1) {
            auto samples = parseHopLine(ttl, rest);
            out.insert(out.end(), samples.begin(), samples.end());
        }

        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    return out;
}

std::optional<double> parsePingRTT(std::string_view text) {
    // Mirrors the Go regex `time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms`.
    const bool hasTimeLess = text.find("time<") != std::string_view::npos;

    std::size_t pos = 0;
    while ((pos = text.find("time", pos)) != std::string_view::npos) {
        std::size_t i = pos + 4;
        if (i >= text.size() || (text[i] != '=' && text[i] != '<')) {
            pos = i;
            continue;
        }
        ++i;
        while (i < text.size() && isSpace(text[i])) ++i;

        std::size_t numStart = i;
        bool any = false;
        while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i]))) {
            ++i;
            any = true;
        }
        if (i < text.size() && text[i] == '.') {
            std::size_t save = i;
            ++i;
            bool frac = false;
            while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i]))) {
                ++i;
                frac = true;
            }
            if (!frac) i = save;
        }
        if (!any) {
            pos = i;
            continue;
        }
        const std::string num(text.substr(numStart, i - numStart));

        std::size_t j = i;
        while (j < text.size() && isSpace(text[j])) ++j;
        if (text.compare(j, 2, "ms") != 0) {
            pos = i;
            continue;
        }

        double v = std::strtod(num.c_str(), nullptr);
        if (hasTimeLess && v == 1) return 0.5;
        return v;
    }
    return std::nullopt;
}

}  // namespace netscope
