// Output parsers for the command fallback backend.
//
// These are deliberately LOCALE-AGNOSTIC rather than locale-forced: they only look
// at hop numbers, IP literals and "<number> ms" groups, all of which are ASCII in
// every Windows display language and in every traceroute build. A Korean or German
// Windows prints a localized "request timed out" line, and this parser does not
// care -- it sees no IP and no time on that line and records a timeout.
//
// Behaviour must match the Go implementation's internal/probe/parse.go; both are
// exercised against the shared fixtures in ../testdata.
#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace netscope {

// One parsed probe from a traceroute/tracert sweep.
struct TraceSample {
    int ttl = 0;
    std::string responder;  // empty means no answer
    double rttMs = 0;
    bool ok = false;
    bool unreachable = false;
    std::string note;
};

// Extracts samples from tracert (Windows) or traceroute (POSIX) output. Both
// layouts are handled by one pass:
//
//   Windows:    "  4    74 ms    73 ms    74 ms  93.184.216.34"   times then host
//   POSIX:      " 4  93.184.216.34  74.1 ms  73.8 ms  74.0 ms"    host then times
//   POSIX/ECMP: " 3  10.0.0.1  1.1 ms  10.0.0.2  1.2 ms"          interleaved
std::vector<TraceSample> parseTraceOutput(std::string_view text);

// Pulls the round-trip time out of a single-shot ping.
// Windows: "Reply from 1.2.3.4: bytes=32 time=74ms TTL=56"
// POSIX:   "64 bytes from 1.2.3.4: icmp_seq=1 ttl=56 time=74.1 ms"
// "time<1ms" yields 0.5.
std::optional<double> parsePingRTT(std::string_view text);

// Exposed for testing: parses a "<n> ms" / "1.234 ms" / "<1 ms" token.
std::optional<double> parseMsToken(std::string_view s);

}  // namespace netscope
