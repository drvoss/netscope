// Mirrors netscope-go/internal/probe/parse_test.go and reads the SAME golden files
// from ../testdata, so a drift in either parser is caught by shared fixtures.
#include <fstream>
#include <sstream>
#include <string>

#include <doctest/doctest.h>

#include "probe_parse.h"

using namespace netscope;

namespace {

std::string golden(const std::string& name) {
    const std::string path = std::string(NETSCOPE_TESTDATA_DIR) + "/" + name;
    std::ifstream in(path, std::ios::binary);
    REQUIRE_MESSAGE(in.good(), "cannot open " << path);
    std::ostringstream os;
    os << in.rdbuf();
    return os.str();
}

}  // namespace

TEST_CASE("tracert on English Windows") {
    const auto got = parseTraceOutput(golden("tracert-windows-en.txt"));
    REQUIRE(got.size() == 12);  // 4 hops x 3 probes
    // Windows puts the times before the host; all three must attach to it.
    for (int i = 0; i < 3; ++i) {
        CHECK(got[static_cast<std::size_t>(i)].ttl == 1);
        CHECK(got[static_cast<std::size_t>(i)].responder == "192.168.0.1");
        CHECK(got[static_cast<std::size_t>(i)].ok);
    }
    CHECK(got[0].rttMs == doctest::Approx(1));
    // hop 3 timed out three times, with no responder
    for (std::size_t i = 6; i < 9; ++i) {
        CHECK(got[i].ttl == 3);
        CHECK_FALSE(got[i].ok);
        CHECK(got[i].responder.empty());
    }
    CHECK(got[9].responder == "93.184.216.34");
    CHECK(got[9].rttMs == doctest::Approx(74));
}

TEST_CASE("tracert on Korean Windows parses without locale knowledge") {
    // The localized timed-out line must still parse as three timeouts: the parser
    // only reads hop numbers, IPs and "<n> ms" groups.
    const auto got = parseTraceOutput(golden("tracert-windows-ko.txt"));
    REQUIRE(got.size() == 12);
    for (std::size_t i = 0; i < 3; ++i) {
        CHECK(got[i].ok);
        // "<1 ms" becomes 0.5, distinguishable from a real zero.
        CHECK(got[i].rttMs == doctest::Approx(0.5));
        CHECK(got[i].responder == "192.168.0.1");
    }
    for (std::size_t i = 6; i < 9; ++i) {
        CHECK(got[i].ttl == 3);
        CHECK_FALSE(got[i].ok);
    }
}

TEST_CASE("traceroute on Linux") {
    const auto got = parseTraceOutput(golden("traceroute-linux.txt"));
    REQUIRE(got.size() == 12);
    // POSIX puts the host first, then the times.
    CHECK(got[0].responder == "192.168.0.1");
    CHECK(got[0].rttMs == doctest::Approx(1.234));
    CHECK(got[11].responder == "93.184.216.34");
    CHECK(got[11].rttMs == doctest::Approx(74.001));
}

TEST_CASE("ECMP times attach to the responder that precedes them") {
    const auto all = parseTraceOutput(golden("traceroute-linux-ecmp.txt"));
    std::vector<TraceSample> hop2;
    for (const auto& s : all) {
        if (s.ttl == 2) hop2.push_back(s);
    }
    REQUIRE(hop2.size() == 3);
    CHECK(hop2[0].responder == "10.20.0.1");
    CHECK(hop2[0].rttMs == doctest::Approx(8.100));
    CHECK(hop2[1].responder == "10.20.0.2");
    CHECK(hop2[1].rttMs == doctest::Approx(8.900));
    CHECK(hop2[2].responder == "10.20.0.1");
    CHECK(hop2[2].rttMs == doctest::Approx(8.300));
}

TEST_CASE("the !H annotation marks samples unreachable") {
    const auto all = parseTraceOutput(golden("traceroute-linux-ecmp.txt"));
    int n = 0;
    for (const auto& s : all) {
        if (s.ttl != 3) continue;
        CHECK(s.unreachable);
        CHECK(s.note == "host unreachable");
        ++n;
    }
    CHECK(n == 3);
}

TEST_CASE("ping RTT parsing") {
    struct Case {
        const char* file;
        double want;
    };
    const Case cases[] = {
        {"ping-windows-en.txt", 74},
        {"ping-linux.txt", 74.1},
        {"ping-windows-subms.txt", 0.5},
    };
    for (const auto& c : cases) {
        const auto got = parsePingRTT(golden(c.file));
        REQUIRE_MESSAGE(got.has_value(), "no rtt found in " << c.file);
        CHECK(*got == doctest::Approx(c.want));
    }
}

TEST_CASE("an unreachable reply yields no RTT") {
    CHECK_FALSE(parsePingRTT(golden("ping-unreachable.txt")).has_value());
}

TEST_CASE("garbage input produces no samples at all") {
    // A wrong locale, a truncated pipe, or a completely different binary on PATH
    // must degrade to "no samples", never crash (DoD: graceful failure paths).
    //
    // The assertion is deliberately "exactly zero samples" rather than "no
    // successful samples": a parser that invented phantom TIMEOUTS from garbage
    // would inflate loss to 100% on a healthy path, and the weaker assertion would
    // not catch it.
    const char* inputs[] = {"",
                            "\n\n",
                            "not a traceroute at all",
                            "  1 ",
                            "  1  garbage garbage",
                            "999999999999 1 ms 1.2.3.4",
                            "Tracing route to example.com [93.184.216.34]",
                            "over a maximum of 30 hops:"};
    for (const char* in : inputs) {
        CHECK(parseTraceOutput(in).empty());
    }
}

TEST_CASE("ms token grammar") {
    CHECK(parseMsToken("1 ms").value() == doctest::Approx(1));
    CHECK(parseMsToken("1.234 ms").value() == doctest::Approx(1.234));
    CHECK(parseMsToken("1ms").value() == doctest::Approx(1));
    CHECK(parseMsToken("<1 ms").value() == doctest::Approx(0.5));
    CHECK_FALSE(parseMsToken("ms").has_value());
    CHECK_FALSE(parseMsToken("1 s").has_value());
    CHECK_FALSE(parseMsToken("1.").has_value());
    CHECK_FALSE(parseMsToken("192.168.0.1").has_value());
}
