// The canonical emitter and the scenario reader are the parity harness (spec §9),
// so their exact output and tolerance for odd input are worth pinning down.
#include <string>

#include <doctest/doctest.h>

#include "json.h"

using namespace netscope;

TEST_CASE("formatF3 is stable and normalizes negative zero") {
    CHECK(formatF3(0) == "0.000");
    CHECK(formatF3(-0.0) == "0.000");
    CHECK(formatF3(1.2) == "1.200");
    CHECK(formatF3(74.1) == "74.100");
    CHECK(formatF3(1.0 / 3.0) == "0.333");
    // Three decimals means microsecond resolution, which is what the Go side emits.
    CHECK(formatF3(0.0005) == "0.001");
}

TEST_CASE("an empty snapshot serializes with the fixed field order") {
    Snapshot s;
    s.revision = 1;
    s.generation = 1;
    s.target.input = "example.com";
    s.target.ip = "1.2.3.4";
    s.cadence = Cadence{1000, 4000, 10, 120000, 1500};

    const std::string out = canonicalJson(s);

    // Field order is part of the contract; a reordering would break the byte diff.
    const auto revision = out.find("\"revision\"");
    const auto generation = out.find("\"generation\"");
    const auto mode = out.find("\"mode\"");
    const auto hops = out.find("\"hops\"");
    const auto events = out.find("\"events\"");
    CHECK(revision < generation);
    CHECK(generation < mode);
    CHECK(mode < hops);
    CHECK(hops < events);

    // Empty arrays are "[]" with no inner whitespace, matching the Go writer.
    CHECK(out.find("\"hops\": []") != std::string::npos);
    CHECK(out.find("\"events\": []") != std::string::npos);
    CHECK(out.back() == '\n');
}

TEST_CASE("optional stats render as null, never as zero") {
    Snapshot s;
    HopPosition h;
    h.ttl = 1;
    h.status = HopStatus::Silent;
    h.sent = 3;
    // lossPct, jitterMs and the rest are deliberately left unset.
    s.hops.push_back(h);

    const std::string out = canonicalJson(s);
    CHECK(out.find("\"lossPct\": null") != std::string::npos);
    CHECK(out.find("\"jitterMs\": null") != std::string::npos);
    CHECK(out.find("\"stdevMs\": null") != std::string::npos);
    CHECK(out.find("\"status\": \"SILENT\"") != std::string::npos);
}

TEST_CASE("strings are escaped") {
    Snapshot s;
    Event e;
    e.kind = EventKind::Error;
    e.text = "quote \" backslash \\ newline \n tab \t";
    s.events.push_back(e);

    const std::string out = canonicalJson(s);
    CHECK(out.find("quote \\\" backslash \\\\ newline \\n tab \\t") != std::string::npos);
}

TEST_CASE("dnsServers are sorted so discovery order cannot leak in") {
    Snapshot s;
    s.local.dnsServers = {"9.9.9.9", "1.1.1.1", "8.8.8.8"};
    const std::string out = canonicalJson(s);
    const auto a = out.find("1.1.1.1");
    const auto b = out.find("8.8.8.8");
    const auto c = out.find("9.9.9.9");
    CHECK(a < b);
    CHECK(b < c);
}

TEST_CASE("the reader handles the scenario shapes we emit") {
    std::string err;
    auto doc = parseJson(R"({
      "name": "x",
      "num": -12.5,
      "flag": true,
      "nil": null,
      "list": ["a", "b"],
      "nested": { "k": 3 },
      "steps": [ {"kind":"probe","ttl":2} ]
    })",
                         err);
    REQUIRE_MESSAGE(doc.has_value(), err);
    CHECK(doc->strOr("name") == "x");
    CHECK(doc->numOr("num") == doctest::Approx(-12.5));
    CHECK(doc->boolOr("flag"));
    CHECK_FALSE(doc->optNum("nil").has_value());
    CHECK(doc->stringsAt("list").size() == 2);

    const JsonValue* nested = doc->find("nested");
    REQUIRE(nested != nullptr);
    CHECK(nested->intOr("k") == 3);

    const JsonValue* steps = doc->find("steps");
    REQUIRE(steps != nullptr);
    REQUIRE(steps->array.size() == 1);
    CHECK(steps->array[0].strOr("kind") == "probe");
    CHECK(steps->array[0].intOr("ttl") == 2);
}

TEST_CASE("the reader rejects malformed input instead of guessing") {
    std::string err;
    CHECK_FALSE(parseJson("{", err).has_value());
    CHECK_FALSE(parseJson("{\"a\"}", err).has_value());
    CHECK_FALSE(parseJson("[1,", err).has_value());
    CHECK_FALSE(parseJson("\"unterminated", err).has_value());
    CHECK_FALSE(parseJson("tru", err).has_value());
}

TEST_CASE("missing keys fall back rather than throwing") {
    std::string err;
    auto doc = parseJson("{}", err);
    REQUIRE(doc.has_value());
    CHECK(doc->strOr("absent", "fallback") == "fallback");
    CHECK(doc->intOr("absent", 7) == 7);
    CHECK(doc->boolOr("absent", true));
    CHECK(doc->stringsAt("absent").empty());
    CHECK(doc->find("absent") == nullptr);
}
