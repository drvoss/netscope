// Mirrors netscope-go/internal/stats/window_test.go. The two suites assert the
// same numbers because docs/netscope-spec.md §4 is a cross-language contract.
#include <cmath>

#include <doctest/doctest.h>

#include "stats.h"

using namespace netscope;

namespace {

void add(Window& w, double atMs, double rttMs, bool ok, const std::string& responder) {
    Sample s;
    s.sentAt = fromMs(atMs);
    s.rtt = fromMs(rttMs);
    s.ok = ok;
    s.responder = responder;
    w.add(s);
}

}  // namespace

TEST_CASE("loss counts only timeouts") {
    Window w;
    add(w, 0, 10, true, "a");
    add(w, 1000, 0, false, "");
    add(w, 2000, 12, true, "a");
    add(w, 3000, 0, false, "");
    REQUIRE(w.lossPct().has_value());
    CHECK(*w.lossPct() == doctest::Approx(50));
}

TEST_CASE("loss is null when the window is empty") {
    Window w;
    CHECK_FALSE(w.lossPct().has_value());
    // A hop that has sent nothing inside the window must render "---", not 0%.
    add(w, 0, 5, true, "a");
    w.prune(kWindowDuration + fromMs(1));
    CHECK_FALSE(w.lossPct().has_value());
}

TEST_CASE("jitter is the mean absolute successive difference") {
    Window w;
    // 10, 12, 15, 11 -> diffs 2, 3, 4 -> mean 3
    add(w, 0, 10, true, "a");
    add(w, 1000, 12, true, "a");
    add(w, 2000, 15, true, "a");
    add(w, 3000, 11, true, "a");
    const RttStats st = w.statsFor("a");
    REQUIRE(st.jitterMs.has_value());
    CHECK(*st.jitterMs == doctest::Approx(3));
    CHECK(*st.avgMs == doctest::Approx(12));
    CHECK(*st.bestMs == doctest::Approx(10));
    CHECK(*st.worstMs == doctest::Approx(15));
    CHECK(*st.lastMs == doctest::Approx(11));
    CHECK(st.samples == 4);
}

TEST_CASE("a timeout breaks the jitter pairing") {
    Window w;
    // 10, 12, [timeout], 40, 42
    // valid adjacent pairs: (10,12) and (40,42) -> diffs 2, 2 -> jitter 2.
    // If the timeout did not break the pairing we would also count |40-12|=28 and
    // jitter would be 10.67, double-counting the loss as jitter.
    add(w, 0, 10, true, "a");
    add(w, 1000, 12, true, "a");
    add(w, 2000, 0, false, "");
    add(w, 3000, 40, true, "a");
    add(w, 4000, 42, true, "a");
    REQUIRE(w.statsFor("a").jitterMs.has_value());
    CHECK(*w.statsFor("a").jitterMs == doctest::Approx(2));
}

TEST_CASE("a responder switch breaks the jitter pairing") {
    Window w;
    // ECMP: two routers alternate at the same TTL. Their RTTs must never be paired
    // with each other (spec §5.3).
    add(w, 0, 10, true, "a");
    add(w, 1000, 90, true, "b");
    add(w, 2000, 12, true, "a");
    add(w, 3000, 95, true, "b");

    const RttStats sa = w.statsFor("a");
    CHECK_FALSE(sa.jitterMs.has_value());
    CHECK(sa.samples == 2);
    CHECK(*sa.avgMs == doctest::Approx(11));

    const RttStats sb = w.statsFor("b");
    CHECK(*sb.avgMs == doctest::Approx(92.5));
}

TEST_CASE("jitter is null with fewer than two pairs") {
    Window w;
    add(w, 0, 10, true, "a");
    CHECK_FALSE(w.statsFor("a").jitterMs.has_value());
    add(w, 1000, 20, true, "a");
    // exactly one pair -> still null, must not render as 0
    CHECK_FALSE(w.statsFor("a").jitterMs.has_value());
    add(w, 2000, 25, true, "a");
    REQUIRE(w.statsFor("a").jitterMs.has_value());
    CHECK(*w.statsFor("a").jitterMs == doctest::Approx(7.5));
}

TEST_CASE("stdev is the sample standard deviation") {
    Window w;
    for (double v : {2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0}) add(w, 0, v, true, "a");
    // population stdev is 2; sample stdev (n-1) is sqrt(32/7)
    REQUIRE(w.statsFor("a").stdevMs.has_value());
    CHECK(*w.statsFor("a").stdevMs == doctest::Approx(std::sqrt(32.0 / 7.0)));
}

TEST_CASE("stdev is null with one sample") {
    Window w;
    add(w, 0, 10, true, "a");
    CHECK_FALSE(w.statsFor("a").stdevMs.has_value());
}

TEST_CASE("prune drops only old samples") {
    Window w;
    add(w, 0, 10, true, "a");
    add(w, 60000, 11, true, "a");
    add(w, 130000, 12, true, "a");
    w.prune(fromMs(130000));
    // the window is 120s wide, so sentAt <= 10s is dropped
    CHECK(w.size() == 2);
    CHECK(*w.statsFor("a").bestMs == doctest::Approx(11));
}

TEST_CASE("the sample cap is enforced") {
    Window w;
    for (int i = 0; i < kWindowMaxSamples + 50; ++i) add(w, i, 10, true, "a");
    CHECK(w.size() == static_cast<std::size_t>(kWindowMaxSamples));
}

TEST_CASE("spark tracks one responder only") {
    Window w;
    add(w, 0, 10, true, "a");
    add(w, 1000, 90, true, "b");
    add(w, 2000, 11, true, "a");
    const auto spark = w.statsFor("a").spark;
    REQUIRE(spark.size() == 2);
    CHECK(spark[0] == doctest::Approx(10));
    CHECK(spark[1] == doctest::Approx(11));
}

TEST_CASE("responders are ordered by count then IP") {
    Window w;
    add(w, 0, 10, true, "10.0.0.2");
    add(w, 1000, 10, true, "10.0.0.1");
    add(w, 2000, 10, true, "10.0.0.1");
    add(w, 3000, 10, true, "10.0.0.3");
    add(w, 4000, 0, false, "");
    const auto got = w.responders();
    REQUIRE(got.size() == 3);
    CHECK(got[0] == "10.0.0.1");
    CHECK(got[1] == "10.0.0.2");
    CHECK(got[2] == "10.0.0.3");
}

TEST_CASE("an out-of-order insert keeps send-order adjacency") {
    Window w;
    add(w, 0, 10, true, "a");
    add(w, 2000, 14, true, "a");
    // a late-delivered result for t=1000 must land between them so the jitter
    // pairing reflects real send order
    add(w, 1000, 12, true, "a");
    const RttStats st = w.statsFor("a");
    REQUIRE(st.jitterMs.has_value());
    CHECK(*st.jitterMs == doctest::Approx(2));
    CHECK(*st.lastMs == doctest::Approx(14));
}

TEST_CASE("reset clears the window") {
    Window w;
    add(w, 0, 10, true, "a");
    w.reset();
    CHECK(w.size() == 0);
    CHECK_FALSE(w.lossPct().has_value());
}
