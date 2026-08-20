// Mirrors netscope-go/internal/ui/layout_test.go. The UX review found the previous
// height budget assembling screens taller than the terminal at 80x24 and 40x12,
// because it forced a minimum body height instead of taking rows away from the log.
#include <doctest/doctest.h>

#include "ui.h"

using namespace netscope;

TEST_CASE("layout never exceeds the terminal height") {
    struct Size {
        int w;
        int h;
    };
    const Size sizes[] = {{40, 12},  {60, 16},  {80, 24},  {80, 30},   {100, 24}, {100, 30},
                          {119, 40}, {120, 24}, {120, 30}, {200, 60},  {300, 100},
                          {40, 200}, {20, 8}};
    for (const Size& s : sizes) {
        const Layout l = planLayout(s.w, s.h);
        const int h = s.h < kMinHeight ? kMinHeight : s.h;
        CHECK_MESSAGE(l.totalHeight() <= h,
                      "size " << s.w << "x" << s.h << " assembled " << l.totalHeight());
        // The path table is the point of the program and always survives.
        CHECK(l.bodyHeight >= kBodyFloor);
        CHECK(l.logLines >= 0);
    }
}

TEST_CASE("layout breakpoints follow spec 8.2") {
    const Layout wide = planLayout(120, 40);
    CHECK_FALSE(wide.narrow);
    CHECK_FALSE(wide.medium);
    CHECK(wide.withRDNS);
    CHECK(wide.rightWidth == 46);
    CHECK(wide.tabHeight == 0);

    const Layout medium = planLayout(110, 40);
    CHECK_FALSE(medium.narrow);
    CHECK(medium.medium);
    // rDNS/ASN is the first column to drop.
    CHECK_FALSE(medium.withRDNS);
    CHECK(medium.rightWidth == 36);

    const Layout narrow = planLayout(99, 40);
    CHECK(narrow.narrow);
    CHECK(narrow.rightWidth == 0);
    CHECK(narrow.tabHeight > 0);
}

TEST_CASE("layout shrinks the log on short terminals") {
    CHECK(planLayout(120, 40).logLines == 4);
    CHECK(planLayout(120, 23).logLines <= 3);
}

TEST_CASE("layout gives up log rows before the body") {
    const Layout l = planLayout(80, 24);
    CHECK(l.totalHeight() <= 24);
    CHECK(l.bodyHeight >= kBodyFloor);
}

TEST_CASE("layout keeps the path table on an unusably small terminal") {
    // 40x12 cannot hold all six regions: header 5 + body 3 + midbar 4 + log 4 + tab 6
    // is 22 rows. Panels must be dropped rather than the screen overflowing.
    const Layout l = planLayout(40, 12);
    CHECK(l.totalHeight() <= 12);
    CHECK(l.bodyHeight >= kBodyFloor);
    CHECK(l.tabHeight == 0);
}

TEST_CASE("layout sacrifice order keeps the mid bar longest") {
    const Layout l = planLayout(120, 20);
    CHECK(l.showMidBar);
    CHECK(l.logLines < 4);
    CHECK(l.totalHeight() <= 20);
}

TEST_CASE("sparkline width and flat series") {
    CHECK(sparkline({}, 5).size() == 5);  // spaces
    // A flat series must read as a mid-level line, not an empty trough.
    const std::string flat = sparkline({10, 10, 10}, 3);
    CHECK_FALSE(flat.empty());
    CHECK(flat.find(' ') == std::string::npos);
    // Longer than the width: only the most recent values are shown.
    const std::string trimmed = sparkline({1, 2, 3, 4, 5}, 2);
    CHECK(trimmed.find(' ') == std::string::npos);
    CHECK(sparkline({1, 2, 3}, 0).empty());
}
