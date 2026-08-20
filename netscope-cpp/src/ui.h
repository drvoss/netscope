// FTXUI front end.
//
// Strictly read-only with respect to measurement state: it renders the immutable
// snapshot it was handed and sends commands back through the runner. It never
// touches engine memory (spec §3.1).
#pragma once

#include <string>
#include <vector>

#include "runner.h"

namespace netscope {

// Layout breakpoints (spec §8.2).
inline constexpr int kWideMin = 120;    // full layout
inline constexpr int kMediumMin = 100;  // narrower right column, rDNS/ASN dropped
inline constexpr int kShortRows = 24;   // below this the log shrinks

// Fixed chrome heights. A box of height H shows H-2 content rows.
inline constexpr int kHeaderHeight = 5;  // 3 content rows + border
inline constexpr int kMidBarHeight = 4;  // 2 content rows + border
inline constexpr int kLogChrome = 3;     // title row + two border rows
inline constexpr int kTabHeightFull = 9;
inline constexpr int kTabHeightMin = 6;
inline constexpr int kBodyPreferred = 5;
inline constexpr int kBodyFloor = 3;
inline constexpr int kMinWidth = 40;
inline constexpr int kMinHeight = 12;

// The resolved plan for one terminal size.
//
// A pure function so it can be unit-tested without a terminal, and so it mirrors
// the Go implementation's PlanLayout exactly. When the terminal is too short,
// panels are GIVEN UP in order of least value -- log rows, then the collapsed
// right-hand tab, then the mid bar, then the log entirely -- rather than letting
// the assembled screen overflow and clip the bottom. The path table always
// survives, because it is the point of the program.
struct Layout {
    bool narrow = false;
    bool medium = false;
    int rightWidth = 0;  // 0 when the right column is collapsed
    int bodyHeight = 0;
    int logLines = 0;    // 0 when the log had to be dropped
    int tabHeight = 0;   // 0 unless narrow and there is room
    bool showMidBar = true;
    bool withRDNS = false;

    int totalHeight() const;
};

Layout planLayout(int w, int h);

// Runs the interactive dashboard until the user quits. Returns the process exit
// code.
int runUI(Runner& runner);

// Renders the last `width` values scaled between the series min and max.
//
// The scale is relative, not absolute: on a stable link every bar would sit at the
// bottom of an absolute scale and the shape would be invisible. The numeric
// min/max are printed next to the bar so the relative scale cannot mislead.
std::string sparkline(const std::vector<double>& values, int width);

}  // namespace netscope
