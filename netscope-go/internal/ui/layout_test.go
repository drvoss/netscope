package ui

import "testing"

// The UX review found the previous height budget assembling screens taller than
// the terminal at 80x24 and 40x12, because it forced a minimum body height instead
// of taking rows away from the log. These are the regression tests for that, and
// the C++ suite asserts the same numbers against its mirror of PlanLayout.

func TestLayoutNeverExceedsTerminalHeight(t *testing.T) {
	sizes := []struct{ w, h int }{
		{40, 12}, {60, 16}, {80, 24}, {80, 30}, {100, 24}, {100, 30},
		{119, 40}, {120, 24}, {120, 30}, {200, 60}, {300, 100},
		{40, 200}, {20, 8}, // below the clamps
	}
	for _, s := range sizes {
		l := PlanLayout(s.w, s.h)
		h := s.h
		if h < 12 {
			h = 12
		}
		if total := l.TotalHeight(); total > h {
			t.Errorf("%dx%d: assembled height %d exceeds terminal height %d (%+v)",
				s.w, s.h, total, h, l)
		}
		// The path table is the point of the program and always survives; the log,
		// the collapsed tab and (last resort) the mid bar are what get given up.
		if l.BodyHeight < bodyFloor {
			t.Errorf("%dx%d: body height %d below the floor", s.w, s.h, l.BodyHeight)
		}
		if l.LogLines < 0 {
			t.Errorf("%dx%d: negative log lines %d", s.w, s.h, l.LogLines)
		}
	}
}

func TestLayoutKeepsThePathTableOnAnUnusablySmallTerminal(t *testing.T) {
	// 40x12 cannot hold all six regions: header 5 + body 3 + midbar 4 + log 4 + tab 6
	// is 22 rows. Panels must be dropped rather than the screen overflowing.
	l := PlanLayout(40, 12)
	if l.TotalHeight() > 12 {
		t.Fatalf("40x12 total %d (%+v)", l.TotalHeight(), l)
	}
	if l.BodyHeight < bodyFloor {
		t.Fatalf("40x12 dropped the path table: %+v", l)
	}
	if l.TabHeight != 0 {
		t.Fatalf("40x12 should have given up the collapsed tab: %+v", l)
	}
}

func TestLayoutSacrificeOrder(t *testing.T) {
	// The mid bar outranks the log rows and the tab, so it must still be present at
	// a height where the log has already been trimmed.
	l := PlanLayout(120, 20)
	if !l.ShowMidBar {
		t.Fatalf("120x20 gave up the mid bar too early: %+v", l)
	}
	if l.LogLines >= 4 {
		t.Fatalf("120x20 should have trimmed the log first: %+v", l)
	}
	if l.TotalHeight() > 20 {
		t.Fatalf("120x20 total %d", l.TotalHeight())
	}
}

func TestLayoutBreakpoints(t *testing.T) {
	// spec §8.2
	wide := PlanLayout(120, 40)
	if wide.Narrow || wide.Medium || !wide.WithRDNS || wide.RightWidth != 46 {
		t.Fatalf("120 wide: %+v", wide)
	}
	if wide.TabHeight != 0 {
		t.Fatalf("wide layout must not reserve the collapsed tab: %+v", wide)
	}

	medium := PlanLayout(110, 40)
	if medium.Narrow || !medium.Medium || medium.WithRDNS || medium.RightWidth != 36 {
		t.Fatalf("110 wide: %+v (rDNS/ASN is the first column to drop)", medium)
	}

	narrow := PlanLayout(99, 40)
	if !narrow.Narrow || narrow.RightWidth != 0 || narrow.TabHeight == 0 {
		t.Fatalf("99 wide: %+v (right column collapses to a Tab-switched panel)", narrow)
	}
}

func TestLayoutShrinksLogOnShortTerminals(t *testing.T) {
	tall := PlanLayout(120, 40)
	if tall.LogLines != 4 {
		t.Fatalf("tall terminal log lines: got %d want 4", tall.LogLines)
	}
	short := PlanLayout(120, 23)
	if short.LogLines > 3 {
		t.Fatalf("short terminal log lines: got %d want <= 3 (spec §8.2)", short.LogLines)
	}
	// The sparkline bar is never given up, however short the terminal.
	if MidBarHeight != 4 {
		t.Fatalf("mid bar height changed: %d", MidBarHeight)
	}
}

func TestLayoutGivesUpLogRowsBeforeTheBody(t *testing.T) {
	// At 80x24 the old code produced a 27-row screen. The body must get its
	// preferred 5 rows only if the log can afford it.
	l := PlanLayout(80, 24)
	if l.TotalHeight() > 24 {
		t.Fatalf("80x24 total %d (%+v)", l.TotalHeight(), l)
	}
	if l.BodyHeight < bodyFloor {
		t.Fatalf("80x24 body %d", l.BodyHeight)
	}
}
