package ui

// Layout planning, kept as a pure function so it can be unit-tested without a
// terminal and so the C++ implementation can mirror it exactly (spec §8.2).
//
// Every panel's height is accounted for BEFORE anything is rendered. When the
// terminal is too short, panels are GIVEN UP in order of least value rather than
// letting the assembled screen overflow and clip the bottom -- which is what the
// UX review found at 80x24 and 40x12.
//
// The order of sacrifice is: log rows, then the collapsed right-hand tab, then the
// mid bar, then the log entirely. The path table always survives, because it is the
// point of the program.

// Fixed chrome heights. A box of height H shows H-2 content rows.
const (
	HeaderHeight = 5 // 3 content rows + border
	MidBarHeight = 4 // 2 content rows + border
	// A log box holds its title row, its entries, and two border rows.
	LogChrome = 3

	tabHeightFull = 9
	tabHeightMin  = 6
	bodyPreferred = 5
	bodyFloor     = 3

	// MinWidth and MinHeight are the smallest terminal the renderer will target;
	// anything smaller is treated as this size and will simply be clipped by the
	// terminal itself.
	MinWidth  = 40
	MinHeight = 12
)

// Layout is the resolved plan for one terminal size.
type Layout struct {
	Narrow     bool
	Medium     bool
	RightWidth int // 0 when the right column is collapsed
	BodyHeight int
	LogLines   int // 0 when the log had to be dropped
	TabHeight  int // 0 unless Narrow and there is room
	ShowMidBar bool
	WithRDNS   bool
}

// TotalHeight is the height of the assembled screen.
func (l Layout) TotalHeight() int {
	total := HeaderHeight + l.BodyHeight + l.TabHeight
	if l.ShowMidBar {
		total += MidBarHeight
	}
	if l.LogLines > 0 {
		total += l.LogLines + LogChrome
	}
	return total
}

// PlanLayout resolves the breakpoints and the height budget for a terminal.
func PlanLayout(w, h int) Layout {
	if w < MinWidth {
		w = MinWidth
	}
	if h < MinHeight {
		h = MinHeight
	}

	var l Layout
	l.Narrow = w < MediumMin
	l.Medium = w >= MediumMin && w < WideMin
	l.WithRDNS = !l.Narrow && !l.Medium
	l.ShowMidBar = true

	switch {
	case l.Narrow:
		l.RightWidth = 0
		l.TabHeight = tabHeightFull
	case l.Medium:
		l.RightWidth = 36
	default:
		l.RightWidth = 46
	}

	l.LogLines = 4
	if h < ShortRows {
		l.LogLines = 3 // spec §8.2: shrink the log, keep the sparkline
	}

	// chrome is everything except the body.
	chrome := func() int {
		c := HeaderHeight + l.TabHeight
		if l.ShowMidBar {
			c += MidBarHeight
		}
		if l.LogLines > 0 {
			c += l.LogLines + LogChrome
		}
		return c
	}

	for {
		l.BodyHeight = h - chrome()
		if l.BodyHeight >= bodyPreferred {
			break
		}
		// Give up, in order of least value.
		if l.LogLines > 1 {
			l.LogLines--
			continue
		}
		if l.TabHeight > tabHeightMin {
			l.TabHeight--
			continue
		}
		if l.TabHeight > 0 {
			l.TabHeight = 0
			continue
		}
		if l.ShowMidBar {
			// Reluctant: the sparkline is the reason for the bar. But a clipped
			// screen is worse than a missing panel.
			l.ShowMidBar = false
			continue
		}
		if l.LogLines > 0 {
			l.LogLines = 0
			continue
		}
		break
	}
	if l.BodyHeight < bodyFloor {
		l.BodyHeight = bodyFloor
	}
	return l
}
