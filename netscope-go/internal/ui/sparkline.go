package ui

import "strings"

var sparkRunes = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// Sparkline renders the last width values scaled between the series min and max.
//
// The scale is relative, not absolute: on a stable link every bar would sit at
// the bottom of an absolute scale and the shape would be invisible. The numeric
// min/max are printed next to the bar so the relative scale cannot mislead.
func Sparkline(values []float64, width int) string {
	if width <= 0 {
		return ""
	}
	if len(values) == 0 {
		return strings.Repeat(" ", width)
	}
	if len(values) > width {
		values = values[len(values)-width:]
	}

	min, max := values[0], values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	span := max - min

	var b strings.Builder
	for _, v := range values {
		idx := 0
		if span > 1e-9 {
			idx = int((v - min) / span * float64(len(sparkRunes)-1))
		} else {
			// A perfectly flat series should read as a mid-level line, not as an
			// empty trough.
			idx = len(sparkRunes) / 2
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkRunes) {
			idx = len(sparkRunes) - 1
		}
		b.WriteRune(sparkRunes[idx])
	}
	if pad := width - len(values); pad > 0 {
		b.WriteString(strings.Repeat(" ", pad))
	}
	return b.String()
}

// SparkRange returns the min and max of a series, for labelling the sparkline.
func SparkRange(values []float64) (float64, float64, bool) {
	if len(values) == 0 {
		return 0, 0, false
	}
	min, max := values[0], values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, max, true
}
