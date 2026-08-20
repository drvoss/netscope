// Package stats implements the moving window and the derived RTT statistics.
//
// Every rule here is a cross-language contract from docs/netscope-spec.md §4 and
// must match netscope-cpp/src/core/stats.cpp exactly.
package stats

import (
	"math"
	"sort"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/model"
)

// Contract constants (spec §4.1). Do not change one implementation only.
const (
	WindowDuration   = 120 * time.Second
	WindowMaxSamples = 120
	ProbeTimeout     = 1500 * time.Millisecond
	SparkMax         = 120
)

// Sample is one probe outcome recorded against a TTL bucket.
//
// There is exactly ONE window per TTL position, with each sample tagged by the
// responder that answered it. That is what lets jitter pairing break both on a
// timeout and on an ECMP responder switch without keeping several parallel
// windows in sync (spec §4.3, §5.3).
type Sample struct {
	SentAt    time.Duration
	RTT       time.Duration
	OK        bool // false == Timeout; only timeouts count as loss (spec §4.2)
	Responder string
}

// Window is a time-based moving window with a hard sample cap.
//
// Time-based, not count-based: cadence differs per TTL, so a fixed sample count
// would represent a different amount of wall time at each hop (spec §4.1).
type Window struct {
	Dur     time.Duration
	Max     int
	samples []Sample
}

func NewWindow() *Window {
	return &Window{Dur: WindowDuration, Max: WindowMaxSamples}
}

// Add records a sample. Samples are expected in non-decreasing SentAt order;
// out-of-order arrivals are inserted so ordering invariants hold for the
// adjacency-sensitive jitter computation.
func (w *Window) Add(s Sample) {
	n := len(w.samples)
	if n == 0 || w.samples[n-1].SentAt <= s.SentAt {
		w.samples = append(w.samples, s)
	} else {
		i := sort.Search(n, func(i int) bool { return w.samples[i].SentAt > s.SentAt })
		w.samples = append(w.samples, Sample{})
		copy(w.samples[i+1:], w.samples[i:])
		w.samples[i] = s
	}
	if len(w.samples) > w.Max {
		w.samples = w.samples[len(w.samples)-w.Max:]
	}
}

// Prune drops samples that fell out of the time window.
func (w *Window) Prune(now time.Duration) {
	if w.Dur <= 0 {
		return
	}
	cut := now - w.Dur
	i := 0
	for i < len(w.samples) && w.samples[i].SentAt <= cut {
		i++
	}
	if i > 0 {
		w.samples = w.samples[i:]
	}
}

// Reset clears the window. Used when a responder change makes older samples
// incomparable (spec §5.3).
func (w *Window) Reset() { w.samples = w.samples[:0] }

// Len is the number of samples currently in the window.
func (w *Window) Len() int { return len(w.samples) }

// Samples exposes the window contents read-only, for tests and the engine.
func (w *Window) Samples() []Sample { return w.samples }

// LossPct is the bucket loss rate: timeouts over probes sent inside the window.
// Returns nil when nothing was sent in the window, which the UI shows as "---"
// rather than as 0% (spec §4.2, §8.3).
func (w *Window) LossPct() *float64 {
	if len(w.samples) == 0 {
		return nil
	}
	lost := 0
	for _, s := range w.samples {
		if !s.OK {
			lost++
		}
	}
	v := 100 * float64(lost) / float64(len(w.samples))
	return &v
}

// Responders lists the distinct responders seen in the window, ordered by
// descending observation count then ascending IP so both implementations agree.
func (w *Window) Responders() []string {
	counts := map[string]int{}
	for _, s := range w.samples {
		if s.OK && s.Responder != "" {
			counts[s.Responder]++
		}
	}
	out := make([]string, 0, len(counts))
	for ip := range counts {
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool {
		if counts[out[i]] != counts[out[j]] {
			return counts[out[i]] > counts[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// StatsFor derives the summary for one responder.
//
// Jitter is the mean absolute difference between ADJACENT successful samples of
// this responder: a timeout or a different responder sitting between two
// samples breaks the pair, so loss is never double-counted as jitter. With
// fewer than two valid pairs jitter is nil, which renders as "—" and not 0
// (spec §4.3).
func (w *Window) StatsFor(responder string) model.RttStats {
	var st model.RttStats
	if responder == "" {
		return st
	}

	rtts := make([]float64, 0, len(w.samples))
	var diffs []float64
	for i, s := range w.samples {
		if !s.OK || s.Responder != responder {
			continue
		}
		ms := float64(s.RTT) / float64(time.Millisecond)
		rtts = append(rtts, ms)
		if i > 0 {
			p := w.samples[i-1]
			if p.OK && p.Responder == responder {
				prev := float64(p.RTT) / float64(time.Millisecond)
				diffs = append(diffs, math.Abs(ms-prev))
			}
		}
	}

	st.Samples = len(rtts)
	if len(rtts) == 0 {
		return st
	}

	best, worst, sum := rtts[0], rtts[0], 0.0
	for _, v := range rtts {
		if v < best {
			best = v
		}
		if v > worst {
			worst = v
		}
		sum += v
	}
	avg := sum / float64(len(rtts))

	st.LastMs = model.F64(rtts[len(rtts)-1])
	st.BestMs = model.F64(best)
	st.WorstMs = model.F64(worst)
	st.AvgMs = model.F64(avg)

	// Jitter needs at least two successive-difference pairs (spec §4.3).
	if len(diffs) >= 2 {
		d := 0.0
		for _, v := range diffs {
			d += v
		}
		st.JitterMs = model.F64(d / float64(len(diffs)))
	}

	// Sample standard deviation, n-1. Reported alongside jitter because the
	// cross-review disagreed on which is the right metric (R1-3).
	if len(rtts) >= 2 {
		ss := 0.0
		for _, v := range rtts {
			ss += (v - avg) * (v - avg)
		}
		st.StdevMs = model.F64(math.Sqrt(ss / float64(len(rtts)-1)))
	}

	if len(rtts) > SparkMax {
		st.Spark = append([]float64(nil), rtts[len(rtts)-SparkMax:]...)
	} else {
		st.Spark = append([]float64(nil), rtts...)
	}
	return st
}
