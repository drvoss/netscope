package stats

import (
	"math"
	"testing"
	"time"
)

func ms(v float64) time.Duration { return time.Duration(v * float64(time.Millisecond)) }

func add(w *Window, atMs float64, rttMs float64, ok bool, resp string) {
	w.Add(Sample{SentAt: ms(atMs), RTT: ms(rttMs), OK: ok, Responder: resp})
}

func wantF(t *testing.T, name string, got *float64, want float64) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s: got nil, want %v", name, want)
	}
	if math.Abs(*got-want) > 1e-9 {
		t.Fatalf("%s: got %v, want %v", name, *got, want)
	}
}

func wantNil(t *testing.T, name string, got *float64) {
	t.Helper()
	if got != nil {
		t.Fatalf("%s: got %v, want nil", name, *got)
	}
}

func TestLossPctCountsOnlyTimeouts(t *testing.T) {
	w := NewWindow()
	add(w, 0, 10, true, "a")
	add(w, 1000, 0, false, "")
	add(w, 2000, 12, true, "a")
	add(w, 3000, 0, false, "")
	wantF(t, "lossPct", w.LossPct(), 50)
}

func TestLossPctNilWhenWindowEmpty(t *testing.T) {
	w := NewWindow()
	wantNil(t, "lossPct", w.LossPct())
	// A hop that has sent nothing inside the window must render "---", not 0%.
	add(w, 0, 5, true, "a")
	w.Prune(WindowDuration + ms(1))
	wantNil(t, "lossPct after prune", w.LossPct())
}

func TestJitterIsMeanAbsoluteSuccessiveDifference(t *testing.T) {
	w := NewWindow()
	// 10, 12, 15, 11 -> diffs 2, 3, 4 -> mean 3
	add(w, 0, 10, true, "a")
	add(w, 1000, 12, true, "a")
	add(w, 2000, 15, true, "a")
	add(w, 3000, 11, true, "a")
	st := w.StatsFor("a")
	wantF(t, "jitter", st.JitterMs, 3)
	wantF(t, "avg", st.AvgMs, 12)
	wantF(t, "best", st.BestMs, 10)
	wantF(t, "worst", st.WorstMs, 15)
	wantF(t, "last", st.LastMs, 11)
	if st.Samples != 4 {
		t.Fatalf("samples: got %d want 4", st.Samples)
	}
}

func TestTimeoutBreaksJitterPairing(t *testing.T) {
	w := NewWindow()
	// 10, 12, [timeout], 40, 42
	// valid adjacent pairs: (10,12) and (40,42) -> diffs 2, 2 -> jitter 2.
	// If the timeout did not break the pairing we would also count |40-12|=28
	// and jitter would be 10.67, double-counting the loss as jitter.
	add(w, 0, 10, true, "a")
	add(w, 1000, 12, true, "a")
	add(w, 2000, 0, false, "")
	add(w, 3000, 40, true, "a")
	add(w, 4000, 42, true, "a")
	st := w.StatsFor("a")
	wantF(t, "jitter", st.JitterMs, 2)
}

func TestResponderSwitchBreaksJitterPairing(t *testing.T) {
	w := NewWindow()
	// ECMP: two routers alternate at the same TTL. Their RTTs must never be
	// paired with each other (spec §5.3).
	add(w, 0, 10, true, "a")
	add(w, 1000, 90, true, "b")
	add(w, 2000, 12, true, "a")
	add(w, 3000, 95, true, "b")
	stA := w.StatsFor("a")
	// a has samples 10 and 12 but they are never adjacent -> no pairs at all.
	wantNil(t, "a jitter", stA.JitterMs)
	if stA.Samples != 2 {
		t.Fatalf("a samples: got %d want 2", stA.Samples)
	}
	wantF(t, "a avg", stA.AvgMs, 11)
	stB := w.StatsFor("b")
	wantF(t, "b avg", stB.AvgMs, 92.5)
}

func TestJitterNilWithFewerThanTwoPairs(t *testing.T) {
	w := NewWindow()
	add(w, 0, 10, true, "a")
	wantNil(t, "one sample", w.StatsFor("a").JitterMs)
	add(w, 1000, 20, true, "a")
	// exactly one pair -> still nil, must not render as 0
	wantNil(t, "one pair", w.StatsFor("a").JitterMs)
	add(w, 2000, 25, true, "a")
	wantF(t, "two pairs", w.StatsFor("a").JitterMs, 7.5)
}

func TestStdevIsSampleStdev(t *testing.T) {
	w := NewWindow()
	for _, v := range []float64{2, 4, 4, 4, 5, 5, 7, 9} {
		add(w, 0, v, true, "a")
	}
	// population stdev is 2, sample stdev (n-1) is 2.13809...
	st := w.StatsFor("a")
	wantF(t, "stdev", st.StdevMs, math.Sqrt(32.0/7.0))
}

func TestStdevNilWithOneSample(t *testing.T) {
	w := NewWindow()
	add(w, 0, 10, true, "a")
	wantNil(t, "stdev", w.StatsFor("a").StdevMs)
}

func TestPruneDropsOldSamplesOnly(t *testing.T) {
	w := NewWindow()
	add(w, 0, 10, true, "a")
	add(w, 60_000, 11, true, "a")
	add(w, 130_000, 12, true, "a")
	w.Prune(ms(130_000))
	// window is 120s wide, so SentAt <= 10_000 is dropped
	if w.Len() != 2 {
		t.Fatalf("len: got %d want 2", w.Len())
	}
	wantF(t, "best after prune", w.StatsFor("a").BestMs, 11)
}

func TestMaxSamplesCap(t *testing.T) {
	w := NewWindow()
	for i := 0; i < WindowMaxSamples+50; i++ {
		add(w, float64(i), 10, true, "a")
	}
	if w.Len() != WindowMaxSamples {
		t.Fatalf("len: got %d want %d", w.Len(), WindowMaxSamples)
	}
}

func TestSparkTracksResponderOnly(t *testing.T) {
	w := NewWindow()
	add(w, 0, 10, true, "a")
	add(w, 1000, 90, true, "b")
	add(w, 2000, 11, true, "a")
	sp := w.StatsFor("a").Spark
	if len(sp) != 2 || sp[0] != 10 || sp[1] != 11 {
		t.Fatalf("spark: got %v want [10 11]", sp)
	}
}

func TestRespondersOrderedByCountThenIP(t *testing.T) {
	w := NewWindow()
	add(w, 0, 10, true, "10.0.0.2")
	add(w, 1000, 10, true, "10.0.0.1")
	add(w, 2000, 10, true, "10.0.0.1")
	add(w, 3000, 10, true, "10.0.0.3")
	add(w, 4000, 0, false, "")
	got := w.Responders()
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	if len(got) != 3 {
		t.Fatalf("responders: got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("responders: got %v want %v", got, want)
		}
	}
}

func TestOutOfOrderInsertKeepsAdjacency(t *testing.T) {
	w := NewWindow()
	add(w, 0, 10, true, "a")
	add(w, 2000, 14, true, "a")
	// a late-delivered result for t=1000 must land between them so the jitter
	// pairing reflects real send order.
	add(w, 1000, 12, true, "a")
	st := w.StatsFor("a")
	wantF(t, "jitter", st.JitterMs, 2)
	wantF(t, "last", st.LastMs, 14)
}

func TestResetClears(t *testing.T) {
	w := NewWindow()
	add(w, 0, 10, true, "a")
	w.Reset()
	if w.Len() != 0 {
		t.Fatalf("len after reset: %d", w.Len())
	}
	wantNil(t, "lossPct", w.LossPct())
}
