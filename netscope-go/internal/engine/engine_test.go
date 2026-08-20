package engine

import (
	"strings"
	"testing"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/model"
)

func ms(v int) time.Duration { return time.Duration(v) * time.Millisecond }

func newTestEngine(mode model.ProbeMode) *Engine {
	return New(model.Target{Input: "example.com", IP: "93.184.216.34", Family: model.FamilyIP4}, mode)
}

// probe feeds one result at the engine's current generation.
func feed(e *Engine, ttl int, attempt uint64, at int, out model.Outcome, resp string, rttMs float64) {
	r := model.ProbeResult{
		ID:        model.ProbeID{Generation: e.Generation(), Family: model.FamilyIP4, TTL: ttl, Attempt: attempt},
		Outcome:   out,
		Responder: resp,
		SentAt:    ms(at),
	}
	if out.Answered() {
		r.RTT = time.Duration(rttMs * float64(time.Millisecond))
		r.RecvAt = r.SentAt + r.RTT
	} else {
		r.RecvAt = r.SentAt + ms(1500)
	}
	e.Ingest(r)
}

func hop(s *model.Snapshot, ttl int) *model.HopPosition {
	for i := range s.Hops {
		if s.Hops[i].TTL == ttl {
			return &s.Hops[i]
		}
	}
	return nil
}

func TestUnknownUntilMinSamples(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	feed(e, 1, 1, 0, model.OutcomeTimeout, "", 0)
	feed(e, 1, 2, 1000, model.OutcomeTimeout, "", 0)
	s := e.Snapshot(ms(2000))
	if got := hop(s, 1).Status; got != model.StatusUnknown {
		t.Fatalf("status: got %s want UNKNOWN (only 2 of %d samples)", got, MinSamples)
	}
	feed(e, 1, 3, 2000, model.OutcomeTimeout, "", 0)
	s = e.Snapshot(ms(3000))
	if got := hop(s, 1).Status; got != model.StatusSilent {
		t.Fatalf("status: got %s want SILENT", got)
	}
}

func TestTransitOnlyRequiresGreaterTTLAnswering(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	// hop 2 never answers
	for i := 1; i <= 3; i++ {
		feed(e, 2, uint64(i), i*1000, model.OutcomeTimeout, "", 0)
	}
	s := e.Snapshot(ms(4000))
	if got := hop(s, 2).Status; got != model.StatusSilent {
		t.Fatalf("without downstream evidence: got %s want SILENT", got)
	}
	// now hop 3 answers -> hop 2 forwards traffic but does not answer probes
	feed(e, 3, 1, 5000, model.OutcomeTTLExpired, "10.0.0.3", 20)
	s = e.Snapshot(ms(6000))
	if got := hop(s, 2).Status; got != model.StatusTransitOnly {
		t.Fatalf("with downstream evidence: got %s want TRANSIT_ONLY", got)
	}
}

func TestDegradedBackendNeverInfersTransitOnly(t *testing.T) {
	// The command backend cannot support the inference (spec §6.4).
	e := newTestEngine(model.ModeCommand)
	for i := 1; i <= 3; i++ {
		feed(e, 2, uint64(i), i*1000, model.OutcomeTimeout, "", 0)
	}
	feed(e, 3, 1, 5000, model.OutcomeTTLExpired, "10.0.0.3", 20)
	s := e.Snapshot(ms(6000))
	if got := hop(s, 2).Status; got != model.StatusSilent {
		t.Fatalf("degraded: got %s want SILENT", got)
	}
}

func TestDegradedBackendSuppressesJitterAndStdev(t *testing.T) {
	e := newTestEngine(model.ModeCommand)
	for i := 0; i < 5; i++ {
		feed(e, 1, uint64(i+1), i*1000, model.OutcomeTTLExpired, "10.0.0.1", float64(10+i))
	}
	h := hop(e.Snapshot(ms(6000)), 1)
	if h.Stats.JitterMs != nil || h.Stats.StdevMs != nil {
		t.Fatalf("degraded mode must null jitter/stdev, got %v/%v", h.Stats.JitterMs, h.Stats.StdevMs)
	}
	if h.Stats.AvgMs == nil {
		t.Fatal("avg should still be reported in degraded mode")
	}
}

func TestHysteresisRespondingToDegradedAndBack(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	at := 0
	send := func(out model.Outcome) {
		at += 1000
		feed(e, 1, uint64(at/1000), at, out, respOf(out), 10)
		e.Snapshot(ms(at + 100))
	}
	for i := 0; i < 3; i++ {
		send(model.OutcomeTTLExpired)
	}
	if got := hop(e.Snapshot(ms(at+200)), 1).Status; got != model.StatusResponding {
		t.Fatalf("got %s want RESPONDING", got)
	}
	// 3 timeouts is below LossStreak=4, must not flap
	for i := 0; i < 3; i++ {
		send(model.OutcomeTimeout)
	}
	if got := hop(e.Snapshot(ms(at+200)), 1).Status; got != model.StatusResponding {
		t.Fatalf("after 3 timeouts: got %s want RESPONDING (LossStreak=%d)", got, LossStreak)
	}
	send(model.OutcomeTimeout) // 4th
	if got := hop(e.Snapshot(ms(at+200)), 1).Status; got != model.StatusDegraded {
		t.Fatalf("after 4 timeouts: got %s want DEGRADED", got)
	}
	// one reply is not enough to recover
	send(model.OutcomeTTLExpired)
	if got := hop(e.Snapshot(ms(at+200)), 1).Status; got != model.StatusDegraded {
		t.Fatalf("after 1 reply: got %s want DEGRADED (RecoverStreak=%d)", got, RecoverStreak)
	}
	send(model.OutcomeTTLExpired)
	if got := hop(e.Snapshot(ms(at+200)), 1).Status; got != model.StatusResponding {
		t.Fatalf("after 2 replies: got %s want RESPONDING", got)
	}
}

func respOf(out model.Outcome) string {
	if out.Answered() {
		return "10.0.0.1"
	}
	return ""
}

func TestUnreachableCountsAsAnswerNotLoss(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	feed(e, 4, 1, 0, model.OutcomeUnreachable, "10.0.0.4", 30)
	feed(e, 4, 2, 1000, model.OutcomeUnreachable, "10.0.0.4", 31)
	h := hop(e.Snapshot(ms(2000)), 4)
	if h.LossPct == nil || *h.LossPct != 0 {
		t.Fatalf("lossPct: got %v want 0 (unreachable is a response)", h.LossPct)
	}
	if h.Replied != 2 {
		t.Fatalf("replied: got %d want 2", h.Replied)
	}
}

func TestStaleGenerationDiscarded(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	feed(e, 1, 1, 0, model.OutcomeTTLExpired, "10.0.0.1", 10)
	e.Reprobe(ms(1000))
	// a result from the old generation arriving late
	e.Ingest(model.ProbeResult{
		ID:        model.ProbeID{Generation: 1, TTL: 1, Attempt: 2},
		Outcome:   model.OutcomeTTLExpired,
		Responder: "10.0.0.1",
		RTT:       ms(10),
		SentAt:    ms(500),
		RecvAt:    ms(510),
	})
	s := e.Snapshot(ms(2000))
	if len(s.Hops) != 0 {
		t.Fatalf("stale result leaked into new generation: %d hops", len(s.Hops))
	}
	if s.Generation != 2 {
		t.Fatalf("generation: got %d want 2", s.Generation)
	}
}

func TestLateReplyDiscarded(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	// 1600ms > probeTimeout 1500ms: we already gave up, counting it would
	// pollute avg and jitter.
	feed(e, 1, 1, 0, model.OutcomeTTLExpired, "10.0.0.1", 1600)
	s := e.Snapshot(ms(2000))
	if len(s.Hops) != 0 {
		t.Fatalf("late reply was recorded: %+v", s.Hops)
	}
}

func TestEcmpRespondersKeepSeparateStats(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	feed(e, 3, 1, 0, model.OutcomeTTLExpired, "10.0.0.9", 10)
	feed(e, 3, 2, 1000, model.OutcomeTTLExpired, "10.0.0.8", 90)
	feed(e, 3, 3, 2000, model.OutcomeTTLExpired, "10.0.0.9", 12)
	h := hop(e.Snapshot(ms(3000)), 3)
	if len(h.Responders) != 2 {
		t.Fatalf("responders: got %d want 2", len(h.Responders))
	}
	if h.Primary != "10.0.0.9" {
		t.Fatalf("primary: got %s want 10.0.0.9 (seen twice)", h.Primary)
	}
	// The two routers' RTTs must not be averaged together into 37.3ms.
	if h.Stats.AvgMs == nil || *h.Stats.AvgMs != 11 {
		t.Fatalf("primary avg: got %v want 11", h.Stats.AvgMs)
	}
	for _, r := range h.Responders {
		if r.IP == "10.0.0.8" && (r.Stats.AvgMs == nil || *r.Stats.AvgMs != 90) {
			t.Fatalf("secondary avg: got %v want 90", r.Stats.AvgMs)
		}
	}
}

func TestRouteChangeNeedsTwoRounds(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	feed(e, 1, 1, 0, model.OutcomeTTLExpired, "10.0.0.1", 5)
	feed(e, 2, 1, 100, model.OutcomeReply, "93.184.216.34", 40)
	e.Snapshot(ms(200))
	e.EndTraceRound(ms(300)) // establishes the baseline

	// hop 1 now answered by a different router; one round must not report it
	feed(e, 1, 2, 1000, model.OutcomeTTLExpired, "10.0.0.2", 6)
	e.Snapshot(ms(1100))
	e.EndTraceRound(ms(1200))
	if countEvents(e, model.EventRouteChange) != 0 {
		t.Fatal("route change reported after a single round (no debounce)")
	}
	feed(e, 1, 3, 2000, model.OutcomeTTLExpired, "10.0.0.2", 6)
	e.Snapshot(ms(2100))
	e.EndTraceRound(ms(2200))
	if countEvents(e, model.EventRouteChange) == 0 {
		t.Fatal("route change not reported after two rounds")
	}
}

func TestTemporarySilenceIsNotARouteChange(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	feed(e, 1, 1, 0, model.OutcomeTTLExpired, "10.0.0.1", 5)
	feed(e, 2, 1, 100, model.OutcomeReply, "93.184.216.34", 40)
	e.Snapshot(ms(200))
	e.EndTraceRound(ms(300))
	// hop 1 goes quiet: window still holds the old sample until it ages out, so
	// force the empty-set case by pruning past the window.
	for round := 0; round < 3; round++ {
		at := 200_000 + round*1000
		feed(e, 1, uint64(round+2), at, model.OutcomeTimeout, "", 0)
		e.Snapshot(ms(at + 100))
		e.EndTraceRound(ms(at + 200))
	}
	if countEvents(e, model.EventRouteChange) != 0 {
		t.Fatal("silence was reported as a route change")
	}
}

func countEvents(e *Engine, kind model.EventKind) int {
	n := 0
	for _, ev := range e.events {
		if ev.Kind == kind {
			n++
		}
	}
	return n
}

func TestPermissionDeniedIsGracefulEvent(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	e.Ingest(model.ProbeResult{
		ID:      model.ProbeID{Generation: 1, TTL: 1},
		Outcome: model.OutcomePermissionDenied,
		Note:    "socket: operation not permitted",
		RecvAt:  ms(10),
	})
	s := e.Snapshot(ms(20))
	if len(s.Hops) != 0 {
		t.Fatal("PermissionDenied must not create a hop row")
	}
	found := false
	for _, ev := range s.Events {
		if ev.Kind == model.EventPermission && strings.Contains(ev.Text, "not permitted") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a permission event, got %+v", s.Events)
	}
}

func TestHopsAreGapFreeAndAscending(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	feed(e, 1, 1, 0, model.OutcomeTTLExpired, "10.0.0.1", 5)
	feed(e, 4, 1, 100, model.OutcomeReply, "93.184.216.34", 40)
	s := e.Snapshot(ms(200))
	if len(s.Hops) != 4 {
		t.Fatalf("hops: got %d want 4 (1..destTTL, gap-free)", len(s.Hops))
	}
	for i, h := range s.Hops {
		if h.TTL != i+1 {
			t.Fatalf("hop %d has ttl %d", i, h.TTL)
		}
	}
	// The filler rows must be UNKNOWN with no invented statistics, not a
	// zero-valued RESPONDING row.
	for _, ttl := range []int{2, 3} {
		h := hop(s, ttl)
		if h.Status != model.StatusUnknown {
			t.Fatalf("filler hop %d: status %s want UNKNOWN", ttl, h.Status)
		}
		if h.LossPct != nil || h.Stats.AvgMs != nil || h.Sent != 0 {
			t.Fatalf("filler hop %d has invented data: %+v", ttl, h)
		}
	}
}

func TestDestinationTTLUnlatchesWhenThePathGrows(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	feed(e, 1, 1, 0, model.OutcomeTTLExpired, "10.0.0.1", 5)
	feed(e, 2, 1, 100, model.OutcomeReply, "93.184.216.34", 40)
	if e.DestTTL() != 2 {
		t.Fatalf("destTTL: got %d want 2", e.DestTTL())
	}
	// A router now answers at TTL 2, so the destination moved further away. Keeping
	// the latch would truncate the table at the old length for good.
	feed(e, 2, 2, 1000, model.OutcomeTTLExpired, "10.0.0.2", 6)
	if e.DestTTL() != 0 {
		t.Fatalf("destTTL: got %d want 0 (unlatched)", e.DestTTL())
	}
}

func TestEcmpJitterIsNotPairedAcrossResponders(t *testing.T) {
	// The avg-only assertion in TestEcmpRespondersKeepSeparateStats would still
	// pass if jitter mixed the two routers, so check jitter explicitly.
	e := newTestEngine(model.ModeRaw)
	feed(e, 2, 1, 0, model.OutcomeTTLExpired, "10.0.0.9", 10)
	feed(e, 2, 2, 1000, model.OutcomeTTLExpired, "10.0.0.8", 90)
	feed(e, 2, 3, 2000, model.OutcomeTTLExpired, "10.0.0.9", 12)
	feed(e, 2, 4, 3000, model.OutcomeTTLExpired, "10.0.0.8", 95)
	h := hop(e.Snapshot(ms(4000)), 2)
	for _, r := range h.Responders {
		if r.Stats.JitterMs != nil {
			t.Fatalf("responder %s got jitter %v; alternating responders are never adjacent",
				r.IP, *r.Stats.JitterMs)
		}
	}
}

func TestDegradedModeReportsOnlyThePrimaryResponder(t *testing.T) {
	// The command backend runs one sweep at a time and cannot tell a real ECMP
	// split from two sweeps taking different paths (spec §6.4).
	e := newTestEngine(model.ModeCommand)
	feed(e, 2, 1, 0, model.OutcomeTTLExpired, "10.0.0.9", 10)
	feed(e, 2, 2, 1000, model.OutcomeTTLExpired, "10.0.0.8", 90)
	feed(e, 2, 3, 2000, model.OutcomeTTLExpired, "10.0.0.9", 12)
	h := hop(e.Snapshot(ms(3000)), 2)
	if len(h.Responders) != 1 {
		t.Fatalf("responders: got %d want 1 in degraded mode", len(h.Responders))
	}
	if h.Responders[0].IP != "10.0.0.9" {
		t.Fatalf("responder: got %s want the primary 10.0.0.9", h.Responders[0].IP)
	}
	// A raw-mode engine with the same input must still show both.
	raw := newTestEngine(model.ModeRaw)
	feed(raw, 2, 1, 0, model.OutcomeTTLExpired, "10.0.0.9", 10)
	feed(raw, 2, 2, 1000, model.OutcomeTTLExpired, "10.0.0.8", 90)
	feed(raw, 2, 3, 2000, model.OutcomeTTLExpired, "10.0.0.9", 12)
	if n := len(hop(raw.Snapshot(ms(3000)), 2).Responders); n != 2 {
		t.Fatalf("raw mode responders: got %d want 2", n)
	}
}

func TestLossOnsetIsReportedAfterTwoRoundsAndNeverBlamesAHop(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	// hops 1-2 clean, hops 3-4 (destination) lossy: loss appears to begin after 2.
	at := 0
	round := func() {
		for i := 0; i < 5; i++ {
			at += 100
			feed(e, 1, uint64(at), at, model.OutcomeTTLExpired, "10.0.0.1", 5)
			at += 100
			feed(e, 2, uint64(at), at, model.OutcomeTTLExpired, "10.0.0.2", 10)
			at += 100
			// 60% loss on the tail
			out := model.OutcomeTimeout
			if i >= 3 {
				out = model.OutcomeTTLExpired
			}
			feed(e, 3, uint64(at), at, out, respOf(out), 20)
			at += 100
			outD := model.OutcomeTimeout
			if i >= 3 {
				outD = model.OutcomeReply
			}
			feed(e, 4, uint64(at), at, outD, "93.184.216.34", 40)
		}
		e.Snapshot(ms(at + 50))
		e.EndTraceRound(ms(at + 60))
	}

	round()
	if n := countLossOnset(e); n != 0 {
		t.Fatalf("loss onset reported after one round: %d", n)
	}
	round()
	if n := countLossOnset(e); n != 1 {
		t.Fatalf("loss onset events: got %d want 1 after two rounds", n)
	}
	// The text must not accuse a hop of causing the loss.
	for _, ev := range e.events {
		if ev.Kind == model.EventTimeoutStreak && strings.Contains(ev.Text, "possible loss") {
			if !strings.Contains(ev.Text, "beginning after hop 2") {
				t.Fatalf("wrong onset hop: %q", ev.Text)
			}
		}
	}
}

func countLossOnset(e *Engine) int {
	n := 0
	for _, ev := range e.events {
		if strings.Contains(ev.Text, "possible loss beginning after hop") {
			n++
		}
	}
	return n
}

func TestResolveTargetFailsGracefully(t *testing.T) {
	// A name that does not resolve must be an error value, never a panic
	// (DoD: graceful failure paths).
	if _, err := ResolveTarget("this-name-should-not-exist.invalid"); err == nil {
		t.Fatal("expected an error for an unresolvable name")
	}
	// A literal address must not need DNS at all.
	got, err := ResolveTarget("192.0.2.1")
	if err != nil {
		t.Fatalf("literal address: %v", err)
	}
	if got.IP != "192.0.2.1" || got.Family != model.FamilyIP4 {
		t.Fatalf("literal address: %+v", got)
	}
	if got, err = ResolveTarget("2001:db8::1"); err != nil || got.Family != model.FamilyIP6 {
		t.Fatalf("ipv6 literal: %+v %v", got, err)
	}
}

func TestEventsNewestFirst(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	e.AddEvent(ms(100), model.EventStart, nil, "first")
	e.AddEvent(ms(200), model.EventStart, nil, "second")
	s := e.Snapshot(ms(300))
	if s.Events[0].Text != "second" {
		t.Fatalf("events not newest-first: %+v", s.Events)
	}
}

func TestPauseToggle(t *testing.T) {
	e := newTestEngine(model.ModeRaw)
	if e.Paused() {
		t.Fatal("should start unpaused")
	}
	e.TogglePause(ms(10))
	if !e.Paused() || !e.Snapshot(ms(20)).Paused {
		t.Fatal("pause not reflected")
	}
	e.TogglePause(ms(30))
	if e.Paused() {
		t.Fatal("resume failed")
	}
}
