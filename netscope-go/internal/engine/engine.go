// Package engine is the single writer of all measurement state.
//
// Probe workers, enrichment workers and the UI all communicate with it by
// passing immutable values in; nothing else mutates hop statistics or route
// state (spec §3.1). The pure part of the engine -- Ingest and Snapshot -- opens
// no sockets and reads no clock of its own, which is what makes the
// deterministic replay parity harness possible (spec §9).
package engine

import (
	"fmt"
	"sort"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/model"
	"github.com/drvoss/netscope/netscope-go/internal/stats"
)

// DefaultCadence is the probe schedule contract from spec §4.4.
func DefaultCadence() model.Cadence {
	return model.Cadence{
		DestIntervalMs:   1000,
		MidIntervalMs:    4000,
		GlobalCapPPS:     10,
		WindowDurationMs: int(stats.WindowDuration / time.Millisecond),
		ProbeTimeoutMs:   int(stats.ProbeTimeout / time.Millisecond),
	}
}

type enrichRec struct {
	rdns string
	asn  string
	org  string
}

// Engine holds all mutable measurement state.
type Engine struct {
	cadence  model.Cadence
	mode     model.ProbeMode
	degraded bool
	target   model.Target

	generation uint64
	revision   uint64
	paused     bool

	hops   map[int]*hopState
	maxTTL int
	// destTTL is the lowest TTL that produced an Echo Reply, i.e. the
	// destination's position. 0 while unknown.
	destTTL int

	events []model.Event
	local  model.LocalInfo
	health model.Health

	enrich map[string]enrichRec

	// route-change debounce: a responder-set difference must persist across two
	// trace rounds before it is reported (spec §5.3).
	lastRoundSet map[int][]string
	changeStreak map[int]int
	lastRoundLen int

	// lossOnsetTTL is the hop after which sustained loss appears to begin, and
	// lossOnsetStreak debounces it. Loss is never attributed to a single hop
	// (spec §5.1); we only say where it seems to start, and only once it has
	// persisted (spec §5.3 debounce, agy QA finding).
	lossOnsetTTL    int
	lossOnsetStreak int
	lossOnsetLogged int
}

// ElevatedLossPct is the per-hop loss level that counts as elevated when looking
// for where sustained loss begins.
const ElevatedLossPct = 10.0

// New creates an engine for a target. Mode and degraded come from backend
// capability detection (spec §6.2).
func New(target model.Target, mode model.ProbeMode) *Engine {
	e := &Engine{
		cadence:      DefaultCadence(),
		mode:         mode,
		degraded:     mode == model.ModeCommand,
		target:       target,
		generation:   1,
		hops:         map[int]*hopState{},
		enrich:       map[string]enrichRec{},
		lastRoundSet: map[int][]string{},
		changeStreak: map[int]int{},
	}
	return e
}

// Generation is the current probe generation. Results from other generations are
// discarded (spec §3.1).
func (e *Engine) Generation() uint64 { return e.generation }

// Cadence returns the schedule in force.
func (e *Engine) Cadence() model.Cadence { return e.cadence }

// SetCadence records the schedule the runner actually applied after dilution, so
// the UI shows the real numbers rather than the nominal ones (spec §4.4).
func (e *Engine) SetCadence(destMs, midMs int) {
	e.cadence.DestIntervalMs = destMs
	e.cadence.MidIntervalMs = midMs
}

// Mode returns the active backend.
func (e *Engine) Mode() model.ProbeMode { return e.mode }

// Paused reports whether probe issuing is suspended.
func (e *Engine) Paused() bool { return e.paused }

// Target returns the current target.
func (e *Engine) Target() model.Target { return e.target }

// DestTTL returns the destination's TTL position, or 0 if not reached yet.
func (e *Engine) DestTTL() int { return e.destTTL }

// MaxTTL returns the highest TTL probed so far.
func (e *Engine) MaxTTL() int { return e.maxTTL }

// SetLocal replaces the LOCAL IF / ROUTE panel content.
func (e *Engine) SetLocal(l model.LocalInfo) { e.local = l }

// SetHealth replaces the mid-bar health content.
func (e *Engine) SetHealth(h model.Health) { e.health = h }

// SetMode records a backend downgrade discovered at runtime.
func (e *Engine) SetMode(m model.ProbeMode, at time.Duration) {
	if e.mode == m {
		return
	}
	e.mode = m
	e.degraded = m == model.ModeCommand
	if e.degraded {
		e.AddEvent(at, model.EventDegradedMode, nil,
			"backend downgraded to command parsing (degraded metrics)")
	}
}

// AddEvent appends to the log timeline. Newest entries end up first in the
// snapshot; storage here is chronological.
func (e *Engine) AddEvent(at time.Duration, kind model.EventKind, ttl *int, text string) {
	e.events = append(e.events, model.Event{At: at, Kind: kind, TTL: ttl, Text: text})
	if len(e.events) > model.MaxEvents {
		e.events = e.events[len(e.events)-model.MaxEvents:]
	}
}

// Ingest folds one probe result into state. It is the only path by which
// measurements enter the engine.
func (e *Engine) Ingest(r model.ProbeResult) {
	// Stale generation: the target changed or the user re-probed (spec §3.1).
	if r.ID.Generation != e.generation {
		return
	}

	switch r.Outcome {
	case model.OutcomePermissionDenied:
		e.AddEvent(r.RecvAt, model.EventPermission, model.Int(r.ID.TTL),
			"raw ICMP not permitted: "+r.Note)
		return
	case model.OutcomeBackendError:
		e.AddEvent(r.RecvAt, model.EventError, model.Int(r.ID.TTL), "probe backend: "+r.Note)
		return
	}

	// Late reply: arrived after we had already given up on this attempt. Counting
	// it would pollute avg and jitter (spec §6.3).
	if r.Outcome.Answered() && r.RTT > stats.ProbeTimeout {
		return
	}
	if r.ID.TTL < 1 {
		return
	}

	h := e.hops[r.ID.TTL]
	if h == nil {
		h = newHopState(r.ID.TTL)
		e.hops[r.ID.TTL] = h
	}
	if r.ID.TTL > e.maxTTL {
		e.maxTTL = r.ID.TTL
	}

	prevResponders := len(h.responders)
	h.record(r)

	if r.Outcome == model.OutcomeReply {
		if e.destTTL == 0 || r.ID.TTL < e.destTTL {
			e.destTTL = r.ID.TTL
		}
	}
	// The destination used to answer at this TTL and now a router does instead:
	// the path grew longer. Unlatch so the sweep can find the new position,
	// otherwise a lengthened path would be permanently truncated in the table.
	if r.Outcome == model.OutcomeTTLExpired && e.destTTL != 0 && r.ID.TTL >= e.destTTL {
		e.destTTL = 0
	}
	if r.Outcome == model.OutcomeUnreachable {
		e.AddEvent(r.RecvAt, model.EventUnreachable, model.Int(r.ID.TTL),
			fmt.Sprintf("hop%d %s unreachable: %s", r.ID.TTL, r.Responder, r.Note))
	}
	// A brand-new responder appearing at an already-known TTL is worth logging
	// immediately; the debounced route-change check runs per trace round.
	if !e.degraded && prevResponders > 0 && len(h.responders) > prevResponders {
		e.AddEvent(r.RecvAt, model.EventResponderChange, model.Int(r.ID.TTL),
			fmt.Sprintf("hop%d new responder %s (%d seen at this TTL)",
				r.ID.TTL, r.Responder, len(h.responders)))
	}
	if h.timeoutStreak == LossStreak {
		e.AddEvent(r.RecvAt, model.EventTimeoutStreak, model.Int(r.ID.TTL),
			fmt.Sprintf("hop%d %d consecutive timeouts", r.ID.TTL, LossStreak))
	}
}

// ApplyEnrich records rDNS / ASN / org for an IP. Enrichment runs off the probe
// path and its failures never block measurement (spec §7).
func (e *Engine) ApplyEnrich(ip, rdns, asn, org string) {
	if ip == "" {
		return
	}
	rec := e.enrich[ip]
	if rdns != "" {
		rec.rdns = rdns
	}
	if asn != "" {
		rec.asn = asn
	}
	if org != "" {
		rec.org = org
	}
	e.enrich[ip] = rec
}

// EndTraceRound runs the debounced route-change comparison. Comparing raw hop
// arrays every snapshot produces a flood of false positives under ECMP churn, so
// a difference must persist across two rounds to be reported (spec §5.3).
func (e *Engine) EndTraceRound(now time.Duration) {
	visible := e.visibleTTL()
	for ttl := 1; ttl <= visible; ttl++ {
		h := e.hops[ttl]
		if h == nil {
			continue
		}
		cur := h.responderSet()
		prev, seen := e.lastRoundSet[ttl]
		if !seen {
			e.lastRoundSet[ttl] = cur
			continue
		}
		if sameSet(prev, cur) {
			e.changeStreak[ttl] = 0
			continue
		}
		// Temporary silence is not a route change (spec §5.3).
		if len(cur) == 0 {
			e.changeStreak[ttl] = 0
			continue
		}
		e.changeStreak[ttl]++
		if e.changeStreak[ttl] >= 2 {
			e.AddEvent(now, model.EventRouteChange, model.Int(ttl),
				fmt.Sprintf("route changed @hop%d %s -> %s",
					ttl, joinOrDash(prev), joinOrDash(cur)))
			e.lastRoundSet[ttl] = cur
			e.changeStreak[ttl] = 0
		}
	}
	if e.lastRoundLen != 0 && visible != 0 && visible != e.lastRoundLen {
		e.AddEvent(now, model.EventRouteChange, nil,
			fmt.Sprintf("path length changed %d -> %d hops", e.lastRoundLen, visible))
	}
	if visible != 0 {
		e.lastRoundLen = visible
	}
	e.checkLossOnset(now, visible)
	e.AddEvent(now, model.EventTraceRound, nil, fmt.Sprintf("trace round complete (%d hops)", visible))
}

// checkLossOnset reports where sustained loss appears to begin.
//
// Forwarding loss is never attributed to the hop that stopped answering: a router
// may simply rate-limit its own ICMP replies while forwarding perfectly. The only
// defensible statement is "loss is elevated from this point onward, including at
// the destination", so that is what gets logged -- and only after it has persisted
// across two trace rounds (spec §5.1).
func (e *Engine) checkLossOnset(now time.Duration, visible int) {
	onset := 0
	if visible >= 1 {
		dest := e.hops[visible]
		destElevated := dest != nil && elevated(dest.win.LossPct())
		if destElevated {
			// Scan down from the destination and stop at the first hop that is NOT
			// elevated; loss appears to begin after it. Because the scan stops
			// there, every hop above it is elevated by construction.
			for ttl := visible; ttl >= 1; ttl-- {
				h := e.hops[ttl]
				if h == nil || h.status == model.StatusSilent || h.status == model.StatusTransitOnly {
					// A hop that never answers tells us nothing about forwarding
					// loss, so it neither confirms nor breaks the run.
					continue
				}
				if elevated(h.win.LossPct()) {
					continue
				}
				onset = ttl
				break
			}
			// onset == 0 means even the first hop is lossy, which points at the
			// local link rather than at a place on the path, so nothing is claimed.
		}
	}

	if onset != e.lossOnsetTTL {
		e.lossOnsetTTL = onset
		// This round counts as the first observation, so the second consecutive
		// round is what trips the report -- "persisted across two rounds".
		e.lossOnsetStreak = 1
		return
	}
	if onset == 0 {
		e.lossOnsetLogged = 0
		return
	}
	e.lossOnsetStreak++
	if e.lossOnsetStreak >= 2 && e.lossOnsetLogged != onset {
		e.lossOnsetLogged = onset
		e.AddEvent(now, model.EventTimeoutStreak, model.Int(onset),
			fmt.Sprintf("possible loss beginning after hop %d (elevated through the destination)", onset))
	}
}

func elevated(loss *float64) bool { return loss != nil && *loss >= ElevatedLossPct }

// Reprobe bumps the generation, clearing all statistics. Outstanding results
// from the previous generation are then discarded by Ingest.
func (e *Engine) Reprobe(now time.Duration) {
	e.generation++
	e.hops = map[int]*hopState{}
	e.maxTTL = 0
	e.destTTL = 0
	e.lastRoundSet = map[int][]string{}
	e.changeStreak = map[int]int{}
	e.lastRoundLen = 0
	e.AddEvent(now, model.EventTraceRound, nil, "re-probe requested, statistics reset")
}

// SetTarget switches target and reprobes.
func (e *Engine) SetTarget(t model.Target, now time.Duration) {
	e.target = t
	e.AddEvent(now, model.EventTargetChange, nil, "target changed to "+t.Input+" ("+t.IP+")")
	e.Reprobe(now)
}

// TogglePause suspends or resumes probe issuing. In-flight probes are still
// collected so the window does not gain an artificial gap.
func (e *Engine) TogglePause(now time.Duration) {
	e.paused = !e.paused
	if e.paused {
		e.AddEvent(now, model.EventPaused, nil, "paused")
	} else {
		e.AddEvent(now, model.EventResumed, nil, "resumed")
	}
}

// visibleTTL is the last TTL worth showing: the destination if we reached it,
// otherwise everything probed so far.
func (e *Engine) visibleTTL() int {
	if e.destTTL > 0 {
		return e.destTTL
	}
	return e.maxTTL
}

// Snapshot builds the immutable view the UI renders. It also finalizes hop
// classification, since that depends on cross-hop information.
func (e *Engine) Snapshot(now time.Duration) *model.Snapshot {
	e.revision++

	visible := e.visibleTTL()

	// Walk TTLs from the far end so "does any greater TTL answer?" is a running
	// flag rather than a nested scan (spec §5.1 TRANSIT_ONLY).
	anyGreater := make([]bool, visible+2)
	for ttl := visible; ttl >= 1; ttl-- {
		greater := anyGreater[ttl+1]
		if h := e.hops[ttl+1]; h != nil && h.everReplied {
			greater = true
		}
		anyGreater[ttl] = greater
	}

	hops := make([]model.HopPosition, 0, visible)
	for ttl := 1; ttl <= visible; ttl++ {
		h := e.hops[ttl]
		if h == nil {
			// Keep the list gap-free so both implementations render the same rows.
			hops = append(hops, model.HopPosition{TTL: ttl, Status: model.StatusUnknown})
			continue
		}
		h.win.Prune(now)
		h.status = classify(h, anyGreater[ttl], e.degraded)

		primary := h.primary()
		hp := model.HopPosition{
			TTL:           ttl,
			Status:        h.status,
			Sent:          h.sent,
			Replied:       h.replied,
			LossPct:       h.win.LossPct(),
			Primary:       primary,
			IsDestination: h.isDestination,
			Stats:         e.statsFor(h, primary),
		}

		// Responders ordered by observation count, then IP, so the table is
		// stable and identical across implementations.
		ips := make([]string, 0, len(h.responders))
		for ip := range h.responders {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool {
			a, b := h.responders[ips[i]], h.responders[ips[j]]
			if a.seen != b.seen {
				return a.seen > b.seen
			}
			return a.ip < b.ip
		})
		// The command backend runs one sweep at a time and cannot distinguish a
		// genuine ECMP split from consecutive sweeps taking different paths, so it
		// reports only the primary responder (spec §6.4, agy QA finding).
		if e.degraded && len(ips) > 1 {
			ips = ips[:1]
		}
		for _, ip := range ips {
			rs := h.responders[ip]
			en := e.enrich[ip]
			hp.Responders = append(hp.Responders, model.Responder{
				IP:          ip,
				RDNS:        en.rdns,
				ASN:         en.asn,
				Org:         en.org,
				Seen:        rs.seen,
				FirstSeenAt: rs.firstSeenAt,
				LastSeenAt:  rs.lastSeenAt,
				Stats:       e.statsFor(h, ip),
			})
		}
		hops = append(hops, hp)
	}

	// Events newest first for display.
	ev := make([]model.Event, len(e.events))
	for i := range e.events {
		ev[i] = e.events[len(e.events)-1-i]
	}

	return &model.Snapshot{
		Revision:   e.revision,
		Generation: e.generation,
		Target:     e.target,
		Now:        now,
		Mode:       e.mode,
		Degraded:   e.degraded,
		Paused:     e.paused,
		Hops:       hops,
		Local:      e.local,
		Health:     e.health,
		Events:     ev,
		Cadence:    e.cadence,
	}
}

// statsFor returns per-responder stats, with the degraded backend suppressing
// the metrics it cannot support (spec §6.4).
func (e *Engine) statsFor(h *hopState, responder string) model.RttStats {
	st := h.win.StatsFor(responder)
	if e.degraded {
		st.JitterMs = nil
		st.StdevMs = nil
	}
	return st
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

func joinOrDash(s []string) string {
	if len(s) == 0 {
		return "*"
	}
	out := s[0]
	for _, v := range s[1:] {
		out += "," + v
	}
	return out
}
