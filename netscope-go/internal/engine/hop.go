package engine

import (
	"sort"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/model"
	"github.com/drvoss/netscope/netscope-go/internal/stats"
)

// Hysteresis constants (spec §5.2). Shared with the C++ implementation.
const (
	MinSamples    = 3 // probes sent at a TTL before we classify it at all
	LossStreak    = 4 // consecutive timeouts before RESPONDING -> DEGRADED
	RecoverStreak = 2 // consecutive replies before DEGRADED -> RESPONDING
)

// respState is the mutable per-responder record. Only the engine loop touches it.
type respState struct {
	ip          string
	rdns        string
	asn         string
	org         string
	seen        uint64
	firstSeenAt time.Duration
	lastSeenAt  time.Duration
}

// hopState is the mutable per-TTL record.
//
// There is a single window per TTL, with every sample tagged by the responder
// that answered. A responder switch therefore already breaks jitter pairing and
// keeps each router's RTTs separate, without maintaining parallel windows that
// could drift out of sync (spec §4.3, §5.3). Samples belonging to a responder
// that stopped answering simply age out of the 120s window.
type hopState struct {
	ttl           int
	win           *stats.Window
	sent          uint64
	replied       uint64
	everReplied   bool
	timeoutStreak int
	replyStreak   int
	status        model.HopStatus
	responders    map[string]*respState
	isDestination bool
}

func newHopState(ttl int) *hopState {
	return &hopState{
		ttl:        ttl,
		win:        stats.NewWindow(),
		status:     model.StatusUnknown,
		responders: map[string]*respState{},
	}
}

// record folds one probe result into the hop state.
func (h *hopState) record(r model.ProbeResult) {
	h.sent++
	if r.Outcome.Answered() {
		h.replied++
		h.everReplied = true
		h.timeoutStreak = 0
		h.replyStreak++
		if r.Responder != "" {
			rs := h.responders[r.Responder]
			if rs == nil {
				rs = &respState{ip: r.Responder, firstSeenAt: r.RecvAt}
				h.responders[r.Responder] = rs
			}
			rs.seen++
			rs.lastSeenAt = r.RecvAt
		}
		if r.Outcome == model.OutcomeReply {
			h.isDestination = true
		}
		h.win.Add(stats.Sample{SentAt: r.SentAt, RTT: r.RTT, OK: true, Responder: r.Responder})
		return
	}
	// Timeout. PermissionDenied / BackendError are not measurements and are
	// filtered out before reaching here.
	h.replyStreak = 0
	h.timeoutStreak++
	h.win.Add(stats.Sample{SentAt: r.SentAt, OK: false})
}

// responderSet returns the window's responders in the canonical order.
func (h *hopState) responderSet() []string { return h.win.Responders() }

// primary is the most-observed responder in the window, or the most-observed
// ever if the window has gone quiet.
func (h *hopState) primary() string {
	if rs := h.win.Responders(); len(rs) > 0 {
		return rs[0]
	}
	// fall back to cumulative observations so a briefly silent hop keeps its label
	best := ""
	var bestSeen uint64
	ips := make([]string, 0, len(h.responders))
	for ip := range h.responders {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	for _, ip := range ips {
		if h.responders[ip].seen > bestSeen {
			best, bestSeen = ip, h.responders[ip].seen
		}
	}
	return best
}

// classify maps hop state onto the five-state enum from spec §5.1.
//
// The FILTERED/LOSS split the plan originally called for was rejected in
// cross-review: silence cannot distinguish an ACL from ICMP rate limiting, a
// busy control plane, MPLS, or an unobserved ECMP branch. TRANSIT_ONLY states
// only the observed fact -- traffic gets through, probes go unanswered.
//
// anyGreaterReplied is true when some strictly greater TTL has ever answered.
// degraded is true for the command backend, which cannot support the
// TRANSIT_ONLY inference (spec §6.4).
func classify(h *hopState, anyGreaterReplied bool, degraded bool) model.HopStatus {
	if !h.everReplied {
		if h.sent < MinSamples {
			return model.StatusUnknown
		}
		if anyGreaterReplied && !degraded {
			return model.StatusTransitOnly
		}
		return model.StatusSilent
	}

	// Has answered at some point. Use hysteresis so a single lost probe does not
	// flap the row, and require sustained replies to come back.
	if h.status == model.StatusDegraded {
		if h.replyStreak >= RecoverStreak {
			return model.StatusResponding
		}
		return model.StatusDegraded
	}
	if h.timeoutStreak >= LossStreak {
		return model.StatusDegraded
	}
	return model.StatusResponding
}
