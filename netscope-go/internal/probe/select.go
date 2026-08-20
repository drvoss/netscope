package probe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/model"
)

// candidate is one backend the platform is willing to try, in preference order.
type candidate struct {
	name string
	open func(net.IP, time.Time) (Backend, error)

	// requireReply raises the detection bar for this candidate: the probe must
	// OBSERVE a reply, not merely be sent. See verify().
	requireReply bool
}

// Select performs capability detection and returns the best working backend plus
// a note for the event log (spec §6.2).
//
// Detection sends one real probe rather than merely opening the handle. A raw
// ICMP socket on Windows opens successfully and then rejects every send, so
// "the constructor returned no error" is not evidence that a backend works.
func Select(dstIP net.IP, start time.Time) (Backend, string) {
	return SelectWith(dstIP, start, false)
}

// SelectWith optionally forces the command fallback, so the degraded path can be
// exercised on a machine where a better backend is available (--force-command).
// Without it, the fallback is only reachable on a host that cannot do better,
// which makes it the least-tested code in the program.
func SelectWith(dstIP net.IP, start time.Time, forceCommand bool) (Backend, string) {
	if forceCommand {
		return NewCommandBackend(dstIP.String(), start),
			"command fallback forced by --force-command (degraded metrics)"
	}
	return selectFrom(platformCandidates(), dstIP, start)
}

// selectFrom walks the candidate list. Split out from SelectWith so a test can
// inject fakes: the loop's obligations -- close a rejected candidate before moving
// on, try the next one, and carry every rejection into the note -- are not visible
// to the replay harness and are easy to break silently (codex/claude R5).
func selectFrom(candidates []candidate, dstIP net.IP, start time.Time) (Backend, string) {
	var notes []string

	for _, c := range candidates {
		b, err := c.open(dstIP, start)
		if err != nil {
			notes = append(notes, c.name+" unavailable ("+err.Error()+")")
			continue
		}
		if ok, why := verify(b, dstIP, c.requireReply); ok {
			note := c.name + " backend active"
			if len(notes) > 0 {
				note += "; " + strings.Join(notes, "; ")
			}
			return b, note
		} else {
			_ = b.Close()
			notes = append(notes, c.name+" opened but unusable ("+why+")")
		}
	}

	notes = append(notes, "using command fallback (degraded metrics)")
	return NewCommandBackend(dstIP.String(), start), strings.Join(notes, "; ")
}

// verifyMaxTTL is how many TTLs a requireReply detection may try before giving up.
// Must equal C++'s kVerifyMaxTTL in probe.h (spec §6.2).
//
// More than one because a first hop that does not answer is ordinary -- plenty of
// home routers and clouds suppress Time Exceeded at TTL 1 -- and rejecting on that
// alone would demote a socket that works. A backend that cannot see TTL expiry AT
// ALL fails every one of them, so the discrimination survives. Retrying the same TTL
// would not help: the question is not whether one packet was lost, it is whether
// this socket can ever observe an expiry.
const verifyMaxTTL = 3

// verify sends TTL-limited probes to confirm the backend actually works. Ordinarily
// one probe is sent and a Timeout counts as success: it proves the packet went out
// and says only that this hop stayed quiet.
//
// requireReply flips that. A Linux ICMP datagram socket sends TTL-limited packets
// perfectly well but never delivers the routers' Time Exceeded messages, because
// those go to the socket error queue (IP_RECVERR / MSG_ERRQUEUE) which this program
// does not read. Such a socket passes the ordinary bar and then reports every
// intermediate hop as silent while still calling itself "raw". So for that candidate
// something must be OBSERVED -- any reply at all -- across TTL 1..verifyMaxTTL, and
// silence throughout rejects it (cross-review R4).
//
// Keep this behaviourally identical to C++'s verifyBackend in probe_select.cpp: it
// decides which backend a host uses, so a difference here is a difference in every
// measurement that follows.
func verify(b Backend, dstIP net.IP, requireReply bool) (bool, string) {
	if !b.SupportsPerTTL() {
		return true, ""
	}

	family := model.FamilyIP4
	if dstIP.To4() == nil {
		family = model.FamilyIP6
	}

	maxTTL := 1
	if requireReply {
		maxTTL = verifyMaxTTL
	}

	for ttl := 1; ttl <= maxTTL; ttl++ {
		// Per probe, not per sweep. A deadline spanning the whole loop would expire
		// partway through and make this diverge from C++, which bounds nothing here
		// and relies on the backend's own probeTimeout (codex R2).
		res := func() model.ProbeResult {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			// Generation 0 is never the engine's live generation, so this probe's
			// result could not be mistaken for a measurement even if it leaked.
			return b.Probe(ctx, model.ProbeID{Generation: 0, Family: family, TTL: ttl})
		}()

		switch res.Outcome {
		case model.OutcomePermissionDenied, model.OutcomeBackendError:
			return false, res.Note
		}
		// Without requireReply the send alone is the evidence, so stop at the first.
		if !requireReply {
			return true, ""
		}
		// Any observed reply proves the receive path: TTLExpired and Unreachable both
		// arrive by the same mechanism that a datagram socket cannot deliver, and Reply
		// means the target is within reach of this TTL, which also came back through
		// the socket. Only Timeout keeps the loop going.
		if res.Outcome.Answered() {
			return true, ""
		}
	}

	// Deliberately "may not": silence across these TTLs is consistent with a socket
	// that cannot see Time Exceeded, but it is also consistent with a genuinely quiet
	// near path. The log must not claim to have distinguished them (codex R5).
	return false, fmt.Sprintf("sent, but nothing observed at ttl 1..%d -- this socket "+
		"may not be able to see Time Exceeded (no IP_RECVERR), so the next candidate "+
		"is tried instead", maxTTL)
}
