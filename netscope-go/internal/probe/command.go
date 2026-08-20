package probe

import (
	"context"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/model"
	"github.com/drvoss/netscope/netscope-go/internal/stats"
)

// CommandBackend is the unprivileged fallback: it shells out to the system
// tracert/traceroute for the path and to ping for the destination, then parses
// the output (plan §5.3, spec §6.2 rank 3).
//
// This backend is DEGRADED by construction and the engine suppresses the metrics
// it cannot honestly support -- jitter, stdev, the TRANSIT_ONLY inference and
// ECMP responder tracking (spec §6.4). agy argued for refusing to run at all
// without raw sockets; the plan explicitly requires this fallback, so it stays,
// clearly labelled, with its weak metrics switched off (cross-review R1-4).
type CommandBackend struct {
	targetIP string
	start    time.Time
	attempt  uint64
}

func NewCommandBackend(targetIP string, start time.Time) *CommandBackend {
	return &CommandBackend{targetIP: targetIP, start: start}
}

func (c *CommandBackend) Mode() model.ProbeMode { return model.ModeCommand }

// SupportsPerTTL is false: a single TTL-limited measurement with an accurate RTT
// is not obtainable from the system ping on Windows (it reports "TTL expired in
// transit" with no time), so the scheduler must use whole sweeps instead.
func (c *CommandBackend) SupportsPerTTL() bool { return false }

func (c *CommandBackend) Close() error { return nil }

func (c *CommandBackend) nextAttempt() uint64 { return atomic.AddUint64(&c.attempt, 1) }

// Probe measures the destination only. The scheduler calls it for the
// destination TTL at the destination cadence.
func (c *CommandBackend) Probe(ctx context.Context, id model.ProbeID) model.ProbeResult {
	sentAt := Elapsed(c.start)
	res := model.ProbeResult{ID: id, SentAt: sentAt}

	name, args := pingCommand(c.targetIP)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = stableLocaleEnv()
	out, err := cmd.CombinedOutput()
	res.RecvAt = Elapsed(c.start)

	if ctx.Err() != nil {
		res.Outcome = model.OutcomeTimeout
		res.Note = "cancelled"
		return res
	}
	if len(out) == 0 && err != nil {
		res.Outcome = model.OutcomeBackendError
		res.Note = name + ": " + err.Error()
		return res
	}

	rtt, ok := ParsePingRTT(string(out))
	if !ok {
		// ping exits non-zero on loss; no parsed time means no answer.
		res.Outcome = model.OutcomeTimeout
		res.RecvAt = sentAt + stats.ProbeTimeout
		return res
	}
	res.Outcome = model.OutcomeReply
	res.Responder = c.targetIP
	res.RTT = time.Duration(rtt * float64(time.Millisecond))
	res.RecvAt = sentAt + res.RTT
	return res
}

// TraceRound runs one full sweep and converts every parsed probe into a result.
//
// Send timestamps are synthesized as evenly spaced offsets from the moment the
// command was launched: the OS tool does not tell us when each individual probe
// left. Order is preserved, which is all the (time-based) window needs, and
// jitter -- the one metric that would be misled by fake spacing -- is disabled in
// this mode anyway.
func (c *CommandBackend) TraceRound(ctx context.Context, generation uint64, maxTTL int) []model.ProbeResult {
	base := Elapsed(c.start)

	name, args := traceCommand(c.targetIP, maxTTL)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = stableLocaleEnv()
	out, err := cmd.CombinedOutput()

	if ctx.Err() != nil {
		return nil
	}
	samples := ParseTraceOutput(string(out))
	if len(samples) == 0 {
		note := "no hops parsed from " + name + " output"
		if err != nil {
			note = name + ": " + err.Error()
		}
		return []model.ProbeResult{{
			ID:      model.ProbeID{Generation: generation, TTL: 1},
			Outcome: model.OutcomeBackendError,
			SentAt:  base,
			RecvAt:  Elapsed(c.start),
			Note:    note,
		}}
	}

	results := make([]model.ProbeResult, 0, len(samples))
	for i, s := range samples {
		sentAt := base + time.Duration(i)*10*time.Millisecond
		r := model.ProbeResult{
			ID: model.ProbeID{
				Generation: generation,
				Family:     familyOf(c.targetIP),
				TTL:        s.TTL,
				Attempt:    c.nextAttempt(),
			},
			SentAt: sentAt,
		}
		switch {
		case !s.OK:
			r.Outcome = model.OutcomeTimeout
			r.RecvAt = sentAt + stats.ProbeTimeout
		case s.Unreachable:
			r.Outcome = model.OutcomeUnreachable
			r.Responder = s.Responder
			r.Note = s.Note
			r.RTT = time.Duration(s.RTTms * float64(time.Millisecond))
			r.RecvAt = sentAt + r.RTT
		default:
			r.Responder = s.Responder
			r.RTT = time.Duration(s.RTTms * float64(time.Millisecond))
			r.RecvAt = sentAt + r.RTT
			if s.Responder == c.targetIP {
				r.Outcome = model.OutcomeReply
			} else {
				r.Outcome = model.OutcomeTTLExpired
			}
		}
		results = append(results, r)
	}
	return results
}

func familyOf(ip string) model.Family {
	for i := 0; i < len(ip); i++ {
		if ip[i] == ':' {
			return model.FamilyIP6
		}
	}
	return model.FamilyIP4
}
