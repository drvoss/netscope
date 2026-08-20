// Package probe holds the measurement backends.
//
// Every backend produces normalized model.ProbeResult values and nothing else;
// classification and aggregation belong to the engine (spec §6.1). A probe's
// destination is ALWAYS the final target -- only the TTL varies. Pinging a
// router's own interface address would measure a different forward/reverse path
// and a different control-plane policy (spec §1, cross-review R1-2).
package probe

import (
	"context"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/model"
)

// Backend is the measurement contract shared by all platforms.
type Backend interface {
	Mode() model.ProbeMode

	// SupportsPerTTL reports whether the scheduler may issue individual
	// TTL-limited probes. Backends that can only run a whole sweep (the command
	// fallback) return false and implement TraceRound instead.
	SupportsPerTTL() bool

	// Probe sends one TTL-limited probe toward the target and blocks until a
	// reply arrives, the probe times out, or ctx is cancelled. It never returns
	// an error: failures are expressed as outcomes so the engine can log them
	// without special-casing (spec §6.1).
	Probe(ctx context.Context, id model.ProbeID) model.ProbeResult

	// TraceRound performs a batch sweep. Returns nil when unsupported.
	TraceRound(ctx context.Context, generation uint64, maxTTL int) []model.ProbeResult

	// Close releases sockets and handles. Must be called before workers are
	// joined so blocking reads are interrupted (spec §3.3 step 3).
	Close() error
}

// Elapsed converts a wall instant into the engine's monotonic offset. Go's
// time.Since is monotonic, satisfying the "no wall clock for RTT" rule
// (spec §4.1).
func Elapsed(start time.Time) time.Duration { return time.Since(start) }
