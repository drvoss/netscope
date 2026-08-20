// Package model holds the data types shared by every other package.
//
// Field names and semantics are fixed by docs/netscope-spec.md and must stay
// identical to the C++ implementation's model.h. Changing one side only is a bug.
package model

import "time"

// Family is the address family a target was resolved to.
type Family string

const (
	FamilyIP4 Family = "ip4"
	FamilyIP6 Family = "ip6"
)

// ProbeMode is the measurement backend actually in use (spec §6.2).
type ProbeMode string

const (
	// ModeRaw is a raw ICMP socket: full control over TTL and id/seq.
	ModeRaw ProbeMode = "raw"
	// ModeHelper is the Windows IP Helper API. C++ only; Go has no binding.
	ModeHelper ProbeMode = "helper"
	// ModeCommand shells out to ping/tracert and parses the output. Degraded.
	ModeCommand ProbeMode = "command"
)

// Outcome is the normalized result of a single probe (spec §6.1).
// Backends produce these; only the engine interprets them.
type Outcome string

const (
	OutcomeReply            Outcome = "Reply"            // Echo Reply: we reached the destination
	OutcomeTTLExpired       Outcome = "TTLExpired"       // Time Exceeded: an intermediate router answered
	OutcomeUnreachable      Outcome = "Unreachable"      // ICMP type 3. A response, not a loss.
	OutcomeTimeout          Outcome = "Timeout"          // no answer within probeTimeout
	OutcomePermissionDenied Outcome = "PermissionDenied" // backend cannot run at all
	OutcomeBackendError     Outcome = "BackendError"     // parse failure, spawn failure, ...
)

// Answered reports whether the outcome counts as a response for loss accounting.
// Only Timeout counts as loss (spec §4.2).
func (o Outcome) Answered() bool {
	return o == OutcomeReply || o == OutcomeTTLExpired || o == OutcomeUnreachable
}

// HopStatus classifies a TTL position. The binary FILTERED/LOSS split was
// discarded during cross-review: silence does not prove filtering (spec §5.1).
type HopStatus string

const (
	StatusUnknown     HopStatus = "UNKNOWN"      // fewer than minSamples probes sent
	StatusResponding  HopStatus = "RESPONDING"   // at least one reply inside the window
	StatusSilent      HopStatus = "SILENT"       // never answered, and nothing beyond it answers either
	StatusTransitOnly HopStatus = "TRANSIT_ONLY" // never answered, but a greater TTL does answer
	StatusDegraded    HopStatus = "DEGRADED"     // answered before, now on a timeout streak
)

// EventKind enumerates the log timeline entries (spec §5.4).
type EventKind string

const (
	EventStart           EventKind = "start"
	EventResolved        EventKind = "resolved"
	EventTraceRound      EventKind = "trace-round"
	EventRouteChange     EventKind = "route-change"
	EventResponderChange EventKind = "responder-change"
	EventUnreachable     EventKind = "unreachable"
	EventTimeoutStreak   EventKind = "timeout-streak"
	EventDegradedMode    EventKind = "degraded-mode"
	EventPermission      EventKind = "permission"
	EventTargetChange    EventKind = "target-change"
	EventPaused          EventKind = "paused"
	EventResumed         EventKind = "resumed"
	EventEnrich          EventKind = "enrich"
	EventHealth          EventKind = "health"
	EventError           EventKind = "error"
)

// ProbeID identifies one attempt. Correlation is done on these internal fields,
// never by trying to recover wire-level id/seq across backends (spec §6.3).
type ProbeID struct {
	Generation uint64
	Family     Family
	TTL        int
	Attempt    uint64
}

// ProbeResult is what a backend hands back. Immutable by convention: workers
// never mutate engine state, they only produce these (spec §3.1).
type ProbeResult struct {
	ID        ProbeID
	Outcome   Outcome
	Responder string        // observed responder IP, "" when none
	RTT       time.Duration // valid only when Outcome.Answered()
	SentAt    time.Duration // monotonic offset from engine start
	RecvAt    time.Duration // monotonic offset from engine start
	Note      string        // human-readable detail, e.g. an ICMP unreachable code
}

// Target is the destination every probe is sent to. Only the TTL varies.
type Target struct {
	Input      string
	IP         string
	Family     Family
	ResolvedAt time.Duration
}

// RttStats is a window-derived summary. Pointer fields are nil when undefined;
// the UI must render nil as "-" / "—" rather than inventing a zero (spec §8.3).
type RttStats struct {
	Samples  int
	LastMs   *float64
	BestMs   *float64
	AvgMs    *float64
	WorstMs  *float64
	JitterMs *float64 // mean absolute successive difference (spec §4.3)
	StdevMs  *float64 // sample standard deviation, n-1
	Spark    []float64
}

// Responder is an IP observed answering at some TTL. ECMP means a single TTL can
// have several; each keeps independent statistics so their RTTs are never mixed
// into one meaningless average (spec §5.3).
type Responder struct {
	IP          string
	RDNS        string // "" not looked up yet, "-" looked up and absent
	ASN         string // "AS15133" form
	Org         string
	Seen        uint64
	FirstSeenAt time.Duration
	LastSeenAt  time.Duration
	Stats       RttStats
}

// HopPosition is one TTL bucket. Deliberately not called "Hop": a TTL is a
// position on the path, not necessarily a single router (spec §6.5).
type HopPosition struct {
	TTL           int
	Status        HopStatus
	Sent          uint64 // cumulative, window-independent
	Replied       uint64 // cumulative, window-independent
	LossPct       *float64
	Responders    []Responder
	Primary       string
	Stats         RttStats // primary responder's stats
	IsDestination bool
}

// LocalInfo is the LOCAL IF / ROUTE panel content.
type LocalInfo struct {
	Interface    string
	Address      string // CIDR form
	Gateway      string
	DNSServers   []string
	DefaultRoute string
	PublicIP     string
	Note         string // "unsupported" etc. rather than a silently blank panel
}

// Health is the L7 / port state shown in the mid bar. Deliberately independent
// of hop classification: ICMP can be blocked end to end while HTTP works.
type Health struct {
	HTTPStatus  int
	HTTPLatency *float64
	HTTPNote    string
	TCPPort     int
	TCPOpen     bool
	TCPNote     string
	CheckedAt   time.Duration
}

// Event is one log timeline entry.
type Event struct {
	At   time.Duration
	Kind EventKind
	TTL  *int
	Text string
}

// Cadence records the probe scheduling actually in force, so both binaries can
// display the same numbers and be compared (spec §4.4).
type Cadence struct {
	DestIntervalMs   int
	MidIntervalMs    int
	GlobalCapPPS     int
	WindowDurationMs int
	ProbeTimeoutMs   int
}

// Snapshot is the immutable state the UI reads. The engine loop is its only
// producer (spec §3.1).
type Snapshot struct {
	Revision   uint64
	Generation uint64
	Target     Target
	Now        time.Duration
	Mode       ProbeMode
	Degraded   bool
	Paused     bool
	Hops       []HopPosition
	Local      LocalInfo
	Health     Health
	Events     []Event // newest first
	Cadence    Cadence
}

// MaxEvents bounds the retained log (spec §2).
const MaxEvents = 200

// Command is a UI-to-engine message. The UI never touches engine state directly.
type Command struct {
	Kind       CommandKind
	Target     string
	TTL        int
	SelectedIP string
}

type CommandKind string

const (
	CmdQuit        CommandKind = "quit"
	CmdTogglePause CommandKind = "toggle-pause"
	CmdReprobe     CommandKind = "reprobe"
	CmdSetTarget   CommandKind = "set-target"
	CmdRefreshDNS  CommandKind = "refresh-dns"
	CmdRefreshASN  CommandKind = "refresh-asn"
	CmdSelectHop   CommandKind = "select-hop"
)

// F64 returns a pointer to v, for the optional stat fields.
func F64(v float64) *float64 { return &v }

// Int returns a pointer to v.
func Int(v int) *int { return &v }
