package probe

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/model"
)

// fakeBackend returns canned outcomes for the detection probes, one per TTL, and
// repeats the last entry once they run out. It exists so the detection RULE can be
// tested without a kernel: the case that matters -- an ICMP datagram socket that
// sends fine but can never observe a Time Exceeded -- cannot be produced on the
// host this project is developed on.
type fakeBackend struct {
	outcomes []model.Outcome
	perTTL   bool

	seen   []model.ProbeID
	closed int
}

func (f *fakeBackend) Mode() model.ProbeMode { return model.ModeRaw }
func (f *fakeBackend) SupportsPerTTL() bool  { return f.perTTL }
func (f *fakeBackend) Close() error          { f.closed++; return nil }

func (f *fakeBackend) Probe(_ context.Context, id model.ProbeID) model.ProbeResult {
	f.seen = append(f.seen, id)
	o := f.outcomes[len(f.outcomes)-1]
	if len(f.seen) <= len(f.outcomes) {
		o = f.outcomes[len(f.seen)-1]
	}
	return model.ProbeResult{ID: id, Outcome: o, Note: "canned"}
}

func (f *fakeBackend) TraceRound(context.Context, uint64, int) []model.ProbeResult {
	return nil
}

func (f *fakeBackend) probes() int { return len(f.seen) }

// Detection must never let its own probe be mistaken for a measurement, and must
// walk TTLs upward from 1. Both facts were previously protected only by a comment.
func (f *fakeBackend) checkIDs(t *testing.T, wantFamily model.Family) {
	t.Helper()
	for i, id := range f.seen {
		if id.Generation != 0 {
			t.Errorf("probe %d: generation %d, want 0 -- a live generation could be "+
				"mistaken for a measurement", i, id.Generation)
		}
		if id.TTL != i+1 {
			t.Errorf("probe %d: ttl %d, want %d", i, id.TTL, i+1)
		}
		if id.Family != wantFamily {
			t.Errorf("probe %d: family %v, want %v", i, id.Family, wantFamily)
		}
	}
}

// The rule, per spec §6.2. Mirrored by the C++ suite in tests/test_select.cpp --
// these two must agree case for case, because this decides which backend a host
// uses and therefore every measurement that follows.
func TestVerifyRequireReply(t *testing.T) {
	dst := net.ParseIP("1.1.1.1")

	cases := []struct {
		name         string
		outcomes     []model.Outcome
		requireReply bool
		wantOK       bool
		wantProbes   int
	}{
		// The defect this rule exists to catch: sent successfully, nothing observed
		// at any TTL it is willing to try.
		{"silence throughout rejects when a reply is required",
			[]model.Outcome{model.OutcomeTimeout}, true, false, verifyMaxTTL},

		// A quiet FIRST hop is ordinary and must not demote a working socket. This is
		// why detection sweeps TTLs instead of retrying TTL 1 (codex/claude R1).
		{"a silent first hop is tolerated when a later one answers",
			[]model.Outcome{model.OutcomeTimeout, model.OutcomeTTLExpired}, true, true, 2},
		{"silent until the last TTL still passes",
			[]model.Outcome{model.OutcomeTimeout, model.OutcomeTimeout, model.OutcomeTTLExpired},
			true, true, 3},

		// The lenient bar sends exactly one probe and accepts the send as evidence.
		{"timeout accepted when no reply is required",
			[]model.Outcome{model.OutcomeTimeout}, false, true, 1},

		// Any observed reply proves the receive path, and stops the sweep early.
		{"ttl expired proves the receive path",
			[]model.Outcome{model.OutcomeTTLExpired}, true, true, 1},
		{"reply proves the receive path",
			[]model.Outcome{model.OutcomeReply}, true, true, 1},
		{"unreachable proves the receive path",
			[]model.Outcome{model.OutcomeUnreachable}, true, true, 1},

		// Hard failures reject at either bar, and abandon the sweep immediately.
		{"permission denied rejects, strict",
			[]model.Outcome{model.OutcomePermissionDenied}, true, false, 1},
		{"permission denied rejects, lenient",
			[]model.Outcome{model.OutcomePermissionDenied}, false, false, 1},
		{"backend error rejects, strict",
			[]model.Outcome{model.OutcomeBackendError}, true, false, 1},
		{"backend error rejects, lenient",
			[]model.Outcome{model.OutcomeBackendError}, false, false, 1},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &fakeBackend{outcomes: tc.outcomes, perTTL: true}
			ok, why := verify(b, dst, tc.requireReply)
			if ok != tc.wantOK {
				t.Fatalf("verify(%v, requireReply=%v) = %v, want %v (why=%q)",
					tc.outcomes, tc.requireReply, ok, tc.wantOK, why)
			}
			if !ok && why == "" {
				t.Error("rejection carried no reason; the event log would say nothing useful")
			}
			if b.probes() != tc.wantProbes {
				t.Errorf("sent %d probes, want %d", b.probes(), tc.wantProbes)
			}
			b.checkIDs(t, model.FamilyIP4)
		})
	}
}

// The rejection reason must not claim more than was observed: silence is also what
// a genuinely quiet near path looks like (codex R4).
func TestVerifyRejectionDoesNotOverclaim(t *testing.T) {
	b := &fakeBackend{outcomes: []model.Outcome{model.OutcomeTimeout}, perTTL: true}
	_, why := verify(b, net.ParseIP("1.1.1.1"), true)
	if strings.Contains(why, "cannot see") {
		t.Errorf("reason asserts what one sweep cannot establish: %q", why)
	}
	if !strings.Contains(why, "may not") {
		t.Errorf("reason should be hedged: %q", why)
	}
}

func TestVerifyUsesTargetFamily(t *testing.T) {
	b := &fakeBackend{outcomes: []model.Outcome{model.OutcomeReply}, perTTL: true}
	verify(b, net.ParseIP("2606:4700:4700::1111"), true)
	b.checkIDs(t, model.FamilyIP6)
}

// A sweep-only backend cannot answer a single TTL-limited probe, so it must be
// accepted without one. Otherwise requireReply would also reject the command
// fallback and the program would be left with no backend at all.
func TestVerifySkipsBackendsWithoutPerTTL(t *testing.T) {
	b := &fakeBackend{outcomes: []model.Outcome{model.OutcomeTimeout}, perTTL: false}
	if ok, why := verify(b, net.ParseIP("1.1.1.1"), true); !ok {
		t.Fatalf("sweep-only backend rejected: %s", why)
	}
	if b.probes() != 0 {
		t.Errorf("sent %d probes to a sweep-only backend, want 0", b.probes())
	}
}

// The loop's obligations: close what you reject, try the next one, and say why in
// the note. None of this is visible to the replay harness.
func TestSelectFromDemotesAndExplains(t *testing.T) {
	demoted := &fakeBackend{outcomes: []model.Outcome{model.OutcomeTimeout}, perTTL: true}
	chosen := &fakeBackend{outcomes: []model.Outcome{model.OutcomeTimeout}, perTTL: true}

	got, note := selectFrom([]candidate{
		{name: "strict one", requireReply: true,
			open: func(net.IP, time.Time) (Backend, error) { return demoted, nil }},
		{name: "lenient one",
			open: func(net.IP, time.Time) (Backend, error) { return chosen, nil }},
	}, net.ParseIP("1.1.1.1"), time.Time{})

	if got != Backend(chosen) {
		t.Fatal("did not fall through to the second candidate")
	}
	if demoted.closed != 1 {
		t.Errorf("rejected candidate closed %d times, want 1 -- a leak here costs a "+
			"socket and a reader thread", demoted.closed)
	}
	if chosen.closed != 0 {
		t.Error("closed the candidate it selected")
	}
	if !strings.Contains(note, "lenient one backend active") ||
		!strings.Contains(note, "strict one opened but unusable") {
		t.Errorf("note does not explain the demotion: %q", note)
	}
}

// A candidate that cannot even be opened is reported and skipped, not fatal.
func TestSelectFromFallsBackToCommand(t *testing.T) {
	_, note := selectFrom([]candidate{
		{name: "absent one",
			open: func(net.IP, time.Time) (Backend, error) { return nil, errors.New("EPERM") }},
	}, net.ParseIP("1.1.1.1"), time.Time{})

	if !strings.Contains(note, "absent one unavailable (EPERM)") {
		t.Errorf("note lost the open failure: %q", note)
	}
	if !strings.Contains(note, "command fallback") {
		t.Errorf("note does not say the fallback was used: %q", note)
	}
}
