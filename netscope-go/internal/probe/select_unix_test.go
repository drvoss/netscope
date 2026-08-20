//go:build !windows

package probe

import "testing"

// The POSIX candidate list must offer the datagram socket first and hold it to the
// strict bar, then SOCK_RAW at the ordinary one. Getting either flag backwards
// re-opens the defect (a datagram socket that reports "raw" while observing no
// intermediate responder) or demotes a working raw socket on a quiet near path.
// Pinning the socket KIND too, not just the label, because the label is only a
// string: a copy-paste that opened the datagram socket twice would otherwise pass.
func TestPosixCandidateTable(t *testing.T) {
	want := []posixCandidate{
		{"raw ICMP (datagram socket)", RawSocketDatagram, true},
		{"raw ICMP (SOCK_RAW)", RawSocketRaw, false},
	}

	if len(posixCandidates) != len(want) {
		t.Fatalf("got %d POSIX candidates, want %d", len(posixCandidates), len(want))
	}
	for i, w := range want {
		if posixCandidates[i] != w {
			t.Errorf("candidate %d = %+v, want %+v", i, posixCandidates[i], w)
		}
	}
}

// ...and platformCandidates must carry that table through faithfully. The closure
// captures the loop variable, which is exactly the kind of thing that silently
// collapses to one socket kind.
func TestPlatformCandidatesMatchTable(t *testing.T) {
	got := platformCandidates()
	if len(got) != len(posixCandidates) {
		t.Fatalf("built %d candidates from %d table rows", len(got), len(posixCandidates))
	}
	for i, pc := range posixCandidates {
		if got[i].name != pc.name {
			t.Errorf("candidate %d: name %q, want %q", i, got[i].name, pc.name)
		}
		if got[i].requireReply != pc.requireReply {
			t.Errorf("candidate %q: requireReply=%v, want %v",
				got[i].name, got[i].requireReply, pc.requireReply)
		}
		if got[i].open == nil {
			t.Errorf("candidate %q has no factory", got[i].name)
		}
	}
}
