//go:build !windows

package probe

import (
	"net"
	"time"
)

// platformCandidates lists POSIX backends in preference order.
//
// There is no IP Helper equivalent here, so ICMP sockets are the only privileged
// option -- but they come in two kinds and are listed SEPARATELY, because
// detection has to hold them to different bars.
//
// The unprivileged datagram socket is still preferred: it needs no capability, so
// an ordinary user gets real per-hop measurement wherever the kernel allows it.
// What changed (cross-review R4) is that it must now PROVE it can observe a reply
// before it is accepted. On Linux it can send TTL-limited probes perfectly well
// and never see a single Time Exceeded, because those go to the socket error queue
// (IP_RECVERR / MSG_ERRQUEUE) and this program does not read it -- the result was a
// socket that called itself "raw", reported degraded: false, and showed no
// intermediate responder at all. Requiring an observed reply demotes it to SOCK_RAW
// on such a kernel, and leaves it in place on one where it works (macOS delivers
// ICMP errors inline, so it is expected to pass there).
//
// SOCK_RAW keeps the ordinary bar -- a Timeout still counts as success. Its ability
// to receive TTL expiry was verified in a real environment on 2026-07-30
// (docs/parity-checklist.md H5), so a silent first hop must not demote it.
// posixCandidate is the declarative form of the list, so a test can pin the socket
// kind each entry opens rather than only the closure's name. Mirrors
// posixCandidates() in netscope-cpp/src/probe_select.cpp: same order, same labels,
// same bars. Flipping a requireReply here silently re-opens the defect that
// cross-review R4 found.
type posixCandidate struct {
	name         string
	kind         RawSocketKind
	requireReply bool
}

var posixCandidates = []posixCandidate{
	{"raw ICMP (datagram socket)", RawSocketDatagram, true},
	{"raw ICMP (SOCK_RAW)", RawSocketRaw, false},
}

func platformCandidates() []candidate {
	out := make([]candidate, 0, len(posixCandidates))
	for _, pc := range posixCandidates {
		kind := pc.kind
		out = append(out, candidate{
			name: pc.name,
			open: func(ip net.IP, start time.Time) (Backend, error) {
				return NewRawBackend(ip, start, kind)
			},
			requireReply: pc.requireReply,
		})
	}
	return out
}
