//go:build windows

package probe

import (
	"net"
	"time"
)

// platformCandidates lists Windows backends in preference order.
//
// There is exactly ONE entry: the IP Helper API. A raw ICMP socket is deliberately
// NOT offered, for two independent reasons.
//
// It does not work well enough to be useful. Verified on Windows while building
// this: a raw ICMP socket receives Echo Replies but NOT the Time Exceeded messages
// intermediate routers send, so raw mode reported every intermediate hop as silent
// and only the destination as responding. That is worse than no path table -- it
// looks like a broken network. IcmpSendEcho reports TTL expiry explicitly, with the
// responding router's address.
//
// And keeping it would break the cross-language contract. The C++ build has no
// Windows raw backend, so a Windows IPv6 target would have run raw here and the
// degraded command fallback there -- different measurement semantics for the same
// input, which is exactly what docs/netscope-spec.md §6.2 exists to prevent
// (codex MEDIUM finding). Windows IPv6 therefore falls through to the command
// fallback in BOTH implementations, and says so in the header.
func platformCandidates() []candidate {
	return []candidate{
		{
			name: "helper (IcmpSendEcho)",
			open: func(ip net.IP, start time.Time) (Backend, error) {
				return NewHelperBackend(ip, start)
			},
		},
	}
}
