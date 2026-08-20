//go:build windows

package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/drvoss/netscope/netscope-go/internal/model"
	"github.com/drvoss/netscope/netscope-go/internal/stats"
)

// HelperBackend is the Windows IP Helper backend (spec §6.2 rank "helper").
//
// Why this exists rather than just using the raw socket: on Windows a raw ICMP
// socket receives Echo Replies but NOT the Time Exceeded messages that
// intermediate routers send, so a raw-socket traceroute sees only the
// destination and reports every intermediate hop as silent. Verified on this
// host: raw mode against 1.1.1.1 produced TRANSIT_ONLY for hops 1-4 and a reply
// only at hop 5. IcmpSendEcho reports TTL expiry explicitly via
// IP_TTL_EXPIRED_TRANSIT together with the responding router's address, which is
// exactly what the path table needs.
//
// This is implemented with the syscall interface, not cgo, so the pure-Go build
// is preserved.
type HelperBackend struct {
	dstIP  net.IP
	family model.Family
	start  time.Time
	closed atomic.Bool
}

var (
	iphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreate   = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpClose    = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho = iphlpapi.NewProc("IcmpSendEcho")
)

// IP_STATUS codes we care about (ipexport.h).
const (
	ipSuccess             = 0
	ipBufTooSmall         = 11001
	ipDestNetUnreachable  = 11002
	ipDestHostUnreachable = 11003
	ipDestProtUnreachable = 11004
	ipDestPortUnreachable = 11005
	ipReqTimedOut         = 11010
	ipTTLExpiredTransit   = 11013
	ipTTLExpiredReassem   = 11014
	ipDestUnreachable     = 11040
	ipDestNoRoute         = 11041
	ipDestAdminProhibited = 11043
)

// ipOptionInformation mirrors IP_OPTION_INFORMATION32, and icmpEchoReply mirrors
// ICMP_ECHO_REPLY32.
//
// The "32" variants are what IcmpSendEcho actually uses on 64-bit Windows: their
// pointer fields are 32 bits wide, so the structures are 8 and 28 bytes rather than
// the 16 and 40 that native pointers would give. Declaring the pointer fields as
// uint32 makes the layout ABI-correct instead of merely happening to agree on the
// first few offsets.
type ipOptionInformation struct {
	TTL         uint8
	Tos         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uint32 // 32-bit pointer, always 0 here
}

type icmpEchoReply struct {
	Address       uint32 // IPv4 address in network byte order
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uint32 // 32-bit pointer into the reply buffer
	Options       ipOptionInformation
}

// NewHelperBackend validates that the IP Helper API is usable for dstIP.
func NewHelperBackend(dstIP net.IP, start time.Time) (*HelperBackend, error) {
	if dstIP.To4() == nil {
		// Icmp6SendEcho2 needs a bound source address and a different reply
		// layout; the raw backend covers IPv6 on Windows where it is available.
		return nil, fmt.Errorf("IP Helper backend supports IPv4 only")
	}
	if err := procIcmpCreate.Find(); err != nil {
		return nil, fmt.Errorf("iphlpapi!IcmpCreateFile unavailable: %w", err)
	}
	if err := procIcmpSendEcho.Find(); err != nil {
		return nil, fmt.Errorf("iphlpapi!IcmpSendEcho unavailable: %w", err)
	}

	h, _, err := procIcmpCreate.Call()
	if windows.Handle(h) == windows.InvalidHandle {
		return nil, fmt.Errorf("IcmpCreateFile: %w", err)
	}
	_, _, _ = procIcmpClose.Call(h)

	return &HelperBackend{dstIP: dstIP.To4(), family: model.FamilyIP4, start: start}, nil
}

func (b *HelperBackend) Mode() model.ProbeMode { return model.ModeHelper }
func (b *HelperBackend) SupportsPerTTL() bool  { return true }

func (b *HelperBackend) TraceRound(context.Context, uint64, int) []model.ProbeResult { return nil }

// Close marks the backend shut. Each probe owns its own ICMP handle and closes
// it before returning, so there is no shared handle to invalidate and no
// reply-buffer lifetime hazard -- the failure mode all three reviewers warned
// about for the asynchronous IcmpSendEcho2 form (spec §3.3).
func (b *HelperBackend) Close() error {
	b.closed.Store(true)
	return nil
}

// Probe sends one TTL-limited echo request via IcmpSendEcho.
//
// The synchronous form is used deliberately: it keeps the reply buffer's
// lifetime confined to this call, so a shutdown racing with an in-flight probe
// cannot free a buffer the OS is still writing into.
func (b *HelperBackend) Probe(ctx context.Context, id model.ProbeID) model.ProbeResult {
	res := model.ProbeResult{ID: id, SentAt: Elapsed(b.start)}

	if b.closed.Load() {
		res.Outcome = model.OutcomeBackendError
		res.Note = "backend closed"
		res.RecvAt = res.SentAt
		return res
	}
	if id.TTL < 1 || id.TTL > 255 {
		res.Outcome = model.OutcomeBackendError
		res.Note = "ttl out of range"
		res.RecvAt = res.SentAt
		return res
	}

	handle, _, err := procIcmpCreate.Call()
	if windows.Handle(handle) == windows.InvalidHandle {
		res.Outcome = model.OutcomePermissionDenied
		res.Note = "IcmpCreateFile: " + err.Error()
		res.RecvAt = Elapsed(b.start)
		return res
	}
	defer procIcmpClose.Call(handle)

	payload := []byte("netscope")
	opts := ipOptionInformation{TTL: uint8(id.TTL)}

	// Reply buffer: one ICMP_ECHO_REPLY, the echoed payload, and slack for the
	// 8-byte trailer the API may append.
	replySize := int(unsafe.Sizeof(icmpEchoReply{})) + len(payload) + 8 + 64
	reply := make([]byte, replySize)

	dst := binary.LittleEndian.Uint32(b.dstIP)
	timeoutMs := uint32(stats.ProbeTimeout / time.Millisecond)

	sentAt := Elapsed(b.start)
	res.SentAt = sentAt

	n, _, lastErr := procIcmpSendEcho.Call(
		handle,
		uintptr(dst),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(uint16(len(payload))),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(uint32(len(reply))),
		uintptr(timeoutMs),
	)
	res.RecvAt = Elapsed(b.start)
	// Application-level round trip, matching the raw backend and the C++ build,
	// rather than the API's integer-millisecond RoundTripTime (spec §4.1).
	res.RTT = res.RecvAt - sentAt

	if ctx.Err() != nil {
		res.Outcome = model.OutcomeTimeout
		res.Note = "cancelled"
		return res
	}

	status := uint32(ipReqTimedOut)
	responder := ""
	if n > 0 {
		// IcmpSendEcho returns the NUMBER OF REPLY RECORDS stored, and stores one
		// for TTL expiry and unreachables too -- their IP_STATUS is in the record.
		r := (*icmpEchoReply)(unsafe.Pointer(&reply[0]))
		status = r.Status
		responder = ipv4String(r.Address)
	} else {
		// Zero means NO record was stored, so the reply buffer holds nothing
		// defined. Reading an address out of it here would be reading
		// uninitialized memory; the status comes from GetLastError alone.
		if errno, ok := lastErr.(windows.Errno); ok {
			status = uint32(errno)
		}
	}

	// A reply that took longer than probeTimeout must be reported as a timeout, not
	// dropped: dropping it would lose the transmission from both the sent and the
	// loss counts (codex HIGH finding).
	if res.RTT > stats.ProbeTimeout && status != ipReqTimedOut {
		status = ipReqTimedOut
		res.Note = "reply arrived after the timeout"
	}

	switch status {
	case ipSuccess:
		res.Outcome = model.OutcomeReply
		res.Responder = b.dstIP.String()

	case ipTTLExpiredTransit, ipTTLExpiredReassem:
		res.Outcome = model.OutcomeTTLExpired
		res.Responder = responder
		if res.Responder == "" {
			// No address means we cannot attribute the hop; treat it as silence
			// rather than inventing a responder.
			res.Outcome = model.OutcomeTimeout
			res.RecvAt = sentAt + stats.ProbeTimeout
			res.RTT = 0
		}

	case ipDestNetUnreachable, ipDestHostUnreachable, ipDestProtUnreachable,
		ipDestPortUnreachable, ipDestUnreachable, ipDestNoRoute, ipDestAdminProhibited:
		res.Outcome = model.OutcomeUnreachable
		res.Responder = responder
		res.Note = helperStatusNote(status)

	case ipReqTimedOut:
		res.Outcome = model.OutcomeTimeout
		res.RecvAt = sentAt + stats.ProbeTimeout
		res.RTT = 0

	case ipBufTooSmall:
		res.Outcome = model.OutcomeBackendError
		res.Note = "reply buffer too small"

	default:
		res.Outcome = model.OutcomeBackendError
		res.Note = fmt.Sprintf("IP_STATUS %d", status)
	}
	return res
}

func ipv4String(addr uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], addr)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

func helperStatusNote(status uint32) string {
	switch status {
	case ipDestNetUnreachable:
		return "net unreachable"
	case ipDestHostUnreachable:
		return "host unreachable"
	case ipDestProtUnreachable:
		return "protocol unreachable"
	case ipDestPortUnreachable:
		return "port unreachable"
	case ipDestNoRoute:
		return "no route"
	case ipDestAdminProhibited:
		return "administratively prohibited"
	}
	return "destination unreachable"
}
