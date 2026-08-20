package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/drvoss/netscope/netscope-go/internal/model"
	"github.com/drvoss/netscope/netscope-go/internal/stats"
)

// RawBackend sends ICMP echo requests with a controlled TTL over one shared
// socket, and correlates replies by sequence number.
//
// Correlation keys on the sequence alone, which is unique per process run
// (spec §6.3). The ICMP id is a filter, not a key, and only on a raw socket:
// there we see other processes' replies too, so an id mismatch discards the
// packet before it can collide with our sequence numbering. On Linux's
// unprivileged ICMP datagram socket the kernel rewrites the id, so checking it
// there would silently drop every reply -- hence the isRaw guard at each check.
type RawBackend struct {
	family model.Family
	dstIP  net.IP
	dst    net.Addr
	start  time.Time

	conn *icmp.PacketConn
	v4   *ipv4.PacketConn
	v6   *ipv6.PacketConn

	// sendMu serializes SetTTL followed by WriteTo. TTL is a socket-level option,
	// so concurrent senders would otherwise clobber each other's TTL.
	sendMu sync.Mutex

	seq uint32

	pendingMu sync.Mutex
	pending   map[int]chan rawReply

	closeOnce sync.Once
	closed    chan struct{}

	id int

	// isRaw distinguishes a SOCK_RAW socket from the unprivileged ICMP datagram
	// socket. A raw socket sees EVERY host ICMP packet, including replies belonging
	// to other processes, so it must validate the ICMP identifier as well as the
	// sequence. A datagram socket is demultiplexed by the kernel, which also
	// rewrites the identifier, so there the identifier must be ignored.
	isRaw bool
}

type rawReply struct {
	responder string
	outcome   model.Outcome
	at        time.Duration
	note      string
}

// RawSocketKind selects which POSIX ICMP socket NewRawBackend opens.
//
// These are two SEPARATE candidates rather than one factory that picks
// internally, because detection has to hold them to different bars -- see
// verify() in select.go and spec §6.2.
type RawSocketKind int

const (
	// RawSocketDatagram is SOCK_DGRAM + IPPROTO_ICMP: unprivileged, but needs
	// net.ipv4.ping_group_range to cover the calling gid on Linux.
	RawSocketDatagram RawSocketKind = iota
	// RawSocketRaw is SOCK_RAW: needs root or cap_net_raw.
	RawSocketRaw
)

// NewRawBackend opens exactly the ICMP socket kind asked for.
//
// It used to try the datagram socket and fall back to raw internally, which hid
// the choice from detection -- and the datagram socket is the one that needs
// checking (spec §6.2, cross-review R4). Returns an error when that kind is
// unavailable so the caller can move to the next candidate.
func NewRawBackend(dstIP net.IP, start time.Time, kind RawSocketKind) (*RawBackend, error) {
	b := &RawBackend{
		dstIP:   dstIP,
		start:   start,
		pending: map[int]chan rawReply{},
		closed:  make(chan struct{}),
		id:      os.Getpid() & 0xffff,
	}

	v4 := dstIP.To4() != nil
	if v4 {
		b.family = model.FamilyIP4
	} else {
		b.family = model.FamilyIP6
	}

	b.isRaw = kind == RawSocketRaw

	var nw, addr string
	switch {
	case v4 && b.isRaw:
		nw, addr = "ip4:icmp", "0.0.0.0"
	case v4:
		nw, addr = "udp4", "0.0.0.0"
	case b.isRaw:
		nw, addr = "ip6:ipv6-icmp", "::"
	default:
		nw, addr = "udp6", "::"
	}

	c, err := icmp.ListenPacket(nw, addr)
	if err != nil {
		// Wording kept identical to C++'s makeRawBackend: this text reaches the event
		// log, and two implementations explaining the same failure differently is the
		// kind of drift the parity contract exists to prevent. The network string is
		// left out for the same reason -- err already names it.
		if b.isRaw {
			return nil, fmt.Errorf("SOCK_RAW: %w (try setcap cap_net_raw+ep or run as root)", err)
		}
		return nil, fmt.Errorf("ICMP datagram socket: %w (needs net.ipv4.ping_group_range to cover this gid)", err)
	}
	b.conn = c
	// The peer address type must match the socket type. An ICMP datagram socket
	// ("udp4"/"udp6") takes *net.UDPAddr; a raw socket ("ip4:icmp") takes
	// *net.IPAddr. Passing the wrong one makes every WriteTo fail with "invalid
	// argument" while the socket itself looks perfectly healthy.
	if b.isRaw {
		b.dst = &net.IPAddr{IP: dstIP}
	} else {
		b.dst = &net.UDPAddr{IP: dstIP}
	}

	if v4 {
		b.v4 = b.conn.IPv4PacketConn()
		if b.v4 == nil {
			b.conn.Close()
			return nil, errors.New("ICMP socket has no IPv4 control interface")
		}
	} else {
		b.v6 = b.conn.IPv6PacketConn()
		if b.v6 == nil {
			b.conn.Close()
			return nil, errors.New("ICMP socket has no IPv6 control interface")
		}
	}

	go b.receive()
	return b, nil
}

func (b *RawBackend) Mode() model.ProbeMode { return model.ModeRaw }
func (b *RawBackend) SupportsPerTTL() bool  { return true }

func (b *RawBackend) TraceRound(context.Context, uint64, int) []model.ProbeResult { return nil }

// Close shuts the socket, which is what actually unblocks the receiver's
// ReadFrom. A cancelled context alone would not (spec §3.3 step 3).
func (b *RawBackend) Close() error {
	var err error
	b.closeOnce.Do(func() {
		close(b.closed)
		err = b.conn.Close()
		// Wake anything still waiting so no worker blocks until its full timeout.
		b.pendingMu.Lock()
		for seq, ch := range b.pending {
			delete(b.pending, seq)
			close(ch)
		}
		b.pendingMu.Unlock()
	})
	return err
}

func (b *RawBackend) setTTL(ttl int) error {
	if b.v4 != nil {
		return b.v4.SetTTL(ttl)
	}
	return b.v6.SetHopLimit(ttl)
}

func (b *RawBackend) echoType() icmp.Type {
	if b.family == model.FamilyIP4 {
		return ipv4.ICMPTypeEcho
	}
	return ipv6.ICMPTypeEchoRequest
}

// Probe sends one TTL-limited echo request and waits for the matching reply.
func (b *RawBackend) Probe(ctx context.Context, id model.ProbeID) model.ProbeResult {
	seq := int(atomic.AddUint32(&b.seq, 1) & 0x7fff)

	res := model.ProbeResult{ID: id}

	ch := make(chan rawReply, 1)
	b.pendingMu.Lock()
	select {
	case <-b.closed:
		b.pendingMu.Unlock()
		res.Outcome = model.OutcomeBackendError
		res.Note = "backend closed"
		res.SentAt = Elapsed(b.start)
		res.RecvAt = res.SentAt
		return res
	default:
	}
	b.pending[seq] = ch
	b.pendingMu.Unlock()

	defer func() {
		b.pendingMu.Lock()
		delete(b.pending, seq)
		b.pendingMu.Unlock()
	}()

	msg := icmp.Message{
		Type: b.echoType(),
		Code: 0,
		Body: &icmp.Echo{
			ID:   b.id,
			Seq:  seq,
			Data: []byte("netscope"),
		},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		res.Outcome = model.OutcomeBackendError
		res.Note = "marshal: " + err.Error()
		res.SentAt = Elapsed(b.start)
		res.RecvAt = res.SentAt
		return res
	}

	b.sendMu.Lock()
	sentAt := Elapsed(b.start)
	if err := b.setTTL(id.TTL); err != nil {
		b.sendMu.Unlock()
		res.Outcome = model.OutcomeBackendError
		res.Note = "set ttl: " + err.Error()
		res.SentAt, res.RecvAt = sentAt, sentAt
		return res
	}
	_, err = b.conn.WriteTo(wire, b.dst)
	b.sendMu.Unlock()

	res.SentAt = sentAt
	if err != nil {
		if isPermission(err) {
			res.Outcome = model.OutcomePermissionDenied
		} else {
			res.Outcome = model.OutcomeBackendError
		}
		res.Note = err.Error()
		res.RecvAt = Elapsed(b.start)
		return res
	}

	timer := time.NewTimer(stats.ProbeTimeout)
	defer timer.Stop()

	select {
	case rep, ok := <-ch:
		if !ok {
			res.Outcome = model.OutcomeBackendError
			res.Note = "backend closed while waiting"
			res.RecvAt = Elapsed(b.start)
			return res
		}
		// A reply can win the race against the deadline by a hair and still be
		// later than probeTimeout. Converting it here rather than letting the
		// engine drop it keeps the transmission counted: dropping the result
		// entirely would lose both the sent and the loss (codex HIGH finding).
		if rep.at-sentAt > stats.ProbeTimeout {
			res.Outcome = model.OutcomeTimeout
			res.RecvAt = sentAt + stats.ProbeTimeout
			res.Note = "reply arrived after the timeout"
			break
		}
		res.Outcome = rep.outcome
		res.Responder = rep.responder
		res.RecvAt = rep.at
		res.RTT = rep.at - sentAt
		res.Note = rep.note
		if res.RTT < 0 {
			res.RTT = 0
		}
	case <-timer.C:
		res.Outcome = model.OutcomeTimeout
		res.RecvAt = sentAt + stats.ProbeTimeout
	case <-ctx.Done():
		res.Outcome = model.OutcomeTimeout
		res.RecvAt = Elapsed(b.start)
		res.Note = "cancelled"
	case <-b.closed:
		res.Outcome = model.OutcomeBackendError
		res.Note = "backend closed"
		res.RecvAt = Elapsed(b.start)
	}
	return res
}

// receive is the single reader. It runs until Close makes ReadFrom fail.
func (b *RawBackend) receive() {
	buf := make([]byte, 1500)
	proto := 1 // ICMPv4
	if b.family == model.FamilyIP6 {
		proto = 58
	}
	for {
		n, peer, err := b.conn.ReadFrom(buf)
		if err != nil {
			select {
			case <-b.closed:
				return
			default:
			}
			// Transient read error: keep going, the socket is still open.
			continue
		}
		at := Elapsed(b.start)
		msg, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}

		seq, outcome, note, ok := b.classifyReply(msg)
		if !ok {
			continue
		}
		b.deliver(seq, rawReply{
			responder: hostOf(peer),
			outcome:   outcome,
			at:        at,
			note:      note,
		})
	}
}

// classifyReply extracts the sequence number and normalized outcome from an
// incoming ICMP message.
func (b *RawBackend) classifyReply(msg *icmp.Message) (seq int, outcome model.Outcome, note string, ok bool) {
	switch body := msg.Body.(type) {
	case *icmp.Echo:
		// Echo Reply means the packet reached the destination.
		if b.isRaw && body.ID != b.id {
			// Another process's ping. On a raw socket we see those too, and a
			// sequence collision would otherwise be mistaken for our own reply.
			return 0, "", "", false
		}
		return body.Seq, model.OutcomeReply, "", true

	case *icmp.TimeExceeded:
		s, id, found := quotedIDSeq(body.Data, b.family)
		if !found || (b.isRaw && id != b.id) {
			return 0, "", "", false
		}
		return s, model.OutcomeTTLExpired, "", true

	case *icmp.DstUnreach:
		s, id, found := quotedIDSeq(body.Data, b.family)
		if !found || (b.isRaw && id != b.id) {
			return 0, "", "", false
		}
		return s, model.OutcomeUnreachable, unreachNote(b.family, msg.Code), true
	}
	return 0, "", "", false
}

// quotedIDSeq pulls the identifier and sequence number out of the original
// datagram that a Time Exceeded or Destination Unreachable message quotes back to
// us.
func quotedIDSeq(data []byte, family model.Family) (seq, id int, ok bool) {
	var off int
	if family == model.FamilyIP4 {
		if len(data) < 20 {
			return 0, 0, false
		}
		ihl := int(data[0]&0x0f) * 4
		if ihl < 20 {
			ihl = 20
		}
		off = ihl
	} else {
		off = 40 // fixed IPv6 header
	}
	// original ICMP header: type(1) code(1) checksum(2) id(2) seq(2)
	if len(data) < off+8 {
		return 0, 0, false
	}
	id = int(data[off+4])<<8 | int(data[off+5])
	seq = int(data[off+6])<<8 | int(data[off+7])
	return seq, id, true
}

func unreachNote(family model.Family, code int) string {
	if family == model.FamilyIP4 {
		switch code {
		case 0:
			return "net unreachable"
		case 1:
			return "host unreachable"
		case 2:
			return "protocol unreachable"
		case 3:
			return "port unreachable"
		case 9, 10:
			return "administratively prohibited"
		case 13:
			return "communication administratively prohibited"
		}
		return fmt.Sprintf("code %d", code)
	}
	switch code {
	case 0:
		return "no route"
	case 1:
		return "administratively prohibited"
	case 3:
		return "address unreachable"
	case 4:
		return "port unreachable"
	}
	return fmt.Sprintf("code %d", code)
}

func (b *RawBackend) deliver(seq int, rep rawReply) {
	b.pendingMu.Lock()
	ch := b.pending[seq]
	if ch != nil {
		delete(b.pending, seq)
	}
	b.pendingMu.Unlock()
	if ch == nil {
		// Late or foreign reply: dropping it keeps avg and jitter clean
		// (spec §6.3).
		return
	}
	select {
	case ch <- rep:
	default:
	}
}

func hostOf(a net.Addr) string {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP.String()
	case *net.IPAddr:
		return v.IP.String()
	}
	if h, _, err := net.SplitHostPort(a.String()); err == nil {
		return h
	}
	return a.String()
}

func isPermission(err error) bool {
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	var se *os.SyscallError
	if errors.As(err, &se) {
		return errors.Is(se.Err, os.ErrPermission)
	}
	return false
}
