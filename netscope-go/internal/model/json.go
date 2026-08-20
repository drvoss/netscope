package model

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Canonical JSON emitter.
//
// This is hand-rolled rather than encoding/json because the output must be
// BYTE-IDENTICAL to the C++ implementation's emitter so that a parity run can
// diff the two (spec §9). encoding/json's float formatting (shortest
// round-trip) is not reproducible in C++, so every float goes out with exactly
// three decimals and every field has a fixed position.
//
// Rules, mirrored in netscope-cpp/src/core/json.cpp:
//   - 2-space indent, one field or array element per line
//   - object fields emitted in the order written below, never sorted
//   - floats: strconv 'f' with precision 3; -0 normalized to 0
//   - durations: integer milliseconds (truncated)
//   - nil optional -> null
//   - empty array -> []

type jsonWriter struct {
	b      strings.Builder
	indent int
	// first tracks whether the next member of the current container is the first,
	// so we know when to emit a separating comma.
	first []bool
}

func newJSONWriter() *jsonWriter {
	return &jsonWriter{first: []bool{true}}
}

func (w *jsonWriter) pad() {
	for i := 0; i < w.indent; i++ {
		w.b.WriteString("  ")
	}
}

func (w *jsonWriter) sep() {
	if w.first[len(w.first)-1] {
		w.first[len(w.first)-1] = false
	} else {
		w.b.WriteString(",\n")
		return
	}
	w.b.WriteString("\n")
}

func (w *jsonWriter) push() {
	w.indent++
	w.first = append(w.first, true)
}

func (w *jsonWriter) pop() {
	w.indent--
	w.first = w.first[:len(w.first)-1]
	w.b.WriteString("\n")
	w.pad()
}

func (w *jsonWriter) beginObject(key string) {
	w.sep()
	w.pad()
	if key != "" {
		w.b.WriteString(quoteJSON(key))
		w.b.WriteString(": ")
	}
	w.b.WriteString("{")
	w.push()
}

func (w *jsonWriter) endObject() {
	if w.first[len(w.first)-1] {
		// empty object: no newline padding
		w.indent--
		w.first = w.first[:len(w.first)-1]
		w.b.WriteString("}")
		return
	}
	w.pop()
	w.b.WriteString("}")
}

func (w *jsonWriter) beginArray(key string) {
	w.sep()
	w.pad()
	w.b.WriteString(quoteJSON(key))
	w.b.WriteString(": [")
	w.push()
}

func (w *jsonWriter) endArray() {
	if w.first[len(w.first)-1] {
		w.indent--
		w.first = w.first[:len(w.first)-1]
		w.b.WriteString("]")
		return
	}
	w.pop()
	w.b.WriteString("]")
}

func (w *jsonWriter) raw(key, val string) {
	w.sep()
	w.pad()
	w.b.WriteString(quoteJSON(key))
	w.b.WriteString(": ")
	w.b.WriteString(val)
}

func (w *jsonWriter) str(key, val string)        { w.raw(key, quoteJSON(val)) }
func (w *jsonWriter) int64f(key string, v int64) { w.raw(key, strconv.FormatInt(v, 10)) }
func (w *jsonWriter) intf(key string, v int)     { w.raw(key, strconv.Itoa(v)) }
func (w *jsonWriter) uintf(key string, v uint64) {
	w.raw(key, strconv.FormatUint(v, 10))
}
func (w *jsonWriter) boolf(key string, v bool) {
	if v {
		w.raw(key, "true")
	} else {
		w.raw(key, "false")
	}
}
func (w *jsonWriter) msf(key string, d time.Duration) {
	w.int64f(key, d.Milliseconds())
}
func (w *jsonWriter) optf(key string, v *float64) {
	if v == nil {
		w.raw(key, "null")
		return
	}
	w.raw(key, FormatF3(*v))
}
func (w *jsonWriter) optInt(key string, v *int) {
	if v == nil {
		w.raw(key, "null")
		return
	}
	w.intf(key, *v)
}

// FormatF3 renders a float with exactly three decimals, normalizing -0.
// Both implementations must agree on this exact rendering.
func FormatF3(v float64) string {
	s := strconv.FormatFloat(v, 'f', 3, 64)
	if s == "-0.000" {
		return "0.000"
	}
	return s
}

func quoteJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				const hex = "0123456789abcdef"
				b.WriteByte(hex[c>>4])
				b.WriteByte(hex[c&0xf])
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (w *jsonWriter) stats(key string, s RttStats) {
	w.beginObject(key)
	w.intf("samples", s.Samples)
	w.optf("lastMs", s.LastMs)
	w.optf("bestMs", s.BestMs)
	w.optf("avgMs", s.AvgMs)
	w.optf("worstMs", s.WorstMs)
	w.optf("jitterMs", s.JitterMs)
	w.optf("stdevMs", s.StdevMs)
	w.beginArray("spark")
	for _, v := range s.Spark {
		w.sep()
		w.pad()
		w.b.WriteString(FormatF3(v))
	}
	w.endArray()
	w.endObject()
}

// CanonicalJSON serializes a snapshot for parity comparison.
func (s *Snapshot) CanonicalJSON() string {
	w := newJSONWriter()
	// top-level object, written without the leading separator logic
	w.b.WriteString("{")
	w.push()

	w.uintf("revision", s.Revision)
	w.uintf("generation", s.Generation)
	w.str("mode", string(s.Mode))
	w.boolf("degraded", s.Degraded)
	w.boolf("paused", s.Paused)
	w.msf("nowMs", s.Now)

	w.beginObject("target")
	w.str("input", s.Target.Input)
	w.str("ip", s.Target.IP)
	w.str("family", string(s.Target.Family))
	w.msf("resolvedAtMs", s.Target.ResolvedAt)
	w.endObject()

	w.beginObject("cadence")
	w.intf("destIntervalMs", s.Cadence.DestIntervalMs)
	w.intf("midIntervalMs", s.Cadence.MidIntervalMs)
	w.intf("globalCapPps", s.Cadence.GlobalCapPPS)
	w.intf("windowDurationMs", s.Cadence.WindowDurationMs)
	w.intf("probeTimeoutMs", s.Cadence.ProbeTimeoutMs)
	w.endObject()

	w.beginArray("hops")
	for i := range s.Hops {
		h := &s.Hops[i]
		w.beginObject("")
		w.intf("ttl", h.TTL)
		w.str("status", string(h.Status))
		w.uintf("sent", h.Sent)
		w.uintf("replied", h.Replied)
		w.optf("lossPct", h.LossPct)
		w.str("primary", h.Primary)
		w.boolf("isDestination", h.IsDestination)
		w.stats("stats", h.Stats)
		w.beginArray("responders")
		for j := range h.Responders {
			r := &h.Responders[j]
			w.beginObject("")
			w.str("ip", r.IP)
			w.str("rdns", r.RDNS)
			w.str("asn", r.ASN)
			w.str("org", r.Org)
			w.uintf("seen", r.Seen)
			w.msf("firstSeenAtMs", r.FirstSeenAt)
			w.msf("lastSeenAtMs", r.LastSeenAt)
			w.stats("stats", r.Stats)
			w.endObject()
		}
		w.endArray()
		w.endObject()
	}
	w.endArray()

	w.beginObject("local")
	w.str("interface", s.Local.Interface)
	w.str("address", s.Local.Address)
	w.str("gateway", s.Local.Gateway)
	w.beginArray("dnsServers")
	dns := append([]string(nil), s.Local.DNSServers...)
	sort.Strings(dns)
	for _, d := range dns {
		w.sep()
		w.pad()
		w.b.WriteString(quoteJSON(d))
	}
	w.endArray()
	w.str("defaultRoute", s.Local.DefaultRoute)
	w.str("publicIp", s.Local.PublicIP)
	w.str("note", s.Local.Note)
	w.endObject()

	w.beginObject("health")
	w.intf("httpStatus", s.Health.HTTPStatus)
	w.optf("httpLatencyMs", s.Health.HTTPLatency)
	w.str("httpNote", s.Health.HTTPNote)
	w.intf("tcpPort", s.Health.TCPPort)
	w.boolf("tcpOpen", s.Health.TCPOpen)
	w.str("tcpNote", s.Health.TCPNote)
	w.endObject()

	w.beginArray("events")
	for i := range s.Events {
		e := &s.Events[i]
		w.beginObject("")
		w.msf("atMs", e.At)
		w.str("kind", string(e.Kind))
		w.optInt("ttl", e.TTL)
		w.str("text", e.Text)
		w.endObject()
	}
	w.endArray()

	w.pop()
	w.b.WriteString("}\n")
	return w.b.String()
}
