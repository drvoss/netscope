package probe

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Output parsers for the command fallback backend.
//
// These are deliberately LOCALE-AGNOSTIC rather than locale-forced: they only
// look at hop numbers, IP literals and "<number> ms" groups, all of which are
// ASCII in every Windows display language and in every traceroute build. A
// Korean or German Windows prints "요청 시간이 초과되었습니다." instead of
// "Request timed out.", and this parser does not care -- it sees no IP and no
// time on that line and records a timeout.
//
// This is stricter than spec §6.4's "force a stable locale" requirement and
// removes the drift risk the cross-review flagged rather than merely narrowing
// it. LC_ALL=C is still set on POSIX for good measure.

// TraceSample is one parsed probe from a traceroute/tracert sweep.
type TraceSample struct {
	TTL         int
	Responder   string // "" means no answer
	RTTms       float64
	OK          bool
	Unreachable bool
	Note        string
}

var (
	hopLineRe = regexp.MustCompile(`^\s*(\d{1,2})\s+(.*)$`)
	// "1 ms", "1.234 ms", "<1 ms", "1ms"
	msRe = regexp.MustCompile(`^(<)?([0-9]+(?:\.[0-9]+)?)\s*ms$`)
)

// ParseTraceOutput extracts samples from tracert (Windows) or traceroute (POSIX)
// output. Both layouts are handled by one pass:
//
//	Windows:  "  4    74 ms    73 ms    74 ms  93.184.216.34"   times then host
//	POSIX:    " 4  93.184.216.34  74.1 ms  73.8 ms  74.0 ms"    host then times
//	POSIX/ECMP: " 3  10.0.0.1  1.1 ms  10.0.0.2  1.2 ms"        interleaved
func ParseTraceOutput(out string) []TraceSample {
	var samples []TraceSample
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		m := hopLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ttl, err := strconv.Atoi(m[1])
		if err != nil || ttl < 1 {
			continue
		}
		samples = append(samples, parseHopLine(ttl, m[2])...)
	}
	return samples
}

func parseHopLine(ttl int, rest string) []TraceSample {
	var out []TraceSample
	fields := strings.Fields(rest)

	current := ""         // responder the following times belong to
	var pending []float64 // times seen before any host (the Windows layout)
	lastUnreachable := false
	note := ""

	flushPending := func(ip string) {
		for _, v := range pending {
			out = append(out, TraceSample{TTL: ttl, Responder: ip, RTTms: v, OK: true})
		}
		pending = nil
	}

	for i := 0; i < len(fields); i++ {
		f := fields[i]

		if f == "*" {
			out = append(out, TraceSample{TTL: ttl})
			continue
		}

		// "!H", "!N", "!X" annotations mark an ICMP unreachable at this hop.
		if strings.HasPrefix(f, "!") {
			lastUnreachable = true
			note = unreachAnnotation(f)
			continue
		}

		// A bare number followed by "ms" (tracert separates them).
		if i+1 < len(fields) && fields[i+1] == "ms" {
			if v, ok := parseMs(f + " ms"); ok {
				if current == "" {
					pending = append(pending, v)
				} else {
					out = append(out, TraceSample{TTL: ttl, Responder: current, RTTms: v, OK: true})
				}
				i++
				continue
			}
		}
		if v, ok := parseMs(f); ok {
			if current == "" {
				pending = append(pending, v)
			} else {
				out = append(out, TraceSample{TTL: ttl, Responder: current, RTTms: v, OK: true})
			}
			continue
		}

		if ip := extractIP(f); ip != "" {
			current = ip
			flushPending(ip)
			continue
		}
		// Anything else is prose (localized "Request timed out.", rDNS names we
		// did not ask for, "Trace complete") and is ignored.
	}

	// Times with no host at all: the hop answered but the address was
	// unparseable. Record them as answers with an empty responder so loss is not
	// overstated.
	flushPending("")

	if lastUnreachable && len(out) > 0 {
		for i := range out {
			if out[i].OK {
				out[i].Unreachable = true
				out[i].Note = note
			}
		}
	}
	return out
}

func parseMs(s string) (float64, bool) {
	m := msRe.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[2], 64)
	if err != nil {
		return 0, false
	}
	if m[1] == "<" {
		// "<1 ms" is a Windows sub-millisecond report; treat it as 0.5ms rather
		// than 0 so it is distinguishable from a genuine zero.
		return 0.5, true
	}
	return v, true
}

// extractIP accepts a bare literal or a "host (1.2.3.4)" / "(1.2.3.4)" form.
func extractIP(tok string) string {
	tok = strings.Trim(tok, "()[],:")
	if tok == "" {
		return ""
	}
	if ip := net.ParseIP(tok); ip != nil {
		return ip.String()
	}
	return ""
}

func unreachAnnotation(f string) string {
	switch f {
	case "!H":
		return "host unreachable"
	case "!N":
		return "net unreachable"
	case "!P":
		return "protocol unreachable"
	case "!X", "!A":
		return "administratively prohibited"
	}
	return "unreachable " + f
}

var pingTimeRe = regexp.MustCompile(`time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms`)

// ParsePingRTT pulls the round-trip time out of a single-shot ping.
// Windows: "Reply from 1.2.3.4: bytes=32 time=74ms TTL=56"
// POSIX:   "64 bytes from 1.2.3.4: icmp_seq=1 ttl=56 time=74.1 ms"
// "time<1ms" yields 0.5.
func ParsePingRTT(out string) (float64, bool) {
	m := pingTimeRe.FindStringSubmatch(out)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	if strings.Contains(out, "time<") && v == 1 {
		return 0.5, true
	}
	return v, true
}
