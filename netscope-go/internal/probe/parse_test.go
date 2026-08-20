package probe

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

// Golden files live at the repository root so the C++ tests parse the exact same
// bytes. If one implementation's parser drifts, the shared fixtures catch it.
func golden(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("..", "..", "..", "testdata", name)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

func closeTo(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestParseTracertWindowsEnglish(t *testing.T) {
	got := ParseTraceOutput(golden(t, "tracert-windows-en.txt"))
	// 4 hops x 3 probes
	if len(got) != 12 {
		t.Fatalf("samples: got %d want 12: %+v", len(got), got)
	}
	// Windows puts the times before the host; all three must attach to it.
	for i := 0; i < 3; i++ {
		if got[i].TTL != 1 || got[i].Responder != "192.168.0.1" || !got[i].OK {
			t.Fatalf("hop1[%d]: %+v", i, got[i])
		}
	}
	if !closeTo(got[0].RTTms, 1) {
		t.Fatalf("hop1 rtt: %v", got[0].RTTms)
	}
	// hop 3 timed out three times, with no responder
	for i := 6; i < 9; i++ {
		if got[i].TTL != 3 || got[i].OK || got[i].Responder != "" {
			t.Fatalf("hop3[%d]: %+v", i, got[i])
		}
	}
	if got[9].Responder != "93.184.216.34" || !closeTo(got[9].RTTms, 74) {
		t.Fatalf("hop4: %+v", got[9])
	}
}

func TestParseTracertKoreanWindowsIsLocaleAgnostic(t *testing.T) {
	// The localized "요청 시간이 만료되었습니다." line must still parse as three
	// timeouts: the parser only reads hop numbers, IPs and "<n> ms" groups.
	got := ParseTraceOutput(golden(t, "tracert-windows-ko.txt"))
	if len(got) != 12 {
		t.Fatalf("samples: got %d want 12: %+v", len(got), got)
	}
	// "<1 ms" becomes 0.5, distinguishable from a real zero.
	for i := 0; i < 3; i++ {
		if !got[i].OK || !closeTo(got[i].RTTms, 0.5) || got[i].Responder != "192.168.0.1" {
			t.Fatalf("hop1[%d]: %+v", i, got[i])
		}
	}
	for i := 6; i < 9; i++ {
		if got[i].TTL != 3 || got[i].OK {
			t.Fatalf("localized timeout line not parsed: %+v", got[i])
		}
	}
}

func TestParseTracerouteLinux(t *testing.T) {
	got := ParseTraceOutput(golden(t, "traceroute-linux.txt"))
	if len(got) != 12 {
		t.Fatalf("samples: got %d want 12: %+v", len(got), got)
	}
	// POSIX puts the host first, then times.
	if got[0].Responder != "192.168.0.1" || !closeTo(got[0].RTTms, 1.234) {
		t.Fatalf("hop1[0]: %+v", got[0])
	}
	if got[11].Responder != "93.184.216.34" || !closeTo(got[11].RTTms, 74.001) {
		t.Fatalf("hop4[2]: %+v", got[11])
	}
}

func TestParseTracerouteEcmpAttributesTimesToTheRightResponder(t *testing.T) {
	got := ParseTraceOutput(golden(t, "traceroute-linux-ecmp.txt"))
	// hop 2 answered by two different routers in one line; each time must be
	// attributed to the address that precedes it, not merged.
	var hop2 []TraceSample
	for _, s := range got {
		if s.TTL == 2 {
			hop2 = append(hop2, s)
		}
	}
	if len(hop2) != 3 {
		t.Fatalf("hop2 samples: got %d want 3: %+v", len(hop2), hop2)
	}
	want := []struct {
		ip  string
		rtt float64
	}{{"10.20.0.1", 8.100}, {"10.20.0.2", 8.900}, {"10.20.0.1", 8.300}}
	for i, w := range want {
		if hop2[i].Responder != w.ip || !closeTo(hop2[i].RTTms, w.rtt) {
			t.Fatalf("hop2[%d]: got %s/%v want %s/%v", i, hop2[i].Responder, hop2[i].RTTms, w.ip, w.rtt)
		}
	}
}

func TestParseTracerouteUnreachableAnnotation(t *testing.T) {
	got := ParseTraceOutput(golden(t, "traceroute-linux-ecmp.txt"))
	n := 0
	for _, s := range got {
		if s.TTL == 3 {
			if !s.Unreachable {
				t.Fatalf("hop3 sample missing unreachable flag: %+v", s)
			}
			if s.Note != "host unreachable" {
				t.Fatalf("hop3 note: %q", s.Note)
			}
			n++
		}
	}
	if n != 3 {
		t.Fatalf("hop3 samples: got %d want 3", n)
	}
}

func TestParsePingRTT(t *testing.T) {
	cases := []struct {
		file string
		want float64
	}{
		{"ping-windows-en.txt", 74},
		{"ping-linux.txt", 74.1},
		{"ping-windows-subms.txt", 0.5},
	}
	for _, c := range cases {
		got, ok := ParsePingRTT(golden(t, c.file))
		if !ok {
			t.Fatalf("%s: no rtt found", c.file)
		}
		if !closeTo(got, c.want) {
			t.Fatalf("%s: got %v want %v", c.file, got, c.want)
		}
	}
}

func TestParsePingUnreachableHasNoRTT(t *testing.T) {
	if _, ok := ParsePingRTT(golden(t, "ping-unreachable.txt")); ok {
		t.Fatal("unreachable reply must not yield an RTT")
	}
}

func TestParseGarbageProducesNoSamples(t *testing.T) {
	// A wrong locale, a truncated pipe, or a completely different binary on PATH
	// must degrade to "no samples", never crash (DoD: graceful failure paths).
	//
	// The assertion is deliberately "exactly zero samples" rather than "no
	// successful samples": a parser that invented phantom TIMEOUTS from garbage
	// would inflate loss to 100% on a healthy path, and the weaker assertion would
	// not catch it.
	for _, in := range []string{"", "\n\n", "not a traceroute at all",
		"  1 ", "  1  garbage garbage", "999999999999 1 ms 1.2.3.4",
		"Tracing route to example.com [93.184.216.34]", "over a maximum of 30 hops:"} {
		if got := ParseTraceOutput(in); len(got) != 0 {
			t.Fatalf("invented %d samples from %q: %+v", len(got), in, got)
		}
	}
}

func TestParseMsGrammar(t *testing.T) {
	// The C++ suite tests its parseMsToken helper directly; without this the Go
	// helper was the only half of the pair with no unit test of its own.
	cases := []struct {
		in   string
		want float64
		ok   bool
	}{
		{"1 ms", 1, true},
		{"1.234 ms", 1.234, true},
		{"1ms", 1, true},
		{"<1 ms", 0.5, true},
		{"ms", 0, false},
		{"1 s", 0, false},
		{"1.", 0, false},
		{"192.168.0.1", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := parseMs(c.in)
		if ok != c.ok {
			t.Fatalf("parseMs(%q): ok=%v want %v", c.in, ok, c.ok)
		}
		if ok && !closeTo(got, c.want) {
			t.Fatalf("parseMs(%q): got %v want %v", c.in, got, c.want)
		}
	}
}
