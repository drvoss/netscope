package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/model"
)

// Deterministic replay (spec §9).
//
// A scenario file supplies a virtual monotonic clock and a fixed stream of
// ProbeResults. Replaying it opens no sockets and reads no real clock, so both
// binaries can be fed the identical stream and their canonical JSON snapshots
// compared byte for byte. Mirroring directory names does not demonstrate parity;
// this does.
//
// The scenario schema is intentionally shallow so the C++ side can parse it with
// a small hand-rolled reader. Keep it in sync with
// netscope-cpp/src/core/replay.cpp.

type ScenarioTarget struct {
	Input        string `json:"input"`
	IP           string `json:"ip"`
	Family       string `json:"family"`
	ResolvedAtMs int64  `json:"resolvedAtMs"`
}

type ScenarioLocal struct {
	Interface    string   `json:"interface"`
	Address      string   `json:"address"`
	Gateway      string   `json:"gateway"`
	DNSServers   []string `json:"dnsServers"`
	DefaultRoute string   `json:"defaultRoute"`
	PublicIP     string   `json:"publicIp"`
	Note         string   `json:"note"`
}

type ScenarioHealth struct {
	HTTPStatus    int      `json:"httpStatus"`
	HTTPLatencyMs *float64 `json:"httpLatencyMs"`
	HTTPNote      string   `json:"httpNote"`
	TCPPort       int      `json:"tcpPort"`
	TCPOpen       bool     `json:"tcpOpen"`
	TCPNote       string   `json:"tcpNote"`
}

// ScenarioStep is a tagged union discriminated by Kind:
// "probe" | "enrich" | "trace-round" | "snapshot" | "event" | "pause" | "reprobe"
type ScenarioStep struct {
	Kind      string  `json:"kind"`
	TMs       int64   `json:"tMs"`
	TTL       int     `json:"ttl"`
	Attempt   uint64  `json:"attempt"`
	Outcome   string  `json:"outcome"`
	Responder string  `json:"responder"`
	RTTMs     float64 `json:"rttMs"`
	IP        string  `json:"ip"`
	RDNS      string  `json:"rdns"`
	ASN       string  `json:"asn"`
	Org       string  `json:"org"`
	EventKind string  `json:"eventKind"`
	Text      string  `json:"text"`
}

type Scenario struct {
	Name     string         `json:"name"`
	Mode     string         `json:"mode"`
	Target   ScenarioTarget `json:"target"`
	Local    ScenarioLocal  `json:"local"`
	Health   ScenarioHealth `json:"health"`
	Steps    []ScenarioStep `json:"steps"`
	EmitAtMs int64          `json:"emitAtMs"`
}

// LoadScenario reads a scenario file.
func LoadScenario(path string) (*Scenario, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Scenario
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Mode == "" {
		s.Mode = string(model.ModeRaw)
	}
	return &s, nil
}

// Replay drives the engine through a scenario and returns the final snapshot.
func Replay(s *Scenario) *model.Snapshot {
	family := model.Family(s.Target.Family)
	if family == "" {
		family = model.FamilyIP4
	}
	e := New(model.Target{
		Input:      s.Target.Input,
		IP:         s.Target.IP,
		Family:     family,
		ResolvedAt: time.Duration(s.Target.ResolvedAtMs) * time.Millisecond,
	}, model.ProbeMode(s.Mode))

	e.SetLocal(model.LocalInfo{
		Interface:    s.Local.Interface,
		Address:      s.Local.Address,
		Gateway:      s.Local.Gateway,
		DNSServers:   s.Local.DNSServers,
		DefaultRoute: s.Local.DefaultRoute,
		PublicIP:     s.Local.PublicIP,
		Note:         s.Local.Note,
	})
	e.SetHealth(model.Health{
		HTTPStatus:  s.Health.HTTPStatus,
		HTTPLatency: s.Health.HTTPLatencyMs,
		HTTPNote:    s.Health.HTTPNote,
		TCPPort:     s.Health.TCPPort,
		TCPOpen:     s.Health.TCPOpen,
		TCPNote:     s.Health.TCPNote,
	})

	for _, st := range s.Steps {
		at := time.Duration(st.TMs) * time.Millisecond
		switch st.Kind {
		case "probe":
			out := model.Outcome(st.Outcome)
			r := model.ProbeResult{
				ID: model.ProbeID{
					Generation: e.Generation(),
					Family:     family,
					TTL:        st.TTL,
					Attempt:    st.Attempt,
				},
				Outcome:   out,
				Responder: st.Responder,
				SentAt:    at,
			}
			if out.Answered() {
				r.RTT = time.Duration(st.RTTMs * float64(time.Millisecond))
				r.RecvAt = at + r.RTT
			} else {
				r.RecvAt = at + time.Duration(e.Cadence().ProbeTimeoutMs)*time.Millisecond
			}
			r.Note = st.Text
			e.Ingest(r)
		case "enrich":
			e.ApplyEnrich(st.IP, st.RDNS, st.ASN, st.Org)
		case "trace-round":
			e.EndTraceRound(at)
		case "snapshot":
			// Classification is stateful (hysteresis), so the scenario controls
			// exactly when snapshots are taken.
			e.Snapshot(at)
		case "event":
			var ttl *int
			if st.TTL != 0 {
				ttl = model.Int(st.TTL)
			}
			e.AddEvent(at, model.EventKind(st.EventKind), ttl, st.Text)
		case "pause":
			e.TogglePause(at)
		case "reprobe":
			e.Reprobe(at)
		}
	}

	return e.Snapshot(time.Duration(s.EmitAtMs) * time.Millisecond)
}
