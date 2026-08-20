// Package ui is the Bubble Tea front end.
//
// It is strictly read-only with respect to measurement state: it renders the
// immutable snapshot it was handed and sends commands back through the runner's
// channel. It never touches engine memory (spec §3.1).
package ui

import (
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/drvoss/netscope/netscope-go/internal/enrich"
	"github.com/drvoss/netscope/netscope-go/internal/model"
)

// Layout breakpoints (spec §8.2).
const (
	WideMin   = 120 // full layout
	MediumMin = 100 // narrower right column, rDNS/ASN column dropped
	ShortRows = 24  // below this the log shrinks
)

type focusArea int

const (
	focusPath focusArea = iota
	focusResolve
	focusLocal
)

// Runner is the subset of engine.Runner the UI needs, kept as an interface so the
// view can be exercised without a live engine.
type Runner interface {
	Snapshots() <-chan *model.Snapshot
	Send(model.Command)
	Records() enrich.Records
	Quit() <-chan struct{}
}

type snapshotMsg struct{ snap *model.Snapshot }
type tickMsg time.Time

// Model is the Bubble Tea model.
type Model struct {
	runner Runner
	snap   *model.Snapshot

	width  int
	height int

	selected int // selected TTL
	focus    focusArea

	input     textinput.Model
	inputMode bool

	toast       string
	toastExpiry time.Time

	startWall time.Time
}

// New builds the UI model.
func New(r Runner, startWall time.Time) Model {
	ti := textinput.New()
	ti.Placeholder = "hostname or IP"
	ti.CharLimit = 253
	ti.Prompt = "target> "

	return Model{
		runner:    r,
		selected:  1,
		input:     ti,
		startWall: startWall,
		width:     120,
		height:    30,
	}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(waitForSnapshot(m.runner.Snapshots()), tick())
}

func waitForSnapshot(ch <-chan *model.Snapshot) tea.Cmd {
	return func() tea.Msg {
		s, ok := <-ch
		if !ok {
			return nil
		}
		return snapshotMsg{snap: s}
	}
}

func tick() tea.Cmd {
	return tea.Tick(250*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case snapshotMsg:
		m.snap = msg.snap
		if before := m.selected; m.clampSelection() != before {
			// A re-probe or a target change can shorten the path; tell the engine
			// about the new selection so enrichment follows the visible row.
			m.runner.Send(model.Command{Kind: model.CmdSelectHop, TTL: m.selected})
		}
		return m, waitForSnapshot(m.runner.Snapshots())

	case tickMsg:
		if m.toast != "" && time.Now().After(m.toastExpiry) {
			m.toast = ""
		}
		return m, tick()

	case tea.KeyMsg:
		if m.inputMode {
			return m.updateInput(msg)
		}
		return m.updateKey(msg)
	}
	return m, nil
}

func (m Model) updateInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.inputMode = false
		m.input.Blur()
		m.input.SetValue("")
		return m, nil
	case "enter":
		v := m.input.Value()
		m.inputMode = false
		m.input.Blur()
		m.input.SetValue("")
		if v != "" {
			m.runner.Send(model.Command{Kind: model.CmdSetTarget, Target: v})
		}
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m Model) updateKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		m.runner.Send(model.Command{Kind: model.CmdQuit})
		return m, tea.Quit

	case "p":
		m.runner.Send(model.Command{Kind: model.CmdTogglePause})

	case "r":
		m.runner.Send(model.Command{Kind: model.CmdReprobe})
		// Without this the key felt dead: the log event only arrives on the next
		// engine tick.
		m.setToast("re-probing: path and statistics reset")

	case "up", "k":
		m.moveSelection(-1)

	case "down", "j":
		m.moveSelection(1)

	case "tab":
		// On a narrow terminal Tab is the tab switcher for the collapsed right
		// column, so it must cycle only the two panels that are actually shown.
		// Including focusPath there made one press in three look like a no-op.
		if m.width < MediumMin {
			if m.focus == focusLocal {
				m.focus = focusResolve
			} else {
				m.focus = focusLocal
			}
		} else {
			m.focus = (m.focus + 1) % 3
		}

	case "d":
		m.runner.Send(model.Command{
			Kind:       model.CmdRefreshDNS,
			TTL:        m.selected,
			SelectedIP: m.selectedIP(),
		})
		m.setToast("DNS refresh requested for hop " + itoa(m.selected))

	case "w":
		m.runner.Send(model.Command{
			Kind:       model.CmdRefreshASN,
			TTL:        m.selected,
			SelectedIP: m.selectedIP(),
		})
		m.setToast("ASN refresh requested for hop " + itoa(m.selected))

	case "s", "n":
		// Reserved. Cross-review agreed speedtest and port scanning are not
		// small extensions of the health check: they need scope, rate limits,
		// cancellation and a safety policy of their own (spec §8.1).
		m.setToast("'" + msg.String() + "' is reserved: not enabled in this build (v1.0)")

	case "/":
		m.inputMode = true
		m.input.SetValue("")
		m.input.Focus()
		return m, textinput.Blink
	}
	return m, nil
}

func (m *Model) setToast(s string) {
	m.toast = s
	m.toastExpiry = time.Now().Add(3 * time.Second)
}

func (m *Model) moveSelection(delta int) {
	if m.snap == nil || len(m.snap.Hops) == 0 {
		return
	}
	n := len(m.snap.Hops)
	sel := m.selected + delta
	if sel < 1 {
		sel = 1
	}
	if sel > n {
		sel = n
	}
	m.selected = sel
	m.runner.Send(model.Command{Kind: model.CmdSelectHop, TTL: sel})
}

// clampSelection keeps the selection inside the current hop list and returns the
// resulting TTL.
func (m *Model) clampSelection() int {
	if m.snap == nil {
		return m.selected
	}
	n := len(m.snap.Hops)
	if n == 0 {
		m.selected = 1
		return m.selected
	}
	if m.selected > n {
		m.selected = n
	}
	if m.selected < 1 {
		m.selected = 1
	}
	return m.selected
}

// selectedHop returns the highlighted hop, or nil.
func (m Model) selectedHop() *model.HopPosition {
	if m.snap == nil {
		return nil
	}
	for i := range m.snap.Hops {
		if m.snap.Hops[i].TTL == m.selected {
			return &m.snap.Hops[i]
		}
	}
	return nil
}

func (m Model) selectedIP() string {
	if h := m.selectedHop(); h != nil {
		return h.Primary
	}
	return ""
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
