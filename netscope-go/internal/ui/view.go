package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"

	"github.com/drvoss/netscope/netscope-go/internal/model"
)

var (
	styleTitle    = lipgloss.NewStyle().Bold(true)
	styleDim      = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	styleGood     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleWarn     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleBad      = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styleSelected = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))
	styleHeader   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("111"))
	styleToast    = lipgloss.NewStyle().Foreground(lipgloss.Color("220"))
)

func (m Model) View() string {
	if m.snap == nil {
		return "NetScope starting..."
	}

	w := m.width
	if w < 40 {
		w = 40
	}
	h := m.height
	if h < 12 {
		h = 12
	}

	l := PlanLayout(w, h)

	header := m.renderHeader(w)

	var body string
	if l.Narrow {
		body = m.renderPath(w, l.BodyHeight, false)
	} else {
		leftW := w - l.RightWidth
		left := m.renderPath(leftW, l.BodyHeight, l.WithRDNS)

		resolveH := l.BodyHeight / 2
		localH := l.BodyHeight - resolveH
		right := lipgloss.JoinVertical(lipgloss.Left,
			m.renderResolve(l.RightWidth, resolveH),
			m.renderLocal(l.RightWidth, localH),
		)
		body = lipgloss.JoinHorizontal(lipgloss.Top, left, right)
	}

	parts := []string{header, body}
	if l.TabHeight > 0 {
		parts = append(parts, m.renderNarrowTab(w, l.TabHeight))
	}
	if l.ShowMidBar {
		parts = append(parts, m.renderMidBar(w))
	}
	if l.LogLines > 0 {
		parts = append(parts, m.renderLog(w, l.LogLines))
	}
	return lipgloss.JoinVertical(lipgloss.Left, parts...)
}

// ---------------------------------------------------------------- header

func (m Model) renderHeader(w int) string {
	s := m.snap

	mode := string(s.Mode)
	if s.Degraded {
		mode = styleWarn.Render(mode + " (degraded)")
	} else {
		mode = styleGood.Render(mode)
	}

	state := ""
	if s.Paused {
		state = styleWarn.Render(" PAUSED")
	}

	pub := s.Local.PublicIP
	if pub == "" {
		pub = "-"
	}

	line1 := fmt.Sprintf("%s  target %s (%s)  up %s  pub-ip %s  mode %s%s",
		styleHeader.Render("NetScope"),
		styleTitle.Render(s.Target.Input),
		s.Target.IP,
		fmtUptime(s.Now),
		pub,
		mode,
		state,
	)

	gw := s.Local.Gateway
	if gw == "" {
		gw = "-"
	}
	dns := strings.Join(s.Local.DNSServers, ", ")
	if dns == "" {
		dns = "-"
	}
	line2 := styleDim.Render(fmt.Sprintf("gw %s  dns %s  probe %dms/%dms cap %dpps",
		gw, truncate(dns, 30), s.Cadence.DestIntervalMs, s.Cadence.MidIntervalMs, s.Cadence.GlobalCapPPS))

	keys := styleDim.Render("[q]uit [p]ause [↑↓]hop [r]eprobe [Tab]focus [d]ns [w]asn [/]target")
	if m.inputMode {
		keys = m.input.View()
	}
	if m.toast != "" {
		keys = styleToast.Render(m.toast)
	}

	return boxed("", strings.Join([]string{line1, line2, keys}, "\n"), w, 5, false)
}

func fmtUptime(d time.Duration) string {
	total := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d:%02d", total/3600, (total%3600)/60, total%60)
}

// ---------------------------------------------------------------- path table

func (m Model) renderPath(w, h int, withRDNS bool) string {
	inner := w - 4
	if inner < 20 {
		inner = 20
	}

	// Column widths. The rDNS/ASN column is the first thing dropped when the
	// terminal narrows (spec §8.2).
	const (
		wMark = 2
		wTTL  = 3
		wLoss = 7
		wAvg  = 7
		wLast = 7
		wJit  = 6
	)
	fixed := wMark + wTTL + wLoss + wAvg + wLast + wJit
	wRDNS := 0
	if withRDNS {
		wRDNS = 22
	}
	wHost := inner - fixed - wRDNS
	if wHost < 12 {
		wHost = 12
	}

	head := pad("", wMark) + pad("#", wTTL) + pad("HOST/IP", wHost)
	if withRDNS {
		head += pad("rDNS/ASN", wRDNS)
	}
	head += lpad("LOSS", wLoss) + lpad("AVG", wAvg) + lpad("LAST", wLast) + lpad("JIT", wJit)

	rows := []string{styleDim.Render(head)}

	// A box of height h shows h-2 content rows; the title takes one and the column
	// header takes another, leaving h-4 for data rows.
	visible := h - 4
	if visible < 1 {
		visible = 1
	}
	hops := m.snap.Hops

	// Scroll so the selection stays centred. The selection is a TTL, not a slice
	// index; they only coincide while the list starts at TTL 1 with no gaps.
	selIdx := 0
	for i := range hops {
		if hops[i].TTL == m.selected {
			selIdx = i
			break
		}
	}
	start := 0
	if len(hops) > visible {
		start = selIdx - visible/2
		if start < 0 {
			start = 0
		}
		if start > len(hops)-visible {
			start = len(hops) - visible
		}
	}
	end := start + visible
	if end > len(hops) {
		end = len(hops)
	}

	for i := start; i < end; i++ {
		rows = append(rows, m.renderHopRow(&hops[i], wMark, wTTL, wHost, wRDNS, wLoss, wAvg, wLast, wJit, withRDNS))
	}
	if len(hops) == 0 {
		rows = append(rows, styleDim.Render("  discovering path..."))
	}

	title := "PATH × PING"
	if m.focus == focusPath {
		title = "PATH × PING ◂"
	}
	return boxed(title, strings.Join(rows, "\n"), w, h, m.focus == focusPath)
}

func (m Model) renderHopRow(hp *model.HopPosition, wMark, wTTL, wHost, wRDNS, wLoss, wAvg, wLast, wJit int, withRDNS bool) string {
	selected := hp.TTL == m.selected

	// The marker is emitted verbatim rather than width-padded. U+25B6 has East
	// Asian Width "Ambiguous", so a width table would put it at 1 or 2 columns
	// depending on locale -- and the Go and C++ width tables do not agree on it.
	// Emitting identical bytes makes both implementations render identically,
	// whatever the terminal decides the glyph is worth.
	mark := "  "
	if selected {
		mark = "▶ "
	}
	_ = wMark

	host := hostLabel(hp)
	rdns := ""
	if withRDNS {
		rdns = rdnsLabel(hp)
	}

	row := mark + pad(itoa(hp.TTL), wTTL) + pad(truncate(host, wHost-1), wHost)
	if withRDNS {
		row += pad(truncate(rdns, wRDNS-1), wRDNS)
	}
	row += lpad(fmtLoss(hp.LossPct), wLoss) +
		lpad(fmtMs(hp.Stats.AvgMs), wAvg) +
		lpad(fmtMs(hp.Stats.LastMs), wLast) +
		lpad(fmtJitter(hp.Stats.JitterMs), wJit)

	switch {
	case selected:
		return styleSelected.Render(row)
	case hp.Status == model.StatusSilent || hp.Status == model.StatusTransitOnly:
		return styleDim.Render(row)
	case hp.Status == model.StatusDegraded:
		return styleBad.Render(row)
	case hp.LossPct != nil && *hp.LossPct >= 10:
		return styleWarn.Render(row)
	}
	return row
}

// hostLabel is careful never to claim a hop is "filtered": TRANSIT_ONLY states
// only the observed fact that traffic passes but probes go unanswered
// (spec §5.1).
func hostLabel(hp *model.HopPosition) string {
	switch hp.Status {
	case model.StatusUnknown:
		return "···"
	case model.StatusSilent:
		return "* (no reply)"
	case model.StatusTransitOnly:
		// "transit ok" read as ambiguous to a network operator in review: OK how,
		// the path or the ICMP? This says exactly what was observed.
		return "* (pass, no ICMP)"
	}
	label := hp.Primary
	if label == "" {
		label = "*"
	}
	// ECMP: several routers answered at this TTL, so the single-address label
	// would be a lie (spec §6.5). Labelled "ecmp" because "+2" alone was not
	// discoverable.
	if n := len(hp.Responders); n > 1 {
		label += fmt.Sprintf(" +%d ecmp", n-1)
	}
	// DEGRADED must not be conveyed by row colour alone -- that is invisible to a
	// monochrome terminal and to a red/green colour-blind reader.
	if hp.Status == model.StatusDegraded {
		label += " !loss"
	}
	return label
}

func rdnsLabel(hp *model.HopPosition) string {
	if len(hp.Responders) == 0 {
		return "-"
	}
	r := hp.Responders[0]
	switch {
	case r.ASN != "" && r.ASN != "-" && r.Org != "" && r.Org != "-":
		return r.ASN + " " + r.Org
	case r.RDNS != "" && r.RDNS != "-":
		return r.RDNS
	case r.ASN != "" && r.ASN != "-":
		return r.ASN
	case r.RDNS == "-":
		return "-"
	}
	return "…"
}

// ---------------------------------------------------------------- right panels

func (m Model) renderResolve(w, h int) string {
	rec := m.runner.Records()
	var b []string

	b = append(b, kv("A", strings.Join(rec.A, ", "), w-6))
	b = append(b, kv("AAAA", strings.Join(rec.AAAA, ", "), w-6))
	b = append(b, kv("PTR", rec.PTR, w-6))
	if rec.Note != "" {
		b = append(b, styleWarn.Render(truncate(rec.Note, w-6)))
	}
	b = append(b, "")

	hp := m.selectedHop()
	if hp != nil {
		b = append(b, styleDim.Render(fmt.Sprintf("hop %d selected", hp.TTL)))
		if len(hp.Responders) == 0 {
			b = append(b, styleDim.Render("  no responder observed"))
		}
		for i, r := range hp.Responders {
			if i >= 3 {
				b = append(b, styleDim.Render(fmt.Sprintf("  +%d more responders", len(hp.Responders)-3)))
				break
			}
			b = append(b, "  "+truncate(r.IP, w-8))
			b = append(b, styleDim.Render("   "+kv("rDNS", orDash(r.RDNS), w-10)))
			b = append(b, styleDim.Render("   "+kv("ASN", orDash(r.ASN), w-10)))
			b = append(b, styleDim.Render("   "+kv("ORG", orDash(r.Org), w-10)))
			// StDev sits here rather than in the table: the cross-review split on
			// whether jitter or stdev is the right metric, so both are shown
			// (cross-review R1-3).
			b = append(b, styleDim.Render("   "+kv("StDev", fmtMs(r.Stats.StdevMs)+" ms", w-10)))
		}
	}

	title := "RESOLVE / ASN"
	if m.focus == focusResolve {
		title = "RESOLVE / ASN ◂"
	}
	return boxed(title, strings.Join(b, "\n"), w, h, m.focus == focusResolve)
}

func (m Model) renderLocal(w, h int) string {
	l := m.snap.Local
	var b []string
	b = append(b, kv("if", orDash(l.Interface)+"  "+orDash(l.Address), w-6))
	b = append(b, kv("gw", orDash(l.Gateway), w-6))
	b = append(b, kv("route", orDash(l.DefaultRoute), w-6))
	dns := strings.Join(l.DNSServers, ", ")
	b = append(b, kv("dns", orDash(dns), w-6))
	b = append(b, kv("pub", orDash(l.PublicIP), w-6))
	if l.Note != "" {
		b = append(b, styleWarn.Render(truncate(l.Note, w-6)))
	}

	title := "LOCAL IF / ROUTE"
	if m.focus == focusLocal {
		title = "LOCAL IF / ROUTE ◂"
	}
	return boxed(title, strings.Join(b, "\n"), w, h, m.focus == focusLocal)
}

// renderNarrowTab is the collapsed right column: Tab switches between the two
// panels when the terminal is too narrow to show both (spec §8.2).
func (m Model) renderNarrowTab(w, h int) string {
	if m.focus == focusLocal {
		return m.renderLocal(w, h)
	}
	return m.renderResolve(w, h)
}

// ---------------------------------------------------------------- mid bar

func (m Model) renderMidBar(w int) string {
	hp := m.selectedHop()

	label := "RTT SPARKLINE (no hop selected)"
	spark := ""
	stat := ""
	if hp != nil {
		label = fmt.Sprintf("RTT hop %d", hp.TTL)
		sparkW := w / 2
		if sparkW < 10 {
			sparkW = 10
		}
		if sparkW > 60 {
			sparkW = 60
		}
		spark = Sparkline(hp.Stats.Spark, sparkW)
		lo, hi, ok := SparkRange(hp.Stats.Spark)
		if ok {
			stat = fmt.Sprintf("%s ms  min %.1f max %.1f  loss %s",
				fmtMs(hp.Stats.LastMs), lo, hi, fmtLoss(hp.LossPct))
		} else {
			stat = "no samples  loss " + fmtLoss(hp.LossPct)
		}
	}

	h := m.snap.Health
	httpPart := "HTTP -"
	if h.HTTPStatus > 0 {
		s := fmt.Sprintf("HTTP %d %s ms", h.HTTPStatus, fmtMs(h.HTTPLatency))
		if h.HTTPStatus < 400 {
			httpPart = styleGood.Render(s)
		} else {
			httpPart = styleWarn.Render(s)
		}
	} else if h.HTTPNote != "" {
		httpPart = styleDim.Render("HTTP " + h.HTTPNote)
	}

	tcpPart := styleDim.Render("TCP -")
	if h.TCPPort > 0 {
		s := fmt.Sprintf("TCP:%d %s", h.TCPPort, h.TCPNote)
		if h.TCPOpen {
			tcpPart = styleGood.Render(s)
		} else {
			tcpPart = styleBad.Render(s)
		}
	}

	line := fmt.Sprintf("%s %s  %s", styleDim.Render(label), spark, stat)
	line2 := httpPart + "  ·  " + tcpPart
	// The health bar is deliberately independent of hop classification: ICMP can
	// be blocked end to end while HTTP works (spec §6.5).
	return boxed("", line+"\n"+line2, w, 4, false)
}

// ---------------------------------------------------------------- log

func (m Model) renderLog(w, lines int) string {
	var b []string
	for i, ev := range m.snap.Events {
		if i >= lines {
			break
		}
		ts := m.startWall.Add(ev.At).Format("15:04:05")
		text := truncate(ev.Text, w-16)
		row := fmt.Sprintf("%s %s", styleDim.Render(ts), text)
		switch ev.Kind {
		case model.EventRouteChange, model.EventResponderChange:
			row = fmt.Sprintf("%s %s", styleDim.Render(ts), styleWarn.Render(text))
		case model.EventError, model.EventPermission, model.EventUnreachable, model.EventTimeoutStreak:
			row = fmt.Sprintf("%s %s", styleDim.Render(ts), styleBad.Render(text))
		}
		b = append(b, row)
	}
	if len(b) == 0 {
		b = append(b, styleDim.Render("no events yet"))
	}
	// lines entries + the title row + two border rows: at lines+2 the last entry
	// was being clipped.
	return boxed("LOG", strings.Join(b, "\n"), w, lines+3, false)
}

// ---------------------------------------------------------------- helpers

func boxed(title, content string, w, h int, focused bool) string {
	border := lipgloss.RoundedBorder()
	st := lipgloss.NewStyle().
		Border(border).
		Width(w - 2).
		Height(h - 2)
	if focused {
		st = st.BorderForeground(lipgloss.Color("81"))
	} else {
		st = st.BorderForeground(lipgloss.Color("240"))
	}
	if title != "" {
		content = styleTitle.Render(title) + "\n" + content
	}
	return st.Render(content)
}

func kv(k, v string, w int) string {
	if v == "" {
		v = "-"
	}
	return styleDim.Render(pad(k, 7)) + truncate(v, w-7)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Display rules from spec §8.3: a missing value is never rendered as zero.
func fmtLoss(v *float64) string {
	if v == nil {
		return "---"
	}
	return fmt.Sprintf("%.1f%%", *v)
}

func fmtMs(v *float64) string {
	if v == nil {
		return "-"
	}
	return fmt.Sprintf("%.1f", *v)
}

func fmtJitter(v *float64) string {
	if v == nil {
		// Fewer than two adjacent successful probes: showing 0 would claim a
		// perfectly stable link (spec §4.3).
		return "—"
	}
	return fmt.Sprintf("%.1f", *v)
}

func pad(s string, w int) string {
	if w <= 0 {
		return ""
	}
	d := w - runewidth.StringWidth(s)
	if d <= 0 {
		return runewidth.Truncate(s, w, "")
	}
	return s + strings.Repeat(" ", d)
}

func lpad(s string, w int) string {
	if w <= 0 {
		return ""
	}
	d := w - runewidth.StringWidth(s)
	if d <= 0 {
		return runewidth.Truncate(s, w, "")
	}
	return strings.Repeat(" ", d) + s
}

func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if runewidth.StringWidth(s) <= w {
		return s
	}
	return runewidth.Truncate(s, w, "…")
}
