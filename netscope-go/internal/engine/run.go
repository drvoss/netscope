package engine

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/enrich"
	"github.com/drvoss/netscope/netscope-go/internal/health"
	"github.com/drvoss/netscope/netscope-go/internal/model"
	"github.com/drvoss/netscope/netscope-go/internal/probe"
	"github.com/drvoss/netscope/netscope-go/internal/stats"
	"github.com/drvoss/netscope/netscope-go/internal/sysinfo"
)

// Scheduling constants (spec §4.4).
const (
	MaxHops           = 30
	SweepConcurrency  = 4
	TraceRoundMinGap  = 30 * time.Second
	SnapshotInterval  = 100 * time.Millisecond // 10 Hz render ceiling (spec §3.2)
	EnrichDebounce    = 300 * time.Millisecond // spec §7
	HealthInterval    = 15 * time.Second
	LocalInfoInterval = 60 * time.Second
	DrainGrace        = stats.ProbeTimeout + time.Second // spec §3.3 step 4
)

// Options are the runtime knobs from the command line.
type Options struct {
	Port         int
	WantPublicIP bool
	// ForceCommand keeps the degraded backend selected across a target change too,
	// so --force-command survives pressing "/".
	ForceCommand bool
}

// Runner owns the live engine: the single-writer loop plus the worker goroutines
// that feed it (spec §3.1).
type Runner struct {
	eng *Engine

	// backend is replaced when the target changes. A backend is bound to one
	// destination address at construction, so reusing it after a target change
	// would keep measuring the OLD address while labelling the results with the
	// new target -- silently wrong output rather than an error.
	backendMu sync.RWMutex
	backend   probe.Backend

	cache *enrich.Cache
	opts  Options
	start time.Time

	results  chan model.ProbeResult
	commands chan model.Command
	enriched chan enrich.Result
	healths  chan model.Health
	locals   chan model.LocalInfo
	records  chan enrich.Records

	// snapshots is capacity-1 and coalescing: a slow terminal must never make
	// stale snapshots pile up (spec §3.1).
	snapshots chan *model.Snapshot

	// latest lets the scheduler read engine-derived state without touching
	// engine memory. Read-only pointer swap, no lock.
	latest atomic.Pointer[model.Snapshot]

	// selected is the hop the UI has highlighted, for debounced enrichment.
	selected atomic.Int64

	// target is kept here as well as in the engine so the aux and enrich workers
	// never have to wait for the first snapshot to be published. Reading it from
	// the snapshot raced at startup: the aux worker could run before the engine
	// loop had published anything, see an empty target IP, and leave the LOCAL IF
	// panel blank until the next 60s refresh.
	targetIP    atomic.Pointer[string]
	targetInput atomic.Pointer[string]

	recordsVal atomic.Pointer[enrich.Records]

	wg     sync.WaitGroup
	cancel context.CancelFunc

	quitOnce sync.Once
	quit     chan struct{}

	rng   *rand.Rand
	rngMu sync.Mutex
}

// NewRunner wires a runner. The backend has already been selected, so its mode
// is known and can be reported in the first snapshot.
func NewRunner(target model.Target, backend probe.Backend, opts Options, start time.Time, backendNote string) *Runner {
	e := New(target, backend.Mode())
	e.AddEvent(0, model.EventStart, nil, "start probing "+target.Input+" ("+target.IP+")")
	e.AddEvent(0, model.EventResolved, nil, "resolved "+target.Input+" -> "+target.IP)
	if backendNote != "" {
		kind := model.EventStart
		if backend.Mode() == model.ModeCommand {
			kind = model.EventDegradedMode
		}
		e.AddEvent(0, kind, nil, backendNote)
	}

	r := &Runner{
		eng:       e,
		backend:   backend,
		cache:     enrich.NewCache(),
		opts:      opts,
		start:     start,
		results:   make(chan model.ProbeResult, 256),
		commands:  make(chan model.Command, 16),
		enriched:  make(chan enrich.Result, 64),
		healths:   make(chan model.Health, 4),
		locals:    make(chan model.LocalInfo, 4),
		records:   make(chan enrich.Records, 4),
		snapshots: make(chan *model.Snapshot, 1),
		quit:      make(chan struct{}),
		rng:       rand.New(rand.NewSource(start.UnixNano())),
	}
	r.selected.Store(1)
	r.setTargetRefs(target)
	return r
}

// currentBackend returns the backend in force. Callers may block on it while a
// target change swaps in a replacement; the old backend stays alive until the last
// reference drops, and its in-flight results are discarded by generation.
func (r *Runner) currentBackend() probe.Backend {
	r.backendMu.RLock()
	defer r.backendMu.RUnlock()
	return r.backend
}

// rebindBackend swaps in a backend for a new destination and closes the old one.
func (r *Runner) rebindBackend(ip net.IP, now time.Duration) {
	next, note := probe.SelectWith(ip, r.start, r.opts.ForceCommand)

	r.backendMu.Lock()
	old := r.backend
	r.backend = next
	r.backendMu.Unlock()

	if old != nil {
		// Closing unblocks anything still waiting on the old socket. Those results
		// carry the previous generation and are discarded by Engine.Ingest.
		_ = old.Close()
	}

	r.eng.SetMode(next.Mode(), now)
	r.eng.AddEvent(now, model.EventStart, nil, "probe backend rebound: "+note)
}

func (r *Runner) setTargetRefs(t model.Target) {
	ip, input := t.IP, t.Input
	r.targetIP.Store(&ip)
	r.targetInput.Store(&input)
}

func (r *Runner) currentTarget() (ip, input string) {
	if p := r.targetIP.Load(); p != nil {
		ip = *p
	}
	if p := r.targetInput.Load(); p != nil {
		input = *p
	}
	return ip, input
}

// Snapshots is the UI's read side.
func (r *Runner) Snapshots() <-chan *model.Snapshot { return r.snapshots }

// Quit is closed when the engine has accepted a quit command.
func (r *Runner) Quit() <-chan struct{} { return r.quit }

// Records exposes the target's DNS records for the RESOLVE panel.
func (r *Runner) Records() enrich.Records {
	if p := r.recordsVal.Load(); p != nil {
		return *p
	}
	return enrich.Records{}
}

// Send hands a command to the engine loop. Non-blocking: dropping a keystroke is
// better than wedging the UI.
func (r *Runner) Send(c model.Command) {
	select {
	case r.commands <- c:
	default:
	}
}

// Start launches the engine loop and all workers.
func (r *Runner) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel

	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.loop(ctx) }()

	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.schedule(ctx) }()

	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.enrichWorker(ctx) }()

	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.auxWorker(ctx) }()
}

// Shutdown implements the ordered teardown from spec §3.3. All three reviewers
// flagged teardown as the highest-risk area, so the order here is deliberate.
func (r *Runner) Shutdown() {
	// 1-2. stop accepting work and ask everyone to stop
	if r.cancel != nil {
		r.cancel()
	}
	// 3. close sockets and handles. Cancelling a context does not interrupt a
	// blocking read; closing the socket does.
	_ = r.currentBackend().Close()

	// 4-6. drain with a bounded grace period, then give up rather than hang.
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(DrainGrace):
	}
}

// loop is the single writer. Nothing else mutates engine state.
func (r *Runner) loop(ctx context.Context) {
	tick := time.NewTicker(SnapshotInterval)
	defer tick.Stop()

	traceRound := time.NewTicker(TraceRoundMinGap)
	defer traceRound.Stop()

	r.publish(r.snap())

	for {
		select {
		case <-ctx.Done():
			return

		case res := <-r.results:
			r.eng.Ingest(res)

		case en := <-r.enriched:
			r.eng.ApplyEnrich(en.IP, en.RDNS, en.ASN, en.Org)

		case h := <-r.healths:
			r.eng.SetHealth(h)

		case l := <-r.locals:
			r.eng.SetLocal(l)

		case rec := <-r.records:
			cp := rec
			r.recordsVal.Store(&cp)

		case <-traceRound.C:
			r.eng.EndTraceRound(r.now())

		case cmd := <-r.commands:
			if r.apply(cmd) {
				return
			}

		case <-tick.C:
			r.publish(r.snap())
		}
	}
}

// snap records the cadence actually in force, then builds the snapshot. Called
// only from the engine loop, so it is still single-writer.
func (r *Runner) snap() *model.Snapshot {
	dest, mid := effectiveCadence(r.eng.DestTTL(), r.eng.MaxTTL())
	r.eng.SetCadence(int(dest/time.Millisecond), int(mid/time.Millisecond))
	return r.eng.Snapshot(r.now())
}

// apply handles a UI command. Returns true when the engine should stop.
func (r *Runner) apply(cmd model.Command) bool {
	now := r.now()
	switch cmd.Kind {
	case model.CmdQuit:
		r.quitOnce.Do(func() { close(r.quit) })
		return true

	case model.CmdTogglePause:
		r.eng.TogglePause(now)

	case model.CmdReprobe:
		r.eng.Reprobe(now)

	case model.CmdSelectHop:
		r.selected.Store(int64(cmd.TTL))

	case model.CmdSetTarget:
		t, err := ResolveTarget(cmd.Target)
		if err != nil {
			r.eng.AddEvent(now, model.EventError, nil, "cannot resolve "+cmd.Target+": "+err.Error())
			break
		}
		ip := net.ParseIP(t.IP)
		if ip == nil {
			r.eng.AddEvent(now, model.EventError, nil, "unusable address for "+cmd.Target)
			break
		}
		t.ResolvedAt = now
		// Order matters: bump the generation first so results still in flight for
		// the old destination are discarded, then rebind the backend.
		r.eng.SetTarget(t, now)
		r.setTargetRefs(t)
		r.rebindBackend(ip, now)

	case model.CmdRefreshDNS:
		if cmd.SelectedIP != "" {
			r.cache.Invalidate(cmd.SelectedIP, true, false)
			r.eng.AddEvent(now, model.EventEnrich, model.Int(cmd.TTL), "rDNS refresh queued for "+cmd.SelectedIP)
		}

	case model.CmdRefreshASN:
		if cmd.SelectedIP != "" {
			r.cache.Invalidate(cmd.SelectedIP, false, true)
			r.eng.AddEvent(now, model.EventEnrich, model.Int(cmd.TTL), "ASN refresh queued for "+cmd.SelectedIP)
		}
	}
	r.publish(r.snap())
	return false
}

// publish swaps in the newest snapshot, replacing any the UI has not consumed.
func (r *Runner) publish(s *model.Snapshot) {
	r.latest.Store(s)
	select {
	case r.snapshots <- s:
	default:
		// Coalesce: drop the pending one and install the newer snapshot.
		select {
		case <-r.snapshots:
		default:
		}
		select {
		case r.snapshots <- s:
		default:
		}
	}
}

func (r *Runner) now() time.Duration { return time.Since(r.start) }

func (r *Runner) jitterFactor() float64 {
	r.rngMu.Lock()
	defer r.rngMu.Unlock()
	return 0.8 + 0.4*r.rng.Float64() // +/-20% (spec §4.4)
}

// schedule issues probes. It reads only the published snapshot, never engine
// memory.
func (r *Runner) schedule(ctx context.Context) {
	if !r.currentBackend().SupportsPerTTL() {
		r.scheduleSweeps(ctx)
		return
	}

	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()

	var (
		// outstanding maps a TTL to the GENERATION of the probe in flight on it, or
		// 0 when free. Storing the generation rather than a bare bool stops a
		// completion from a previous generation clearing the slot of a new one,
		// which would let the scheduler issue a second probe on a TTL that already
		// had one in flight (codex HIGH finding).
		outstanding = map[int]uint64{}
		nextDue     = map[int]time.Duration{}
		attempt     uint64
		lastSend    time.Duration
		mu          sync.Mutex
		inflight    sync.WaitGroup
		generation  uint64
	)

	minGap := time.Second / time.Duration(DefaultCadence().GlobalCapPPS)

	for {
		select {
		case <-ctx.Done():
			// Wait for probes already in flight so their results are not lost
			// mid-write; Shutdown bounds this with DrainGrace.
			inflight.Wait()
			return
		case <-tick.C:
		}

		snap := r.latest.Load()
		if snap == nil || snap.Paused {
			continue
		}
		if snap.Generation != generation {
			// New generation: forget the old schedule entirely.
			mu.Lock()
			outstanding = map[int]uint64{}
			nextDue = map[int]time.Duration{}
			mu.Unlock()
			generation = snap.Generation
		}

		now := r.now()
		if now-lastSend < minGap {
			continue
		}

		destTTL, maxTTL := destAndMax(snap)
		dest, mid := effectiveCadence(destTTL, maxTTL)

		ttl := r.pickTTL(snap, destTTL, maxTTL, now, nextDue, outstanding, &mu, dest, mid)
		if ttl == 0 {
			continue
		}

		mu.Lock()
		outstanding[ttl] = snap.Generation
		mu.Unlock()
		lastSend = now
		attempt++

		id := model.ProbeID{
			Generation: snap.Generation,
			Family:     snap.Target.Family,
			TTL:        ttl,
			Attempt:    attempt,
		}
		interval := mid
		if destTTL != 0 && ttl >= destTTL {
			interval = dest
		}
		due := now + time.Duration(float64(interval)*r.jitterFactor())

		inflight.Add(1)
		go func() {
			defer inflight.Done()
			res := r.currentBackend().Probe(ctx, id)
			mu.Lock()
			// Only release the slot and re-arm the timer if they still belong to
			// this probe's generation.
			if outstanding[id.TTL] == id.Generation {
				outstanding[id.TTL] = 0
				nextDue[id.TTL] = due
			}
			mu.Unlock()
			select {
			case r.results <- res:
			case <-ctx.Done():
			}
		}()
	}
}

// pickTTL chooses the next TTL to probe: unexplored TTLs first (the sweep), then
// whichever known TTL is most overdue.
func (r *Runner) pickTTL(snap *model.Snapshot, destTTL, maxTTL int, now time.Duration,
	nextDue map[int]time.Duration, outstanding map[int]uint64, mu *sync.Mutex,
	dest, mid time.Duration) int {

	mu.Lock()
	defer mu.Unlock()

	countOutstanding := 0
	for _, gen := range outstanding {
		if gen != 0 {
			countOutstanding++
		}
	}

	// Sweep phase: extend the path while the destination is unknown.
	if destTTL == 0 && maxTTL < MaxHops {
		if countOutstanding < SweepConcurrency {
			for ttl := 1; ttl <= MaxHops; ttl++ {
				if _, known := nextDue[ttl]; known {
					continue
				}
				if outstanding[ttl] != 0 {
					continue
				}
				return ttl
			}
		}
	}

	// Steady state: one outstanding probe per TTL (spec §4.4).
	last := maxTTL
	if destTTL > 0 {
		last = destTTL
	}
	if last == 0 {
		last = 1
	}

	best, bestOverdue := 0, time.Duration(-1)
	for ttl := 1; ttl <= last; ttl++ {
		if outstanding[ttl] != 0 {
			continue
		}
		due, known := nextDue[ttl]
		if !known {
			return ttl
		}
		if now < due {
			continue
		}
		if over := now - due; over > bestOverdue {
			best, bestOverdue = ttl, over
		}
	}
	return best
}

// effectiveCadence dilutes the intermediate-hop interval when the hop count would
// push the global packet rate over the cap. The destination keeps priority
// (spec §4.4).
func effectiveCadence(destTTL, maxTTL int) (dest, mid time.Duration) {
	c := DefaultCadence()
	dest = time.Duration(c.DestIntervalMs) * time.Millisecond
	mid = time.Duration(c.MidIntervalMs) * time.Millisecond

	n := maxTTL
	if destTTL > 0 {
		n = destTTL
	}
	if n <= 1 {
		return dest, mid
	}

	destPPS := 1.0 / dest.Seconds()
	budget := float64(c.GlobalCapPPS) - destPPS
	if budget <= 0 {
		return dest, mid
	}
	needed := float64(n-1) / mid.Seconds()
	if needed <= budget {
		return dest, mid
	}
	mid = time.Duration(float64(n-1) / budget * float64(time.Second))
	return dest, mid
}

func destAndMax(s *model.Snapshot) (destTTL, maxTTL int) {
	for i := range s.Hops {
		if s.Hops[i].TTL > maxTTL {
			maxTTL = s.Hops[i].TTL
		}
		if s.Hops[i].IsDestination && destTTL == 0 {
			destTTL = s.Hops[i].TTL
		}
	}
	return destTTL, maxTTL
}

// scheduleSweeps drives the command backend, which can only measure whole sweeps
// plus a destination ping.
func (r *Runner) scheduleSweeps(ctx context.Context) {
	sweep := time.NewTicker(TraceRoundMinGap)
	defer sweep.Stop()
	ping := time.NewTicker(time.Duration(DefaultCadence().DestIntervalMs) * time.Millisecond)
	defer ping.Stop()

	run := func() {
		snap := r.latest.Load()
		// Pause must stop sweeps too, not only the destination ping: a sweep is by
		// far the larger share of the traffic (codex MEDIUM finding).
		if snap == nil || snap.Paused {
			return
		}
		for _, res := range r.currentBackend().TraceRound(ctx, snap.Generation, MaxHops) {
			select {
			case r.results <- res:
			case <-ctx.Done():
				return
			}
		}
	}
	run()

	var attempt uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			run()
		case <-ping.C:
			snap := r.latest.Load()
			if snap == nil || snap.Paused {
				continue
			}
			destTTL, _ := destAndMax(snap)
			if destTTL == 0 {
				continue
			}
			attempt++
			res := r.currentBackend().Probe(ctx, model.ProbeID{
				Generation: snap.Generation,
				Family:     snap.Target.Family,
				TTL:        destTTL,
				Attempt:    attempt,
			})
			select {
			case r.results <- res:
			case <-ctx.Done():
				return
			}
		}
	}
}

// enrichWorker resolves rDNS/ASN for the selected hop after a debounce, plus a
// slow background pass over the rest of the path.
func (r *Runner) enrichWorker(ctx context.Context) {
	debounce := time.NewTimer(EnrichDebounce)
	defer debounce.Stop()

	background := time.NewTicker(2 * time.Second)
	defer background.Stop()

	lastSelected := int64(-1)
	done := map[string]bool{}

	lookup := func(ip string) {
		if ip == "" {
			return
		}
		res := r.cache.Lookup(ctx, ip)
		select {
		case r.enriched <- res:
		case <-ctx.Done():
		}
	}

	for {
		select {
		case <-ctx.Done():
			return

		case <-debounce.C:
			sel := r.selected.Load()
			if sel != lastSelected {
				lastSelected = sel
				if snap := r.latest.Load(); snap != nil {
					for i := range snap.Hops {
						if snap.Hops[i].TTL == int(sel) {
							lookup(snap.Hops[i].Primary)
						}
					}
				}
			}
			debounce.Reset(EnrichDebounce)

		case <-background.C:
			snap := r.latest.Load()
			if snap == nil {
				continue
			}
			for i := range snap.Hops {
				for _, resp := range snap.Hops[i].Responders {
					if resp.IP == "" || done[resp.IP] {
						continue
					}
					done[resp.IP] = true
					lookup(resp.IP)
					break
				}
			}
		}
	}
}

// auxWorker refreshes the local panel, the target's DNS records and the health
// bar. All of it is off the probe path.
func (r *Runner) auxWorker(ctx context.Context) {
	localTick := time.NewTicker(LocalInfoInterval)
	defer localTick.Stop()
	healthTick := time.NewTicker(HealthInterval)
	defer healthTick.Stop()

	refreshLocal := func() {
		ip, _ := r.currentTarget()
		info := sysinfo.Gather(ctx, ip, r.opts.WantPublicIP)
		select {
		case r.locals <- info:
		case <-ctx.Done():
		}
	}
	refreshRecords := func() {
		_, input := r.currentTarget()
		if input == "" {
			return
		}
		rec := r.cache.LookupRecords(ctx, input)
		select {
		case r.records <- rec:
		case <-ctx.Done():
		}
	}
	refreshHealth := func() {
		ip, input := r.currentTarget()
		if ip == "" {
			return
		}
		h := health.Check(ctx, input, ip, r.opts.Port, r.now())
		select {
		case r.healths <- h:
		case <-ctx.Done():
		}
	}

	refreshLocal()
	refreshRecords()
	refreshHealth()

	for {
		select {
		case <-ctx.Done():
			return
		case <-localTick.C:
			refreshLocal()
			refreshRecords()
		case <-healthTick.C:
			refreshHealth()
		}
	}
}

// ResolveTarget turns user input into a target, preferring IPv4 so the default
// path matches what most users expect from ping/tracert.
func ResolveTarget(input string) (model.Target, error) {
	t := model.Target{Input: input}
	if ip := net.ParseIP(input); ip != nil {
		t.IP = ip.String()
		t.Family = model.FamilyIP4
		if ip.To4() == nil {
			t.Family = model.FamilyIP6
		}
		return t, nil
	}
	ips, err := net.LookupIP(input)
	if err != nil {
		return t, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			t.IP, t.Family = v4.String(), model.FamilyIP4
			return t, nil
		}
	}
	t.IP, t.Family = ips[0].String(), model.FamilyIP6
	return t, nil
}
