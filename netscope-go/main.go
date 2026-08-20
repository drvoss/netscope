// Command netscope is the Go reference implementation of NetScope: a
// single-screen TUI that fuses ping and traceroute.
//
// See docs/netscope-spec.md for the cross-language behavioural contract that
// keeps this binary and the C++ nscope binary observably equivalent.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/drvoss/netscope/netscope-go/internal/engine"
	"github.com/drvoss/netscope/netscope-go/internal/model"
	"github.com/drvoss/netscope/netscope-go/internal/probe"
	"github.com/drvoss/netscope/netscope-go/internal/ui"
)

const version = "0.3.0"

func main() {
	var (
		port         = flag.Int("port", 443, "TCP port for the health check")
		noPublicIP   = flag.Bool("no-public-ip", false, "skip the public-IP reflector lookup")
		replayPath   = flag.String("replay", "", "replay a scenario file instead of probing")
		emitSnap     = flag.Bool("emit-snapshot", false, "print the canonical JSON snapshot and exit")
		headless     = flag.Duration("headless", 0, "probe for this long with no TUI, then print the snapshot (e.g. 10s)")
		forceCommand = flag.Bool("force-command", false, "force the degraded command fallback backend")
		showVersion  = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("netscope " + version)
		return
	}

	// Deterministic replay: no sockets, no wall clock, byte-comparable output.
	// This is the parity harness both implementations share (spec §9).
	if *replayPath != "" {
		if err := runReplay(*replayPath, *emitSnap); err != nil {
			fmt.Fprintln(os.Stderr, "netscope: "+err.Error())
			os.Exit(1)
		}
		return
	}

	args := flag.Args()
	if len(args) != 1 {
		usage()
		os.Exit(2)
	}

	if *headless > 0 {
		if err := runHeadless(args[0], *port, !*noPublicIP, *forceCommand, *headless); err != nil {
			fmt.Fprintln(os.Stderr, "netscope: "+err.Error())
			os.Exit(1)
		}
		return
	}

	if err := run(args[0], *port, !*noPublicIP, *forceCommand); err != nil {
		fmt.Fprintln(os.Stderr, "netscope: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `netscope %s - ping x traceroute dashboard

usage:
  netscope [flags] <hostname|ip>
  netscope --replay <scenario.json> --emit-snapshot

flags:
`, version)
	flag.PrintDefaults()
}

func runReplay(path string, emit bool) error {
	sc, err := engine.LoadScenario(path)
	if err != nil {
		return err
	}
	snap := engine.Replay(sc)
	if emit {
		fmt.Print(snap.CanonicalJSON())
		return nil
	}
	fmt.Printf("replayed %q: %d hops, revision %d\n", sc.Name, len(snap.Hops), snap.Revision)
	return nil
}

// runHeadless probes for a fixed duration with no terminal attached, then prints
// the canonical snapshot. This is how real-environment behaviour is verified in
// CI and over a pipe, where the TUI cannot run.
func runHeadless(target string, port int, wantPublicIP, forceCommand bool, d time.Duration) error {
	runner, _, err := setup(target, port, wantPublicIP, forceCommand)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	runner.Start(ctx)

	var last *model.Snapshot
	deadline := time.After(d)
	for {
		select {
		case s := <-runner.Snapshots():
			last = s
		case <-deadline:
			runner.Shutdown()
			if last == nil {
				return fmt.Errorf("no snapshot produced in %s", d)
			}
			fmt.Print(last.CanonicalJSON())
			return nil
		case <-ctx.Done():
			runner.Shutdown()
			if last != nil {
				fmt.Print(last.CanonicalJSON())
			}
			return nil
		}
	}
}

// setup resolves the target and selects a backend, shared by the TUI and
// headless paths.
func setup(target string, port int, wantPublicIP, forceCommand bool) (*engine.Runner, time.Time, error) {
	start := time.Now()

	t, err := engine.ResolveTarget(target)
	if err != nil {
		// A name that does not resolve is a normal user error, not a crash
		// (DoD: graceful failure paths).
		return nil, start, fmt.Errorf("cannot resolve %q: %w", target, err)
	}

	ip := net.ParseIP(t.IP)
	if ip == nil {
		return nil, start, fmt.Errorf("resolved %q to an unusable address %q", target, t.IP)
	}

	backend, note := probe.SelectWith(ip, start, forceCommand)

	return engine.NewRunner(t, backend, engine.Options{
		Port:         port,
		WantPublicIP: wantPublicIP,
		ForceCommand: forceCommand,
	}, start, note), start, nil
}

func run(target string, port int, wantPublicIP, forceCommand bool) error {
	runner, start, err := setup(target, port, wantPublicIP, forceCommand)
	if err != nil {
		return err
	}

	// Ctrl+C outside the TUI (for example when the terminal is not a TTY) must
	// still tear down in the documented order.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	runner.Start(ctx)

	prog := tea.NewProgram(
		ui.New(runner, start),
		tea.WithAltScreen(),
		tea.WithContext(ctx),
	)

	_, runErr := prog.Run()

	// Ordered teardown: sockets closed, workers drained with a bounded grace
	// period, then state released (spec §3.3).
	runner.Shutdown()

	if runErr != nil && ctx.Err() == nil {
		return runErr
	}
	return nil
}
