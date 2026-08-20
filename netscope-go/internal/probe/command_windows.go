//go:build windows

package probe

import (
	"os"
	"strconv"
)

// traceCommand builds the Windows path-discovery command.
//
// -d skips reverse DNS (enrichment does that off the probe path), -w bounds each
// probe, -h bounds the sweep.
func traceCommand(targetIP string, maxTTL int) (string, []string) {
	return "tracert", []string{"-d", "-w", "1500", "-h", strconv.Itoa(maxTTL), targetIP}
}

// pingCommand builds a single-shot ping for the destination.
func pingCommand(targetIP string) (string, []string) {
	return "ping", []string{"-n", "1", "-w", "1500", targetIP}
}

// stableLocaleEnv is the child environment. On Windows the display language
// cannot be forced this way, so the parsers are written to be locale-agnostic
// instead -- they read only hop numbers, IP literals and "<n> ms" groups, which
// are ASCII in every localization (see parse.go).
func stableLocaleEnv() []string { return os.Environ() }
