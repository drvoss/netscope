//go:build !windows

package probe

import (
	"os"
	"strconv"
)

// traceCommand builds the POSIX path-discovery command.
//
// -n skips reverse DNS, -q 3 sends three probes per hop, -w 2 bounds each wait,
// -m bounds the sweep. ICMP mode (-I) is deliberately NOT requested: it needs
// privileges, and if we had them we would be using the raw backend instead. The
// default UDP probes mean the observed path can differ from the raw backend's
// ICMP path -- one more reason this mode is labelled degraded (spec §6.4).
func traceCommand(targetIP string, maxTTL int) (string, []string) {
	return "traceroute", []string{"-n", "-q", "3", "-w", "2", "-m", strconv.Itoa(maxTTL), targetIP}
}

// pingCommand builds a single-shot ping for the destination.
func pingCommand(targetIP string) (string, []string) {
	return "ping", []string{"-c", "1", "-W", "2", "-n", targetIP}
}

// stableLocaleEnv forces the C locale so numeric formatting and message text do
// not shift with the user's settings (spec §6.4).
func stableLocaleEnv() []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if len(kv) >= 7 && kv[:7] == "LC_ALL=" {
			continue
		}
		if len(kv) >= 5 && kv[:5] == "LANG=" {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "LC_ALL=C", "LANG=C")
}
