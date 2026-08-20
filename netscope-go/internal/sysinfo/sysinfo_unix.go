//go:build !windows

package sysinfo

import (
	"net"
	"os"
	"sort"
	"strings"
)

// routeInfo reads the IPv4 default route.
//
// iproute2 first, then a BSD/macOS `netstat -rn` fallback. codex correctly noted
// that "POSIX" is not one platform; when neither tool exists the panel says so
// instead of showing a blank gateway (cross-review R1-4).
func routeInfo() (gateway, route, note string) {
	if out, err := runCommand("ip", "-4", "route", "show", "default"); err == nil && out != "" {
		// default via 192.168.0.1 dev eth0 proto dhcp metric 100
		f := strings.Fields(out)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "via" && net.ParseIP(f[i+1]) != nil {
				return f[i+1], "default via " + f[i+1], ""
			}
		}
	}
	if out, err := runCommand("netstat", "-rn"); err == nil && out != "" {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			if f[0] != "default" && f[0] != "0.0.0.0" {
				continue
			}
			if net.ParseIP(f[1]) == nil {
				continue
			}
			return f[1], "default via " + f[1], ""
		}
	}
	return "", "", "no route tool available (tried ip, netstat)"
}

// dnsServers reads /etc/resolv.conf.
//
// This misses systemd-resolved / NetworkManager / VPN split-DNS detail, which
// codex flagged; the loopback stub is reported honestly rather than pretended to
// be the real upstream resolver.
func dnsServers() ([]string, string) {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, "cannot read /etc/resolv.conf"
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ip := net.ParseIP(f[1])
		if ip == nil || seen[f[1]] {
			continue
		}
		seen[f[1]] = true
		out = append(out, f[1])
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, "no nameserver lines in /etc/resolv.conf"
	}
	note := ""
	if len(out) == 1 && strings.HasPrefix(out[0], "127.") {
		note = "resolv.conf points at a local stub resolver; upstream servers not visible"
	}
	return out, note
}
