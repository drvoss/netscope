//go:build windows

package sysinfo

import (
	"net"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// routeInfo reads the IPv4 default route from `route print -4`.
//
// Only the numeric columns are read, so the localized column headers on a
// non-English Windows do not matter: we look for the row whose destination and
// mask are both 0.0.0.0 and take the gateway from it.
func routeInfo() (gateway, route, note string) {
	out, err := runCommand("route", "print", "-4")
	if err != nil && out == "" {
		return "", "", "route print unavailable"
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 4 {
			continue
		}
		if f[0] != "0.0.0.0" || f[1] != "0.0.0.0" {
			continue
		}
		if net.ParseIP(f[2]) == nil {
			continue
		}
		return f[2], "0.0.0.0/0 via " + f[2], ""
	}
	return "", "", "no IPv4 default route found"
}

// dnsServers reads the resolvers from the registry rather than parsing
// `ipconfig /all`, whose labels are localized. Static NameServer wins over
// DhcpNameServer on the same interface, matching Windows' own precedence.
func dnsServers() ([]string, string) {
	const base = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.READ)
	if err != nil {
		return nil, "cannot read DNS configuration from registry"
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, "cannot enumerate network interfaces"
	}

	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		sub, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+n, registry.READ)
		if err != nil {
			continue
		}
		value := ""
		if v, _, err := sub.GetStringValue("NameServer"); err == nil && strings.TrimSpace(v) != "" {
			value = v
		} else if v, _, err := sub.GetStringValue("DhcpNameServer"); err == nil {
			value = v
		}
		sub.Close()
		for _, s := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ' ' || r == ',' || r == ';'
		}) {
			s = strings.TrimSpace(s)
			if net.ParseIP(s) == nil || seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, "no DNS servers configured"
	}
	return out, ""
}
