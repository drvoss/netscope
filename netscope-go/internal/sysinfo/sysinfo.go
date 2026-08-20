// Package sysinfo fills the LOCAL IF / ROUTE panel.
//
// The platform-specific parts sit behind the small contract below so the panel
// never renders silently blank: when a platform cannot answer, it says so in
// Note rather than leaving empty fields (spec §6.5, cross-review R1-1 #9).
package sysinfo

import (
	"context"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/model"
)

// Gather collects local addressing for the route toward targetIP.
func Gather(ctx context.Context, targetIP string, wantPublicIP bool) model.LocalInfo {
	info := model.LocalInfo{}

	if src := sourceAddrFor(targetIP); src != nil {
		info.Interface, info.Address = interfaceFor(src)
	}

	gw, route, note := routeInfo()
	info.Gateway = gw
	info.DefaultRoute = route
	if note != "" {
		info.Note = note
	}

	dns, dnsNote := dnsServers()
	sort.Strings(dns)
	info.DNSServers = dns
	if dnsNote != "" {
		if info.Note != "" {
			info.Note += "; "
		}
		info.Note += dnsNote
	}

	if wantPublicIP {
		if ip := publicIP(ctx); ip != "" {
			info.PublicIP = ip
		}
	}

	return info
}

// sourceAddrFor asks the kernel which local address would be used to reach the
// target. A UDP "connect" sends no packets; it only performs a route lookup.
func sourceAddrFor(targetIP string) net.IP {
	if targetIP == "" {
		return nil
	}
	host := net.JoinHostPort(targetIP, "80")
	c, err := net.DialTimeout("udp", host, 2*time.Second)
	if err != nil {
		return nil
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return ua.IP
}

// interfaceFor finds the interface owning src and returns its name and the
// address in CIDR form.
func interfaceFor(src net.IP) (string, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", src.String()
	}
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipn.IP.Equal(src) {
				ones, _ := ipn.Mask.Size()
				return ifi.Name, src.String() + "/" + itoa(ones)
			}
		}
	}
	return "", src.String()
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// publicIP asks a public reflector for our externally visible address.
//
// This is the one outbound call NetScope makes to a third party that is not the
// user's chosen target; the plan's header spec requires "pub-ip". Disable it with
// --no-public-ip.
func publicIP(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.ipify.org", nil)
	if err != nil {
		return ""
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if net.ParseIP(s) == nil {
		return ""
	}
	return s
}

// runCommand is a small helper for the platform files.
func runCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return runCommandCtx(ctx, name, args...)
}
