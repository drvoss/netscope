// Package health implements the L7 / port checks shown in the mid bar.
//
// These results are kept independent of hop classification on purpose: ICMP can
// be blocked end to end while HTTP works perfectly, and conflating the two would
// make the dashboard lie in both directions (spec §6.5).
package health

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/drvoss/netscope/netscope-go/internal/model"
)

// Check performs an HTTP status probe and a TCP connect probe.
//
// host is the name the user typed (so TLS SNI and Host are correct);
// ip is the resolved address actually being measured, so the check follows the
// same path as the probes rather than re-resolving to a different CDN node.
func Check(ctx context.Context, host, ip string, port int, now time.Duration) model.Health {
	h := model.Health{TCPPort: port, CheckedAt: now}

	h.TCPOpen, h.TCPNote = tcpCheck(ctx, ip, port)
	h.HTTPStatus, h.HTTPLatency, h.HTTPNote = httpCheck(ctx, host, ip, port)
	return h
}

func tcpCheck(ctx context.Context, ip string, port int) (bool, string) {
	d := net.Dialer{Timeout: 3 * time.Second}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return false, "timeout"
		}
		return false, "refused"
	}
	c.Close()
	return true, "open"
}

// httpCheck issues a HEAD and falls back to a ranged GET, because a fair number
// of servers answer HEAD with 405 while serving GET normally.
func httpCheck(ctx context.Context, host, ip string, port int) (int, *float64, string) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s", scheme, host)
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		url = fmt.Sprintf("%s://%s:%d", scheme, host, port)
	}

	// Pin the connection to the IP we are probing while keeping Host/SNI as the
	// user's hostname.
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(ip, strconv.Itoa(port)))
		},
		TLSClientConfig:   &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		// Report the first hop's status rather than following redirects, so the
		// number in the bar corresponds to the host we measured.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer transport.CloseIdleConnections()

	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return 0, nil, "bad url"
		}
		if method == http.MethodGet {
			req.Header.Set("Range", "bytes=0-0")
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			if method == http.MethodGet {
				return 0, nil, shortErr(err)
			}
			continue
		}
		lat := float64(time.Since(start)) / float64(time.Millisecond)
		resp.Body.Close()
		if resp.StatusCode == http.StatusMethodNotAllowed && method == http.MethodHead {
			continue
		}
		note := method
		return resp.StatusCode, &lat, note
	}
	return 0, nil, "no response"
}

func shortErr(err error) string {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "timeout"
	}
	s := err.Error()
	if len(s) > 48 {
		return s[len(s)-48:]
	}
	return s
}
