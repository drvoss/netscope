// Package enrich resolves reverse DNS and ASN/org ownership.
//
// It is deliberately a separate subsystem with its own cache, not a step inside
// the probe loop: rDNS and Cymru TXT lookups can stall for seconds and must never
// hold up measurement (spec §7, cross-review R1-1 #8).
package enrich

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Cache TTLs (spec §7).
const (
	RDNSTTL = 10 * time.Minute
	ASNTTL  = 60 * time.Minute
	DNSTTL  = 5 * time.Minute
)

// Result is what the engine folds into a responder.
type Result struct {
	IP   string
	RDNS string
	ASN  string
	Org  string
}

type entry struct {
	val string
	at  time.Time
}

type recordEntry struct {
	val Records
	at  time.Time
}

// Cache holds enrichment results with per-kind expiry.
type Cache struct {
	mu      sync.Mutex
	rdns    map[string]entry
	asn     map[string]entry
	org     map[string]entry
	records map[string]recordEntry

	resolver *net.Resolver
}

func NewCache() *Cache {
	return &Cache{
		rdns:     map[string]entry{},
		asn:      map[string]entry{},
		org:      map[string]entry{},
		records:  map[string]recordEntry{},
		resolver: &net.Resolver{},
	}
}

func (c *Cache) get(m map[string]entry, key string, ttl time.Duration) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := m[key]
	if !ok || time.Since(e.at) > ttl {
		return "", false
	}
	return e.val, true
}

func (c *Cache) put(m map[string]entry, key, val string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m[key] = entry{val: val, at: time.Now()}
}

// Invalidate drops cached values for an IP so a manual refresh (keys d / w)
// actually re-queries.
func (c *Cache) Invalidate(ip string, dns, asn bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if dns {
		delete(c.rdns, ip)
	}
	if asn {
		delete(c.asn, ip)
		delete(c.org, ip)
	}
}

// Lookup fills rDNS and ASN/org for one IP.
//
// Private, loopback, link-local and CGNAT addresses are never sent to a public
// resolver: they are meaningless to Cymru and leaking the internal topology of a
// network to a third party would be rude at best (spec §7).
func (c *Cache) Lookup(ctx context.Context, ip string) Result {
	res := Result{IP: ip}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return res
	}

	if IsPrivateOrReserved(parsed) {
		res.RDNS = c.reverseDNS(ctx, ip)
		if res.RDNS == "" {
			res.RDNS = "-"
		}
		res.ASN, res.Org = "-", "-"
		return res
	}

	res.RDNS = c.reverseDNS(ctx, ip)
	if res.RDNS == "" {
		res.RDNS = "-"
	}
	res.ASN, res.Org = c.asnLookup(ctx, parsed)
	return res
}

func (c *Cache) reverseDNS(ctx context.Context, ip string) string {
	if v, ok := c.get(c.rdns, ip, RDNSTTL); ok {
		return v
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	names, err := c.resolver.LookupAddr(ctx, ip)
	val := ""
	if err == nil && len(names) > 0 {
		val = strings.TrimSuffix(names[0], ".")
	} else {
		val = "-"
	}
	c.put(c.rdns, ip, val)
	return val
}

// asnLookup uses Team Cymru's DNS-based origin service.
//
// This is an ASN/org lookup, NOT a full WHOIS: the plan's `w` key and the UI
// label both say ASN for that reason (cross-review R1-1 #10). A real WHOIS parser
// across five RIR formats is out of scope.
func (c *Cache) asnLookup(ctx context.Context, ip net.IP) (string, string) {
	if a, ok := c.get(c.asn, ip.String(), ASNTTL); ok {
		o, _ := c.get(c.org, ip.String(), ASNTTL)
		return a, o
	}

	name, err := cymruOriginName(ip)
	if err != nil {
		return "", ""
	}

	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	txts, err := c.resolver.LookupTXT(ctx, name)
	if err != nil || len(txts) == 0 {
		c.put(c.asn, ip.String(), "-")
		c.put(c.org, ip.String(), "-")
		return "-", "-"
	}

	// "15133 | 93.184.216.0/24 | US | arin | 2008-06-02"
	asn := firstField(txts[0])
	if asn == "" {
		c.put(c.asn, ip.String(), "-")
		c.put(c.org, ip.String(), "-")
		return "-", "-"
	}
	asnLabel := "AS" + asn
	c.put(c.asn, ip.String(), asnLabel)

	org := "-"
	// "15133 | US | arin | 2007-03-23 | EDGECAST, US"
	if txt, err := c.resolver.LookupTXT(ctx, "AS"+asn+".asn.cymru.com"); err == nil && len(txt) > 0 {
		parts := strings.Split(txt[0], "|")
		if len(parts) >= 5 {
			org = strings.TrimSpace(parts[len(parts)-1])
		}
	}
	c.put(c.org, ip.String(), org)
	return asnLabel, org
}

func firstField(txt string) string {
	parts := strings.Split(txt, "|")
	if len(parts) == 0 {
		return ""
	}
	f := strings.TrimSpace(parts[0])
	for _, r := range f {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return f
}

// cymruOriginName builds the reversed query name for the origin service.
func cymruOriginName(ip net.IP) (string, error) {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0]), nil
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", fmt.Errorf("not an IP: %v", ip)
	}
	const hex = "0123456789abcdef"
	var b strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		b.WriteByte(hex[v6[i]&0xf])
		b.WriteByte('.')
		b.WriteByte(hex[v6[i]>>4])
		b.WriteByte('.')
	}
	b.WriteString("origin6.asn.cymru.com")
	return b.String(), nil
}

// cgnat is the RFC 6598 shared address space, which is neither public nor
// RFC1918 and which net.IP.IsPrivate does not cover.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// IsPrivateOrReserved reports whether an address should be excluded from public
// lookups.
func IsPrivateOrReserved(ip net.IP) bool {
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast() ||
		cgnat.Contains(ip)
}

// Records is the RESOLVE panel content for the target.
type Records struct {
	A    []string
	AAAA []string
	PTR  string
	Note string
}

// LookupRecords resolves the target's forward and reverse records.
//
// Cached for DNSTTL so the periodic refresh does not re-query every cycle
// (spec §7); a failed lookup is not cached, so a transient DNS outage recovers on
// the next refresh instead of being remembered for five minutes.
func (c *Cache) LookupRecords(ctx context.Context, host string) Records {
	c.mu.Lock()
	if e, ok := c.records[host]; ok && time.Since(e.at) <= DNSTTL {
		c.mu.Unlock()
		return e.val
	}
	c.mu.Unlock()

	var r Records
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := c.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		r.Note = "lookup failed: " + err.Error()
		return r
	}
	for _, ia := range ips {
		if v4 := ia.IP.To4(); v4 != nil {
			r.A = append(r.A, v4.String())
		} else {
			r.AAAA = append(r.AAAA, ia.IP.String())
		}
	}
	if len(r.A) > 0 {
		if names, err := c.resolver.LookupAddr(ctx, r.A[0]); err == nil && len(names) > 0 {
			r.PTR = strings.TrimSuffix(names[0], ".")
		} else {
			r.PTR = "-"
		}
	}

	c.mu.Lock()
	c.records[host] = recordEntry{val: r, at: time.Now()}
	c.mu.Unlock()
	return r
}
