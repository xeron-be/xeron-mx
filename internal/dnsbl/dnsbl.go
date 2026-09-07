package dnsbl

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xeron-be/xeron-mx/internal/config"
)

type Checker struct {
	enabled   bool
	zones     []string
	timeout   time.Duration
	whitelist []*net.IPNet
	resolver  *net.Resolver
}

type Result struct {
	Listed   bool          `json:"listed"`
	Zone     string        `json:"zone,omitempty"`
	Record   string        `json:"record,omitempty"`
	Duration time.Duration `json:"duration"`
}

type CheckDetail struct {
	Zone   string `json:"zone"`
	Listed bool   `json:"listed"`
	Record string `json:"record,omitempty"`
	Error  string `json:"error,omitempty"`
}

type DetailedResult struct {
	IP       string        `json:"ip"`
	Listed   bool          `json:"listed"`
	Zone     string        `json:"zone,omitempty"`
	Record   string        `json:"record,omitempty"`
	Duration time.Duration `json:"duration"`
	Details  []CheckDetail `json:"details"`
}

var defaultPrivateRanges = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
	"fe80::/10",
}

func New(cfg config.DNSBLConfig, resolver ...*net.Resolver) *Checker {
	var r *net.Resolver
	if len(resolver) > 0 && resolver[0] != nil {
		r = resolver[0]
	} else {
		r = net.DefaultResolver
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}

	var whitelist []*net.IPNet
	for _, cidr := range defaultPrivateRanges {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			whitelist = append(whitelist, ipNet)
		}
	}
	for _, raw := range cfg.Whitelist {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if !strings.Contains(trimmed, "/") {
			if strings.Contains(trimmed, ":") {
				trimmed += "/128"
			} else {
				trimmed += "/32"
			}
		}
		if _, ipNet, err := net.ParseCIDR(trimmed); err == nil {
			whitelist = append(whitelist, ipNet)
		}
	}

	return &Checker{
		enabled:   cfg.Enabled,
		zones:     cfg.Zones,
		timeout:   timeout,
		whitelist: whitelist,
		resolver:  r,
	}
}

func (c *Checker) Enabled() bool {
	return c.enabled
}

func (c *Checker) Zones() []string {
	cp := make([]string, len(c.zones))
	copy(cp, c.zones)
	return cp
}

func (c *Checker) IsWhitelisted(ip net.IP) bool {
	for _, network := range c.whitelist {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func ParseIPString(addr string) (net.IP, error) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return nil, fmt.Errorf("empty IP address")
	}
	if host, _, err := net.SplitHostPort(trimmed); err == nil {
		trimmed = host
	}
	ip := net.ParseIP(trimmed)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %q", addr)
	}
	return ip, nil
}

func ReverseIPv4(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])
}

func ReverseIPv6(ip net.IP) string {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return ""
	}
	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		b := ip16[i]
		low := b & 0x0f
		high := (b >> 4) & 0x0f
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.WriteString(fmt.Sprintf("%x.%x", low, high))
	}
	return sb.String()
}

func ReverseIP(ip net.IP) string {
	if ip4 := ip.To4(); ip4 != nil {
		return ReverseIPv4(ip4)
	}
	return ReverseIPv6(ip)
}

func (c *Checker) Check(ctx context.Context, remoteAddr string) (*Result, error) {
	start := time.Now()
	res := &Result{Duration: 0}

	if !c.enabled || len(c.zones) == 0 {
		res.Duration = time.Since(start)
		return res, nil
	}

	ip, err := ParseIPString(remoteAddr)
	if err != nil {
		res.Duration = time.Since(start)
		return res, nil
	}

	if c.IsWhitelisted(ip) {
		res.Duration = time.Since(start)
		return res, nil
	}

	rev := ReverseIP(ip)
	if rev == "" {
		res.Duration = time.Since(start)
		return res, nil
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	type lookupResult struct {
		zone   string
		record string
		listed bool
	}

	ch := make(chan lookupResult, len(c.zones))
	var wg sync.WaitGroup

	for _, zone := range c.zones {
		wg.Add(1)
		go func(z string) {
			defer wg.Done()
			query := fmt.Sprintf("%s.%s", rev, z)
			addrs, err := c.resolver.LookupHost(ctxTimeout, query)
			if err != nil {
				return
			}
			for _, a := range addrs {
				if isListingCode(a) {
					select {
					case ch <- lookupResult{zone: z, record: a, listed: true}:
					default:
					}
					return
				}
			}
		}(zone)
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	for r := range ch {
		if r.listed {
			res.Listed = true
			res.Zone = r.zone
			res.Record = r.record
			res.Duration = time.Since(start)
			return res, nil
		}
	}

	res.Duration = time.Since(start)
	return res, nil
}

func (c *Checker) CheckDetailed(ctx context.Context, ipStr string) (*DetailedResult, error) {
	start := time.Now()
	ip, err := ParseIPString(ipStr)
	if err != nil {
		return nil, err
	}

	ret := &DetailedResult{
		IP:      ip.String(),
		Details: make([]CheckDetail, 0, len(c.zones)),
	}

	if c.IsWhitelisted(ip) {
		ret.Duration = time.Since(start)
		return ret, nil
	}

	rev := ReverseIP(ip)
	if rev == "" {
		ret.Duration = time.Since(start)
		return ret, nil
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, zone := range c.zones {
		wg.Add(1)
		go func(z string) {
			defer wg.Done()
			detail := CheckDetail{Zone: z}
			query := fmt.Sprintf("%s.%s", rev, z)
			addrs, err := c.resolver.LookupHost(ctxTimeout, query)
			if err != nil {
				if isNotFound(err) {
					detail.Listed = false
				} else {
					detail.Error = err.Error()
				}
			} else {
				for _, a := range addrs {
					if isListingCode(a) {
						detail.Listed = true
						detail.Record = a
						break
					}
				}
			}

			mu.Lock()
			ret.Details = append(ret.Details, detail)
			if detail.Listed && !ret.Listed {
				ret.Listed = true
				ret.Zone = detail.Zone
				ret.Record = detail.Record
			}
			mu.Unlock()
		}(zone)
	}

	wg.Wait()
	ret.Duration = time.Since(start)
	return ret, nil
}

func isListingCode(addr string) bool {
	if strings.HasPrefix(addr, "127.255.255.") {
		return false
	}
	if strings.HasPrefix(addr, "127.") {
		return true
	}
	return false
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	var dnsErr *net.DNSError
	if errorsAs(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such host") || strings.Contains(msg, "not found")
}

func errorsAs(err error, target any) bool {
	if dnsErr, ok := target.(**net.DNSError); ok {
		if de, ok := err.(*net.DNSError); ok {
			*dnsErr = de
			return true
		}
	}
	return false
}
