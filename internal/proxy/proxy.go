package proxy

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pires/go-proxyproto"
)

const HeaderTimeout = 5 * time.Second

func ParseTrusted(list []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range list {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("%q is neither an address nor a CIDR range", entry)
			}
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("%q is not a valid CIDR range", entry)
		}
		out = append(out, n)
	}
	return out, nil
}

func Listen(ln net.Listener, trusted []*net.IPNet) net.Listener {
	if len(trusted) == 0 {
		return ln
	}
	return &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: HeaderTimeout,
		ConnPolicy: func(o proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			if Trusted(o.Upstream, trusted) {
				return proxyproto.REQUIRE, nil
			}
			return proxyproto.SKIP, nil
		},
	}
}

func Trusted(addr net.Addr, trusted []*net.IPNet) bool {
	var ip net.IP
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip = a.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return false
		}
		ip = net.ParseIP(host)
	}
	if ip == nil {
		return false
	}
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
