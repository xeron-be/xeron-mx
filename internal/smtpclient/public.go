package smtpclient

import (
	"errors"
	"fmt"
	"net/netip"
	"syscall"
)

var ErrNonPublicAddress = errors.New("destination is not a public address (queue.allow_private_destinations)")

var nonPublicPrefixes = func() []netip.Prefix {
	var prefixes []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"::/128",
		"::1/128",
		"64:ff9b:1::/48",
		"100::/64",
		"2001::/23",
		"2001:db8::/32",
		"2002::/16",
		"fc00::/7",
		"fe80::/10",
		"ff00::/8",
	} {
		prefixes = append(prefixes, netip.MustParsePrefix(s))
	}
	return prefixes
}()

func IsPublic(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	for _, p := range nonPublicPrefixes {
		if p.Contains(addr) {
			return false
		}
	}
	return true
}

func rejectNonPublic(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrNonPublicAddress, address)
	}
	if !IsPublic(ap.Addr()) {
		return fmt.Errorf("%w: %s", ErrNonPublicAddress, ap.Addr())
	}
	return nil
}
