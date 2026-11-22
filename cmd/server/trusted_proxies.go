package main

import (
	"errors"
	"net/netip"
	"strings"

	"github.com/gin-gonic/gin"
)

// defaultTrustedProxies are the proxies believed when TRUSTED_PROXIES is
// unset: private networks, as every release so far. Loopback is not one
// of them. A connection from 127.0.0.1 shows only that it passed
// through this machine, not that a proxy rewrote its headers, and the
// address keys rate limits and lockouts.
var defaultTrustedProxies = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}

// trustProxies sets whose X-Forwarded-For and X-Real-Ip the engine
// believes, from TRUSTED_PROXIES: unset or empty keeps the defaults,
// "none" believes no proxy, anything else is exactly the IPs and CIDRs
// listed, comma separated. List only HTTP proxies that set or append
// X-Forwarded-For and overwrite X-Real-Ip: a client's own header passed
// through by anything else, a plain TCP forwarder included, would
// choose its address. ClientIP reads X-Forwarded-For from the right,
// skipping trusted addresses, and falls back to X-Real-Ip when that
// header is missing or unreadable. It returns what it trusts.
func trustProxies(r *gin.Engine, setting string) ([]string, error) {
	var proxies []string
	switch setting = strings.TrimSpace(setting); strings.ToLower(setting) {
	case "":
		proxies = defaultTrustedProxies
	case "none":
	default:
		for p := range strings.SplitSeq(setting, ",") {
			if p = strings.TrimSpace(p); p == "" {
				continue
			}
			// gin gives a bare IPv4-mapped address the IPv4 /32, which
			// makes it the IPv6 network ::/32. Written as IPv4, it is
			// the one address meant.
			if a, err := netip.ParseAddr(p); err == nil {
				p = a.Unmap().String()
			}
			proxies = append(proxies, p)
		}
		if len(proxies) == 0 {
			return nil, errors.New("no address in " + setting)
		}
	}
	r.RemoteIPHeaders = []string{"X-Forwarded-For", "X-Real-Ip"}
	// nil, not the gin default, which believes every peer.
	return proxies, r.SetTrustedProxies(proxies)
}

// trustsEveryone reports a list that believes any peer's headers.
func trustsEveryone(proxies []string) bool {
	for _, p := range proxies {
		if pre, err := netip.ParsePrefix(p); err == nil && pre.Bits() == 0 {
			return true
		}
	}
	return false
}
