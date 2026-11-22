package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/gin-gonic/gin"
)

// The address rate limits and lockouts key on comes from the forwarding
// headers only when the connection is from a proxy TRUSTED_PROXIES
// names, the private networks when it is unset, and never otherwise.
func TestClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := func(t *testing.T, setting string) *gin.Engine {
		t.Helper()
		r := gin.New()
		if _, err := trustProxies(r, setting); err != nil {
			t.Fatal(err)
		}
		r.GET("/ip", func(c *gin.Context) { c.String(http.StatusOK, c.ClientIP()) })
		return r
	}
	type req struct{ remote, xff, realIP string }
	ip := func(r *gin.Engine, q req) string {
		hr := httptest.NewRequest(http.MethodGet, "/ip", nil)
		hr.RemoteAddr = q.remote
		if q.xff != "" {
			hr.Header.Set("X-Forwarded-For", q.xff)
		}
		if q.realIP != "" {
			hr.Header.Set("X-Real-Ip", q.realIP)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, hr)
		return w.Body.String()
	}

	for _, tc := range []struct {
		setting, name string
		q             req
		want          string
	}{
		// Unset: the private networks, as before; loopback is not trusted.
		{"", "direct", req{"203.0.113.5:4000", "", ""}, "203.0.113.5"},
		{"", "direct, header forged", req{"203.0.113.5:4000", "198.51.100.1", ""}, "203.0.113.5"},
		{"", "direct, X-Real-Ip forged", req{"203.0.113.5:4000", "", "198.51.100.1"}, "203.0.113.5"},
		{"", "private network", req{"172.17.0.1:4000", "198.51.100.7", ""}, "198.51.100.7"},
		{"", "private ipv6", req{"[fd00::1]:4000", "198.51.100.7", ""}, "198.51.100.7"},
		{"", "loopback is not trusted", req{"127.0.0.1:4000", "198.51.100.7", ""}, "127.0.0.1"},
		{"", "10/8", req{"10.255.0.1:4000", "198.51.100.7", ""}, "198.51.100.7"},
		{"", "192.168/16", req{"192.168.1.1:4000", "198.51.100.7", ""}, "198.51.100.7"},
		{"", "top of 172.16/12", req{"172.31.255.255:4000", "198.51.100.7", ""}, "198.51.100.7"},
		{"", "just past 172.16/12", req{"172.32.0.1:4000", "198.51.100.7", ""}, "172.32.0.1"},
		{"", "fc00::/7", req{"[fc00::1]:4000", "198.51.100.7", ""}, "198.51.100.7"},
		{"  ", "blank means unset", req{"172.17.0.1:4000", "198.51.100.7", ""}, "198.51.100.7"},
		{"", "cloudflare is not trusted", req{"172.68.1.1:4000", "198.51.100.7", ""}, "172.68.1.1"},

		// Named proxies only: the defaults no longer apply.
		{"127.0.0.1, ::1", "the proxy named", req{"127.0.0.1:4000", "198.51.100.7", ""}, "198.51.100.7"},
		{"127.0.0.1, ::1", "over ipv6", req{"[::1]:4000", "198.51.100.7", ""}, "198.51.100.7"},
		{"127.0.0.1, ::1", "a hop the client forged is skipped", req{"127.0.0.1:4000", "6.6.6.6, 198.51.100.7", ""}, "198.51.100.7"},
		{"127.0.0.1, ::1", "X-Real-Ip from the proxy", req{"127.0.0.1:4000", "", "198.51.100.7"}, "198.51.100.7"},
		{"127.0.0.1, ::1", "X-Forwarded-For wins over X-Real-Ip", req{"127.0.0.1:4000", "198.51.100.7", "6.6.6.6"}, "198.51.100.7"},
		{"127.0.0.1, ::1", "another loopback address is not named", req{"127.0.0.6:4000", "198.51.100.7", ""}, "127.0.0.6"},
		{"127.0.0.1, ::1", "a private network is no longer trusted", req{"172.17.0.1:4000", "198.51.100.7", ""}, "172.17.0.1"},
		{"172.18.0.0/16", "a docker network named", req{"172.18.0.1:4000", "198.51.100.7", ""}, "198.51.100.7"},
		{"172.18.0.0/16", "outside it", req{"172.17.0.1:4000", "198.51.100.7", ""}, "172.17.0.1"},

		// none: no proxy at all.
		{"none", "private network ignored", req{"172.17.0.1:4000", "198.51.100.7", ""}, "172.17.0.1"},
		{"NONE", "loopback ignored", req{"127.0.0.1:4000", "198.51.100.7", "198.51.100.8"}, "127.0.0.1"},
		{" none ", "with spaces", req{"10.0.0.1:4000", "198.51.100.7", ""}, "10.0.0.1"},

		// A bare IPv4-mapped address means the IPv4 address, not ::/32.
		{"::ffff:10.0.0.1", "mapped entry trusts its address", req{"10.0.0.1:4000", "198.51.100.7", ""}, "198.51.100.7"},
		{"::ffff:10.0.0.1", "and not ::/32", req{"[::1]:4000", "198.51.100.7", ""}, "::1"},
	} {
		if got := ip(engine(t, tc.setting), tc.q); got != tc.want {
			t.Errorf("TRUSTED_PROXIES=%q, %s: client %s, want %s", tc.setting, tc.name, got, tc.want)
		}
	}
}

// A value that is not a list of addresses stops the server at startup
// rather than quietly trusting nothing, or everything.
func TestTrustedProxiesRejectsBadValues(t *testing.T) {
	for _, bad := range []string{"localhost", "none, 127.0.0.1", "10.0.0.0/33", "*", ",", " , "} {
		if _, err := trustProxies(gin.New(), bad); err == nil {
			t.Errorf("TRUSTED_PROXIES=%q accepted", bad)
		}
	}
	got, err := trustProxies(gin.New(), " 10.0.0.1 ,, 2001:db8::/32 ")
	if err != nil || len(got) != 2 {
		t.Fatalf("list with spaces and an empty item: %v %v", got, err)
	}
}

// Unset keeps exactly the list every release before trusted.
func TestDefaultTrustedProxiesUnchanged(t *testing.T) {
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}
	if !slices.Equal(defaultTrustedProxies, want) {
		t.Fatalf("default trusted proxies %v, want %v", defaultTrustedProxies, want)
	}
	if !trustsEveryone([]string{"10.0.0.1", "0.0.0.0/0"}) || !trustsEveryone([]string{"::/0"}) || trustsEveryone(want) {
		t.Fatal("trustsEveryone")
	}
}
