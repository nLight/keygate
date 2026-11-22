package payment

import "testing"

func TestIsLocalhostURL(t *testing.T) {
	cases := []struct {
		url  string
		want bool
	}{
		{"http://localhost:8080", true},
		{"http://LOCALHOST", true},
		{"http://localhost.:8080", true},
		{"http://app.localhost:3000", true},
		{"http://127.0.0.1:8080", true},
		{"http://127.1.2.3", true},
		{"http://[::1]:8080", true},
		{"http://0.0.0.0:8080", true},
		{"https://license.example.com", false},
		{"https://localhost-licenses.example.com", false},
		{"https://notlocalhost.example.com", false},
		{"https://127.0.0.1.nip.io", false},
		{"https://license.example.com/localhost", false},
		{"https://keys.example.com/?next=http://127.0.0.1", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsLocalhostURL(c.url); got != c.want {
			t.Errorf("IsLocalhostURL(%q) = %v, want %v", c.url, got, c.want)
		}
	}
}
