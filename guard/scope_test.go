package guard

import "testing"

func TestScopeMatcherBoundaries(t *testing.T) {
	m := NewScopeMatcher([]ScopeRule{
		{Kind: "domain", Value: "Example.COM."},
		{Kind: "cidr", Value: "10.20.0.0/16"},
		{Kind: "cidr", Value: "2001:db8:42::/48"},
		{Kind: "ip", Value: "192.0.2.8"},
	})
	for _, tc := range []struct {
		host string
		want ScopeVerdict
	}{
		{"example.com", ScopeIn}, {"API.EXAMPLE.COM.:443", ScopeIn},
		{"badexample.com", ScopeOut}, {"example.com.attacker.net", ScopeOut},
		{"10.20.255.254:8080", ScopeIn}, {"10.21.0.1", ScopeOut},
		{"[2001:db8:42::1]:443", ScopeIn}, {"2001:db8:43::1", ScopeOut},
		{"192.0.2.8", ScopeIn}, {"192.0.2.9", ScopeOut},
		{"localhost", ScopeIn}, {"127.0.0.1", ScopeIn}, {"::1", ScopeIn},
		{"192.168.0.1", ScopeOut}, {"172.16.0.1", ScopeOut},
		{"10.20.1.0/24", ScopeIn}, {"10.0.0.0/8", ScopeOut},
		{"10.21.0.0/16", ScopeOut}, {"2001:db8:42:1::/64", ScopeIn},
		{"2001:db8::/32", ScopeOut},
	} {
		t.Run(tc.host, func(t *testing.T) {
			if got := m.Check(tc.host); got != tc.want {
				t.Fatalf("Check(%q)=%v want %v", tc.host, got, tc.want)
			}
		})
	}
	m.AllowLocal = false
	if m.Check("127.0.0.1") != ScopeOut {
		t.Fatal("local exemption must be configurable")
	}
	if NewScopeMatcher(nil).Check("outside.example") != ScopeUnknown {
		t.Fatal("unregistered scope must remain Unknown")
	}
}
