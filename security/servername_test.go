package security

import "testing"

// TestServerNameFromAddress verifies the TLS server name is taken from the sinful "alias"
// when present, otherwise the host portion -- so a client verifies the peer certificate
// against the real hostname instead of the "unknown" placeholder that produced
// "certificate is valid for <host>, not unknown".
func TestServerNameFromAddress(t *testing.T) {
	cases := []struct {
		addr, want string
	}{
		{"cm-1.ospool.osg-htc.org:9618", "cm-1.ospool.osg-htc.org"},
		{"<192.170.227.219:9618?alias=cm-1.ospool.osg-htc.org&noUDP&sock=collector>", "cm-1.ospool.osg-htc.org"},
		{"<192.170.227.219:9618?noUDP>", "192.170.227.219"},
		{"192.170.227.219:9618", "192.170.227.219"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := serverNameFromAddress(tc.addr); got != tc.want {
			t.Errorf("serverNameFromAddress(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}
