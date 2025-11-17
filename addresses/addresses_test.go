package addresses

import (
	"testing"
)

func TestParseHTCondorAddress(t *testing.T) {
	tests := []struct {
		address        string
		expectedAddr   string
		expectedID     string
		expectedShared bool
	}{
		{
			address:        "192.168.1.100:9618?sock=startd",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "startd",
			expectedShared: true,
		},
		{
			address:        "<192.168.1.100:9618?sock=schedd>",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "schedd",
			expectedShared: true,
		},
		{
			address:        "192.168.1.100:9618?sock=collector&timeout=30",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "collector",
			expectedShared: true,
		},
		{
			address:        "192.168.1.100:9618?sock=negotiator?other=param",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "negotiator",
			expectedShared: true,
		},
		{
			address:        "192.168.1.100:9618",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "",
			expectedShared: false,
		},
		{
			address:        "<192.168.1.100:9618>",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "",
			expectedShared: false,
		},
		{
			address:        "cm.example.org:9618?sock=startd",
			expectedAddr:   "cm.example.org:9618",
			expectedID:     "startd",
			expectedShared: true,
		},
		{
			address:        "<127.0.0.1:41919?addrs=127.0.0.1-41919&alias=runnervmg1sw1.kajs0ggquhde3gzpd0bbohzbxe.dx.internal.cloudapp.net>",
			expectedAddr:   "127.0.0.1:41919",
			expectedID:     "",
			expectedShared: false,
		},
		{
			address:        "192.168.1.100:9618?addrs=192.168.1.100-9618&noUDP&CCBID=1.2.3.4:5678#123",
			expectedAddr:   "192.168.1.100:9618",
			expectedID:     "",
			expectedShared: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			addrInfo := ParseHTCondorAddress(tt.address)
			if addrInfo.ServerAddr != tt.expectedAddr {
				t.Errorf("ParseHTCondorAddress(%q).ServerAddr = %q, want %q", tt.address, addrInfo.ServerAddr, tt.expectedAddr)
			}
			if addrInfo.SharedPortID != tt.expectedID {
				t.Errorf("ParseHTCondorAddress(%q).SharedPortID = %q, want %q", tt.address, addrInfo.SharedPortID, tt.expectedID)
			}
			if addrInfo.IsSharedPort != tt.expectedShared {
				t.Errorf("ParseHTCondorAddress(%q).IsSharedPort = %v, want %v", tt.address, addrInfo.IsSharedPort, tt.expectedShared)
			}
		})
	}
}

func TestIsValidSharedPortID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"startd", true},
		{"schedd", true},
		{"collector", true},
		{"negotiator", true},
		{"shared-port", true},
		{"test_daemon", true},
		{"daemon.123", true},
		{"DAEMON", true},
		{"Daemon1", true},
		{"123", true},
		{"", false},
		{"bad/path", false},
		{"bad\\path", false},
		{"bad space", false},
		{"bad|pipe", false},
		{"bad;semicolon", false},
		{"bad:colon", false},
		{"bad@at", false},
		{"bad#hash", false},
		{"bad$dollar", false},
		{"bad%percent", false},
		{"bad^caret", false},
		{"bad&amp", false},
		{"bad*star", false},
		{"bad(paren", false},
		{"bad)paren", false},
		{"bad[bracket", false},
		{"bad]bracket", false},
		{"bad{brace", false},
		{"bad}brace", false},
		{"bad+plus", false},
		{"bad=equals", false},
		{"bad!exclaim", false},
		{"bad?question", false},
		{"bad<less", false},
		{"bad>greater", false},
		{"bad,comma", false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			result := IsValidSharedPortID(tt.id)
			if result != tt.valid {
				t.Errorf("IsValidSharedPortID(%q) = %v, want %v", tt.id, result, tt.valid)
			}
		})
	}
}

func TestSharedPortInfo(t *testing.T) {
	info := SharedPortInfo{
		ServerAddr:   "192.168.1.100:9618",
		SharedPortID: "startd",
		IsSharedPort: true,
	}

	if info.ServerAddr != "192.168.1.100:9618" {
		t.Errorf("Expected ServerAddr to be '192.168.1.100:9618', got '%s'", info.ServerAddr)
	}
	if info.SharedPortID != "startd" {
		t.Errorf("Expected SharedPortID to be 'startd', got '%s'", info.SharedPortID)
	}
	if !info.IsSharedPort {
		t.Error("Expected IsSharedPort to be true")
	}
}
