package addresses

import (
	"reflect"
	"testing"
)

func TestParseSinfulPlain(t *testing.T) {
	info, err := ParseSinful("<192.168.1.100:9618>")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.PrimaryAddr != "192.168.1.100:9618" {
		t.Errorf("PrimaryAddr = %q", info.PrimaryAddr)
	}
	if info.Host != "192.168.1.100" || info.Port != "9618" {
		t.Errorf("host/port = %q/%q", info.Host, info.Port)
	}
	if info.IsCCB() || info.IsSharedPort() {
		t.Errorf("plain address should be neither CCB nor shared-port")
	}
}

func TestParseSinfulSharedPort(t *testing.T) {
	info, err := ParseSinful("192.168.1.100:9618?sock=schedd_1234_abcd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.IsSharedPort() || info.SharedPortID != "schedd_1234_abcd" {
		t.Errorf("SharedPortID = %q", info.SharedPortID)
	}
}

func TestParseSinfulCCBSingle(t *testing.T) {
	// '#' and ':' are not url-escaped by HTCondor; the broker address has no
	// angle brackets in a ccbid contact.
	info, err := ParseSinful("<192.168.1.100:9618?ccbid=128.105.1.2:9618#142&noUDP>")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !info.IsCCB() {
		t.Fatalf("expected CCB address")
	}
	if len(info.CCBContacts) != 1 {
		t.Fatalf("got %d contacts, want 1", len(info.CCBContacts))
	}
	c := info.CCBContacts[0]
	if c.BrokerAddr != "128.105.1.2:9618" || c.CCBID != "142" {
		t.Errorf("contact = %+v", c)
	}
	if !info.NoUDP {
		t.Errorf("expected noUDP set")
	}
}

func TestParseSinfulCCBMultiAndPrivAddr(t *testing.T) {
	// Two brokers (space -> %20) plus a url-encoded PrivAddr (<...> -> %3c/%3e).
	in := "<192.168.1.100:9618?ccbid=10.0.0.1:9618#1%2010.0.0.2:9618#2&PrivAddr=%3c10.5.5.5:9618%3e>"
	info, err := ParseSinful(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(info.CCBContacts) != 2 {
		t.Fatalf("got %d contacts, want 2", len(info.CCBContacts))
	}
	want := []CCBContact{
		{BrokerAddr: "10.0.0.1:9618", CCBID: "1", Raw: "10.0.0.1:9618#1"},
		{BrokerAddr: "10.0.0.2:9618", CCBID: "2", Raw: "10.0.0.2:9618#2"},
	}
	if !reflect.DeepEqual(info.CCBContacts, want) {
		t.Errorf("contacts = %+v, want %+v", info.CCBContacts, want)
	}
	if info.PrivateAddr != "<10.5.5.5:9618>" {
		t.Errorf("PrivateAddr = %q", info.PrivateAddr)
	}
}

func TestParseSinfulAddrs(t *testing.T) {
	info, err := ParseSinful("127.0.0.1:9618?addrs=127.0.0.1-9618+[--1]-9618&alias=host.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"127.0.0.1-9618", "[--1]-9618"}
	if !reflect.DeepEqual(info.Addrs, want) {
		t.Errorf("Addrs = %v, want %v", info.Addrs, want)
	}
	if info.Alias != "host.example" {
		t.Errorf("Alias = %q", info.Alias)
	}
}

func TestSplitCCBContact(t *testing.T) {
	tests := []struct {
		in         string
		broker, id string
		ok         bool
	}{
		{"128.105.1.2:9618#142", "128.105.1.2:9618", "142", true},
		{"<128.105.1.2:9618>#9", "128.105.1.2:9618", "9", true},
		{"no-hash-here", "", "", false},
		{"#142", "", "", false},
		{"addr#", "", "", false},
	}
	for _, tc := range tests {
		broker, id, ok := SplitCCBContact(tc.in)
		if ok != tc.ok || broker != tc.broker || id != tc.id {
			t.Errorf("SplitCCBContact(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.in, broker, id, ok, tc.broker, tc.id, tc.ok)
		}
	}
}

func TestUrlDecode(t *testing.T) {
	tests := map[string]string{
		"plain":          "plain",
		"%3c10.0.0.5%3e": "<10.0.0.5>",
		"a%20b":          "a b",
		"1+2":            "1+2", // '+' is literal, not space
		"%2526":          "%26",
	}
	for in, want := range tests {
		got, err := urlDecode(in)
		if err != nil {
			t.Errorf("urlDecode(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("urlDecode(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := urlDecode("bad%2"); err == nil {
		t.Errorf("expected error for truncated escape")
	}
	if _, err := urlDecode("bad%zz"); err == nil {
		t.Errorf("expected error for invalid hex")
	}
}
