package addresses

import "testing"

// A real starter address from the OSPool, as it arrived in a
// GET_JOB_CONNECT_INFO reply. Kept verbatim -- the point of this test is
// that the shapes a production pool actually emits parse, and a
// hand-written approximation is what let the bug through in the first
// place: the key is spelled "CCBID", and every test that exercised CCB
// used "ccbid" because the parser did.
const realOSPoolStarterSinful = `<10.136.81.217:38677?CCBID=128.105.82.148:9618%3faddrs%3d128.105.82.148-9618+` +
	`[2607-f388-2200-93-2f59-6ff4-f755-7c10]-9618%26alias%3dospool-ccb.osg.chtc.io%26noUDP%26sock%3dcollector7` +
	`#12749893%2067.58.49.91:9618%3faddrs%3d67.58.49.91-9618+[fdf0-17b3-c3ec-1f79-10-0-2-1c69]-9618` +
	`%26alias%3dccb-2.ospool.osg-htc.org%26noUDP%26sock%3dcollector9#6062063` +
	`&PrivNet=comp-cc-0447&addrs=10.136.81.217-38677&alias=comp-cc-0447&noUDP>`

// The address must route through CCB.
//
// It did not: the parser looked for a lower-case "ccbid", found nothing,
// and reported no broker contacts. IsCCB() then answered false and the
// dialer connected directly to 10.136.81.217 -- a private address on a
// firewalled worker node -- so the failure was a connect timeout that
// never mentioned CCB at all.
func TestRealOSPoolSinfulRoutesViaCCB(t *testing.T) {
	info, err := ParseSinful(realOSPoolStarterSinful)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if !info.IsCCB() {
		t.Fatalf("IsCCB() = false; the dialer will connect straight to %s, which is unreachable",
			info.PrimaryAddr)
	}
	if len(info.CCBContacts) != 2 {
		t.Fatalf("got %d broker contacts, want 2 -- the pool advertises a pair for redundancy",
			len(info.CCBContacts))
	}

	// Both brokers, in order, with their ids. The broker address is itself
	// a full sinful carrying its own parameters, so this also pins that the
	// contact splits on the id separator and not on something inside it.
	want := []struct{ broker, id string }{
		{"128.105.82.148:9618", "12749893"},
		{"67.58.49.91:9618", "6062063"},
	}
	for i, w := range want {
		got := info.CCBContacts[i]
		gotBroker, err := ParseSinful(got.BrokerAddr)
		if err != nil {
			t.Errorf("contact %d: broker address does not parse: %v", i, err)
			continue
		}
		if gotBroker.PrimaryAddr != w.broker {
			t.Errorf("contact %d: broker = %q, want %q", i, gotBroker.PrimaryAddr, w.broker)
		}
		if got.CCBID != w.id {
			t.Errorf("contact %d: ccbid = %q, want %q", i, got.CCBID, w.id)
		}
	}

	// The rest of the address must still read correctly; the primary
	// address stays the private one, which is precisely why it must not be
	// dialed on its own.
	if info.PrimaryAddr != "10.136.81.217:38677" {
		t.Errorf("primary = %q", info.PrimaryAddr)
	}
	if info.PrivateNet != "comp-cc-0447" {
		t.Errorf("PrivNet = %q, want comp-cc-0447", info.PrivateNet)
	}
	if !info.NoUDP {
		t.Error("noUDP was not seen")
	}
}

// HTCondor spells it "CCBID" (ATTR_CCBID). Accept the other spellings too
// rather than silently treating an unrecognised one as "no broker".
func TestCCBIDKeyIsCaseTolerant(t *testing.T) {
	for _, key := range []string{"CCBID", "ccbid", "CcbId"} {
		t.Run(key, func(t *testing.T) {
			info, err := ParseSinful("<10.0.0.1:9618?" + key + "=192.0.2.1:9618%2342>")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !info.IsCCB() {
				t.Fatalf("%s= produced no broker contacts", key)
			}
			if got := info.CCBContacts[0].CCBID; got != "42" {
				t.Errorf("ccbid = %q, want 42", got)
			}
		})
	}
}

// Params reports a known parameter under HTCondor's own spelling whatever
// case it arrived in, because the fold happens while decoding. That is
// what lets every read be a plain map hit instead of a scan, and it means
// a caller reading Params directly does not have to repeat the guesswork.
func TestParamsUseTheCanonicalSpelling(t *testing.T) {
	info, err := ParseSinful("<10.0.0.1:9618?ccbid=192.0.2.1:9618%2342&PRIVNET=net-a&Sock=collector1>")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for key, want := range map[string]string{
		"CCBID":   "192.0.2.1:9618#42",
		"PrivNet": "net-a",
		"sock":    "collector1",
	} {
		if got := info.Params[key]; got != want {
			t.Errorf("Params[%q] = %q, want %q", key, got, want)
		}
	}
	// And the parsed fields agree with them.
	if info.PrivateNet != "net-a" || info.SharedPortID != "collector1" || !info.IsCCB() {
		t.Errorf("fields disagree with Params: PrivNet=%q sock=%q IsCCB=%v",
			info.PrivateNet, info.SharedPortID, info.IsCCB())
	}
}

// An unknown parameter is left exactly as it arrived -- the fold is a fixed
// set of names, not a general lower-casing.
func TestUnknownParamsAreUntouched(t *testing.T) {
	info, err := ParseSinful("<10.0.0.1:9618?SomeFutureThing=Value>")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := info.Params["SomeFutureThing"]; got != "Value" {
		t.Errorf("Params[\"SomeFutureThing\"] = %q, want %q", got, "Value")
	}
}
