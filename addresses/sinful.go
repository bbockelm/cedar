package addresses

import (
	"fmt"
	"net/url"
	"strings"
)

// CCBContact is a single Condor Connection Broker contact extracted from a
// sinful string's "ccbid" parameter. On the wire a contact has the form
// "<broker-address>#<ccbid>" where the broker address has NO angle brackets
// (e.g. "192.168.1.1:9618#42"), matching CCBServer::CCBIDToContactString in
// the HTCondor C++ source.
type CCBContact struct {
	BrokerAddr string // broker address without angle brackets, e.g. "192.168.1.1:9618"
	CCBID      string // the broker-assigned id, e.g. "42"
	Raw        string // the full "addr#id" contact string
}

// SinfulInfo is the parsed form of an HTCondor "sinful" string. It supersedes
// SharedPortInfo (which only understood the "sock" parameter) by also
// understanding CCB routing ("ccbid"), private addresses ("PrivAddr"),
// "noUDP", and the other v0 sinful query parameters. The v0 format is:
//
//	<host:port?key1=value1&key2=value2&...>
//
// where keys and values are url-encoded with %XX escapes and pairs are
// delimited by '&' or ';' (see parseUrlEncodedParams in condor_sinful.cpp).
type SinfulInfo struct {
	Raw          string            // the original input
	PrimaryAddr  string            // primary "host:port" (brackets/params stripped)
	Host         string            // host portion of PrimaryAddr
	Port         string            // port portion of PrimaryAddr
	SharedPortID string            // "sock" parameter, if any
	CCBContacts  []CCBContact      // "ccbid" parameter, parsed (space-separated list)
	PrivateAddr  string            // "PrivAddr" parameter, if any
	PrivateNet   string            // "PrivNet" parameter, if any
	Alias        string            // "alias" parameter, if any
	NoUDP        bool              // "noUDP" parameter present
	Addrs        []string          // "addrs" parameter, split on '+'
	Params       map[string]string // all decoded query parameters
}

// IsSharedPort reports whether the address routes through a shared-port daemon.
func (s SinfulInfo) IsSharedPort() bool { return s.SharedPortID != "" }

// IsCCB reports whether the address must be reached via the Condor Connection
// Broker (i.e. it carries one or more ccb contacts).
func (s SinfulInfo) IsCCB() bool { return len(s.CCBContacts) > 0 }

// lookupParam reads a sinful parameter, preferring the exact spelling and
// falling back to a case-insensitive match.
//
// HTCondor's own parser is a plain case-sensitive map, so the exact spellings
// are what daemons emit and what we should expect. The fallback exists because
// getting one of them wrong is invisible: an unmatched key is not an error,
// it just leaves a field empty, and the address then means something different
// and entirely plausible. That is exactly how the CCBID case bug survived --
// a missing broker contact reads as "this daemon is directly reachable".
func lookupParam(params map[string]string, key string) string {
	if v, ok := params[key]; ok {
		return v
	}
	for k, v := range params {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// ParseSinful parses an HTCondor v0 sinful string. Angle brackets are
// optional. It never fails on unknown parameters; an error is returned only
// for malformed url-encoding.
func ParseSinful(addr string) (SinfulInfo, error) {
	info := SinfulInfo{Raw: addr, Params: map[string]string{}}

	// Strip surrounding angle brackets if present.
	s := strings.TrimSpace(addr)
	s = strings.TrimPrefix(s, "<")
	s = strings.TrimSuffix(s, ">")

	// Split primary address from the query string.
	primary := s
	var query string
	if i := strings.IndexByte(s, '?'); i != -1 {
		primary = s[:i]
		query = s[i+1:]
	}
	info.PrimaryAddr = primary
	if h, p, ok := splitHostPort(primary); ok {
		info.Host, info.Port = h, p
	}

	if query == "" {
		return info, nil
	}

	params, err := parseSinfulParams(query)
	if err != nil {
		return info, err
	}
	info.Params = params

	info.SharedPortID = lookupParam(params, "sock")
	info.PrivateAddr = lookupParam(params, "PrivAddr")
	info.PrivateNet = lookupParam(params, "PrivNet")
	info.Alias = lookupParam(params, "alias")
	if _, ok := params["noUDP"]; ok {
		info.NoUDP = true
	} else if lookupParam(params, "noUDP") != "" {
		info.NoUDP = true
	}
	if addrs := lookupParam(params, "addrs"); addrs != "" {
		info.Addrs = strings.Split(addrs, "+")
	}
	// "CCBID", not "ccbid": ATTR_CCBID in condor_attributes.h is upper case,
	// and Sinful::setCCBContact writes it verbatim. This read the lower-case
	// spelling, which no HTCondor daemon emits in a v0 sinful -- the lower
	// case one belongs to the newer v1 address parser. Every real CCB address
	// therefore parsed to zero contacts and IsCCB() answered false, so the
	// dialer skipped the broker and connected straight to the primary
	// address. On a firewalled execute node that is a private IP, so the
	// symptom was a connect timeout rather than anything naming CCB.
	if ccbid := lookupParam(params, "CCBID"); ccbid != "" {
		for _, contact := range strings.Fields(ccbid) {
			if broker, id, ok := SplitCCBContact(contact); ok {
				info.CCBContacts = append(info.CCBContacts, CCBContact{
					BrokerAddr: broker,
					CCBID:      id,
					Raw:        contact,
				})
			}
		}
	}

	return info, nil
}

// SplitCCBContact splits a "<broker-address>#<ccbid>" contact into its broker
// address and id, peeling ONE hop. It splits on the LAST '#' so that a *nested*
// (multi-hop tunnel) contact works: brokerAddr may itself be a contact, e.g.
// "192.0.2.10:9618#42#17" -> broker="192.0.2.10:9618#42", id="17" (recurse on the
// broker; see the CCB tunneling design §4.7). A flat single-hop contact has one
// '#', for which split-on-last == split-on-first, so normal CCB is unchanged.
//
// Angle brackets are stripped only when they wrap the whole broker (a bare
// "<host:port>" entry broker), never when the broker is itself a nested contact
// like "<host:port>#42" (whose brackets belong to the inner sinful). Use '#'
// (not '%') as the hop separator because '%' collides with %XX sinful escaping.
func SplitCCBContact(contact string) (brokerAddr, ccbid string, ok bool) {
	s := strings.TrimSpace(contact)
	i := strings.LastIndexByte(s, '#')
	if i == -1 {
		return "", "", false
	}
	broker := strings.TrimSpace(s[:i])
	id := strings.TrimSpace(s[i+1:])
	if len(broker) >= 2 && broker[0] == '<' && broker[len(broker)-1] == '>' {
		broker = broker[1 : len(broker)-1] // matched pair around a bare entry broker
	}
	if broker == "" || id == "" {
		return "", "", false
	}
	return broker, id, true
}

// BrokerIsCCB reports whether a broker address extracted by SplitCCBContact is
// itself CCB-routed (a nested contact with a further hop), i.e. it still carries a
// '#'. A new client uses this to decide whether to recurse.
func BrokerIsCCB(brokerAddr string) bool {
	return strings.ContainsRune(brokerAddr, '#')
}

// splitHostPort splits "host:port" on the LAST colon so that bracketed IPv6
// literals and bare host:port both work. It does not require brackets.
func splitHostPort(addr string) (host, port string, ok bool) {
	i := strings.LastIndexByte(addr, ':')
	if i == -1 {
		return addr, "", false
	}
	return addr[:i], addr[i+1:], true
}

// parseSinfulParams parses "key1=value1&key2=value2" with %XX url-decoding,
// matching parseUrlEncodedParams in condor_sinful.cpp. Pairs are delimited by
// '&' or ';'. If a key repeats, the last value wins.
func parseSinfulParams(s string) (map[string]string, error) {
	params := map[string]string{}
	for _, pair := range strings.FieldsFunc(s, func(r rune) bool { return r == '&' || r == ';' }) {
		key := pair
		val := ""
		if i := strings.IndexByte(pair, '='); i != -1 {
			key = pair[:i]
			val = pair[i+1:]
		}
		dkey, err := urlDecode(key)
		if err != nil {
			return nil, fmt.Errorf("sinful: bad url-encoding in key %q: %w", key, err)
		}
		dval, err := urlDecode(val)
		if err != nil {
			return nil, fmt.Errorf("sinful: bad url-encoding in value %q: %w", val, err)
		}
		params[dkey] = dval
	}
	return params, nil
}

// urlDecode decodes %XX escapes. HTCondor uses '+' as a literal separator
// between addresses rather than as an encoded space, which is exactly the
// semantics of url.PathUnescape (url.QueryUnescape would wrongly turn '+'
// into a space).
func urlDecode(s string) (string, error) {
	return url.PathUnescape(s)
}
