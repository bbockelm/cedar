package addresses

import (
	"fmt"
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

	info.SharedPortID = params["sock"]
	info.PrivateAddr = params["PrivAddr"]
	info.PrivateNet = params["PrivNet"]
	info.Alias = params["alias"]
	if _, ok := params["noUDP"]; ok {
		info.NoUDP = true
	}
	if addrs := params["addrs"]; addrs != "" {
		info.Addrs = strings.Split(addrs, "+")
	}
	if ccbid := params["ccbid"]; ccbid != "" {
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

// SplitCCBContact splits a "<broker-address>#<ccbid>" contact string into its
// broker address (no angle brackets) and id. Mirrors
// CCBClient::SplitCCBContact in the HTCondor C++ source, splitting on the
// first '#'.
func SplitCCBContact(contact string) (brokerAddr, ccbid string, ok bool) {
	i := strings.IndexByte(contact, '#')
	if i == -1 {
		return "", "", false
	}
	broker := strings.TrimSpace(contact[:i])
	// Defensive: a contact may legally carry angle brackets in some
	// encodings; strip them so callers get a dialable "host:port".
	broker = strings.TrimPrefix(broker, "<")
	broker = strings.TrimSuffix(broker, ">")
	id := strings.TrimSpace(contact[i+1:])
	if broker == "" || id == "" {
		return "", "", false
	}
	return broker, id, true
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

// urlDecode decodes %XX escapes. Unlike form decoding it does NOT treat '+'
// as a space (HTCondor uses '+' as a literal separator between addresses).
func urlDecode(s string) (string, error) {
	if !strings.ContainsRune(s, '%') {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("truncated %% escape")
		}
		hi, ok1 := fromHex(s[i+1])
		lo, ok2 := fromHex(s[i+2])
		if !ok1 || !ok2 {
			return "", fmt.Errorf("invalid %% escape %q", s[i:i+3])
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

func fromHex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
