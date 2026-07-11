package ccb

import (
	"context"
	"fmt"
	"net"

	"strings"
)

// resolveContact resolves a (possibly nested/tunneled) CCB contact to a byte pipe
// to the target using the recursive, registration-channel model (Model 1): it
// splits the contact "<entry>#id0#...#idN" into the flat entry broker "<entry>" and
// the ordered route [id0, ..., idN], dials only the entry broker, and issues ONE
// streaming CCB_REQUEST carrying the whole route (ccbid=id0, CCBRoute="id1 ...
// idN"). The entry broker and each inner broker then recurse server-side over their
// registration channels (each asks the next hop to reverse-connect and splices), so
// the client does exactly one CEDAR handshake with the entry broker and one
// end-to-end handshake with the target -- never a per-hop handshake with an inner
// broker, and it authenticates only to the entry broker. The returned conn is
// spliced end-to-end through every CCB.
func resolveContact(ctx context.Context, contact string, opts DialOptions) (net.Conn, error) {
	entry, ccbid, route, ok := splitFlatEntryAndRoute(contact)
	if !ok {
		return nil, fmt.Errorf("ccb: malformed CCB contact %q", contact)
	}
	connectID, err := GenerateConnectID()
	if err != nil {
		return nil, err
	}
	return proxyRequestDial(ctx, entry, ccbid, route, connectID, opts)
}

// splitFlatEntryAndRoute splits a (possibly nested) contact "<entry>#id0#...#idN"
// into the flat entry-broker address, the entry broker's target id (id0), and the
// remaining route ("id1 ... idN", space-separated, empty for a single hop). It
// splits on the FIRST '#' (the opposite of SplitCCBContact's peel-innermost), since
// the whole id chain is handed to the entry broker to forward inward.
func splitFlatEntryAndRoute(contact string) (entry, ccbid, route string, ok bool) {
	s := strings.TrimSpace(contact)
	i := strings.IndexByte(s, '#')
	if i == -1 {
		return "", "", "", false
	}
	entry = strings.TrimSpace(s[:i])
	if len(entry) >= 2 && entry[0] == '<' && entry[len(entry)-1] == '>' {
		entry = entry[1 : len(entry)-1]
	}
	ids := strings.Split(strings.TrimSpace(s[i+1:]), "#")
	if entry == "" || len(ids) == 0 || ids[0] == "" {
		return "", "", "", false
	}
	ccbid = strings.TrimSpace(ids[0])
	rest := make([]string, 0, len(ids)-1)
	for _, id := range ids[1:] {
		if t := strings.TrimSpace(id); t != "" {
			rest = append(rest, t)
		}
	}
	return entry, ccbid, strings.Join(rest, " "), true
}

// proxyRequestDial dials the entry broker (TCP or shared-port), authenticates as
// CCB_REQUEST, version-gates streaming, and issues the streaming request for ccbid
// with the remaining route, returning the spliced pipe.
func proxyRequestDial(ctx context.Context, broker, ccbid, route, connectID string, opts DialOptions) (net.Conn, error) {
	brokerConn, brokerStream, neg, err := dialBrokerAuth(ctx, broker, opts.Security)
	if err != nil {
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			_ = brokerConn.Close()
		}
	}()
	if !brokerSupportsStreaming(neg) {
		return nil, fmt.Errorf("ccb: entry broker %s does not support streaming (required for nested routing)", broker)
	}
	pipe, err := proxyRequestOnStream(ctx, brokerConn, brokerStream, ccbid, route, connectID, opts.ProxyReturnAddr, requesterName(opts.TargetDesc))
	if err != nil {
		return nil, err
	}
	handedOff = true
	return pipe, nil
}
