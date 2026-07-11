package stream

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"testing"
)

// establishEncryptedPair returns two streams over a connected net.Pipe with the
// SAME 32-byte AES-256-GCM key applied in both directions, then exchanges a few
// messages EACH WAY so both streams are past counter 0 with finishedSend/RecvAAD
// true -- i.e. a realistic mid-stream state, exactly what exists after an
// ACTIVATE_CLAIM OK reply.
func establishEncryptedPair(t *testing.T) (sA, sB *Stream, connA, connB net.Conn) {
	t.Helper()
	connA, connB = net.Pipe()

	sA = NewStream(connA)
	sB = NewStream(connB)

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	if err := sA.SetSymmetricKey(key); err != nil {
		t.Fatalf("failed to set key on sA: %v", err)
	}
	if err := sB.SetSymmetricKey(key); err != nil {
		t.Fatalf("failed to set key on sB: %v", err)
	}

	// A few messages each way to move both directions past counter 0.
	exchange(t, sA, sB, []byte("A->B hello 1"))
	exchange(t, sB, sA, []byte("B->A hello 1"))
	exchange(t, sA, sB, []byte("A->B hello 2"))
	exchange(t, sB, sA, []byte("B->A hello 2"))

	return sA, sB, connA, connB
}

// exchange sends a single-frame message from -> to and verifies it decrypts.
func exchange(t *testing.T, from, to *Stream, msg []byte) {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- from.SendMessage(context.Background(), msg) }()

	got, err := to.ReceiveFrame(context.Background())
	if err != nil {
		t.Fatalf("receive failed: %v", err)
	}
	if serr := <-errc; serr != nil {
		t.Fatalf("send failed: %v", serr)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("payload mismatch: sent %q got %q", msg, got)
	}
}

// exchangeMulti sends msg via the buffered WriteMessage/EndMessage path (which
// splits into multiple frames once DefaultFrameThreshold is crossed) and reads
// it back with ReceiveCompleteMessage, verifying the reassembled bytes.
func exchangeMulti(t *testing.T, from, to *Stream, msg []byte) {
	t.Helper()
	errc := make(chan error, 1)
	go func() {
		from.StartMessage()
		if err := from.WriteMessage(context.Background(), msg); err != nil {
			errc <- err
			return
		}
		errc <- from.EndMessage(context.Background())
	}()

	got, err := to.ReceiveCompleteMessage(context.Background())
	if err != nil {
		t.Fatalf("ReceiveCompleteMessage failed: %v", err)
	}
	if serr := <-errc; serr != nil {
		t.Fatalf("multi-frame send failed: %v", serr)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("multi-frame payload mismatch: %d bytes sent, %d bytes got", len(msg), len(got))
	}
}

// TestExportImportRoundTrip is the definitive proof of mid-stream resume: export
// sA's live crypto state at a clean boundary, rebuild an equivalent stream around
// the SAME underlying connection, and continue the conversation in both
// directions with small and >4KB (multi-frame) messages -- no IV retransmission,
// no GCM auth failure, counters in lockstep.
func TestExportImportRoundTrip(t *testing.T) {
	sA, sB, connA, _ := establishEncryptedPair(t)

	// Sanity: both directions are mid-stream.
	if !sA.finishedSendAAD || !sA.finishedRecvAAD {
		t.Fatalf("precondition: sA not past handshake (send=%v recv=%v)", sA.finishedSendAAD, sA.finishedRecvAAD)
	}
	if sA.encryptCounter == 0 || sA.decryptCounter == 0 {
		t.Fatalf("precondition: sA counters still zero (enc=%d dec=%d)", sA.encryptCounter, sA.decryptCounter)
	}

	blob, err := sA.ExportCryptoState()
	if err != nil {
		t.Fatalf("ExportCryptoState at clean boundary returned error: %v", err)
	}

	// Rebuild around the SAME connA (the fd survives the handoff in the real flow).
	sA2, err := NewStreamWithCryptoState(connA, blob)
	if err != nil {
		t.Fatalf("NewStreamWithCryptoState failed: %v", err)
	}

	// Counters/IVs/flags must match the exported stream exactly.
	if sA2.encryptCounter != sA.encryptCounter || sA2.decryptCounter != sA.decryptCounter {
		t.Fatalf("counter mismatch after import: enc %d/%d dec %d/%d",
			sA2.encryptCounter, sA.encryptCounter, sA2.decryptCounter, sA.decryptCounter)
	}
	if sA2.encryptIV != sA.encryptIV || sA2.decryptIV != sA.decryptIV {
		t.Fatalf("IV mismatch after import")
	}
	if !sA2.encrypted || !sA2.finishedSendAAD || !sA2.finishedRecvAAD {
		t.Fatalf("flags not restored: enc=%v fsa=%v fra=%v", sA2.encrypted, sA2.finishedSendAAD, sA2.finishedRecvAAD)
	}

	// Continue the conversation sA2 <-> sB in BOTH directions, varying sizes.
	exchange(t, sA2, sB, []byte("resume A->B small 1"))
	exchange(t, sB, sA2, []byte("resume B->A small 1"))
	exchange(t, sA2, sB, []byte("resume A->B small 2"))
	exchange(t, sB, sA2, []byte("resume B->A small 2"))

	// >4KB single-frame messages (crosses the encrypted-size path, exercises IV
	// non-retransmission with a large body).
	big := make([]byte, 5000)
	if _, err := rand.Read(big); err != nil {
		t.Fatalf("rand: %v", err)
	}
	exchange(t, sA2, sB, big)
	exchange(t, sB, sA2, big)

	// Multi-frame messages via the buffered path: >4KB payload splits into a
	// partial frame at the threshold plus a final frame, advancing counters by
	// more than one per message. Proves byte-exact multi-frame resume.
	multi := make([]byte, 4096+1234) // > DefaultFrameThreshold -> 2 frames
	if _, err := rand.Read(multi); err != nil {
		t.Fatalf("rand: %v", err)
	}
	exchangeMulti(t, sA2, sB, multi)
	exchangeMulti(t, sB, sA2, multi)

	// After all exchanges the counters must still be in lockstep across the pair.
	if sA2.encryptCounter != sB.decryptCounter {
		t.Fatalf("A2.enc(%d) != B.dec(%d): send stream desynchronized", sA2.encryptCounter, sB.decryptCounter)
	}
	if sB.encryptCounter != sA2.decryptCounter {
		t.Fatalf("B.enc(%d) != A2.dec(%d): recv stream desynchronized", sB.encryptCounter, sA2.decryptCounter)
	}
}

// TestExportCryptoStateNotEncrypted rejects a plaintext stream.
func TestExportCryptoStateNotEncrypted(t *testing.T) {
	connA, connB := net.Pipe()
	defer func() { _ = connA.Close() }()
	defer func() { _ = connB.Close() }()

	s := NewStream(connA)
	_, err := s.ExportCryptoState()
	if err == nil {
		t.Fatal("expected error exporting a non-encrypted stream")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("not encrypted")) {
		t.Fatalf("error should name the not-encrypted condition, got: %v", err)
	}
}

// TestExportCryptoStatePartialSend rejects a stream with a partial outbound
// message buffered (buffered-bytes hazard).
func TestExportCryptoStatePartialSend(t *testing.T) {
	sA, _, _, _ := establishEncryptedPair(t)

	// Buffer some bytes below the flush threshold: sendBuffer stays non-empty.
	sA.StartMessage()
	if err := sA.WriteMessage(context.Background(), []byte("partial")); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	if len(sA.sendBuffer) == 0 {
		t.Fatal("precondition: expected non-empty sendBuffer")
	}

	_, err := sA.ExportCryptoState()
	if err == nil {
		t.Fatal("expected error exporting mid-outbound-message")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("sendBuffer")) {
		t.Fatalf("error should name sendBuffer, got: %v", err)
	}
}

// TestExportCryptoStateMidReceive rejects a stream mid multi-frame receive.
func TestExportCryptoStateMidReceive(t *testing.T) {
	sA, _, _, _ := establishEncryptedPair(t)

	// Simulate a receive in progress with a buffered inbound frame.
	sA.inMessage = true
	sA.receiveBuffer = []byte{1, 2, 3, 4}

	_, err := sA.ExportCryptoState()
	if err == nil {
		t.Fatal("expected error exporting mid-inbound-message")
	}
	// inMessage is checked first; its condition must be named.
	if !bytes.Contains([]byte(err.Error()), []byte("inMessage")) {
		t.Fatalf("error should name inMessage, got: %v", err)
	}

	// With inMessage cleared but a buffered frame remaining, the receiveBuffer
	// condition must fire.
	sA.inMessage = false
	_, err = sA.ExportCryptoState()
	if err == nil {
		t.Fatal("expected error with buffered receiveBuffer")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("receiveBuffer")) {
		t.Fatalf("error should name receiveBuffer, got: %v", err)
	}
}

// TestExportCryptoStateBeforeHandshake rejects a freshly-keyed stream that has
// not yet exchanged any encrypted frame (finishedSend/RecvAAD false).
func TestExportCryptoStateBeforeHandshake(t *testing.T) {
	connA, connB := net.Pipe()
	defer func() { _ = connA.Close() }()
	defer func() { _ = connB.Close() }()

	s := NewStream(connA)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	if err := s.SetSymmetricKey(key); err != nil {
		t.Fatalf("SetSymmetricKey: %v", err)
	}

	_, err := s.ExportCryptoState()
	if err == nil {
		t.Fatal("expected error exporting before handshake frames exchanged")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("past handshake")) {
		t.Fatalf("error should name the handshake condition, got: %v", err)
	}
}

// TestNewStreamWithCryptoStateBadBlobs covers version, magic, and truncation.
func TestNewStreamWithCryptoStateBadBlobs(t *testing.T) {
	sA, _, connA, _ := establishEncryptedPair(t)
	blob, err := sA.ExportCryptoState()
	if err != nil {
		t.Fatalf("ExportCryptoState: %v", err)
	}

	// Truncated blob.
	if _, err := NewStreamWithCryptoState(connA, blob[:cryptoStateFixedLen-1]); err == nil {
		t.Fatal("expected error on truncated blob")
	}

	// Wrong version: bump the version field (bytes 4:6).
	bad := append([]byte(nil), blob...)
	bad[4] = 0xFF
	bad[5] = 0xFF
	if _, err := NewStreamWithCryptoState(connA, bad); err == nil {
		t.Fatal("expected error on version mismatch")
	} else if !bytes.Contains([]byte(err.Error()), []byte("version")) {
		t.Fatalf("error should name version, got: %v", err)
	}

	// Bad magic.
	badMagic := append([]byte(nil), blob...)
	badMagic[0] = 'X'
	if _, err := NewStreamWithCryptoState(connA, badMagic); err == nil {
		t.Fatal("expected error on bad magic")
	}

	// Truncated variable trailer (cut inside the length-prefixed fields).
	if _, err := NewStreamWithCryptoState(connA, blob[:cryptoStateFixedLen+1]); err == nil {
		t.Fatal("expected error on truncated variable trailer")
	}
}
