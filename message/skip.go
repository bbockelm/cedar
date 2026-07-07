package message

import (
	"context"
	"fmt"
	"io"
)

// SkipClassAdRaw reads and discards one raw ClassAd off the stream -- the leading
// expression count, that many expression strings, then MyType and TargetType --
// without allocating any of its text. It is the drain counterpart of
// GetClassAdRaw, for a caller that must consume an ad to stay framed on the
// connection but does not need its contents: counting query results, skipping ads
// that fail a cheap pre-filter, or a throughput benchmark that isolates the sender
// from client-side decode cost.
func (m *Message) SkipClassAdRaw(ctx context.Context) error {
	numExprs, err := m.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to read expression count: %w", err)
	}
	for i := 0; i < numExprs; i++ {
		if err := m.SkipString(ctx); err != nil {
			return fmt.Errorf("failed to skip expression %d (expected %d): %w", i, numExprs, err)
		}
	}
	if err := m.SkipString(ctx); err != nil {
		return fmt.Errorf("failed to skip MyType: %w", err)
	}
	if err := m.SkipString(ctx); err != nil {
		return fmt.Errorf("failed to skip TargetType: %w", err)
	}
	return nil
}

// SkipString reads and discards one CEDAR string, matching GetString's framing
// (encrypted: an int32 length prefix followed by that many bytes; plaintext: bytes
// up to a null terminator) but allocating nothing for the value.
func (m *Message) SkipString(ctx context.Context) error {
	if m.stream.IsEncrypted() {
		length, err := m.GetInt32(ctx)
		if err != nil {
			return err
		}
		return m.discard(ctx, int(length))
	}
	for {
		if err := m.ensureData(ctx, 1); err != nil {
			if err == io.EOF {
				return nil // end of message: treat as terminated
			}
			return err
		}
		b, err := m.buffer.ReadByte()
		if err != nil {
			return err
		}
		if b == 0 {
			return nil // null terminator
		}
	}
}

// discard consumes and drops n bytes from the frame buffer, pulling in more frame
// data as needed, without allocating a buffer to hold them. buffer.Next advances
// the read cursor and returns a slice we ignore, so no copy is made.
func (m *Message) discard(ctx context.Context, n int) error {
	for n > 0 {
		if err := m.ensureData(ctx, 1); err != nil {
			return err
		}
		take := m.buffer.Len()
		if take > n {
			take = n
		}
		m.buffer.Next(take)
		n -= take
	}
	return nil
}
