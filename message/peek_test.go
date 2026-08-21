// Copyright 2025 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package message

import (
	"context"
	"testing"
)

// TestPeekEndOfMessage verifies the optional-trailing-field pattern the FS-auth
// server uses: read a leading int, then peek to decide whether a trailing string
// follows, across the three framings that can occur.
func TestPeekEndOfMessage(t *testing.T) {
	ctx := context.Background()

	// encode runs fn against an encoder and returns the frames it produced.
	encode := func(fn func(m *Message)) ([][]byte, []bool) {
		enc := NewMessageForStream(NewMockStream(false))
		fn(enc)
		mock := enc.stream.(*MockStream)
		return mock.frames, mock.frameEOMs
	}
	decoder := func(frames [][]byte, eoms []bool) *Message {
		m := NewMockStream(false)
		for i := range frames {
			m.AddFrame(frames[i], eoms[i])
		}
		return NewMessageFromStream(m)
	}

	t.Run("int only, single EOM frame -> at end", func(t *testing.T) {
		frames, eoms := encode(func(m *Message) {
			_ = m.PutInt(ctx, 0)
			_ = m.FinishMessage(ctx)
		})
		dec := decoder(frames, eoms)
		if _, err := dec.GetInt(ctx); err != nil {
			t.Fatalf("GetInt: %v", err)
		}
		atEnd, err := dec.PeekEndOfMessage(ctx)
		if err != nil {
			t.Fatalf("Peek: %v", err)
		}
		if !atEnd {
			t.Fatalf("expected at end, got more data")
		}
	})

	t.Run("int + string, single EOM frame -> more data", func(t *testing.T) {
		frames, eoms := encode(func(m *Message) {
			_ = m.PutInt(ctx, 0)
			_ = m.PutString(ctx, "127.0.0.1:9618")
			_ = m.FinishMessage(ctx)
		})
		dec := decoder(frames, eoms)
		if _, err := dec.GetInt(ctx); err != nil {
			t.Fatalf("GetInt: %v", err)
		}
		atEnd, err := dec.PeekEndOfMessage(ctx)
		if err != nil {
			t.Fatalf("Peek: %v", err)
		}
		if atEnd {
			t.Fatalf("expected more data, got end")
		}
		s, err := dec.GetStringWithMaxSize(ctx, 4096)
		if err != nil {
			t.Fatalf("GetString: %v", err)
		}
		if s != "127.0.0.1:9618" {
			t.Fatalf("got %q", s)
		}
	})

	t.Run("int and string in separate frames -> more data", func(t *testing.T) {
		frames, eoms := encode(func(m *Message) {
			_ = m.PutInt(ctx, 0)
			_ = m.FlushFrame(ctx, false) // close the int in a non-EOM frame
			_ = m.PutString(ctx, "127.0.0.1:9618")
			_ = m.FinishMessage(ctx)
		})
		if len(frames) < 2 {
			t.Fatalf("expected fragmented frames, got %d", len(frames))
		}
		dec := decoder(frames, eoms)
		if _, err := dec.GetInt(ctx); err != nil {
			t.Fatalf("GetInt: %v", err)
		}
		// The string lives in a later frame; Peek must pull it in.
		atEnd, err := dec.PeekEndOfMessage(ctx)
		if err != nil {
			t.Fatalf("Peek: %v", err)
		}
		if atEnd {
			t.Fatalf("expected more data across the frame boundary, got end")
		}
		s, err := dec.GetStringWithMaxSize(ctx, 4096)
		if err != nil {
			t.Fatalf("GetString: %v", err)
		}
		if s != "127.0.0.1:9618" {
			t.Fatalf("got %q", s)
		}
	})
}
