package watch

import (
	"bytes"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		adType     string
		constraint string
		cursor     []byte
	}{
		{"StartdAd", "", nil},
		{"StartdAd", "", []byte{0x01, 0x02, 0xff, 0x00}},
		{"ScheddAd", `DAGManJobId == 42`, []byte("cursor-bytes")},
		{"JobAd", `Owner == "alice" && ClusterId == 7`, nil},
	} {
		ad := EncodeRequest(tc.adType, tc.constraint, tc.cursor)
		gotType, gotConstraint, gotCursor, err := DecodeRequest(ad)
		if err != nil {
			t.Fatalf("DecodeRequest(%q): %v", tc.adType, err)
		}
		if gotType != tc.adType {
			t.Errorf("adType: got %q want %q", gotType, tc.adType)
		}
		if gotConstraint != tc.constraint {
			t.Errorf("constraint: got %q want %q", gotConstraint, tc.constraint)
		}
		if !bytes.Equal(gotCursor, tc.cursor) {
			t.Errorf("cursor: got %x want %x", gotCursor, tc.cursor)
		}
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		kind   Kind
		key    []byte
		cursor []byte
	}{
		{KindUpsert, []byte("slot1@host"), nil},
		{KindDelete, []byte("slot2@host"), nil},
		{KindReset, nil, nil},
		{KindSynced, nil, []byte{0x00, 0x01, 0x02}},
		{KindResync, nil, nil},
		{KindUpsert, []byte("k"), []byte("live-cursor")},
	} {
		ad := EncodeHeader(tc.kind, tc.key, tc.cursor)
		gotKind, gotKey, gotCursor, err := DecodeHeader(ad)
		if err != nil {
			t.Fatalf("DecodeHeader(%v): %v", tc.kind, err)
		}
		if gotKind != tc.kind {
			t.Errorf("kind: got %v want %v", gotKind, tc.kind)
		}
		if !bytes.Equal(gotKey, tc.key) {
			t.Errorf("key: got %q want %q", gotKey, tc.key)
		}
		if !bytes.Equal(gotCursor, tc.cursor) {
			t.Errorf("cursor: got %x want %x", gotCursor, tc.cursor)
		}
		if tc.kind.HasAd() != (tc.kind == KindUpsert) {
			t.Errorf("HasAd wrong for %v", tc.kind)
		}
	}
}
