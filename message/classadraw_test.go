package message

import (
	"context"
	"testing"
)

// TestPutClassAdRawRoundTrip verifies PutClassAdRaw writes wire bytes that
// GetClassAd reads back into the equivalent ad (attributes plus MyType/TargetType).
func TestPutClassAdRawRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMockStream(false)

	enc := NewMessageForStream(s)
	exprs := []string{`Name = "slot1@host"`, `Cpus = 8`, `Ready = true`, `Load = 0.5`}
	if err := enc.PutClassAdRaw(ctx, exprs, "Machine", "Job"); err != nil {
		t.Fatalf("PutClassAdRaw: %v", err)
	}
	if err := enc.FinishMessage(ctx); err != nil {
		t.Fatalf("FinishMessage: %v", err)
	}

	dec := NewMessageFromStream(s)
	ad, err := dec.GetClassAd(ctx)
	if err != nil {
		t.Fatalf("GetClassAd: %v", err)
	}
	if v, _ := ad.EvaluateAttrString("Name"); v != "slot1@host" {
		t.Errorf("Name = %q, want slot1@host", v)
	}
	if v, ok := ad.EvaluateAttrInt("Cpus"); !ok || v != 8 {
		t.Errorf("Cpus = %d (ok=%v), want 8", v, ok)
	}
	if v, ok := ad.EvaluateAttrBool("Ready"); !ok || !v {
		t.Errorf("Ready = %v (ok=%v), want true", v, ok)
	}
	if mt, _ := ad.EvaluateAttrString("MyType"); mt != "Machine" {
		t.Errorf("MyType = %q, want Machine", mt)
	}
	if tt, _ := ad.EvaluateAttrString("TargetType"); tt != "Job" {
		t.Errorf("TargetType = %q, want Job", tt)
	}
}

// TestPutClassAdRawBytesRoundTrip is TestPutClassAdRawRoundTrip for the []byte
// (zero-per-expr-alloc) variant.
func TestPutClassAdRawBytesRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewMockStream(false)

	enc := NewMessageForStream(s)
	exprs := [][]byte{[]byte(`Name = "slot1@host"`), []byte(`Cpus = 8`), []byte(`Ready = true`)}
	if err := enc.PutClassAdRawBytes(ctx, exprs, "Machine", "Job"); err != nil {
		t.Fatalf("PutClassAdRawBytes: %v", err)
	}
	if err := enc.FinishMessage(ctx); err != nil {
		t.Fatalf("FinishMessage: %v", err)
	}

	ad, err := NewMessageFromStream(s).GetClassAd(ctx)
	if err != nil {
		t.Fatalf("GetClassAd: %v", err)
	}
	if v, _ := ad.EvaluateAttrString("Name"); v != "slot1@host" {
		t.Errorf("Name = %q, want slot1@host", v)
	}
	if v, ok := ad.EvaluateAttrInt("Cpus"); !ok || v != 8 {
		t.Errorf("Cpus = %d (ok=%v), want 8", v, ok)
	}
	if mt, _ := ad.EvaluateAttrString("MyType"); mt != "Machine" {
		t.Errorf("MyType = %q, want Machine", mt)
	}
}
