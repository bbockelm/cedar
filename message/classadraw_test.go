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

// TestSkipClassAdRawConsumesExactly verifies SkipClassAdRaw drains exactly one raw
// ad -- no more, no less -- by writing a raw ad followed by a sentinel int in the
// same message and confirming the sentinel reads back after the skip.
func TestSkipClassAdRawConsumesExactly(t *testing.T) {
	ctx := context.Background()
	s := NewMockStream(false)

	enc := NewMessageForStream(s)
	exprs := [][]byte{[]byte(`Name = "slot1@host"`), []byte(`Cpus = 8`), []byte(`Str = "a\nb"`), []byte(`Empty = ""`)}
	if err := enc.PutClassAdRawBytes(ctx, exprs, "Machine", "Job"); err != nil {
		t.Fatalf("PutClassAdRawBytes: %v", err)
	}
	if err := enc.PutInt32(ctx, 0xBEEF); err != nil {
		t.Fatalf("PutInt32 sentinel: %v", err)
	}
	if err := enc.FinishMessage(ctx); err != nil {
		t.Fatalf("FinishMessage: %v", err)
	}

	dec := NewMessageFromStream(s)
	if err := dec.SkipClassAdRaw(ctx); err != nil {
		t.Fatalf("SkipClassAdRaw: %v", err)
	}
	got, err := dec.GetInt32(ctx)
	if err != nil {
		t.Fatalf("GetInt32 after skip: %v", err)
	}
	if got != 0xBEEF {
		t.Errorf("sentinel after skip = %#x, want 0xBEEF (skip consumed wrong byte count)", got)
	}
}

// TestGetClassAdRawRejectsDesyncedTypeField simulates the startd-private-ad wire
// desync: a claim-id expression lands in the trailing MyType slot. Previously
// GetClassAdRaw stamped it via %q ("MyType = \"ClaimId = \\\"...\\\"\""),
// silently corrupting the ad AND leaking the claim id. It must now be rejected
// with an error that does not contain the secret.
func TestGetClassAdRawRejectsDesyncedTypeField(t *testing.T) {
	ctx := context.Background()
	s := NewMockStream(false)

	secret := `<128.104.100.17:9618?sock=startd_1>#1783747566#19094#[Integrity="YES";CryptoMethods="BLOWFISH";]409352deadbeefsecret883a`
	desyncedMyType := `ClaimId = "` + secret + `"`

	enc := NewMessageForStream(s)
	if err := enc.PutClassAdRaw(ctx, []string{`Name = "slot1@h"`}, desyncedMyType, ""); err != nil {
		t.Fatalf("PutClassAdRaw: %v", err)
	}
	if err := enc.FinishMessage(ctx); err != nil {
		t.Fatalf("FinishMessage: %v", err)
	}

	dec := NewMessageFromStream(s)
	_, err := dec.GetClassAdRaw(ctx)
	if err == nil {
		t.Fatal("expected GetClassAdRaw to reject a desynced type field, got nil")
	}
	// The error must not leak the claim id / secret material.
	for _, leak := range []string{"deadbeefsecret", "BLOWFISH", "409352", "Integrity"} {
		if contains(err.Error(), leak) {
			t.Errorf("error message leaks secret %q: %v", leak, err)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestIsTypeName locks the type-name predicate: real type names pass, desync
// signatures (containing '=', quote, newline) fail.
func TestIsTypeName(t *testing.T) {
	for _, ok := range []string{"Machine", "Job", "Scheduler", "Query", "DaemonMaster", ""} {
		if !isTypeName(ok) {
			t.Errorf("isTypeName(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{`ClaimId = "x"`, `a"b`, "a\nb", `x = y`, `back\slash`} {
		if isTypeName(bad) {
			t.Errorf("isTypeName(%q) = true, want false", bad)
		}
	}
}

// TestGetClassAdRawHandlesSecretMarker reproduces the startd private-ad wire
// pattern: a private attribute (a claim id) is sent as SecretMarker ("ZKM")
// followed by the real "Attr = Value" -- two wire items counted as ONE expression
// (matching C++ classad_oldnew.cpp). The reader must consume the secret as the
// expression, NOT surface the bare marker and shift the claim id into the trailing
// MyType slot (the observed corruption: a "ZKM" line + MyType = "ClaimId = ...").
func TestGetClassAdRawHandlesSecretMarker(t *testing.T) {
	ctx := context.Background()
	s := NewMockStream(false)

	claimIDExpr := `ClaimId = "<10.0.0.1:9618?sock=startd_1>#123#456#[Integrity=\"YES\";CryptoMethods=\"BLOWFISH\";]deadbeefhash"`

	// Wire, exactly as C++ putClassAd emits it on an unencrypted channel:
	// numExprs counts 3 attributes (Name, MyType, ClaimId); the ClaimId occupies
	// TWO wire items (SecretMarker + the value); then two empty trailing type fields.
	enc := NewMessageForStream(s)
	if err := enc.PutInt(ctx, 3); err != nil {
		t.Fatal(err)
	}
	for _, item := range []string{
		`Name = "slot1@h"`,
		`MyType = "Machine"`,
		SecretMarker,
		claimIDExpr,
		"", // trailing MyType (always empty on the wire)
		"", // trailing TargetType
	} {
		if err := enc.PutString(ctx, item); err != nil {
			t.Fatal(err)
		}
	}
	if err := enc.FinishMessage(ctx); err != nil {
		t.Fatal(err)
	}

	dec := NewMessageFromStream(s)
	text, err := dec.GetClassAdRaw(ctx)
	if err != nil {
		t.Fatalf("GetClassAdRaw: %v", err)
	}

	// The claim id must come through as its own real expression...
	if !contains(text, `ClaimId = "`) || !contains(text, "deadbeefhash") {
		t.Errorf("claim id lost/garbled:\n%s", text)
	}
	// ...the bare marker must NOT appear as a line...
	for _, line := range splitLines(text) {
		if line == SecretMarker {
			t.Errorf("SecretMarker leaked as a bare expression line:\n%s", text)
		}
	}
	// ...and it must NOT have been mis-quoted into a MyType value (the corruption).
	if contains(text, `MyType = "ClaimId`) {
		t.Errorf("claim id corrupted into MyType (desync not fixed):\n%s", text)
	}
	// The real MyType expression survives.
	if !contains(text, `MyType = "Machine"`) {
		t.Errorf("MyType expression lost:\n%s", text)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
