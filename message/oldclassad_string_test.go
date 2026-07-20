package message

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// TestDecodeOldClassAdString covers the receive-side of old-ClassAd string quoting:
// backslash is literal, only \" is an escaped quote, and an unescaped interior quote
// means "not a lone string literal" (defer to the expression parser).
func TestDecodeOldClassAdString(t *testing.T) {
	cases := []struct {
		in     string // content between the quotes
		want   string
		wantOK bool
	}{
		{``, ``, true},
		{`plain`, `plain`, true},
		{`X86_64`, `X86_64`, true},
		{`\S`, `\S`, true},                       // agetty escape: backslash literal, NOT an escape
		{`C:\Users\me`, `C:\Users\me`, true},     // Windows path: literal backslashes
		{`a\r\l\m`, `a\r\l\m`, true},             // more agetty escapes, all literal
		{`he said \"hi\"`, `he said "hi"`, true}, // \" -> literal quote
		{`a" + "b`, ``, false},                   // unescaped interior quote: expression, defer
	}
	for _, c := range cases {
		got, ok := decodeOldClassAdString(c.in)
		if ok != c.wantOK || (ok && got != c.want) {
			t.Errorf("decodeOldClassAdString(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

// TestParseAndInsertBackslashString is the regression guard for the OSIssue = "\S"
// drop: an old-ClassAd-quoted value carrying a literal backslash (which the strict
// new-ClassAd lexer rejects as an invalid escape) must still be stored, via the
// old-ClassAd fallback, rather than dropping the attribute.
func TestParseAndInsertBackslashString(t *testing.T) {
	ad := classad.New()
	if err := parseAndInsertExpression(ad, `OSIssue = "\S"`); err != nil {
		t.Fatalf("parseAndInsertExpression(OSIssue = %q) errored: %v", `"\S"`, err)
	}
	v, ok := ad.EvaluateAttrString("OSIssue")
	if !ok || v != `\S` {
		t.Fatalf("OSIssue = %q (ok=%v), want %q", v, ok, `\S`)
	}

	// A valid new-ClassAd string with known escapes still decodes via ParseExpr
	// (the fallback must not shadow it): \\ -> \, \n -> newline.
	ad2 := classad.New()
	if err := parseAndInsertExpression(ad2, `Path = "C:\\tmp\nx"`); err != nil {
		t.Fatalf("parseAndInsertExpression(Path) errored: %v", err)
	}
	if v, ok := ad2.EvaluateAttrString("Path"); !ok || v != "C:\\tmp\nx" {
		t.Fatalf("Path = %q (ok=%v), want %q", v, ok, "C:\\tmp\nx")
	}
}
