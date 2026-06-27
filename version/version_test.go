package version

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in       string
		maj, min int
		ok       bool
	}{
		{"$CondorVersion: 25.4.0 2025-10-31 BuildID: 847437 $", 25, 4, true},
		{"24.0.1", 24, 0, true},
		{"nope", 0, 0, false},
	}
	for _, tc := range tests {
		v, ok := Parse(tc.in)
		if ok != tc.ok || (ok && (v.Major != tc.maj || v.Minor != tc.min)) {
			t.Errorf("Parse(%q) = %+v,%v want %d.%d,%v", tc.in, v, ok, tc.maj, tc.min, tc.ok)
		}
	}
}

func TestAtLeast(t *testing.T) {
	threshold := CondorVersion{25, 5, 0}
	cases := map[string]bool{
		"25.5.0": true,
		"25.6.0": true,
		"26.0.0": true,
		"25.4.9": false,
		"24.9.9": false,
	}
	for s, want := range cases {
		v, _ := Parse(s)
		if got := v.AtLeast(threshold); got != want {
			t.Errorf("%s AtLeast 25.5.0 = %v, want %v", s, got, want)
		}
	}
}

func TestString(t *testing.T) {
	if got := (CondorVersion{25, 12, 3}).String(); got != "25.12.3" {
		t.Errorf("String() = %q, want 25.12.3", got)
	}
}
