package metrics

import (
	"strings"
	"testing"
)

func TestEscapeLabelClosesTheValue(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{`example.com`, `example.com`},
		{`a".b`, `a\".b`},
		{`evil",job="prometheus`, `evil\",job=\"prometheus`},
		{`back\slash`, `back\\slash`},
		{"new\nline", `new\nline`},
		{`both"\`, `both\"\\`},
	}
	for _, tc := range cases {
		if got := escapeLabel(tc.in); got != tc.want {
			t.Errorf("escapeLabel(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSampleKeepsForgedLabelsInsideOneValue(t *testing.T) {
	var sb strings.Builder
	b := &builder{w: &sb}
	b.sample("xeronmx_primary_up", 1, label{"domain", `evil",job="forged`})

	line := strings.TrimSpace(sb.String())
	if strings.Count(line, `="`) != 1 {
		t.Fatalf("SECURITY: a forged label survived escaping: %s", line)
	}
	if !strings.Contains(line, `domain="evil\",job=\"forged"`) {
		t.Fatalf("escaped rendering is wrong: %s", line)
	}
}

func TestSubtleCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"token", "token", 1},
		{"token", "tokeN", 0},
		{"token", "token-longer", 0},
		{"", "", 1},
		{"token", "", 0},
	}
	for _, tc := range cases {
		if got := subtleCompare(tc.a, tc.b); got != tc.want {
			t.Errorf("subtleCompare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
