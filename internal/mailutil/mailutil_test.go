package mailutil

import (
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNewIDIsUniqueHex(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
			t.Fatalf("id %q is not 32 lowercase hex characters", id)
		}
		if seen[id] {
			t.Fatalf("id %q generated twice", id)
		}
		seen[id] = true
	}
}

func TestPeekHeadersReplaysTheWholeStream(t *testing.T) {
	msg := "Subject: hello\r\n\r\n" + strings.Repeat("body line\r\n", 1000)

	head, rest := PeekHeaders(strings.NewReader(msg), 64)
	if string(head) != msg[:64] {
		t.Fatalf("head = %q; want the first 64 bytes", head)
	}
	all, err := io.ReadAll(rest)
	if err != nil {
		t.Fatal(err)
	}
	if string(all) != msg {
		t.Fatalf("replayed %d bytes; want the original %d", len(all), len(msg))
	}
}

func TestPeekHeadersOnAMessageShorterThanTheLimit(t *testing.T) {
	msg := "Subject: tiny\r\n\r\nhi\r\n"

	head, rest := PeekHeaders(strings.NewReader(msg), 64<<10)
	if string(head) != msg {
		t.Fatalf("head = %q; want the whole message", head)
	}
	all, _ := io.ReadAll(rest)
	if string(all) != msg {
		t.Fatalf("replayed %q; want %q", all, msg)
	}
}

func TestExtractSubject(t *testing.T) {
	cases := []struct {
		name string
		head string
		want string
	}{
		{"simple", "From: a@b\r\nSubject: Hello\r\n\r\nbody", "Hello"},
		{"lower case", "subject: hello\r\n\r\n", "hello"},
		{"upper case", "SUBJECT: HELLO\r\n\r\n", "HELLO"},
		{"bare LF", "From: a@b\nSubject: Unix\n\nbody", "Unix"},
		{"surrounding space", "Subject:    padded   \r\n\r\n", "padded"},
		{"empty", "Subject:\r\n\r\n", ""},
		{"missing", "From: a@b\r\nTo: c@d\r\n\r\nSubject: in the body\r\n", ""},
		{"folded", "Subject: a subject\r\n that continues\r\n\ton two lines\r\nTo: c@d\r\n\r\n", "a subject that continues on two lines"},
		{"fold stops at the body", "Subject: last header\r\n\r\n indented body line\r\n", "last header"},
		{"not a prefix match", "Subject-Extra: nope\r\nSubject: yes\r\n\r\n", "yes"},
		{"first one wins", "Subject: one\r\nSubject: two\r\n\r\n", "one"},
		{"encoded word", "Subject: =?UTF-8?B?w6ljaGVj?=\r\n\r\n", "échec"},
		{"encoded words mixed with plain text", "Subject: =?utf-8?b?UsOpcG9uc2Ugw6A=?= votre ticket TEC-2026-0002 - =?utf-8?b?UHJvYmzDqG1l?= serveur mails\r\n\r\n", "Réponse à votre ticket TEC-2026-0002 - Problème serveur mails"},
		{"quoted printable", "Subject: =?ISO-8859-1?Q?caf=E9_cr=E8me?=\r\n\r\n", "café crème"},
		{"folded encoded words", "Subject: =?UTF-8?B?UsOpcG9uc2U=?=\r\n =?UTF-8?B?IMOg?= vous\r\n\r\n", "Réponse à vous"},
		{"windows-1252", "Subject: =?windows-1252?Q?=93quoted=94?=\r\n\r\n", "\u201cquoted\u201d"},
		{"unknown charset kept as is", "Subject: =?x-unknown?B?YWJj?=\r\n\r\n", "=?x-unknown?B?YWJj?="},
		{"malformed word kept as is", "Subject: =?UTF-8?B?!!!?=\r\n\r\n", "=?UTF-8?B?!!!?="},
		{"encoded line breaks flattened", "Subject: =?UTF-8?B?YQ0KYg==?=\r\n\r\n", "a  b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ExtractSubject([]byte(c.head)); got != c.want {
				t.Fatalf("ExtractSubject = %q; want %q", got, c.want)
			}
		})
	}
}

func TestExtractSubjectIsBoundedAndValidUTF8(t *testing.T) {
	long := "Subject: " + strings.Repeat("x", 2000) + "\r\n\r\n"
	if got := ExtractSubject([]byte(long)); len(got) != 500 {
		t.Fatalf("subject is %d bytes; want it cut at 500", len(got))
	}

	accented := "Subject: " + strings.Repeat("é", 400) + "\r\n\r\n"
	if got := ExtractSubject([]byte(accented)); !utf8.ValidString(got) {
		t.Fatal("subject cut inside a multibyte character is not valid UTF-8")
	}
	encoded := "Subject: =?UTF-8?B?" + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("é", 400))) + "?=\r\n\r\n"
	if got := ExtractSubject([]byte(encoded)); !utf8.ValidString(got) || len(got) != 500 || got != strings.Repeat("é", 250) {
		t.Fatalf("decoded subject is %d bytes; want 250 whole characters", len(got))
	}
	latin1 := "Subject: caf\xe9\r\n\r\n"
	if got := ExtractSubject([]byte(latin1)); got != "caf" {
		t.Fatalf("ExtractSubject(latin-1) = %q; want the invalid byte dropped", got)
	}
}
