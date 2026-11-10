package ses

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The vectors below come from AWS's own documentation and Signature Version 4
// test suite, so a mistake in our canonicalisation cannot hide behind a test
// written to match it.
const (
	exampleKeyID  = "AKIDEXAMPLE"
	exampleSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
)

func TestSigningKeyMatchesTheDocumentedDerivation(t *testing.T) {
	got := hex.EncodeToString(SigningKey(exampleSecret, "20120215", "us-east-1", "iam"))
	want := "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
	if got != want {
		t.Fatalf("signing key = %s; want %s", got, want)
	}
}

func TestSignatureMatchesTheSuite(t *testing.T) {
	at := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	cases := []struct {
		name   string
		method string
		url    string
		want   string
	}{
		{"get-vanilla", http.MethodGet, "https://example.amazonaws.com/",
			"5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"},
		{"post-vanilla", http.MethodPost, "https://example.amazonaws.com/",
			"5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, tc.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			Sign(req, nil, exampleKeyID, exampleSecret, "us-east-1", "service", at)

			auth := req.Header.Get("Authorization")
			wantPrefix := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
				"SignedHeaders=host;x-amz-date, Signature="
			if !strings.HasPrefix(auth, wantPrefix) {
				t.Fatalf("Authorization = %q", auth)
			}
			if got := strings.TrimPrefix(auth, wantPrefix); got != tc.want {
				t.Fatalf("signature = %s; want %s", got, tc.want)
			}
			if req.Header.Get("X-Amz-Date") != "20150830T123600Z" {
				t.Fatalf("X-Amz-Date = %q", req.Header.Get("X-Amz-Date"))
			}
		})
	}
}

func TestQueryAndPathAreCanonicalised(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://example.amazonaws.com/a%20b/c?b=2&a=1&a=0", nil)
	if got := canonicalURI(req.URL); got != "/a%2520b/c" {
		t.Fatalf("canonical URI = %q; want the path encoded twice", got)
	}
	if got := canonicalQuery(req.URL); got != "a=0&a=1&b=2" {
		t.Fatalf("canonical query = %q", got)
	}
}

func TestContentTypeIsSignedWhenSet(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://email.eu-west-3.amazonaws.com/v2/email/identities", nil)
	req.Header.Set("Content-Type", "application/json")
	Sign(req, []byte(`{}`), "AKID", "secret", "eu-west-3", "ses", time.Now())
	if !strings.Contains(req.Header.Get("Authorization"), "SignedHeaders=content-type;host;x-amz-date,") {
		t.Fatalf("Authorization = %q", req.Header.Get("Authorization"))
	}
}
