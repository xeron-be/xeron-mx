package ses

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testClient(t *testing.T, h http.HandlerFunc) *HTTPClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := NewHTTPClient("eu-west-3", "AKIDTEST", "secret")
	c.Endpoint = srv.URL
	c.now = func() time.Time { return time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC) }
	return c
}

func TestCreateAsksForEasyDKIM2048(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v2/email/identities" {
			t.Errorf("%s %s", r.Method, r.URL.Path)
		}
		if !strings.Contains(r.Header.Get("Authorization"), "/20261110/eu-west-3/ses/aws4_request") {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		if body["EmailIdentity"] != "client.example" {
			t.Errorf("EmailIdentity = %v", body["EmailIdentity"])
		}
		attrs, _ := body["DkimSigningAttributes"].(map[string]any)
		if attrs["NextSigningKeyLength"] != "RSA_2048_BIT" {
			t.Errorf("DkimSigningAttributes = %v", attrs)
		}
		w.Write([]byte(`{"IdentityType":"DOMAIN","VerifiedForSendingStatus":false,
			"DkimAttributes":{"SigningEnabled":true,"Status":"PENDING","Tokens":["t1","t2","t3"]}}`))
	})
	id, err := c.CreateIdentity(context.Background(), "client.example")
	if err != nil {
		t.Fatal(err)
	}
	if id.Status != StatusPending || len(id.DKIMTokens) != 3 || id.VerifiedForSending {
		t.Fatalf("identity = %+v", id)
	}
}

func TestGetReadsTheVerificationStatus(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/email/identities/example.org" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`{"VerifiedForSendingStatus":true,"VerificationStatus":"SUCCESS",
			"DkimAttributes":{"Status":"SUCCESS","Tokens":["a","b","c"]}}`))
	})
	id, err := c.GetIdentity(context.Background(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	if id.Status != StatusSuccess || !id.VerifiedForSending {
		t.Fatalf("identity = %+v", id)
	}
}

func TestErrorsAreClassified(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header string
		body   string
		want   error
	}{
		{"not found from the header", 404, "NotFoundException:http://internal.amazon.com/coral/", `{"message":"Email identity x does not exist."}`, ErrNotFound},
		{"already exists from the body", 400, "", `{"__type":"com.amazonaws#AlreadyExistsException","message":"exists"}`, ErrAlreadyExists},
		{"bare 404", 404, "", ``, ErrNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.header != "" {
					w.Header().Set("X-Amzn-ErrorType", tc.header)
				}
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			})
			_, err := c.GetIdentity(context.Background(), "x.example")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v; want %v", err, tc.want)
			}
		})
	}
}

func TestAccessDeniedIsNeitherNotFoundNorExists(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Amzn-ErrorType", "AccessDeniedException")
		w.WriteHeader(403)
		w.Write([]byte(`{"Message":"User is not authorized to perform ses:GetEmailIdentity"}`))
	})
	_, err := c.GetIdentity(context.Background(), "x.example")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "AccessDeniedException" || errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("the message from SES is lost: %v", err)
	}
}

func TestDelete(t *testing.T) {
	called := false
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		called = r.Method == http.MethodDelete && r.URL.Path == "/v2/email/identities/old.example"
		w.Write([]byte(`{}`))
	})
	if err := c.DeleteIdentity(context.Background(), "old.example"); err != nil || !called {
		t.Fatalf("delete: %v, called %v", err, called)
	}
}
