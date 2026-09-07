package cluster

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const secret = "a shared secret at least sixteen"

func signed(t *testing.T, method, path string, body []byte) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	SignRequest(req, secret, "mx1", body)
	return req
}

func TestVerifyAcceptsWhatSignRequestProduced(t *testing.T) {
	body := []byte(`{"node_id":"mx1"}`)
	peer, err := Verify(signed(t, http.MethodPost, HeartbeatPath, body), secret, "mx2", body)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if peer != "mx1" {
		t.Fatalf("peer = %q, want mx1", peer)
	}
}

func TestVerifyRejectsATamperedBody(t *testing.T) {
	body := []byte(`{"node_id":"mx1","queue_pending":0}`)
	req := signed(t, http.MethodPost, HeartbeatPath, body)

	tampered := []byte(`{"node_id":"mx1","queue_pending":9999}`)
	if _, err := Verify(req, secret, "mx2", tampered); !errors.Is(err, ErrBadSig) {
		t.Fatalf("SECURITY: a modified body verified (err = %v)", err)
	}
}

func TestVerifyIsBoundToTheRequestLine(t *testing.T) {
	body := []byte(`{"node_id":"mx1"}`)
	req := signed(t, http.MethodPost, HeartbeatPath, body)

	moved := httptest.NewRequest(http.MethodPost, ConfigPath, strings.NewReader(string(body)))
	for _, h := range []string{NodeHeader, TimestampHeader, SignatureHeader} {
		moved.Header.Set(h, req.Header.Get(h))
	}
	if _, err := Verify(moved, secret, "mx2", body); !errors.Is(err, ErrBadSig) {
		t.Fatalf("SECURITY: a heartbeat signature was accepted on another endpoint (err = %v)", err)
	}
}

func TestVerifyRejectsTheWrongSecret(t *testing.T) {
	body := []byte(`{}`)
	req := signed(t, http.MethodPost, HeartbeatPath, body)
	if _, err := Verify(req, "a different shared secret!!", "mx2", body); !errors.Is(err, ErrBadSig) {
		t.Fatalf("SECURITY: a foreign secret verified (err = %v)", err)
	}
}

func TestVerifyRejectsAReplay(t *testing.T) {
	body := []byte(`{}`)
	req := signed(t, http.MethodPost, HeartbeatPath, body)
	stale := time.Now().Add(-MaxSkew - time.Minute).Unix()
	req.Header.Set(TimestampHeader, strconv.FormatInt(stale, 10))

	if _, err := Verify(req, secret, "mx2", body); err == nil {
		t.Fatal("SECURITY: a request older than the skew window was accepted")
	}
}

func TestVerifyRejectsAFutureTimestamp(t *testing.T) {
	body := []byte(`{}`)
	req := signed(t, http.MethodPost, HeartbeatPath, body)
	req.Header.Set(TimestampHeader,
		strconv.FormatInt(time.Now().Add(MaxSkew+time.Minute).Unix(), 10))

	if _, err := Verify(req, secret, "mx2", body); !errors.Is(err, ErrStale) {
		t.Fatalf("SECURITY: a request stamped in the future was accepted (err = %v)", err)
	}
}

func TestVerifyRefusesWithoutASecret(t *testing.T) {
	body := []byte(`{}`)
	req := signed(t, http.MethodPost, HeartbeatPath, body)
	if _, err := Verify(req, "", "mx2", body); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("SECURITY: an empty secret did not refuse outright (err = %v)", err)
	}
}

func TestVerifyRefusesUnsigned(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, HeartbeatPath, nil)
	if _, err := Verify(req, secret, "mx2", nil); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("an unsigned request gave err = %v, want ErrUnsigned", err)
	}
}

func TestVerifyRefusesACallFromItself(t *testing.T) {
	body := []byte(`{}`)
	req := signed(t, http.MethodPost, HeartbeatPath, body)
	if _, err := Verify(req, secret, "mx1", body); !errors.Is(err, ErrSelfCall) {
		t.Fatalf("SECURITY: a node accepted a call claiming to be itself (err = %v)", err)
	}
}

func TestSelfCheckHappensAfterTheSignature(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, HeartbeatPath, nil)
	req.Header.Set(NodeHeader, "mx1")
	req.Header.Set(TimestampHeader, strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set(SignatureHeader, "sha256=deadbeef")

	if _, err := Verify(req, secret, "mx1", nil); !errors.Is(err, ErrBadSig) {
		t.Fatalf("SECURITY: an unsigned probe learned the node id (err = %v)", err)
	}
}

func TestVerifyRejectsAMalformedTimestamp(t *testing.T) {
	body := []byte(`{}`)
	req := signed(t, http.MethodPost, HeartbeatPath, body)
	req.Header.Set(TimestampHeader, "not-a-number")
	if _, err := Verify(req, secret, "mx2", body); !errors.Is(err, ErrBadHeader) {
		t.Fatalf("err = %v, want ErrBadHeader", err)
	}
}
