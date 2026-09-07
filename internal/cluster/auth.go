package cluster

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	NodeHeader      = "X-XeronMX-Cluster-Node"
	TimestampHeader = "X-XeronMX-Cluster-Timestamp"
	SignatureHeader = "X-XeronMX-Cluster-Signature"
)

const MaxSkew = 5 * time.Minute

var (
	ErrUnsigned  = errors.New("cluster: the request carries no signature")
	ErrBadSig    = errors.New("cluster: the signature does not match")
	ErrStale     = errors.New("cluster: the request is outside the accepted time window")
	ErrNoSecret  = errors.New("cluster: no shared secret is configured")
	ErrSelfCall  = errors.New("cluster: a node signed a request to itself")
	ErrBadHeader = errors.New("cluster: the signature headers are malformed")
)

func signingString(timestamp int64, method, path string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return fmt.Appendf(nil, "%d.%s.%s.%s",
		timestamp, strings.ToUpper(method), path, hex.EncodeToString(sum[:]))
}

func sign(secret string, timestamp int64, method, path string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(signingString(timestamp, method, path, body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func SignRequest(req *http.Request, secret, nodeID string, body []byte) {
	ts := time.Now().Unix()
	req.Header.Set(NodeHeader, nodeID)
	req.Header.Set(TimestampHeader, strconv.FormatInt(ts, 10))
	req.Header.Set(SignatureHeader, sign(secret, ts, req.Method, req.URL.Path, body))
}

func Verify(r *http.Request, secret, selfID string, body []byte) (string, error) {
	if secret == "" {
		return "", ErrNoSecret
	}

	node := r.Header.Get(NodeHeader)
	rawTS := r.Header.Get(TimestampHeader)
	presented := r.Header.Get(SignatureHeader)
	if node == "" || rawTS == "" || presented == "" {
		return "", ErrUnsigned
	}

	ts, err := strconv.ParseInt(rawTS, 10, 64)
	if err != nil {
		return "", ErrBadHeader
	}
	if skew := time.Since(time.Unix(ts, 0)); skew > MaxSkew || skew < -MaxSkew {
		return "", ErrStale
	}

	expected := sign(secret, ts, r.Method, r.URL.Path, body)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) != 1 {
		return "", ErrBadSig
	}
	if node == selfID {
		return "", ErrSelfCall
	}
	return node, nil
}
