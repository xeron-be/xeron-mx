package ses

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	sigAlgorithm = "AWS4-HMAC-SHA256"
	amzDateFmt   = "20060102T150405Z"
)

// Sign adds the AWS Signature Version 4 headers (X-Amz-Date, Authorization)
// to req. It signs the Host header, X-Amz-* headers and Content-Type when set:
// enough for SESv2, and the same set AWS's own test suite uses.
func Sign(req *http.Request, body []byte, accessKey, secretKey, region, service string, now time.Time) {
	amzDate := now.UTC().Format(amzDateFmt)
	date := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)

	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	names, canonicalHeaders := canonicalHeaders(req.Header, host)
	signed := strings.Join(names, ";")

	payload := sha256.Sum256(body)
	canonical := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL),
		canonicalHeaders,
		signed,
		hex.EncodeToString(payload[:]),
	}, "\n")

	scope := date + "/" + region + "/" + service + "/aws4_request"
	hashed := sha256.Sum256([]byte(canonical))
	toSign := sigAlgorithm + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(hashed[:])

	signature := hex.EncodeToString(hmacSHA256(SigningKey(secretKey, date, region, service), toSign))
	req.Header.Set("Authorization", sigAlgorithm+
		" Credential="+accessKey+"/"+scope+
		", SignedHeaders="+signed+
		", Signature="+signature)
}

// SigningKey derives the per-day, per-region, per-service key.
func SigningKey(secretKey, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secretKey), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func canonicalHeaders(h http.Header, host string) ([]string, string) {
	values := map[string]string{"host": strings.TrimSpace(host)}
	for name, vs := range h {
		lower := strings.ToLower(name)
		if lower != "content-type" && !strings.HasPrefix(lower, "x-amz-") {
			continue
		}
		trimmed := make([]string, len(vs))
		for i, v := range vs {
			trimmed[i] = strings.Join(strings.Fields(v), " ")
		}
		values[lower] = strings.Join(trimmed, ",")
	}
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(values[n])
		b.WriteByte('\n')
	}
	return names, b.String()
}

// canonicalURI encodes each path segment twice, as SigV4 requires of every
// service but S3: once for the URI, once more for the canonical request.
func canonicalURI(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, s := range segments {
		segments[i] = uriEncode(s)
	}
	return strings.Join(segments, "/")
}

func canonicalQuery(u *url.URL) string {
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncode(k)+"="+uriEncode(v))
		}
	}
	return strings.Join(parts, "&")
}

// uriEncode is RFC 3986 encoding with AWS's rules: everything but the
// unreserved characters is percent-encoded, with upper-case hex.
func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}
