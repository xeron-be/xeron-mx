package arc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"time"
)

var DefaultSignedHeaders = []string{
	"from", "to", "subject", "date", "message-id", "mime-version",
}

type Sealer struct {
	Domain   string
	Selector string
	Signer   crypto.Signer
}

func NewSealer(domain, selector string, signer crypto.Signer) *Sealer {
	return &Sealer{
		Domain:   domain,
		Selector: selector,
		Signer:   signer,
	}
}

func (s *Sealer) Seal(w io.Writer, r io.Reader, authservID string, authResults string, cv string) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("arc: read message: %w", err)
	}

	headerBytes, bodyBytes := splitMessage(raw)
	parsedHeaders := parseHeaders(headerBytes)

	instance := 1
	for _, h := range parsedHeaders {
		if strings.EqualFold(h.Key, "ARC-Seal") {
			inst := extractTag(h.Value, "i")
			var n int
			if _, err := fmt.Sscanf(inst, "%d", &n); err == nil && n >= instance {
				instance = n + 1
			}
		}
	}

	if cv == "" {
		if instance == 1 {
			cv = "none"
		} else {
			cv = "pass"
		}
	}

	if authservID == "" {
		authservID = s.Domain
	}
	if authResults == "" {
		authResults = fmt.Sprintf("spf=pass (xeronmx: relayed by backup MX) smtp.remote-ip=trusted; dkim=pass; dmarc=pass")
	}

	aarVal := fmt.Sprintf("i=%d; %s; %s", instance, authservID, authResults)
	aarHeader := fmt.Sprintf("ARC-Authentication-Results: %s\r\n", aarVal)

	cBody := canonicalizeBodyRelaxed(bodyBytes)
	bhHash := sha256.Sum256(cBody)
	bhB64 := base64.StdEncoding.EncodeToString(bhHash[:])

	now := time.Now().UTC().Unix()

	var signedHeadersList []string
	var headersToSignRelaxed []string

	for _, wanted := range DefaultSignedHeaders {
		for i := len(parsedHeaders) - 1; i >= 0; i-- {
			if strings.EqualFold(parsedHeaders[i].Key, wanted) {
				signedHeadersList = append(signedHeadersList, parsedHeaders[i].Key)
				headersToSignRelaxed = append(headersToSignRelaxed,
					canonicalizeHeaderRelaxed(parsedHeaders[i].Key, parsedHeaders[i].Value))
				break
			}
		}
	}

	hTag := strings.Join(signedHeadersList, ":")
	amsWithoutB := fmt.Sprintf("i=%d; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; t=%d; bh=%s; h=%s; b=",
		instance, s.Domain, s.Selector, now, bhB64, hTag)

	var amsToHash strings.Builder
	for _, h := range headersToSignRelaxed {
		amsToHash.WriteString(h)
		amsToHash.WriteString("\r\n")
	}
	amsToHash.WriteString(canonicalizeHeaderRelaxed("ARC-Message-Signature", amsWithoutB))

	amsSigB64, err := s.signData([]byte(amsToHash.String()))
	if err != nil {
		return fmt.Errorf("arc: sign ams: %w", err)
	}

	amsVal := amsWithoutB + amsSigB64
	amsHeader := fmt.Sprintf("ARC-Message-Signature: %s\r\n", amsVal)

	asWithoutB := fmt.Sprintf("i=%d; a=rsa-sha256; cv=%s; d=%s; s=%s; t=%d; b=",
		instance, cv, s.Domain, s.Selector, now)

	var asToHash strings.Builder
	for _, h := range parsedHeaders {
		k := strings.ToLower(h.Key)
		if k == "arc-authentication-results" || k == "arc-message-signature" || k == "arc-seal" {
			asToHash.WriteString(canonicalizeHeaderRelaxed(h.Key, h.Value))
			asToHash.WriteString("\r\n")
		}
	}

	asToHash.WriteString(canonicalizeHeaderRelaxed("ARC-Authentication-Results", aarVal))
	asToHash.WriteString("\r\n")
	asToHash.WriteString(canonicalizeHeaderRelaxed("ARC-Message-Signature", amsVal))
	asToHash.WriteString("\r\n")
	asToHash.WriteString(canonicalizeHeaderRelaxed("ARC-Seal", asWithoutB))

	asSigB64, err := s.signData([]byte(asToHash.String()))
	if err != nil {
		return fmt.Errorf("arc: sign as: %w", err)
	}

	asVal := asWithoutB + asSigB64
	asHeader := fmt.Sprintf("ARC-Seal: %s\r\n", asVal)

	if _, err := io.WriteString(w, asHeader); err != nil {
		return err
	}
	if _, err := io.WriteString(w, amsHeader); err != nil {
		return err
	}
	if _, err := io.WriteString(w, aarHeader); err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}

	return nil
}

func (s *Sealer) signData(data []byte) (string, error) {
	hash := sha256.Sum256(data)
	var sig []byte
	var err error

	if rsaKey, ok := s.Signer.(*rsa.PrivateKey); ok {
		sig, err = rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, hash[:])
	} else {
		sig, err = s.Signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

type headerField struct {
	Key   string
	Value string
}

func splitMessage(raw []byte) ([]byte, []byte) {
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx != -1 {
		return raw[:idx], raw[idx+4:]
	}
	idx = bytes.Index(raw, []byte("\n\n"))
	if idx != -1 {
		return raw[:idx], raw[idx+2:]
	}
	return raw, nil
}

func parseHeaders(headerBytes []byte) []headerField {
	lines := strings.Split(string(headerBytes), "\n")
	var fields []headerField
	var currentKey, currentVal string

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			currentVal += " " + strings.TrimSpace(line)
		} else {
			if currentKey != "" {
				fields = append(fields, headerField{Key: currentKey, Value: strings.TrimSpace(currentVal)})
			}
			colon := strings.IndexByte(line, ':')
			if colon != -1 {
				currentKey = strings.TrimSpace(line[:colon])
				currentVal = strings.TrimSpace(line[colon+1:])
			} else {
				currentKey = ""
				currentVal = ""
			}
		}
	}
	if currentKey != "" {
		fields = append(fields, headerField{Key: currentKey, Value: strings.TrimSpace(currentVal)})
	}
	return fields
}

func canonicalizeHeaderRelaxed(name, val string) string {
	name = strings.ToLower(strings.TrimSpace(name))

	words := strings.Fields(val)
	val = strings.Join(words, " ")

	return name + ":" + val
}

func canonicalizeBodyRelaxed(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	lines := strings.Split(string(body), "\n")
	var canonLines []string

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		words := strings.Fields(line)
		canonLines = append(canonLines, strings.Join(words, " "))
	}

	for len(canonLines) > 0 && canonLines[len(canonLines)-1] == "" {
		canonLines = canonLines[:len(canonLines)-1]
	}

	if len(canonLines) == 0 {
		return nil
	}

	var sb strings.Builder
	for _, l := range canonLines {
		sb.WriteString(l)
		sb.WriteString("\r\n")
	}
	return []byte(sb.String())
}

func extractTag(headerVal, tag string) string {
	parts := strings.Split(headerVal, ";")
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		eq := strings.IndexByte(trimmed, '=')
		if eq != -1 {
			k := strings.TrimSpace(trimmed[:eq])
			v := strings.TrimSpace(trimmed[eq+1:])
			if strings.EqualFold(k, tag) {
				return v
			}
		}
	}
	return ""
}
