package arc

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var (
	ErrUnvalidatedChain = errors.New("arc: the message already carries an ARC chain that was not validated")
	ErrFailedChain      = errors.New("arc: the message's ARC chain was already marked failed")
	ErrChainTooLong     = errors.New("arc: the message's ARC chain has reached its maximum length")
)

var DefaultSignedHeaders = []string{
	"from", "to", "cc", "subject", "date", "message-id", "reply-to",
	"in-reply-to", "references", "mime-version", "content-type",
	"content-transfer-encoding", "dkim-signature",
}

type Sealer struct {
	Domain   string
	Selector string
	Signer   crypto.Signer
	Now      func() time.Time
}

func NewSealer(domain, selector string, signer crypto.Signer) *Sealer {
	return &Sealer{
		Domain:   domain,
		Selector: selector,
		Signer:   signer,
	}
}

func (s *Sealer) algorithm() string {
	if _, ok := s.Signer.Public().(ed25519.PublicKey); ok {
		return "ed25519-sha256"
	}
	return "rsa-sha256"
}

func (s *Sealer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Sealer) Seal(w io.Writer, r io.Reader, authservID string, authResults string, cv string) error {
	original, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("arc: read message: %w", err)
	}

	fields, body := splitMessage(normalizeLineEndings(original))
	c, err := collect(fields)
	if err != nil {
		if cv != CVPass && cv != CVFail {
			return ErrUnvalidatedChain
		}
		return ErrFailedChain
	}

	instance := len(c.sets) + 1
	switch {
	case instance > MaxInstances:
		return ErrChainTooLong
	case instance > 1 && c.latestCV() == CVFail:
		return ErrFailedChain
	case instance > 1 && cv != CVPass && cv != CVFail:
		return ErrUnvalidatedChain
	case instance == 1:
		cv = CVNone
	}

	if authservID == "" {
		authservID = s.Domain
	}
	if authResults == "" {
		authResults = "none"
	}
	aar := field{name: aarName, raw: fmt.Sprintf("%s: i=%d; %s; %s", aarName, instance, authservID, authResults)}

	algo := s.algorithm()
	t := s.now().UTC().Unix()

	bh := sha256.Sum256(canonBody(body, true))
	var signed []string
	var headerInput strings.Builder
	for _, name := range DefaultSignedHeaders {
		for i := len(fields) - 1; i >= 0; i-- {
			if strings.EqualFold(fields[i].name, name) {
				signed = append(signed, name)
				headerInput.WriteString(canonHeader(fields[i], true))
			}
		}
	}

	ams := field{name: amsName, raw: fmt.Sprintf("%s: i=%d; a=%s; c=relaxed/relaxed; d=%s; s=%s; t=%d; bh=%s; h=%s; b=",
		amsName, instance, algo, s.Domain, s.Selector, t,
		base64.StdEncoding.EncodeToString(bh[:]), strings.Join(signed, ":"))}
	headerInput.WriteString(strings.TrimSuffix(canonHeader(ams, true), "\r\n"))
	sig, err := s.sign([]byte(headerInput.String()))
	if err != nil {
		return fmt.Errorf("arc: sign ams: %w", err)
	}
	ams.raw += sig

	as := field{name: asName, raw: fmt.Sprintf("%s: i=%d; a=%s; cv=%s; d=%s; s=%s; t=%d; b=",
		asName, instance, algo, cv, s.Domain, s.Selector, t)}
	sig, err = s.sign(sealInput(c.sets, &set{aar: &aar, ams: &ams, as: &as}))
	if err != nil {
		return fmt.Errorf("arc: sign seal: %w", err)
	}
	as.raw += sig

	for _, f := range []field{as, ams, aar} {
		if _, err := io.WriteString(w, f.raw+"\r\n"); err != nil {
			return err
		}
	}
	_, err = w.Write(original)
	return err
}

func (s *Sealer) sign(data []byte) (string, error) {
	hash := sha256.Sum256(data)
	var (
		sig []byte
		err error
	)
	if _, ok := s.Signer.Public().(ed25519.PublicKey); ok {
		sig, err = s.Signer.Sign(rand.Reader, hash[:], crypto.Hash(0))
	} else {
		sig, err = s.Signer.Sign(rand.Reader, hash[:], crypto.SHA256)
	}
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}
