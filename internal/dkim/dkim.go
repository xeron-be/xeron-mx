package dkim

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"github.com/emersion/go-msgauth/dkim"

	"github.com/xeron-be/xeron-mx/internal/store"
)

const (
	rsaBits = 2048

	DefaultSelector = "xeronmx"
)

var SignedHeaders = []string{
	"From", "To", "Subject", "Date", "Message-ID", "MIME-Version",
}

type Key struct {
	Selector   string
	Algorithm  string
	PrivatePEM []byte
	PublicB64  string
}

func Generate(selector, algorithm string) (*Key, error) {
	if selector = strings.TrimSpace(selector); selector == "" {
		selector = DefaultSelector
	}
	if !validSelector(selector) {
		return nil, fmt.Errorf("dkim: %q is not a usable selector: use letters, digits, hyphens and dots", selector)
	}

	switch algorithm {
	case store.AlgorithmEd25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("dkim: generate ed25519 key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		return &Key{
			Selector:   selector,
			Algorithm:  store.AlgorithmEd25519,
			PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
			PublicB64:  base64.StdEncoding.EncodeToString(pub),
		}, nil

	case "", store.AlgorithmRSA:
		priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			return nil, fmt.Errorf("dkim: generate rsa key: %w", err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		return &Key{
			Selector:   selector,
			Algorithm:  store.AlgorithmRSA,
			PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
			PublicB64:  base64.StdEncoding.EncodeToString(pubDER),
		}, nil

	default:
		return nil, fmt.Errorf("dkim: unknown algorithm %q", algorithm)
	}
}

func validSelector(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

func RecordName(selector, domain string) string {
	return fmt.Sprintf("%s._domainkey.%s.", selector, domain)
}

func RecordValue(algorithm, publicB64 string) string {
	k := "rsa"
	if algorithm == store.AlgorithmEd25519 {
		k = "ed25519"
	}
	return fmt.Sprintf("v=DKIM1; k=%s; p=%s", k, publicB64)
}

func ParsePrivate(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("dkim: the stored key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("dkim: parse private key: %w", err)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("dkim: the stored key cannot sign")
	}
	return signer, nil
}

type Signer struct {
	domain   string
	selector string
	signer   crypto.Signer
}

func NewSigner(domain, selector string, privatePEM []byte) (*Signer, error) {
	signer, err := ParsePrivate(privatePEM)
	if err != nil {
		return nil, err
	}
	return &Signer{domain: domain, selector: selector, signer: signer}, nil
}

func (s *Signer) Sign(w io.Writer, r io.Reader) error {
	return dkim.Sign(w, r, &dkim.SignOptions{
		Domain:                 s.domain,
		Selector:               s.selector,
		Signer:                 s.signer,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderKeys:             SignedHeaders,
	})
}
