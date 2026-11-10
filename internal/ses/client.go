// Package ses manages the Amazon SES sending identities of the configured
// domains, so that mail submitted on port 587 and relayed through SES is only
// accepted for a domain SES will actually send for.
//
// It talks to the SESv2 REST API directly, signed with Signature Version 4,
// rather than through the AWS SDK: three calls do not justify the dozen modules
// the SDK brings into a mail relay (CONTRIBUTING.md, "No unnecessary
// dependencies"). The signature is checked against AWS's published vectors.
package ses

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SES verification states, as SESv2 names them.
const (
	StatusPending          = "PENDING"
	StatusSuccess          = "SUCCESS"
	StatusFailed           = "FAILED"
	StatusTemporaryFailure = "TEMPORARY_FAILURE"
	StatusNotStarted       = "NOT_STARTED"
)

var (
	ErrNotFound      = errors.New("ses: identity not found")
	ErrAlreadyExists = errors.New("ses: identity already exists")
)

// Identity is what XeronMX needs to know about an SES email identity.
type Identity struct {
	Name               string
	Status             string
	VerifiedForSending bool
	DKIMTokens         []string
}

// Client is the part of SESv2 XeronMX uses. Tests substitute a fake.
type Client interface {
	CreateIdentity(ctx context.Context, domain string) (*Identity, error)
	GetIdentity(ctx context.Context, domain string) (*Identity, error)
	DeleteIdentity(ctx context.Context, domain string) error
}

// APIError is an error answered by SES itself, as opposed to a transport one.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("ses: %s (HTTP %d)", e.Code, e.StatusCode)
	}
	return fmt.Sprintf("ses: %s: %s", e.Code, e.Message)
}

func (e *APIError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Code == "NotFoundException"
	case ErrAlreadyExists:
		return e.Code == "AlreadyExistsException"
	}
	return false
}

// HTTPClient calls the real SESv2 endpoint of one region.
type HTTPClient struct {
	Region    string
	Endpoint  string
	AccessKey string
	SecretKey string
	HTTP      *http.Client
	now       func() time.Time
}

func NewHTTPClient(region, accessKey, secretKey string) *HTTPClient {
	return &HTTPClient{
		Region:    region,
		Endpoint:  "https://email." + region + ".amazonaws.com",
		AccessKey: accessKey,
		SecretKey: secretKey,
		HTTP:      &http.Client{Timeout: 20 * time.Second},
		now:       time.Now,
	}
}

type dkimAttributes struct {
	Status string   `json:"Status"`
	Tokens []string `json:"Tokens"`
}

type identityResponse struct {
	VerifiedForSendingStatus bool           `json:"VerifiedForSendingStatus"`
	VerificationStatus       string         `json:"VerificationStatus"`
	DkimAttributes           dkimAttributes `json:"DkimAttributes"`
}

func (r *identityResponse) identity(name string) *Identity {
	status := r.VerificationStatus
	if status == "" {
		// CreateEmailIdentity does not return VerificationStatus; for a domain
		// identity with Easy DKIM, the DKIM status is what decides it.
		status = r.DkimAttributes.Status
	}
	if r.VerifiedForSendingStatus {
		status = StatusSuccess
	}
	if status == "" {
		status = StatusPending
	}
	return &Identity{
		Name:               name,
		Status:             status,
		VerifiedForSending: r.VerifiedForSendingStatus,
		DKIMTokens:         r.DkimAttributes.Tokens,
	}
}

func (c *HTTPClient) CreateIdentity(ctx context.Context, domain string) (*Identity, error) {
	body, err := json.Marshal(map[string]any{
		"EmailIdentity": domain,
		"DkimSigningAttributes": map[string]string{
			"NextSigningKeyLength": "RSA_2048_BIT",
		},
	})
	if err != nil {
		return nil, err
	}
	var out identityResponse
	if err := c.do(ctx, http.MethodPost, "/v2/email/identities", body, &out); err != nil {
		return nil, err
	}
	return out.identity(domain), nil
}

func (c *HTTPClient) GetIdentity(ctx context.Context, domain string) (*Identity, error) {
	var out identityResponse
	if err := c.do(ctx, http.MethodGet, identityPath(domain), nil, &out); err != nil {
		return nil, err
	}
	return out.identity(domain), nil
}

func (c *HTTPClient) DeleteIdentity(ctx context.Context, domain string) error {
	return c.do(ctx, http.MethodDelete, identityPath(domain), nil, nil)
}

func identityPath(domain string) string {
	return "/v2/email/identities/" + url.PathEscape(domain)
}

func (c *HTTPClient) do(ctx context.Context, method, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.Endpoint+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	Sign(req, body, c.AccessKey, c.SecretKey, c.Region, "ses", c.now().UTC())

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("ses: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("ses: read response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return parseError(resp, raw)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("ses: decode response: %w", err)
	}
	return nil
}

func parseError(resp *http.Response, raw []byte) error {
	e := &APIError{StatusCode: resp.StatusCode}
	var body struct {
		Type    string `json:"__type"`
		Code    string `json:"code"`
		Message string `json:"message"`
		Upper   string `json:"Message"`
	}
	_ = json.Unmarshal(raw, &body)
	e.Message = body.Message
	if e.Message == "" {
		e.Message = body.Upper
	}
	// The error type comes as "NotFoundException:http://internal.amazon.com/..."
	// in a header, or in the body under one of two names.
	for _, candidate := range []string{resp.Header.Get("X-Amzn-ErrorType"), body.Type, body.Code} {
		if candidate == "" {
			continue
		}
		if i := strings.IndexAny(candidate, ":"); i >= 0 {
			candidate = candidate[:i]
		}
		if i := strings.LastIndex(candidate, "#"); i >= 0 {
			candidate = candidate[i+1:]
		}
		e.Code = candidate
		break
	}
	if e.Code == "" {
		switch resp.StatusCode {
		case http.StatusNotFound:
			e.Code = "NotFoundException"
		default:
			e.Code = http.StatusText(resp.StatusCode)
		}
	}
	return e
}
