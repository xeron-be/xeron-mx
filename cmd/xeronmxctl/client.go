package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const maxResponseBytes = 32 << 20

type Settings struct {
	URL      string `yaml:"url"`
	Token    string `yaml:"token"`
	Insecure bool   `yaml:"insecure"`
}

type Client struct {
	base  string
	token string
	http  *http.Client
}

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("the server answered %d", e.Status)
	}
	return e.Message
}

func NewClient(s Settings) (*Client, error) {
	if s.URL == "" {
		return nil, errors.New("no server URL. Pass --url, set XERONMX_URL, " +
			"or run: xeronmxctl login --url https://mx2.example.com --token xmx_...")
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%q is not a URL", s.URL)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("the URL must start with http:// or https://")
	}
	if s.Token == "" {
		return nil, errors.New("no API token. Pass --token, set XERONMX_TOKEN, or run: xeronmxctl login")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	if s.Insecure {
		fmt.Fprintln(os.Stderr, "warning: TLS certificate verification is off")
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		base:  strings.TrimRight(s.URL, "/"),
		token: s.Token,
		http:  &http.Client{Timeout: 60 * time.Second, Transport: transport},
	}, nil
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "xeronmxctl")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope struct {
			Error string `json:"error"`
		}
		json.Unmarshal(raw, &envelope)
		if envelope.Error == "" {
			envelope.Error = strings.TrimSpace(string(raw))
		}
		return &APIError{Status: resp.StatusCode, Message: envelope.Error}
	}

	if out == nil {
		return nil
	}
	if target, ok := out.(*[]byte); ok {
		*target = raw
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("the server returned something unexpected: %w", err)
	}
	return nil
}

func (c *Client) postRaw(ctx context.Context, path, contentType string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "xeronmxctl")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var envelope struct {
			Error string `json:"error"`
		}
		json.Unmarshal(raw, &envelope)
		if envelope.Error == "" {
			envelope.Error = strings.TrimSpace(string(raw))
		}
		return &APIError{Status: resp.StatusCode, Message: envelope.Error}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodGet, path, nil, out)
}

func (c *Client) post(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPost, path, body, out)
}

func (c *Client) patch(ctx context.Context, path string, body, out any) error {
	return c.do(ctx, http.MethodPatch, path, body, out)
}

func (c *Client) delete(ctx context.Context, path string, out any) error {
	return c.do(ctx, http.MethodDelete, path, nil, out)
}

func ConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "xeronmx", "cli.yaml"), nil
}

func LoadSettings(flags Settings) (Settings, error) {
	s := Settings{}

	if path, err := ConfigPath(); err == nil {
		if raw, err := os.ReadFile(path); err == nil {
			if err := yaml.Unmarshal(raw, &s); err != nil {
				return s, fmt.Errorf("parse %s: %w", path, err)
			}
			warnIfReadable(path)
		}
	}

	if v := os.Getenv("XERONMX_URL"); v != "" {
		s.URL = v
	}
	if v := os.Getenv("XERONMX_TOKEN"); v != "" {
		s.Token = v
	}

	if flags.URL != "" {
		s.URL = flags.URL
	}
	if flags.Token != "" {
		s.Token = flags.Token
	}
	if flags.Insecure {
		s.Insecure = true
	}
	return s, nil
}

func SaveSettings(s Settings) (string, error) {
	path, err := ConfigPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	raw, err := yaml.Marshal(s)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func warnIfReadable(path string) {
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(os.Stderr,
			"warning: %s holds an API token and is readable by other users (mode %04o)\n",
			path, info.Mode().Perm())
	}
}
