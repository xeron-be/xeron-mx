package dkim

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DNSCheckResult struct {
	Valid      bool     `json:"valid"`
	Found      bool     `json:"found"`
	Matched    bool     `json:"matched"`
	RecordName string   `json:"record_name"`
	Records    []string `json:"records,omitempty"`
	Status     string   `json:"status,omitempty"`
	Error      string   `json:"error,omitempty"`
}

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
	Comment string `json:"Comment"`
}

func CleanTXTRecord(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "\" \"") {
		parts := strings.Split(raw, "\" \"")
		var sb strings.Builder
		for _, p := range parts {
			sb.WriteString(strings.Trim(p, "\""))
		}
		return sb.String()
	}
	return strings.Trim(raw, "\"")
}

func ExtractPublicKey(record string) string {
	parts := strings.Split(record, ";")
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(trimmed), "p=") {
			val := trimmed[2:]
			val = strings.ReplaceAll(val, " ", "")
			val = strings.ReplaceAll(val, "\"", "")
			val = strings.ReplaceAll(val, "\t", "")
			val = strings.ReplaceAll(val, "\r", "")
			val = strings.ReplaceAll(val, "\n", "")
			return val
		}
	}
	return ""
}

func CheckDNS(ctx context.Context, domain, selector, expectedPublicB64 string) (*DNSCheckResult, error) {
	if selector == "" {
		selector = DefaultSelector
	}
	recordName := fmt.Sprintf("%s._domainkey.%s", selector, domain)
	res := &DNSCheckResult{
		RecordName: recordName,
	}

	expectedClean := strings.ReplaceAll(expectedPublicB64, " ", "")
	expectedClean = strings.ReplaceAll(expectedClean, "\n", "")
	expectedClean = strings.ReplaceAll(expectedClean, "\r", "")

	rawRecords, dohStatus, err := queryDoH(ctx, recordName)
	if err != nil {
		lookupCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		sysRecords, sysErr := net.DefaultResolver.LookupTXT(lookupCtx, recordName)
		if sysErr != nil {
			res.Status = "LOOKUP_FAILED"
			res.Error = sysErr.Error()
			return res, nil
		}
		rawRecords = sysRecords
		dohStatus = 0
	}

	switch dohStatus {
	case 0:
		res.Status = "NOERROR"
	case 3:
		res.Status = "NXDOMAIN"
		res.Error = "Record not found (NXDOMAIN)"
		return res, nil
	default:
		res.Status = fmt.Sprintf("DNS_STATUS_%d", dohStatus)
	}

	if len(rawRecords) == 0 {
		res.Error = "No TXT records returned"
		return res, nil
	}

	res.Found = true
	for _, raw := range rawRecords {
		cleaned := CleanTXTRecord(raw)
		res.Records = append(res.Records, cleaned)
		pub := ExtractPublicKey(cleaned)
		if pub != "" && pub == expectedClean {
			res.Matched = true
			res.Valid = true
		}
	}

	if !res.Matched {
		res.Error = "Record found but public key does not match"
	}

	return res, nil
}

func queryDoH(ctx context.Context, name string) ([]string, int, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	endpoints := []string{
		"https://dns.google/resolve?name=" + url.QueryEscape(name) + "&type=TXT",
		"https://1.1.1.1/dns-query?name=" + url.QueryEscape(name) + "&type=TXT",
	}

	var allRecords []string
	bestStatus := -1
	var lastErr error

	for _, ep := range endpoints {
		recs, status, err := queryDoHEndpoint(ctx, client, ep)
		if err == nil {
			if bestStatus == -1 || status == 0 {
				bestStatus = status
			}
			for _, r := range recs {
				exists := false
				for _, existing := range allRecords {
					if existing == r {
						exists = true
						break
					}
				}
				if !exists {
					allRecords = append(allRecords, r)
				}
			}
		} else {
			lastErr = err
		}
	}

	if len(allRecords) == 0 && bestStatus == -1 {
		return nil, -1, lastErr
	}
	return allRecords, bestStatus, nil
}

func queryDoHEndpoint(ctx context.Context, client *http.Client, endpoint string) ([]string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, -1, err
	}
	req.Header.Set("Accept", "application/dns-json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, -1, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, -1, fmt.Errorf("doh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, -1, err
	}

	var doh dohResponse
	if err := json.Unmarshal(body, &doh); err != nil {
		return nil, -1, err
	}

	var records []string
	for _, ans := range doh.Answer {
		if ans.Type == 16 && ans.Data != "" {
			records = append(records, ans.Data)
		}
	}
	return records, doh.Status, nil
}
