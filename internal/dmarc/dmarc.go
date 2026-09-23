package dmarc

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	msgdmarc "github.com/emersion/go-msgauth/dmarc"
)

type CheckResult struct {
	Valid           bool     `json:"valid"`
	Found           bool     `json:"found"`
	RecordName      string   `json:"record_name"`
	Records         []string `json:"records,omitempty"`
	Policy          string   `json:"policy,omitempty"`
	SubdomainPolicy string   `json:"subdomain_policy,omitempty"`
	RUA             []string `json:"rua,omitempty"`
	DKIMAlignment   string   `json:"adkim,omitempty"`
	SPFAlignment    string   `json:"aspf,omitempty"`
	Status          string   `json:"status,omitempty"`
	Error           string   `json:"error,omitempty"`
}

type dohResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func RecordName(domain string) string {
	d := strings.Trim(domain, ".")
	return fmt.Sprintf("_dmarc.%s.", d)
}

func DefaultValue(domain string, policy string) string {
	d := strings.Trim(domain, ".")
	p := policy
	if p == "" {
		p = "quarantine"
	}
	return fmt.Sprintf("v=DMARC1; p=%s; sp=%s; rua=mailto:dmarc@%s; pct=100", p, p, d)
}

func CheckDNS(ctx context.Context, domain string) (*CheckResult, error) {
	d := strings.Trim(domain, ".")
	recordName := fmt.Sprintf("_dmarc.%s", d)
	res := &CheckResult{
		RecordName: recordName,
	}

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

	var dmarcRecords []string
	for _, r := range rawRecords {
		cleaned := cleanTXT(r)
		if strings.HasPrefix(strings.ToUpper(cleaned), "V=DMARC1") {
			dmarcRecords = append(dmarcRecords, cleaned)
		}
	}

	if len(dmarcRecords) == 0 {
		if len(rawRecords) > 0 {
			res.Error = "TXT record found at _dmarc host but missing v=DMARC1 tag"
		} else {
			res.Error = "No TXT records returned"
		}
		return res, nil
	}

	res.Found = true
	res.Records = dmarcRecords

	parsed, err := msgdmarc.Parse(dmarcRecords[0])
	if err != nil {
		res.Error = fmt.Sprintf("invalid DMARC syntax: %v", err)
		return res, nil
	}

	res.Valid = true
	res.Policy = string(parsed.Policy)
	res.SubdomainPolicy = string(parsed.SubdomainPolicy)
	res.DKIMAlignment = string(parsed.DKIMAlignment)
	res.SPFAlignment = string(parsed.SPFAlignment)
	res.RUA = parsed.ReportURIAggregate

	return res, nil
}

func cleanTXT(raw string) string {
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
			if len(allRecords) > 0 {
				return allRecords, status, nil
			}
		} else {
			lastErr = err
		}
	}

	if len(allRecords) > 0 {
		return allRecords, bestStatus, nil
	}
	return nil, bestStatus, lastErr
}

func queryDoHEndpoint(ctx context.Context, client *http.Client, endpoint string) ([]string, int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
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
		return nil, -1, fmt.Errorf("doh: status %d", resp.StatusCode)
	}

	var doh dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&doh); err != nil {
		return nil, -1, err
	}

	var records []string
	for _, ans := range doh.Answer {
		if ans.Type == 16 {
			records = append(records, ans.Data)
		}
	}
	return records, doh.Status, nil
}
