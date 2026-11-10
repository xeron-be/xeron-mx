package ses

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const (
	FeedbackBounce    = "bounce"
	FeedbackComplaint = "complaint"
)

// Feedback is one recipient's hard bounce or complaint, as SES reported it.
type Feedback struct {
	Kind         string
	Sender       string
	Recipient    string
	FeedbackID   string
	SESMessageID string
	Detail       string
	At           time.Time
}

type sesEvent struct {
	EventType        string `json:"eventType"`
	NotificationType string `json:"notificationType"`
	Mail             struct {
		Source    string `json:"source"`
		MessageID string `json:"messageId"`
	} `json:"mail"`
	Bounce *struct {
		BounceType        string `json:"bounceType"`
		BounceSubType     string `json:"bounceSubType"`
		FeedbackID        string `json:"feedbackId"`
		Timestamp         string `json:"timestamp"`
		BouncedRecipients []struct {
			EmailAddress   string `json:"emailAddress"`
			Status         string `json:"status"`
			DiagnosticCode string `json:"diagnosticCode"`
		} `json:"bouncedRecipients"`
	} `json:"bounce"`
	Complaint *struct {
		FeedbackID            string `json:"feedbackId"`
		Timestamp             string `json:"timestamp"`
		ComplaintFeedbackType string `json:"complaintFeedbackType"`
		ComplainedRecipients  []struct {
			EmailAddress string `json:"emailAddress"`
		} `json:"complainedRecipients"`
	} `json:"complaint"`
}

// ParseEvent reads one queue message: an SES event, either raw or wrapped in
// an SNS notification. It returns only what counts against a sender's
// reputation the way AWS counts it: permanent bounces and complaints. Soft
// bounces, mail SES refused because the address was already on a suppression
// list (it was never sent), and anything else yield nothing.
func ParseEvent(body string) ([]Feedback, error) {
	if !strings.HasPrefix(strings.TrimSpace(body), "{") {
		// SES checks a new event destination by publishing a line of plain
		// text ("Successfully validated SNS topic for Amazon SES event
		// publishing."): not an event, and not an error either.
		return nil, nil
	}
	var envelope struct {
		Type    string `json:"Type"`
		Message string `json:"Message"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return nil, fmt.Errorf("ses event: not JSON: %w", err)
	}
	raw := body
	if envelope.Type != "" {
		if envelope.Type != "Notification" {
			// SubscriptionConfirmation and the like: nothing to count.
			return nil, nil
		}
		raw = envelope.Message
	}

	var ev sesEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		return nil, fmt.Errorf("ses event: %w", err)
	}
	kind := ev.EventType
	if kind == "" {
		kind = ev.NotificationType
	}

	sender := strings.ToLower(strings.TrimSpace(ev.Mail.Source))
	var out []Feedback
	switch kind {
	case "Bounce":
		b := ev.Bounce
		if b == nil || b.BounceType != "Permanent" || suppressed(b.BounceSubType) {
			return nil, nil
		}
		at := parseTimestamp(b.Timestamp)
		for _, r := range b.BouncedRecipients {
			detail := r.DiagnosticCode
			if detail == "" {
				detail = strings.TrimSpace(r.Status + " " + b.BounceSubType)
			}
			out = append(out, Feedback{
				Kind: FeedbackBounce, Sender: sender, Recipient: strings.ToLower(r.EmailAddress),
				FeedbackID: b.FeedbackID, SESMessageID: ev.Mail.MessageID, Detail: detail, At: at,
			})
		}
	case "Complaint":
		c := ev.Complaint
		if c == nil || c.ComplaintFeedbackType == "not-spam" {
			return nil, nil
		}
		at := parseTimestamp(c.Timestamp)
		for _, r := range c.ComplainedRecipients {
			out = append(out, Feedback{
				Kind: FeedbackComplaint, Sender: sender, Recipient: strings.ToLower(r.EmailAddress),
				FeedbackID: c.FeedbackID, SESMessageID: ev.Mail.MessageID, Detail: c.ComplaintFeedbackType, At: at,
			})
		}
	}
	return out, nil
}

func suppressed(subType string) bool {
	return subType == "Suppressed" || subType == "OnAccountSuppressionList"
}

func parseTimestamp(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}
