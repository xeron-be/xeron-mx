package ses

import (
	"encoding/json"
	"testing"
)

func TestARawPermanentBounceCounts(t *testing.T) {
	body := `{"eventType":"Bounce","mail":{"source":"Alice@Client.example","messageId":"0100"},
		"bounce":{"bounceType":"Permanent","bounceSubType":"General","feedbackId":"fb1",
		"timestamp":"2026-11-10T10:00:00.000Z",
		"bouncedRecipients":[{"emailAddress":"Gone@far.example","status":"5.1.1","diagnosticCode":"smtp; 550 5.1.1 no such user"},
		{"emailAddress":"also@far.example","status":"5.1.1"}]}}`
	got, err := ParseEvent(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d feedback entries; want one per recipient", len(got))
	}
	f := got[0]
	if f.Kind != FeedbackBounce || f.Sender != "alice@client.example" || f.Recipient != "gone@far.example" ||
		f.FeedbackID != "fb1" || f.Detail != "smtp; 550 5.1.1 no such user" || f.At.Year() != 2026 {
		t.Fatalf("feedback = %+v", f)
	}
	if got[1].Detail != "5.1.1 General" {
		t.Fatalf("detail without a diagnostic = %q", got[1].Detail)
	}
}

func TestAnSNSWrappedComplaintCounts(t *testing.T) {
	inner := `{"notificationType":"Complaint","mail":{"source":"bob@client.example","messageId":"0200"},
		"complaint":{"feedbackId":"fb2","timestamp":"2026-11-10T11:00:00Z","complaintFeedbackType":"abuse",
		"complainedRecipients":[{"emailAddress":"angry@far.example"}]}}`
	wrapped, _ := json.Marshal(map[string]string{"Type": "Notification", "Message": inner})
	got, err := ParseEvent(string(wrapped))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != FeedbackComplaint || got[0].Recipient != "angry@far.example" {
		t.Fatalf("got %+v", got)
	}
}

func TestWhatAWSDoesNotCountIsIgnored(t *testing.T) {
	for name, body := range map[string]string{
		"soft bounce": `{"eventType":"Bounce","mail":{"source":"a@b.example"},"bounce":{"bounceType":"Transient","feedbackId":"x",
			"bouncedRecipients":[{"emailAddress":"c@d.example"}]}}`,
		"account suppression list": `{"eventType":"Bounce","mail":{"source":"a@b.example"},"bounce":{"bounceType":"Permanent",
			"bounceSubType":"OnAccountSuppressionList","feedbackId":"x","bouncedRecipients":[{"emailAddress":"c@d.example"}]}}`,
		"global suppression list": `{"eventType":"Bounce","mail":{"source":"a@b.example"},"bounce":{"bounceType":"Permanent",
			"bounceSubType":"Suppressed","feedbackId":"x","bouncedRecipients":[{"emailAddress":"c@d.example"}]}}`,
		"not-spam report": `{"eventType":"Complaint","mail":{"source":"a@b.example"},"complaint":{"feedbackId":"x",
			"complaintFeedbackType":"not-spam","complainedRecipients":[{"emailAddress":"c@d.example"}]}}`,
		"delivery":     `{"eventType":"Delivery","mail":{"source":"a@b.example"}}`,
		"subscription": `{"Type":"SubscriptionConfirmation","Message":"confirm"}`,
		"topic check":  "Successfully validated SNS topic for Amazon SES event publishing.",
	} {
		got, err := ParseEvent(body)
		if err != nil || len(got) != 0 {
			t.Errorf("%s: got %v, %v; want nothing", name, got, err)
		}
	}
}

func TestGarbageIsAnError(t *testing.T) {
	if _, err := ParseEvent("{not json"); err == nil {
		t.Fatal("garbage was accepted")
	}
}
