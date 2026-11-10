package submission

import (
	"context"
	"errors"
	"testing"

	"github.com/emersion/go-smtp"

	"github.com/xeron-be/xeron-mx/internal/store"
)

func withSES(s *Server) { s.cfg.SES.Region = "eu-west-3" }

func (h *harness) sesStatus(t *testing.T, domainID int64, status string) {
	t.Helper()
	if err := h.db.SaveSESIdentity(context.Background(), &store.SESIdentity{
		DomainID: domainID, Identity: "example.com", Status: status,
	}); err != nil {
		t.Fatal(err)
	}
}

func smtpCode(err error) int {
	var reply *smtp.SMTPError
	if errors.As(err, &reply) {
		return reply.Code
	}
	return 0
}

func TestSESGatesTheSenderDomain(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   int
	}{
		{"never checked yet", "", 451},
		{"pending", store.SESPending, 451},
		{"unreachable before any identity", store.SESError, 451},
		{"failed", store.SESFailed, 550},
		{"verified", store.SESVerified, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, withSES)
			id := h.addDomain(t, "example.com")
			h.addUser(t, "mailserver", nil)
			if tc.status != "" {
				h.sesStatus(t, id, tc.status)
			}
			err := h.send(t, "a@example.com", "x@far.example")
			if got := smtpCode(err); got != tc.want {
				t.Fatalf("reply %d (%v); want %d", got, err, tc.want)
			}
			msgs, _ := h.db.ListMessages(context.Background(), store.ListFilter{})
			if queued := len(msgs) == 1; queued != (tc.want == 0) {
				t.Fatalf("queued %d messages", len(msgs))
			}
		})
	}
}

func TestWithoutSESNothingChanges(t *testing.T) {
	h := newHarness(t)
	h.addDomain(t, "example.com")
	h.addUser(t, "mailserver", nil)
	if err := h.send(t, "a@example.com", "x@far.example"); err != nil {
		t.Fatalf("a domain with no SES identity was refused with SES off: %v", err)
	}
}
