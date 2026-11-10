package sestest

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/xeron-be/xeron-mx/internal/ses"
)

type Queue struct {
	mu      sync.Mutex
	pending []ses.QueueMessage
	next    int
	Deleted []string
	Err     error
}

func (q *Queue) Push(bodies ...string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, b := range bodies {
		q.next++
		q.pending = append(q.pending, ses.QueueMessage{
			ID: fmt.Sprintf("m%d", q.next), ReceiptHandle: fmt.Sprintf("r%d", q.next), Body: b,
		})
	}
}

func (q *Queue) Receive(context.Context) ([]ses.QueueMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.Err != nil {
		return nil, q.Err
	}
	n := min(len(q.pending), 10)
	out := append([]ses.QueueMessage(nil), q.pending[:n]...)
	q.pending = q.pending[n:]
	return out, nil
}

func (q *Queue) Delete(_ context.Context, handles []string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.Deleted = append(q.Deleted, handles...)
	return nil
}

func Bounce(sender, recipient, feedbackID string) string {
	return event(map[string]any{
		"eventType": "Bounce",
		"mail":      map[string]any{"source": sender, "messageId": "ses-" + feedbackID},
		"bounce": map[string]any{
			"bounceType": "Permanent", "bounceSubType": "General", "feedbackId": feedbackID,
			"timestamp": now(),
			"bouncedRecipients": []map[string]any{
				{"emailAddress": recipient, "status": "5.1.1", "diagnosticCode": "smtp; 550 5.1.1 user unknown"},
			},
		},
	})
}

func Complaint(sender, recipient, feedbackID string) string {
	return event(map[string]any{
		"eventType": "Complaint",
		"mail":      map[string]any{"source": sender, "messageId": "ses-" + feedbackID},
		"complaint": map[string]any{
			"feedbackId": feedbackID, "timestamp": now(),
			"complaintFeedbackType": "abuse",
			"complainedRecipients":  []map[string]any{{"emailAddress": recipient}},
		},
	})
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func event(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
