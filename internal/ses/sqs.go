package ses

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type QueueMessage struct {
	ID            string
	ReceiptHandle string
	Body          string
}

type Queue interface {
	Receive(ctx context.Context) ([]QueueMessage, error)
	Delete(ctx context.Context, receiptHandles []string) error
}

type SQSQueue struct {
	QueueURL  string
	Endpoint  string
	Region    string
	AccessKey string
	SecretKey string
	HTTP      *http.Client
	Wait      time.Duration
	now       func() time.Time
}

func NewSQSQueue(queueURL, region, accessKey, secretKey string) (*SQSQueue, error) {
	u, err := url.Parse(queueURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("sqs: invalid queue URL %q", queueURL)
	}
	return &SQSQueue{
		QueueURL:  queueURL,
		Endpoint:  u.Scheme + "://" + u.Host + "/",
		Region:    region,
		AccessKey: accessKey,
		SecretKey: secretKey,
		HTTP:      &http.Client{Timeout: 40 * time.Second},
		Wait:      20 * time.Second,
		now:       time.Now,
	}, nil
}

func (q *SQSQueue) Receive(ctx context.Context) ([]QueueMessage, error) {
	var out struct {
		Messages []struct {
			MessageID     string `json:"MessageId"`
			ReceiptHandle string `json:"ReceiptHandle"`
			Body          string `json:"Body"`
		} `json:"Messages"`
	}
	err := q.call(ctx, "ReceiveMessage", map[string]any{
		"QueueUrl":            q.QueueURL,
		"MaxNumberOfMessages": 10,
		"WaitTimeSeconds":     int(q.Wait / time.Second),
	}, &out)
	if err != nil {
		return nil, err
	}
	msgs := make([]QueueMessage, len(out.Messages))
	for i, m := range out.Messages {
		msgs[i] = QueueMessage{ID: m.MessageID, ReceiptHandle: m.ReceiptHandle, Body: m.Body}
	}
	return msgs, nil
}

func (q *SQSQueue) Delete(ctx context.Context, receiptHandles []string) error {
	for len(receiptHandles) > 0 {
		n := min(len(receiptHandles), 10)
		entries := make([]map[string]string, n)
		for i, h := range receiptHandles[:n] {
			entries[i] = map[string]string{"Id": fmt.Sprintf("m%d", i), "ReceiptHandle": h}
		}
		var out struct {
			Failed []struct {
				ID      string `json:"Id"`
				Message string `json:"Message"`
			} `json:"Failed"`
		}
		if err := q.call(ctx, "DeleteMessageBatch", map[string]any{
			"QueueUrl": q.QueueURL,
			"Entries":  entries,
		}, &out); err != nil {
			return err
		}
		if len(out.Failed) > 0 {
			return fmt.Errorf("sqs: %d messages not deleted: %s", len(out.Failed), out.Failed[0].Message)
		}
		receiptHandles = receiptHandles[n:]
	}
	return nil
}

func (q *SQSQueue) call(ctx context.Context, action string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, q.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.0")
	req.Header.Set("X-Amz-Target", "AmazonSQS."+action)
	Sign(req, body, q.AccessKey, q.SecretKey, q.Region, "sqs", q.now().UTC())

	resp, err := q.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("sqs: %s: %w", action, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("sqs: read response: %w", err)
	}
	if resp.StatusCode >= 300 {
		return parseError(resp, raw)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("sqs: decode %s: %w", action, err)
	}
	return nil
}
