package ses

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSQSReceiveAndDelete(t *testing.T) {
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "/eu-west-3/sqs/aws4_request") {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if !strings.Contains(r.Header.Get("Authorization"), "x-amz-target") {
			t.Errorf("the target header is not signed: %q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		if body["QueueUrl"] != "http://"+r.Host+"/123/xeronmx-ses-events" {
			t.Errorf("QueueUrl = %v", body["QueueUrl"])
		}
		switch r.Header.Get("X-Amz-Target") {
		case "AmazonSQS.ReceiveMessage":
			if body["WaitTimeSeconds"] != float64(20) {
				t.Errorf("WaitTimeSeconds = %v", body["WaitTimeSeconds"])
			}
			w.Write([]byte(`{"Messages":[{"MessageId":"a","ReceiptHandle":"h1","Body":"{}"}]}`))
		case "AmazonSQS.DeleteMessageBatch":
			for _, e := range body["Entries"].([]any) {
				deleted = append(deleted, e.(map[string]any)["ReceiptHandle"].(string))
			}
			w.Write([]byte(`{"Successful":[]}`))
		default:
			t.Errorf("target %q", r.Header.Get("X-Amz-Target"))
		}
	}))
	defer srv.Close()

	q, err := NewSQSQueue(srv.URL+"/123/xeronmx-ses-events", "eu-west-3", "AKID", "secret")
	if err != nil {
		t.Fatal(err)
	}
	if q.Endpoint != srv.URL+"/" {
		t.Fatalf("endpoint = %q", q.Endpoint)
	}
	q.now = func() time.Time { return time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC) }
	msgs, err := q.Receive(context.Background())
	if err != nil || len(msgs) != 1 || msgs[0].ReceiptHandle != "h1" {
		t.Fatalf("receive = %v, %v", msgs, err)
	}
	handles := make([]string, 13)
	for i := range handles {
		handles[i] = "h" + string(rune('a'+i))
	}
	if err := q.Delete(context.Background(), handles); err != nil {
		t.Fatal(err)
	}
	if len(deleted) != 13 {
		t.Fatalf("deleted %d of 13 (batches of 10)", len(deleted))
	}
}

func TestSQSErrorsAreReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"__type":"com.amazonaws.sqs#QueueDoesNotExist","message":"The specified queue does not exist."}`))
	}))
	defer srv.Close()
	q, _ := NewSQSQueue(srv.URL+"/1/q", "eu-west-3", "AKID", "secret")
	_, err := q.Receive(context.Background())
	if err == nil || !strings.Contains(err.Error(), "QueueDoesNotExist") {
		t.Fatalf("err = %v", err)
	}
}
