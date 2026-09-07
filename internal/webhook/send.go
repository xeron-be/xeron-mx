package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/xeron-be/xeron-mx/internal/store"
)

const (
	SignatureHeader = "X-XeronMX-Signature"
	EventHeader     = "X-XeronMX-Event"
	DeliveryHeader  = "X-XeronMX-Delivery"
	AttemptHeader   = "X-XeronMX-Attempt"
	NodeHeader      = "X-XeronMX-Node"
)

const maxResponseBytes = 4096

func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func (d *Dispatcher) post(ctx context.Context, hook *store.Webhook, del *store.Delivery) (int, error) {
	return d.send(ctx, hook, del.EventType, []byte(del.Payload), del.ID, del.Attempts+1)
}

func (d *Dispatcher) send(ctx context.Context, hook *store.Webhook, eventType string, body []byte, deliveryID int64, attempt int) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "XeronMX")
	req.Header.Set(EventHeader, eventType)
	req.Header.Set(NodeHeader, d.node)
	if deliveryID > 0 {
		req.Header.Set(DeliveryHeader, strconv.FormatInt(deliveryID, 10))
	}
	req.Header.Set(AttemptHeader, strconv.Itoa(attempt))

	if len(hook.Secret) > 0 {
		secret, err := d.seal.Unseal(hook.Secret)
		if err != nil {
			return http.StatusBadRequest, fmt.Errorf("the signing secret could not be read: %w", err)
		}
		req.Header.Set(SignatureHeader, Sign(secret, body))
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("the endpoint answered %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func (d *Dispatcher) Test(ctx context.Context, hook *store.Webhook) (int, error) {
	body, err := json.Marshal(Payload{
		ID:    0,
		Event: "test",
		At:    time.Now().UTC(),
		Node:  d.node,
		Data: map[string]any{
			"message": "This is a test delivery from XeronMX. " +
				"Nothing happened; somebody pressed a button.",
			"webhook": hook.Name,
		},
	})
	if err != nil {
		return 0, err
	}
	return d.send(ctx, hook, "test", body, 0, 1)
}
