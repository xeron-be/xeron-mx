package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAPITokenRoundTrip(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	userID, err := db.CreateUser(ctx, "admin@test.example", "hash", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Now().UTC().Add(time.Hour)

	id, err := db.CreateAPIToken(ctx, &APIToken{
		Name: "ci", Prefix: "xmx_abcd1234", Role: RoleViewer,
		CreatedBy: &userID, ExpiresAt: &expires,
	}, "thehash")
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}

	got, err := db.APITokenByHash(ctx, "thehash")
	if err != nil {
		t.Fatalf("APITokenByHash: %v", err)
	}
	if got.ID != id || got.Name != "ci" || got.Role != RoleViewer {
		t.Fatalf("token came back wrong: %+v", got)
	}
	if got.CreatedBy == nil || *got.CreatedBy != userID {
		t.Fatal("the token lost its owner")
	}
}

func TestExpiredAPITokenIsNotFound(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	past := time.Now().UTC().Add(-time.Minute)
	if _, err := db.CreateAPIToken(ctx, &APIToken{
		Name: "stale", Prefix: "xmx_00000000", Role: RoleAdmin, ExpiresAt: &past,
	}, "stalehash"); err != nil {
		t.Fatal(err)
	}

	if _, err := db.APITokenByHash(ctx, "stalehash"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SECURITY: an expired token resolved with err = %v, want ErrNotFound", err)
	}
}

func TestDeletingAnOwnerOrphansTheirTokens(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	userID, err := db.CreateUser(ctx, "leaver@test.example", "hash", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateAPIToken(ctx, &APIToken{
		Name: "theirs", Prefix: "xmx_11111111", Role: RoleAdmin, CreatedBy: &userID,
	}, "ownedhash"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID); err != nil {
		t.Fatal(err)
	}

	got, err := db.APITokenByHash(ctx, "ownedhash")
	if err != nil {
		t.Fatalf("the token row vanished entirely: %v", err)
	}
	if got.CreatedBy != nil {
		t.Fatalf("SECURITY: the token still claims owner %d after that account was deleted", *got.CreatedBy)
	}
}

func TestTouchAPITokenIsThrottled(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	id, err := db.CreateAPIToken(ctx, &APIToken{
		Name: "probe", Prefix: "xmx_22222222", Role: RoleViewer,
	}, "probehash")
	if err != nil {
		t.Fatal(err)
	}

	db.TouchAPIToken(ctx, id)
	first, err := db.APITokenByHash(ctx, "probehash")
	if err != nil || first.LastUsedAt == nil {
		t.Fatalf("the first use was not recorded: %v", err)
	}

	db.TouchAPIToken(ctx, id)
	second, err := db.APITokenByHash(ctx, "probehash")
	if err != nil {
		t.Fatal(err)
	}
	if !second.LastUsedAt.Equal(*first.LastUsedAt) {
		t.Error("a second use within the minute took the write lock again")
	}
}

func TestWebhookWants(t *testing.T) {
	cases := []struct {
		name    string
		hook    Webhook
		event   string
		want    bool
		because string
	}{
		{"empty list means everything", Webhook{Enabled: true}, EventMailReceived, true,
			"a subscriber that named nothing must not miss event types added later"},
		{"named event matches", Webhook{Enabled: true, Events: []string{EventPrimaryDown}},
			EventPrimaryDown, true, ""},
		{"unnamed event does not", Webhook{Enabled: true, Events: []string{EventPrimaryDown}},
			EventMailReceived, false, ""},
		{"disabled wants nothing", Webhook{Enabled: false}, EventMailReceived, false,
			"switching a subscription off must stop deliveries, not just new ones"},
	}
	for _, tc := range cases {
		if got := tc.hook.Wants(tc.event); got != tc.want {
			t.Errorf("%s: Wants(%q) = %v, want %v %s", tc.name, tc.event, got, tc.want, tc.because)
		}
	}
}

func TestDeliveryLifecycle(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	hookID, err := db.CreateWebhook(ctx, &Webhook{
		Name: "chat", URL: "https://hooks.test/x", Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	due, err := db.EnqueueDelivery(ctx, hookID, EventMailReceived, `{"id":1}`, now)
	if err != nil {
		t.Fatal(err)
	}
	later, err := db.EnqueueDelivery(ctx, hookID, EventMailReceived, `{"id":2}`, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.DueDeliveries(ctx, now, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != due {
		t.Fatalf("DueDeliveries returned %d rows; a future attempt must not be picked up early", len(rows))
	}

	next := now.Add(30 * time.Second)
	if err := db.RescheduleDelivery(ctx, due, 503, "endpoint answered 503", next); err != nil {
		t.Fatal(err)
	}
	if rows, _ = db.DueDeliveries(ctx, now, 10); len(rows) != 0 {
		t.Fatal("a rescheduled delivery is still due at the old time")
	}
	if rows, _ = db.DueDeliveries(ctx, next, 10); len(rows) != 1 || rows[0].Attempts != 1 {
		t.Fatalf("the retry did not come back due with an incremented attempt count: %+v", rows)
	}

	if err := db.MarkDeliverySucceeded(ctx, due, 200); err != nil {
		t.Fatal(err)
	}
	hook, err := db.Webhook(ctx, hookID)
	if err != nil {
		t.Fatal(err)
	}
	if hook.LastSuccessAt == nil {
		t.Error("a successful delivery did not clear the subscription's health")
	}
	if hook.LastError != "" {
		t.Errorf("last_error is still %q after a success", hook.LastError)
	}

	_ = later
}

func TestPurgeDeliveriesSparesPending(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	hookID, err := db.CreateWebhook(ctx, &Webhook{Name: "x", URL: "https://h.test", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-48 * time.Hour)

	pending, _ := db.EnqueueDelivery(ctx, hookID, EventStartup, "{}", old)
	done, _ := db.EnqueueDelivery(ctx, hookID, EventStartup, "{}", old)
	if err := db.MarkDeliverySucceeded(ctx, done, 200); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`UPDATE webhook_deliveries SET created_at = ?`, formatTime(old)); err != nil {
		t.Fatal(err)
	}

	n, err := db.PurgeDeliveries(ctx, time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("purged %d rows, want only the resolved one", n)
	}
	rows, _ := db.ListDeliveries(ctx, hookID, 10)
	if len(rows) != 1 || rows[0].ID != pending {
		t.Fatal("the pending delivery was purged; it was still owed to a subscriber")
	}
}

func TestDeletingAWebhookTakesItsDeliveries(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	hookID, _ := db.CreateWebhook(ctx, &Webhook{Name: "x", URL: "https://h.test", Enabled: true})
	if _, err := db.EnqueueDelivery(ctx, hookID, EventStartup, "{}", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteWebhook(ctx, hookID); err != nil {
		t.Fatal(err)
	}

	rows, err := db.ListDeliveries(ctx, 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("%d deliveries survived their subscription", len(rows))
	}
}

func TestEventsSinceIsOrderedAndBounded(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		if err := db.RecordEvent(ctx, &Event{Type: EventStartup}); err != nil {
			t.Fatal(err)
		}
	}

	head, err := db.MaxEventID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if head != 5 {
		t.Fatalf("MaxEventID = %d, want 5", head)
	}

	events, err := db.EventsSince(ctx, 2, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("EventsSince(2) returned %d events, want 3", len(events))
	}
	for i, e := range events {
		if want := int64(3 + i); e.ID != want {
			t.Fatalf("event %d has id %d, want %d — a tailer needs them oldest first", i, e.ID, want)
		}
	}
}

func TestMaxEventIDOnAnEmptyLog(t *testing.T) {
	db := newDB(t)
	head, err := db.MaxEventID(context.Background())
	if err != nil {
		t.Fatalf("MaxEventID on an empty table: %v", err)
	}
	if head != 0 {
		t.Fatalf("MaxEventID = %d on an empty table, want 0", head)
	}
}

func TestMetaRoundTrip(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	if _, err := db.Meta(ctx, "absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Meta on a missing key = %v, want ErrNotFound", err)
	}
	if err := db.SetMetaInt(ctx, "cursor", 42); err != nil {
		t.Fatal(err)
	}
	if err := db.SetMetaInt(ctx, "cursor", 43); err != nil {
		t.Fatalf("SetMeta did not overwrite: %v", err)
	}
	n, err := db.MetaInt(ctx, "cursor")
	if err != nil || n != 43 {
		t.Fatalf("MetaInt = %d, %v; want 43", n, err)
	}
}

func TestUpsertNodeKeepsFirstSeen(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	if err := db.UpsertNode(ctx, &Node{ID: "mx2", Role: NodePrimary, ConfigHash: "aaa"}); err != nil {
		t.Fatal(err)
	}
	nodes, _ := db.ListNodes(ctx)
	first := nodes[0].FirstSeen

	time.Sleep(5 * time.Millisecond)
	if err := db.UpsertNode(ctx, &Node{ID: "mx2", Role: NodeFollower, ConfigHash: "bbb",
		QueuePending: 7}); err != nil {
		t.Fatal(err)
	}

	nodes, _ = db.ListNodes(ctx)
	if len(nodes) != 1 {
		t.Fatalf("%d rows for one node id", len(nodes))
	}
	got := nodes[0]
	if !got.FirstSeen.Equal(first) {
		t.Error("first_seen moved; it is what tells a long-standing node from one that just appeared")
	}
	if got.LastSeen.Before(first) || got.LastSeen.Equal(first) {
		t.Error("last_seen did not advance on the second heartbeat")
	}
	if got.Role != NodeFollower || got.ConfigHash != "bbb" || got.QueuePending != 7 {
		t.Fatalf("the update did not take: %+v", got)
	}
}

func TestUpsertNodeRejectsAnUnknownRole(t *testing.T) {
	db := newDB(t)
	if err := db.UpsertNode(context.Background(), &Node{ID: "mx2", Role: "emperor"}); err != nil {
		t.Fatalf("an unknown role should be normalised, not rejected: %v", err)
	}
	nodes, _ := db.ListNodes(context.Background())
	if nodes[0].Role != NodeFollower {
		t.Fatalf("role = %q, want it normalised to follower", nodes[0].Role)
	}
}

func TestNodeHealthy(t *testing.T) {
	now := time.Now().UTC()
	n := &Node{LastSeen: now.Add(-time.Minute)}
	if !n.Healthy(now, 90*time.Second) {
		t.Error("a node seen a minute ago is not healthy within 90s")
	}
	if n.Healthy(now, 30*time.Second) {
		t.Error("a node seen a minute ago is healthy within 30s")
	}
}

func TestForgetStaleNodes(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	if err := db.UpsertNode(ctx, &Node{ID: "old"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertNode(ctx, &Node{ID: "current"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE cluster_nodes SET last_seen = ? WHERE node_id = 'old'`,
		formatTime(time.Now().UTC().Add(-30*24*time.Hour))); err != nil {
		t.Fatal(err)
	}

	n, err := db.ForgetStaleNodes(ctx, time.Now().UTC().Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("forgot %d nodes, want 1", n)
	}
	nodes, _ := db.ListNodes(ctx)
	if len(nodes) != 1 || nodes[0].ID != "current" {
		t.Fatal("the wrong node was forgotten")
	}
}

func TestOIDCLookupIsBySubjectNotEmail(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	id, err := db.CreateOIDCUser(ctx, "Ops@Test.Example", RoleViewer, "https://id.test", "sub-1")
	if err != nil {
		t.Fatal(err)
	}

	got, err := db.UserByOIDC(ctx, "https://id.test", "sub-1")
	if err != nil {
		t.Fatalf("UserByOIDC: %v", err)
	}
	if got.ID != id {
		t.Fatal("the wrong account came back")
	}
	if got.Email != "ops@test.example" {
		t.Errorf("email = %q, want it normalised", got.Email)
	}
	if got.HasPassword() {
		t.Error("SECURITY: a directory-provisioned account has a password hash")
	}
	if !got.FromDirectory() {
		t.Error("the account does not report itself as directory-backed")
	}

	if _, err := db.UserByOIDC(ctx, "https://other.test", "sub-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SECURITY: a subject matched across issuers (err = %v)", err)
	}
}

func TestOIDCSubjectIsUniquePerIssuer(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	if _, err := db.CreateOIDCUser(ctx, "a@test.example", RoleViewer, "https://id.test", "sub-1"); err != nil {
		t.Fatal(err)
	}
	_, err := db.CreateOIDCUser(ctx, "b@test.example", RoleViewer, "https://id.test", "sub-1")
	if err == nil {
		t.Fatal("SECURITY: two accounts were bound to one provider identity")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unique") {
		t.Logf("rejected, as required, with: %v", err)
	}
}

func TestLinkOIDCBindsAnExistingAccount(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	id, err := db.CreateUser(ctx, "local@test.example", "argonhash", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.LinkOIDC(ctx, id, "https://id.test", "sub-9"); err != nil {
		t.Fatal(err)
	}

	got, err := db.UserByOIDC(ctx, "https://id.test", "sub-9")
	if err != nil {
		t.Fatalf("the link did not take: %v", err)
	}
	if got.ID != id {
		t.Fatal("the wrong account was linked")
	}
	if !got.HasPassword() {
		t.Error("linking a provider identity removed the local password; the break-glass path is gone")
	}
}

func TestListUpdateDeleteUser(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	id1, err := db.CreateUser(ctx, "admin1@test.example", "hash1", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := db.CreateUser(ctx, "viewer1@test.example", "", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}

	users, err := db.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 {
		t.Fatalf("ListUsers = %d, want 2", len(users))
	}

	if err := db.UpdateUserRole(ctx, id2, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	u2, err := db.UserByID(ctx, id2)
	if err != nil || u2.Role != RoleAdmin {
		t.Fatalf("UpdateUserRole did not promote user: %v", err)
	}

	if err := db.DeleteUser(ctx, id1); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	users, err = db.ListUsers(ctx)
	if err != nil || len(users) != 1 {
		t.Fatalf("after delete, ListUsers = %d, want 1", len(users))
	}
}

func TestCannotDeleteOrDemoteLastAdmin(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	adminID, err := db.CreateUser(ctx, "soleadmin@test.example", "hash", RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.UpdateUserRole(ctx, adminID, RoleViewer); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expected ErrLastAdmin when demoting sole admin, got %v", err)
	}

	if err := db.DeleteUser(ctx, adminID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expected ErrLastAdmin when deleting sole admin, got %v", err)
	}
}

func TestEventCatalogueCoversTheConstants(t *testing.T) {
	for _, known := range []string{
		EventMailReceived, EventMailDelivered, EventPrimaryDown, EventPrimaryUp,
		EventQueueFull, EventLogin, EventStartup, EventTokenCreated,
		EventWebhookCreated, EventClusterSynced, EventDKIMCreated, EventRouteCreated,
	} {
		if !KnownEventType(known) {
			t.Errorf("%s is emitted but is not in the catalogue, so nobody can subscribe to it", known)
		}
	}
	if KnownEventType("mail_recieved") {
		t.Error("a typo was accepted as an event type; a subscription for it would never fire")
	}
}

func TestConcurrentWritersDoNotDeadlock(t *testing.T) {
	db := newDB(t)
	ctx := context.Background()

	domains := make([]int64, 4)
	for i := range domains {
		domains[i] = newDomain(t, db, fmt.Sprintf("d%d.test", i))
	}
	hookID, err := db.CreateWebhook(ctx, &Webhook{Name: "x", URL: "https://h.test", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	const rounds = 40
	errs := make(chan error, 8*rounds)
	var wg sync.WaitGroup

	for _, id := range domains {
		wg.Add(1)
		go func(domainID int64) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if _, _, err := db.RecordProbe(ctx, domainID, i%2 == 0, "", 1, 1, time.Now().UTC()); err != nil {
					errs <- fmt.Errorf("RecordProbe: %w", err)
					return
				}
			}
		}(id)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if err := db.SetMetaInt(ctx, "webhook.cursor", int64(i)); err != nil {
				errs <- fmt.Errorf("SetMetaInt: %w", err)
				return
			}
			if _, err := db.EnqueueDelivery(ctx, hookID, EventStartup, "{}", time.Now().UTC()); err != nil {
				errs <- fmt.Errorf("EnqueueDelivery: %w", err)
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			id, err := db.EnqueueDelivery(ctx, hookID, EventStartup, "{}", time.Now().UTC())
			if err != nil {
				errs <- fmt.Errorf("EnqueueDelivery: %w", err)
				return
			}
			if err := db.MarkDeliverySucceeded(ctx, id, 200); err != nil {
				errs <- fmt.Errorf("MarkDeliverySucceeded: %w", err)
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if err := db.UpsertNode(ctx, &Node{
				ID: "mx-1", Role: NodeFollower, QueuePending: int64(i),
			}); err != nil {
				errs <- fmt.Errorf("UpsertNode: %w", err)
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			if err := db.RecordEvent(ctx, &Event{Type: EventStartup}); err != nil {
				errs <- fmt.Errorf("RecordEvent: %w", err)
				return
			}
		}
	}()

	wg.Wait()
	close(errs)

	var failures []string
	for err := range errs {
		failures = append(failures, err.Error())
	}
	if len(failures) > 0 {
		t.Fatalf("%d writes failed under contention; the first was:\n  %s",
			len(failures), failures[0])
	}
}
