package store_test

import (
	"crypto/rand"
	"errors"
	"slices"
	"testing"

	"authentikManager/internal/joinrequest"
	"authentikManager/internal/store"
)

// createTestRequest stores a pending request by username for a group no other
// test uses, since the table is not wiped.
func createTestRequest(t *testing.T, s *store.Store, userPK int, username string) joinrequest.Request {
	t.Helper()
	jr, err := s.CreateJoinRequest(t.Context(), joinrequest.Request{
		GroupPK:   "g-" + rand.Text(),
		GroupName: "staff",
		UserPK:    userPK,
		Username:  username,
		Message:   "hi",
	})
	if err != nil {
		t.Fatalf("CreateJoinRequest: %v", err)
	}
	return jr
}

func TestStore_createJoinRequest(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()

	ann := createTestRequest(t, s, 1, "ann")
	if ann.ID == 0 || ann.Status != joinrequest.StatusPending || ann.CreatedAt.IsZero() || ann.DecidedAt != nil || ann.Message != "hi" {
		t.Errorf("created = %+v, want a pending request with ID and time", ann)
	}
	again := joinrequest.Request{GroupPK: ann.GroupPK, GroupName: "staff", UserPK: 1, Username: "ann"}
	if _, err := s.CreateJoinRequest(ctx, again); !errors.Is(err, joinrequest.ErrPending) {
		t.Errorf("duplicate CreateJoinRequest = %v, want ErrPending", err)
	}
	got, err := s.GetJoinRequest(ctx, ann.ID)
	if err != nil || got.Username != "ann" || got.GroupPK != ann.GroupPK {
		t.Errorf("GetJoinRequest = %+v, %v, want the created request", got, err)
	}
	if _, err := s.GetJoinRequest(ctx, -1); !errors.Is(err, joinrequest.ErrNotFound) {
		t.Errorf("GetJoinRequest(-1) = %v, want ErrNotFound", err)
	}
}

func TestStore_listJoinRequests(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()

	ann := createTestRequest(t, s, 1, "ann")
	bob := createTestRequest(t, s, 2, "bob")
	if _, err := s.DecideJoinRequest(ctx, ann.ID, joinrequest.StatusRejected, "admin"); err != nil {
		t.Fatalf("DecideJoinRequest: %v", err)
	}
	groups := []string{ann.GroupPK, bob.GroupPK}

	tests := []struct {
		name     string
		query    joinrequest.Query
		expected []int64
	}{
		{name: "groups newest first", query: joinrequest.Query{GroupPKs: groups}, expected: []int64{bob.ID, ann.ID}},
		{name: "pending", query: joinrequest.Query{Status: joinrequest.StatusPending, GroupPKs: groups}, expected: []int64{bob.ID}},
		{name: "by username", query: joinrequest.Query{Username: "ann", GroupPKs: groups}, expected: []int64{ann.ID}},
		{name: "no groups", query: joinrequest.Query{GroupPKs: []string{}}, expected: []int64{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := s.ListJoinRequests(ctx, tt.query)
			if err != nil {
				t.Fatalf("ListJoinRequests: %v", err)
			}
			if ids := requestIDs(list); !slices.Equal(ids, tt.expected) {
				t.Errorf("ids = %v, want %v", ids, tt.expected)
			}
		})
	}
}

func TestStore_decideJoinRequest(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	ann := createTestRequest(t, s, 1, "ann")

	approved, err := s.DecideJoinRequest(ctx, ann.ID, joinrequest.StatusApproved, "admin")
	if err != nil {
		t.Fatalf("DecideJoinRequest: %v", err)
	}
	if approved.Status != joinrequest.StatusApproved || approved.DecidedBy != "admin" || approved.DecidedAt == nil {
		t.Errorf("approved = %+v", approved)
	}
	if _, err := s.DecideJoinRequest(ctx, ann.ID, joinrequest.StatusRejected, "admin"); !errors.Is(err, joinrequest.ErrDecided) {
		t.Errorf("second decision = %v, want ErrDecided", err)
	}
	if _, err := s.DecideJoinRequest(ctx, -1, joinrequest.StatusRejected, "admin"); !errors.Is(err, joinrequest.ErrNotFound) {
		t.Errorf("unknown decision = %v, want ErrNotFound", err)
	}
	if _, err := s.DecideJoinRequest(ctx, ann.ID, joinrequest.StatusPending, "admin"); err == nil {
		t.Error("deciding pending succeeded, want an error")
	}
	// Once decided, the user may ask again.
	again := joinrequest.Request{GroupPK: ann.GroupPK, GroupName: "staff", UserPK: 1, Username: "ann"}
	if _, err := s.CreateJoinRequest(ctx, again); err != nil {
		t.Errorf("CreateJoinRequest after a decision: %v", err)
	}
}

func TestStore_reopenJoinRequest(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	bob := createTestRequest(t, s, 2, "bob")

	if _, err := s.DecideJoinRequest(ctx, bob.ID, joinrequest.StatusApproved, "admin"); err != nil {
		t.Fatalf("DecideJoinRequest: %v", err)
	}
	if err := s.ReopenJoinRequest(ctx, bob.ID); err != nil {
		t.Fatalf("ReopenJoinRequest: %v", err)
	}
	reopened, err := s.GetJoinRequest(ctx, bob.ID)
	if err != nil {
		t.Fatalf("GetJoinRequest: %v", err)
	}
	if reopened.Status != joinrequest.StatusPending || reopened.DecidedAt != nil || reopened.DecidedBy != "" {
		t.Errorf("reopened = %+v, want pending without decision", reopened)
	}
}

func TestStore_withdrawJoinRequest(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	bob := createTestRequest(t, s, 2, "bob")

	if err := s.WithdrawJoinRequest(ctx, bob.ID, "ann"); !errors.Is(err, joinrequest.ErrNotFound) {
		t.Errorf("withdraw by another user = %v, want ErrNotFound", err)
	}
	if err := s.WithdrawJoinRequest(ctx, bob.ID, "bob"); err != nil {
		t.Fatalf("WithdrawJoinRequest: %v", err)
	}
	if _, err := s.GetJoinRequest(ctx, bob.ID); !errors.Is(err, joinrequest.ErrNotFound) {
		t.Errorf("GetJoinRequest after withdrawal = %v, want ErrNotFound", err)
	}
}

func requestIDs(list []joinrequest.Request) []int64 {
	ids := make([]int64, len(list))
	for i, jr := range list {
		ids[i] = jr.ID
	}
	return ids
}
