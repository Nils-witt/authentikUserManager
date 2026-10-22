package store_test

import (
	"errors"
	"testing"
	"time"

	"authentikManager/internal/apikey"
	"authentikManager/internal/store"
)

// createTestAPIKey stores a new API key of the user with userPK and returns it with the key.
func createTestAPIKey(t *testing.T, s *store.Store, userPK int, expiresAt *time.Time) (apikey.Key, string) {
	t.Helper()
	key, start, hash := apikey.New()
	k, err := s.CreateAPIKey(t.Context(), apikey.Key{
		UserPK:      userPK,
		Username:    "svc",
		Description: "deploy",
		Start:       start,
		CreatedBy:   "ann",
		ExpiresAt:   expiresAt,
	}, hash)
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	return k, key
}

func TestStore_createAPIKey(t *testing.T) {
	s := openTestStore(t)

	k, key := createTestAPIKey(t, s, uniqueUserPK(), nil)
	if k.ID == 0 || k.CreatedAt.IsZero() || k.LastUsedAt != nil || k.Start != key[:len(k.Start)] {
		t.Errorf("created = %+v, want an unused key with ID, creation time and start of %q", k, key)
	}
}

func TestStore_listAPIKeys(t *testing.T) {
	s := openTestStore(t)
	userPK := uniqueUserPK()

	first, _ := createTestAPIKey(t, s, userPK, nil)
	second, _ := createTestAPIKey(t, s, userPK, nil)
	createTestAPIKey(t, s, userPK+1, nil)

	list, err := s.ListAPIKeys(t.Context(), userPK)
	if err != nil {
		t.Fatalf("ListAPIKeys: %v", err)
	}
	if len(list) != 2 || list[0].ID != second.ID || list[1].ID != first.ID {
		t.Errorf("ListAPIKeys = %+v, want keys %d and %d, newest first", list, second.ID, first.ID)
	}
}

func TestStore_deleteAPIKey(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	userPK := uniqueUserPK()
	k, _ := createTestAPIKey(t, s, userPK, nil)

	if _, err := s.DeleteAPIKey(ctx, userPK+1, k.ID); !errors.Is(err, apikey.ErrNotFound) {
		t.Errorf("DeleteAPIKey of another user: err = %v, want ErrNotFound", err)
	}
	deleted, err := s.DeleteAPIKey(ctx, userPK, k.ID)
	if err != nil || deleted.ID != k.ID {
		t.Fatalf("DeleteAPIKey = %+v, %v, want key %d", deleted, err, k.ID)
	}
	if _, err := s.DeleteAPIKey(ctx, userPK, k.ID); !errors.Is(err, apikey.ErrNotFound) {
		t.Errorf("DeleteAPIKey again: err = %v, want ErrNotFound", err)
	}
}

func TestStore_deleteUserAPIKeys(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	userPK := uniqueUserPK()
	createTestAPIKey(t, s, userPK, nil)
	createTestAPIKey(t, s, userPK, nil)
	createTestAPIKey(t, s, userPK+1, nil)

	n, err := s.DeleteUserAPIKeys(ctx, userPK)
	if err != nil || n != 2 {
		t.Fatalf("DeleteUserAPIKeys = %d, %v, want 2", n, err)
	}
	list, err := s.ListAPIKeys(ctx, userPK+1)
	if err != nil || len(list) != 1 {
		t.Errorf("keys of another user = %+v, %v, want 1 left", list, err)
	}
}

func TestStore_authenticateAPIKey(t *testing.T) {
	s := openTestStore(t)
	ctx := t.Context()
	now := time.Now().Truncate(time.Microsecond)
	userPK := uniqueUserPK()

	k, key := createTestAPIKey(t, s, userPK, new(now.Add(time.Hour)))
	got, err := s.AuthenticateAPIKey(ctx, apikey.Hash(key), now)
	if err != nil {
		t.Fatalf("AuthenticateAPIKey: %v", err)
	}
	if got.ID != k.ID || got.LastUsedAt == nil || !got.LastUsedAt.Equal(now) {
		t.Errorf("AuthenticateAPIKey = %+v, want key %d last used at %v", got, k.ID, now)
	}

	if _, err := s.AuthenticateAPIKey(ctx, apikey.Hash(key), now.Add(time.Hour)); !errors.Is(err, apikey.ErrNotFound) {
		t.Errorf("AuthenticateAPIKey of an expired key: err = %v, want ErrNotFound", err)
	}
	if _, err := s.AuthenticateAPIKey(ctx, apikey.Hash(key+"x"), now); !errors.Is(err, apikey.ErrNotFound) {
		t.Errorf("AuthenticateAPIKey of an unknown key: err = %v, want ErrNotFound", err)
	}
}
