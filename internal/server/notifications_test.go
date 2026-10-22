package server_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"authentikManager/internal/access"
	"authentikManager/internal/authentik"
	"authentikManager/internal/joinrequest"
	"authentikManager/internal/notification"
	"authentikManager/internal/server"
)

// memoryNotifications is an in-memory notification.Store.
type memoryNotifications struct {
	mu            sync.Mutex
	notifications []notification.Notification
	prefs         map[int]notification.Preferences
}

func (m *memoryNotifications) CreateNotification(_ context.Context, n notification.Notification) (notification.Notification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n.ID = int64(len(m.notifications) + 1)
	m.notifications = append(m.notifications, n)
	return n, nil
}

// find returns the index of the notification with id of userPK, or -1.
func (m *memoryNotifications) find(userPK int, id int64) int {
	return slices.IndexFunc(m.notifications, func(n notification.Notification) bool {
		return n.ID == id && n.UserPK == userPK
	})
}

func (m *memoryNotifications) ListNotifications(_ context.Context, userPK int, q notification.Query) ([]notification.Notification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []notification.Notification{}
	for _, n := range slices.Backward(m.notifications) {
		if n.UserPK == userPK && (q.Before == 0 || n.ID < q.Before) && len(out) < q.Limit {
			out = append(out, n)
		}
	}
	return out, nil
}

func (m *memoryNotifications) CountUnreadNotifications(_ context.Context, userPK int) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, n := range m.notifications {
		if n.UserPK == userPK && n.ReadAt == nil {
			count++
		}
	}
	return count, nil
}

func (m *memoryNotifications) MarkNotificationRead(_ context.Context, userPK int, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.find(userPK, id)
	if i < 0 {
		return notification.ErrNotFound
	}
	now := time.Now()
	m.notifications[i].ReadAt = &now
	return nil
}

func (m *memoryNotifications) MarkAllNotificationsRead(_ context.Context, userPK int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.notifications {
		if m.notifications[i].UserPK == userPK {
			now := time.Now()
			m.notifications[i].ReadAt = &now
		}
	}
	return nil
}

func (m *memoryNotifications) DeleteNotification(_ context.Context, userPK int, id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	i := m.find(userPK, id)
	if i < 0 {
		return notification.ErrNotFound
	}
	m.notifications = slices.Delete(m.notifications, i, i+1)
	return nil
}

func (m *memoryNotifications) DeleteAllNotifications(_ context.Context, userPK int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifications = slices.DeleteFunc(m.notifications, func(n notification.Notification) bool { return n.UserPK == userPK })
	return nil
}

func (m *memoryNotifications) NotificationPreferences(_ context.Context, userPK int) (notification.Preferences, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.prefs[userPK], nil
}

func (m *memoryNotifications) PutNotificationPreferences(_ context.Context, userPK int, p notification.Preferences) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.prefs == nil {
		m.prefs = map[int]notification.Preferences{}
	}
	m.prefs[userPK] = p
	return nil
}

// sent returns the headers of the notifications of userPK, oldest first.
func (m *memoryNotifications) sent(userPK int) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []string{}
	for _, n := range m.notifications {
		if n.UserPK == userPK {
			out = append(out, n.Header)
		}
	}
	return out
}

// last returns the newest notification, failing the test when there is none.
func (m *memoryNotifications) last(t *testing.T) notification.Notification {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.notifications) == 0 {
		t.Fatal("no notification sent")
	}
	return m.notifications[len(m.notifications)-1]
}

// recordingReceiver records the addresses it delivers to, as an email receiver would.
type recordingReceiver struct {
	mu        sync.Mutex
	delivered []string
}

func (*recordingReceiver) Name() notification.Channel { return "email" }

func (*recordingReceiver) Label() string { return "Email" }

func (r *recordingReceiver) Receive(_ context.Context, rcpt notification.Recipient, n notification.Notification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.delivered = append(r.delivered, rcpt.Email+": "+n.Header)
	return nil
}

func (r *recordingReceiver) deliveries() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.delivered)
}

// notifyEnv is a server with notifications recorded in memory.
type notifyEnv struct {
	srv   *server.Server
	notes *memoryNotifications
	email *recordingReceiver
	// stop waits until the queued deliveries to email are done.
	stop func()
}

// newNotifier returns a notifier storing in a new memoryNotifications and
// delivering to a recordingReceiver, running until the test ends.
func newNotifier(t *testing.T) (*notification.Notifier, *memoryNotifications, *recordingReceiver, func()) {
	t.Helper()
	notes := &memoryNotifications{}
	email := &recordingReceiver{}
	n, err := notification.NewNotifier(notes, slog.New(slog.DiscardHandler), email)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Go(func() { n.Run(ctx) })
	stop := func() {
		cancel()
		wg.Wait()
	}
	t.Cleanup(stop)
	return n, notes, email, stop
}

// newNotifyEnv returns a server for the operator "admin" in groups with the
// test rules, completed by complete, and notifications.
func newNotifyEnv(t *testing.T, users server.UserService, complete func(*server.Deps), groups ...string) *notifyEnv {
	t.Helper()
	rules := newFakeRules()
	policy, err := access.NewPolicy([]string{"admins"}, rules)
	if err != nil {
		t.Fatal(err)
	}
	n, notes, email, stop := newNotifier(t)
	d := server.Deps{
		Users:         users,
		Auth:          fakeAuth{groups: groups},
		Policy:        policy,
		Rules:         rules,
		Audit:         &fakeAudit{},
		Logger:        slog.New(slog.DiscardHandler),
		Notifications: n,
	}
	if complete != nil {
		complete(&d)
	}
	return &notifyEnv{srv: server.New(d), notes: notes, email: email, stop: stop}
}

// ownAccountPK is the primary key of the signed-in test operator's account in ownAccountUsers.
const ownAccountPK = 7

func TestNotifications_disabled(t *testing.T) {
	t.Parallel()
	rec := do(t, newServer(t, ownAccountUsers()), http.MethodGet, "/api/notifications", "")
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status = %d, want 501", rec.Code)
	}
}

func TestNotifications_requireInternalUser(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{listed: []authentik.User{}}
	env := newNotifyEnv(t, users, nil)
	rec := do(t, env.srv, http.MethodGet, "/api/notifications", "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestNotifications_inbox(t *testing.T) {
	t.Parallel()
	env := newNotifyEnv(t, ownAccountUsers(), nil)
	ctx := t.Context()
	for _, header := range []string{"first", "second", "third"} {
		if _, err := env.notes.CreateNotification(ctx, notification.Notification{
			UserPK: ownAccountPK, Category: notification.CategoryProfile, Header: header, Message: "m",
		}); err != nil {
			t.Fatal(err)
		}
	}
	other, err := env.notes.CreateNotification(ctx, notification.Notification{
		UserPK: 99, Category: notification.CategoryProfile, Header: "other", Message: "m",
	})
	if err != nil {
		t.Fatal(err)
	}

	var page struct {
		Notifications []notification.Notification `json:"notifications"`
		Next          int64                       `json:"next"`
		Unread        int                         `json:"unread"`
	}
	rec := do(t, env.srv, http.MethodGet, "/api/notifications?limit=2", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d %s", rec.Code, rec.Body)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Notifications) != 2 || page.Notifications[0].Header != "third" || page.Next != page.Notifications[1].ID || page.Unread != 3 {
		t.Errorf("page = %+v, want the two newest, a next page and 3 unread", page)
	}

	steps := []struct {
		name           string
		method, target string
		expectedStatus int
		expectedUnread string
	}{
		{name: "read another user's", method: http.MethodPost, target: "/api/notifications/" + strconv.FormatInt(other.ID, 10) + "/read", expectedStatus: http.StatusNotFound},
		{name: "invalid id", method: http.MethodPost, target: "/api/notifications/x/read", expectedStatus: http.StatusBadRequest},
		{name: "read one", method: http.MethodPost, target: "/api/notifications/1/read", expectedStatus: http.StatusNoContent, expectedUnread: `{"unread":2}`},
		{name: "delete another user's", method: http.MethodDelete, target: "/api/notifications/" + strconv.FormatInt(other.ID, 10), expectedStatus: http.StatusNotFound},
		{name: "delete one", method: http.MethodDelete, target: "/api/notifications/2", expectedStatus: http.StatusNoContent, expectedUnread: `{"unread":1}`},
		{name: "read all", method: http.MethodPost, target: "/api/notifications/read-all", expectedStatus: http.StatusNoContent, expectedUnread: `{"unread":0}`},
		{name: "delete all", method: http.MethodDelete, target: "/api/notifications", expectedStatus: http.StatusNoContent, expectedUnread: `{"unread":0}`},
	}
	for _, step := range steps {
		rec := do(t, env.srv, step.method, step.target, "")
		if rec.Code != step.expectedStatus {
			t.Fatalf("%s = %d %s, want %d", step.name, rec.Code, rec.Body, step.expectedStatus)
		}
		if step.expectedUnread != "" {
			checkUnread(t, env.srv, step.expectedUnread)
		}
	}
	if got := env.notes.sent(ownAccountPK); len(got) != 0 {
		t.Errorf("after delete all = %v, want none", got)
	}
	if got := env.notes.sent(99); len(got) != 1 {
		t.Errorf("other user's notifications = %v, want them kept", got)
	}
}

// checkUnread checks the response of the unread count.
func checkUnread(t *testing.T, srv http.Handler, expected string) {
	t.Helper()
	if got := strings.TrimSpace(do(t, srv, http.MethodGet, "/api/notifications/unread-count", "").Body.String()); got != expected {
		t.Errorf("unread = %s, want %s", got, expected)
	}
}

func TestNotifications_preferences(t *testing.T) {
	t.Parallel()
	env := newNotifyEnv(t, ownAccountUsers(), nil)

	rec := do(t, env.srv, http.MethodGet, "/api/notifications/preferences", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get = %d %s", rec.Code, rec.Body)
	}
	for _, want := range []string{`{"name":"in_app","label":"In-app"}`, `{"name":"email","label":"Email"}`, `"name":"settings","label":"Notification settings","mandatory":true`} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("get = %s, want %s", rec.Body, want)
		}
	}

	rec = do(t, env.srv, http.MethodPut, "/api/notifications/preferences", `{"preferences":{"profile":{"email":false}}}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"profile":{"email":false,"in_app":true}`) {
		t.Fatalf("put = %d %s", rec.Code, rec.Body)
	}
	env.stop()
	if got := env.notes.sent(ownAccountPK); !slices.Equal(got, []string{"Notification settings changed"}) {
		t.Errorf("notifications = %v, want the settings change", got)
	}
	if got := env.email.deliveries(); !slices.Equal(got, []string{"admin@example.com: Notification settings changed"}) {
		t.Errorf("emails = %v, want the settings change", got)
	}

	rec = do(t, env.srv, http.MethodPut, "/api/notifications/preferences", `{"preferences":{"profile":{"sms":false}}}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "unknown channel") {
		t.Errorf("invalid put = %d %s, want 400", rec.Code, rec.Body)
	}
}

// updatingUsers is a fakeUsers whose UpdateUser applies the update to its
// user, as authentik returns the updated user.
type updatingUsers struct {
	*fakeUsers
}

func (u updatingUsers) UpdateUser(ctx context.Context, id int, req authentik.UpdateUserRequest) (*authentik.User, error) {
	if _, err := u.fakeUsers.UpdateUser(ctx, id, req); err != nil {
		return nil, err
	}
	updated := *u.user
	updated.PK = id
	if req.Username != nil {
		updated.Username = *req.Username
	}
	if req.Name != nil {
		updated.Name = *req.Name
	}
	if req.Email != nil {
		updated.Email = *req.Email
	}
	if req.IsActive != nil {
		updated.IsActive = *req.IsActive
	}
	if req.Path != nil {
		updated.Path = *req.Path
	}
	if req.Attributes != nil {
		updated.Attributes = req.Attributes
	}
	return &updated, nil
}

func TestNotifications_profileUpdate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		target         *authentik.User
		body           string
		expected       []string
		expectedEmails []string
		expectMessage  []string
	}{
		{
			name:           "name and email",
			target:         member("staff"),
			body:           `{"name":"Ann Smith","email":"new@example.com"}`,
			expected:       []string{"Your profile was updated"},
			expectedEmails: []string{"new@example.com: Your profile was updated", "target@example.com: Your profile was updated"},
			expectMessage:  []string{"changed by admin", "Name: (none) → Ann Smith", "Email address: target@example.com → new@example.com"},
		},
		{
			name:     "deactivated",
			target:   &authentik.User{Username: "target", Type: authentik.UserTypeInternal, IsActive: true},
			body:     `{"is_active":false}`,
			expected: []string{"Your profile was updated"}, expectMessage: []string{"Account: deactivated"},
		},
		{name: "hidden only", target: member("staff"), body: `{"hidden":true}`, expected: []string{}},
		{name: "unchanged", target: member("staff"), body: `{"email":"target@example.com"}`, expected: []string{}},
		{
			name:     "service account",
			target:   &authentik.User{Username: "svc", Type: authentik.UserTypeServiceAccount},
			body:     `{"name":"Robot"}`,
			expected: []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			users := updatingUsers{&fakeUsers{user: tt.target}}
			env := newNotifyEnv(t, users, nil, "admins")
			path := "/api/users/5"
			if tt.target.Type == authentik.UserTypeServiceAccount {
				path = "/api/service-accounts/5"
			}
			if rec := do(t, env.srv, http.MethodPatch, path, tt.body); rec.Code != http.StatusOK {
				t.Fatalf("update = %d %s", rec.Code, rec.Body)
			}
			env.stop()
			if got := env.notes.sent(5); !slices.Equal(got, tt.expected) {
				t.Fatalf("notifications = %v, want %v", got, tt.expected)
			}
			for _, want := range tt.expectMessage {
				if msg := env.notes.last(t).Message; !strings.Contains(msg, want) {
					t.Errorf("message = %q, want %q", msg, want)
				}
			}
			if tt.expectedEmails != nil {
				got := env.email.deliveries()
				slices.Sort(got)
				if !slices.Equal(got, tt.expectedEmails) {
					t.Errorf("emails = %v, want %v", got, tt.expectedEmails)
				}
			}
		})
	}
}

func TestNotifications_setGroups(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{user: withPrimary(member("staff", "students"), "staff"), groups: testGroups()}
	env := newNotifyEnv(t, users, nil, "admins")
	rec := do(t, env.srv, http.MethodPut, "/api/users/5/groups", `{"groups":["staff","teachers"],"primary_group":"teachers"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("set groups = %d %s", rec.Code, rec.Body)
	}
	if got := env.notes.sent(5); !slices.Equal(got, []string{"Your groups were changed"}) {
		t.Fatalf("notifications = %v, want one about the groups", got)
	}
	msg := env.notes.last(t).Message
	for _, want := range []string{`Added to the group "teachers"`, "Primary group: staff → teachers", `Removed from the group "students"`} {
		if !strings.Contains(msg, want) {
			t.Errorf("message = %q, want %q", msg, want)
		}
	}
}

func TestNotifications_groupMembers(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{user: member("staff"), groups: testGroups()}
	env := newNotifyEnv(t, users, nil, "admins")
	if rec := do(t, env.srv, http.MethodPut, "/api/groups/g2/members/5", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("add member = %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, env.srv, http.MethodDelete, "/api/groups/g2/members/5", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("remove member = %d %s", rec.Code, rec.Body)
	}
	if got := env.notes.sent(5); !slices.Equal(got, []string{"Your groups were changed", "Your groups were changed"}) {
		t.Errorf("notifications = %v, want one per change", got)
	}
}

func TestNotifications_joinDecision(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		action   string
		expected string
	}{
		{name: "granted", action: "approve", expected: "Join request granted"},
		{name: "denied", action: "reject", expected: "Join request denied"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			jrs := &fakeJoinRequests{requests: []joinrequest.Request{pending(1, "g1", "staff", "ann")}}
			users := &fakeUsers{groups: joinTestGroups(), user: &authentik.User{Username: "ann", Type: authentik.UserTypeInternal}}
			env := newNotifyEnv(t, users, func(d *server.Deps) { d.JoinRequests = jrs }, "helpdesk")
			if rec := do(t, env.srv, http.MethodPost, "/api/join-requests/1/"+tt.action, ""); rec.Code != http.StatusOK {
				t.Fatalf("%s = %d %s", tt.action, rec.Code, rec.Body)
			}
			if got := env.notes.sent(5); !slices.Equal(got, []string{tt.expected}) {
				t.Fatalf("notifications = %v, want %q", got, tt.expected)
			}
			if msg := env.notes.last(t).Message; !strings.Contains(msg, `"staff"`) || !strings.Contains(msg, "by admin") {
				t.Errorf("message = %q, want the group and the decider", msg)
			}
		})
	}
}

func TestNotifications_certificateIssued(t *testing.T) {
	t.Parallel()
	env := newCertServer(t, ownAccountUsers())
	issued := issue(t, env, `{"format":"pem"}`)
	if got := env.notes.sent(ownAccountPK); !slices.Equal(got, []string{"Certificate issued"}) {
		t.Fatalf("notifications = %v, want the issued certificate", got)
	}
	msg := env.notes.last(t).Message
	if !strings.Contains(msg, issued.Certificate.Serial) || !strings.Contains(msg, "by you") {
		t.Errorf("message = %q, want the serial, issued by the user", msg)
	}
}

func TestNotifications_certificateRevoked(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		target        string
		groups        []string
		expectMessage string
	}{
		{name: "by operator", target: "/api/users/5/certificates/ab/revoke", groups: []string{"admins"}, expectMessage: "revoked by admin"},
		{name: "by access administrator", target: "/api/certificates/ab/revoke", groups: []string{"admins"}, expectMessage: "revoked by admin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, staffUser("staff"), tt.groups...)
			addCertificates(env)
			if rec := do(t, env.srv, http.MethodPost, tt.target, ""); rec.Code != http.StatusOK {
				t.Fatalf("revoke = %d %s", rec.Code, rec.Body)
			}
			if got := env.notes.sent(5); !slices.Equal(got, []string{"Certificate revoked"}) {
				t.Fatalf("notifications = %v, want the revoked certificate", got)
			}
			if msg := env.notes.last(t).Message; !strings.Contains(msg, tt.expectMessage) || !strings.Contains(msg, "ab") {
				t.Errorf("message = %q, want %q and the serial", msg, tt.expectMessage)
			}
		})
	}
}

func TestNotifications_certificatesRevokedWithUser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		method   string
		body     string
		expected []string
	}{
		{name: "deactivated", method: http.MethodPatch, body: `{"is_active":false}`, expected: []string{"Certificate revoked"}},
		{name: "deleted", method: http.MethodDelete, expected: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			env := newCertServer(t, staffUser("staff"), "admins")
			addCertificates(env)
			if rec := do(t, env.srv, tt.method, "/api/users/5", tt.body); rec.Code >= http.StatusBadRequest {
				t.Fatalf("status = %d %s", rec.Code, rec.Body)
			}
			got := slices.DeleteFunc(env.notes.sent(5), func(h string) bool { return !strings.HasPrefix(h, "Certificate") })
			if !slices.Equal(got, tt.expected) {
				t.Fatalf("certificate notifications = %v, want %v", got, tt.expected)
			}
			if len(got) > 0 {
				if msg := env.notes.last(t).Message; !strings.Contains(msg, "user deactivated") {
					t.Errorf("message = %q, want the reason", msg)
				}
			}
		})
	}
}
