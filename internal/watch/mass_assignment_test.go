package watch

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Injecting a privileged field into a request from an outsider (the technique
// known as mass assignment).
func TestMirrorDetectsMassAssignment(t *testing.T) {
	events := []Event{}
	server := NewMirrorServer(MirrorConfig{
		PrivilegedFields: []string{"role_id", "is_admin", "balance", "status_id"},
		AllowPaths:       []string{"/dashboard/", "/service/"},
	}, nil, func(e Event) { events = append(events, e) })

	request := httptest.NewRequest(http.MethodPost, "/auth/register",
		strings.NewReader(`{"email":"x@example.com","password":"Qwerty123!","role_id":1}`))
	request.Header.Set("X-Original-URI", "/auth/register")
	request.Header.Set("CF-Connecting-IP", "185.147.215.4")
	server.handle(httptest.NewRecorder(), request)

	if len(events) != 1 {
		t.Fatalf("expected one event, got %+v", events)
	}
	if events[0].Kind != "mass_assignment_attempt" || events[0].Severity != SevAlert {
		t.Errorf("unexpected event: %+v", events[0])
	}
	if events[0].Details["field"] != "role_id" || events[0].IP != "185.147.215.4" {
		t.Errorf("the field or the address is missing: %+v", events[0].Details)
	}
}

// The main false-alarm check: an administrator changing a status from the admin
// area is doing their job, and that must not raise an alarm.
func TestMirrorQuietOnAdminPaths(t *testing.T) {
	events := []Event{}
	server := NewMirrorServer(MirrorConfig{
		PrivilegedFields: []string{"role_id", "status_id", "balance"},
		AllowPaths:       []string{"/dashboard/", "/service/"},
	}, nil, func(e Event) { events = append(events, e) })

	for _, path := range []string{"/service/user/2648", "/dashboard/subscriptions", "/service/subscription/5392"} {
		request := httptest.NewRequest(http.MethodPut, path,
			strings.NewReader(`{"status_id":2,"balance":10,"role_id":2}`))
		request.Header.Set("X-Original-URI", path)
		server.handle(httptest.NewRecorder(), request)
	}

	if len(events) != 0 {
		t.Fatalf("admin paths must not raise alarms: %+v", events)
	}
}

// The field name is matched as a name, not as a substring: words that happen to
// contain it raise no alarm.
func TestMirrorNoFalseAlarmOnSimilarNames(t *testing.T) {
	events := []Event{}
	server := NewMirrorServer(MirrorConfig{
		PrivilegedFields: []string{"role_id"},
	}, nil, func(e Event) { events = append(events, e) })

	request := httptest.NewRequest(http.MethodPost, "/api/feedback",
		strings.NewReader(`{"message":"please describe your role_id_description in the ticket","email":"a@b.c"}`))
	server.handle(httptest.NewRecorder(), request)

	if len(events) != 0 {
		t.Fatalf("an accidental match inside a word must not raise an alarm: %+v", events)
	}
}

// A plain form body (not JSON) is checked as well.
func TestMirrorDetectsFormEncoded(t *testing.T) {
	events := []Event{}
	server := NewMirrorServer(MirrorConfig{
		PrivilegedFields: []string{"is_admin"},
	}, nil, func(e Event) { events = append(events, e) })

	request := httptest.NewRequest(http.MethodPost, "/auth/register",
		strings.NewReader("email=x%40example.com&password=Qwerty123!&is_admin=1"))
	server.handle(httptest.NewRecorder(), request)

	if len(events) != 1 || events[0].Details["field"] != "is_admin" {
		t.Fatalf("injection in a plain form was not noticed: %+v", events)
	}
}

// The table and column names of a watch are validated: the watcher must not
// itself become the hole through which a foreign query reaches the database.
func TestValidateIdentifiers(t *testing.T) {
	good := ColumnWatch{Table: "users", Key: "id", Columns: []string{"role_id", "is_banned"}, Where: "role_id = 1"}
	if err := validateIdentifiers(good); err != nil {
		t.Errorf("a sensible watch must be accepted: %v", err)
	}

	bad := []ColumnWatch{
		{Table: "users; DROP TABLE users", Key: "id", Columns: []string{"role_id"}},
		{Table: "users", Key: "id", Columns: []string{"role_id, (SELECT password FROM users)"}},
		{Table: "users", Key: "id", Columns: []string{"role_id"}, Where: "1=1; DELETE FROM users"},
		{Table: "users", Key: "id", Columns: []string{"role_id"}, Where: "1=1 -- comment"},
		{Table: "users", Key: "id", Columns: []string{}},
	}
	for _, watch := range bad {
		if err := validateIdentifiers(watch); err == nil {
			t.Errorf("must be rejected: %+v", watch)
		}
	}
}
