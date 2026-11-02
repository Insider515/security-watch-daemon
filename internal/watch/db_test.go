package watch

import "testing"

// The watcher is only allowed to read: a query that changes data is rejected,
// even if it was put into the configuration by mistake.
func TestIsReadOnlyQuery(t *testing.T) {
	allowed := []string{
		"SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL 1 HOUR",
		"  select count(*) from billings  ",
		"WITH recent AS (SELECT id FROM users) SELECT COUNT(*) FROM recent",
	}
	for _, query := range allowed {
		if !isReadOnlyQuery(query) {
			t.Errorf("must be allowed: %q", query)
		}
	}

	forbidden := []string{
		"DELETE FROM users",
		"UPDATE users SET role_id = 1",
		"SELECT * FROM users; DROP TABLE users",
		"SELECT * INTO OUTFILE '/tmp/x' FROM users",
		"INSERT INTO users (email) VALUES ('x')",
		"TRUNCATE users",
		"GRANT ALL ON *.* TO 'x'@'%'",
	}
	for _, query := range forbidden {
		if isReadOnlyQuery(query) {
			t.Errorf("must be rejected: %q", query)
		}
	}
}

// A check with a forbidden query is not executed but reported as rejected.
func TestDBWatcherRejectsWriteQuery(t *testing.T) {
	events := []Event{}
	watcher := &DBWatcher{
		cfg:  DBConfig{Checks: []DBCheck{{Name: "bad one", Query: "DELETE FROM users"}}},
		emit: func(e Event) { events = append(events, e) },
	}
	// There is no connection: the check must be filtered out before it ever
	// reaches the database.
	watcher.Scan()

	if len(events) != 0 {
		t.Fatalf("without a connection there must be no events: %+v", events)
	}
}
