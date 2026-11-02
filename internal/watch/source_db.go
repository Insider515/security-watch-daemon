// Watching the database: what is only visible from the inside - mass
// registrations, role changes, money movements, settings edits.
package watch

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

// DBConfig - the database connection and the list of checks. The checks are
// defined as queries in the configuration; there are none in the code.
type DBConfig struct {
	Enabled bool   `json:"enabled"`
	DSN     string `json:"dsn"`
	// Which database: mysql (also mariadb) or postgres. Empty means mysql.
	Driver   string    `json:"driver"`
	Interval Duration  `json:"interval"`
	Checks   []DBCheck `json:"checks"`
	// Watching individual columns of individual tables (see source_db_columns.go).
	ColumnWatches []ColumnWatch `json:"column_watches"`
}

// DBCheck is one check. The query must return a single row with a single
// number; if the number exceeds the threshold, an event is emitted.
type DBCheck struct {
	Name      string   `json:"name"`
	Query     string   `json:"query"`
	Threshold float64  `json:"threshold"`
	Severity  Severity `json:"severity"`
	// The description goes into the event, so whoever reads the message does not
	// have to decipher the query.
	Description string `json:"description"`
}

// DBWatcher runs the checks on schedule.
type DBWatcher struct {
	cfg     DBConfig
	db      *sql.DB
	columns *ColumnWatcher
	emit    func(Event)
}

// NewDBWatcher opens the connection. The driver connects on the first query, so
// an unreachable database does not keep the service from starting.
func NewDBWatcher(cfg DBConfig, stateDir string, emit func(Event)) (*DBWatcher, error) {
	if !cfg.Enabled || cfg.DSN == "" {
		return &DBWatcher{cfg: cfg, emit: emit}, nil
	}
	driver := strings.ToLower(strings.TrimSpace(cfg.Driver))
	switch driver {
	case "", "mysql", "mariadb":
		driver = "mysql"
	case "postgres", "postgresql":
		driver = "postgres"
	default:
		return nil, fmt.Errorf("unknown database %q: mysql and postgres are supported", cfg.Driver)
	}
	db, err := sql.Open(driver, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("database connection: %w", err)
	}
	// One connection is enough for the watcher: it asks rarely and little.
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(time.Hour)
	watcher := &DBWatcher{cfg: cfg, db: db, emit: emit}
	watcher.columns = NewColumnWatcher(db, cfg.ColumnWatches, stateDir, driver, emit)
	return watcher, nil
}

// Scan runs every check.
func (d *DBWatcher) Scan() {
	if d.db == nil {
		return
	}
	if d.columns != nil {
		d.columns.Scan()
	}
	for _, check := range d.cfg.Checks {
		if strings.TrimSpace(check.Query) == "" {
			continue
		}
		// Read-only: a query that changes data has no place in a watcher - the
		// service must stay harmless even with a mistake in the configuration.
		if !isReadOnlyQuery(check.Query) {
			d.emit(Event{
				At: time.Now(), Source: "db", Kind: "check_rejected", Severity: SevWarn,
				Subject: check.Name, Count: 1,
				Details: map[string]string{"reason": "the query is not read-only"},
			})
			continue
		}

		var value sql.NullFloat64
		if err := d.db.QueryRow(check.Query).Scan(&value); err != nil {
			d.emit(Event{
				At: time.Now(), Source: "db", Kind: "check_failed", Severity: SevWarn,
				Subject: check.Name, Count: 1,
				Details: map[string]string{"error": err.Error()},
			})
			continue
		}
		if !value.Valid || value.Float64 <= check.Threshold {
			continue
		}
		severity := check.Severity
		if severity == "" {
			severity = SevWarn
		}
		d.emit(Event{
			At: time.Now(), Source: "db", Kind: "threshold_exceeded", Severity: severity,
			Subject: check.Name, Count: int(value.Float64),
			Details: map[string]string{
				"value":       strconv.FormatFloat(value.Float64, 'f', -1, 64),
				"threshold":   strconv.FormatFloat(check.Threshold, 'f', -1, 64),
				"description": check.Description,
			},
		})
	}
}

// Close closes the connection.
func (d *DBWatcher) Close() {
	if d.db != nil {
		_ = d.db.Close()
	}
}

// isReadOnlyQuery checks that the query only reads: it must start with SELECT or
// WITH, and words that change data are forbidden.
func isReadOnlyQuery(query string) bool {
	normalized := strings.ToLower(strings.TrimSpace(query))
	if !strings.HasPrefix(normalized, "select") && !strings.HasPrefix(normalized, "with") {
		return false
	}
	for _, forbidden := range []string{
		"insert ", "update ", "delete ", "drop ", "alter ", "create ",
		"truncate ", "grant ", "revoke ", "into outfile", "load_file",
	} {
		if strings.Contains(normalized, forbidden) {
			return false
		}
	}
	return true
}
