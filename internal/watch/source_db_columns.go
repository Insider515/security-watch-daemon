// Watching individual columns in individual tables: what changed, in which row,
// and from which value to which.
package watch

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// ColumnWatch is one watch: a table, a key and the columns. Columns that change
// rarely are a good fit: role, administrator flag, API key, settings. Columns
// that change often raise an alarm on every edit.
type ColumnWatch struct {
	Name     string   `json:"name"`
	Table    string   `json:"table"`
	Key      string   `json:"key"`
	Columns  []string `json:"columns"`
	Where    string   `json:"where"`
	Severity Severity `json:"severity"`
	// Row limit: the watcher must not pull millions of records.
	MaxRows int `json:"max_rows"`
}

// ColumnWatcher compares column values against the previous snapshot.
type ColumnWatcher struct {
	db        *sql.DB
	watches   []ColumnWatch
	statePath string
	emit      func(Event)
	// The quoting character for identifiers: a backtick for MySQL/MariaDB, a
	// double quote for PostgreSQL. Without quoting a column named like a
	// reserved word (key, order, group) makes the query fail.
	quote string
}

// NewColumnWatcher creates the column watcher. driver selects how identifiers
// are quoted.
func NewColumnWatcher(db *sql.DB, watches []ColumnWatch, stateDir, driver string, emit func(Event)) *ColumnWatcher {
	quote := "`"
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(driver)), "postgres") {
		quote = `"`
	}
	return &ColumnWatcher{
		db:        db,
		watches:   watches,
		statePath: filepath.Join(stateDir, "columns.state.json"),
		emit:      emit,
		quote:     quote,
	}
}

// quoted wraps an identifier in the quoting character of the database. The name
// is checked by validateIdentifiers beforehand, so it cannot contain the
// quoting character itself.
func (c *ColumnWatcher) quoted(name string) string {
	return c.quote + name + c.quote
}

// Scan checks every watch.
func (c *ColumnWatcher) Scan() {
	if c.db == nil || len(c.watches) == 0 {
		return
	}
	previous := c.loadState()
	current := map[string]map[string]string{}

	for _, watch := range c.watches {
		snapshot, err := c.snapshot(watch)
		if err != nil {
			c.emit(Event{
				At: time.Now(), Source: "db", Kind: "column_watch_failed", Severity: SevWarn,
				Subject: watch.Name, Count: 1,
				Details: map[string]string{"error": err.Error()},
			})
			continue
		}
		current[watch.Name] = snapshot

		before, had := previous[watch.Name]
		if !had {
			continue // the first pass only remembers
		}
		severity := watch.Severity
		if severity == "" {
			severity = SevAlert
		}
		for key, value := range snapshot {
			old, existed := before[key]
			switch {
			case !existed:
				c.emit(Event{
					At: time.Now(), Source: "db", Kind: "row_added", Severity: severity,
					Subject: fmt.Sprintf("%s %s=%s", watch.Table, watch.Key, key), Count: 1,
					Details: map[string]string{"watch": watch.Name, "values": value},
				})
			case old != value:
				c.emit(Event{
					At: time.Now(), Source: "db", Kind: "column_changed", Severity: severity,
					Subject: fmt.Sprintf("%s %s=%s", watch.Table, watch.Key, key), Count: 1,
					Details: map[string]string{"watch": watch.Name, "before": old, "after": value},
				})
			}
		}
		for key := range before {
			if _, still := snapshot[key]; !still {
				c.emit(Event{
					At: time.Now(), Source: "db", Kind: "row_removed", Severity: severity,
					Subject: fmt.Sprintf("%s %s=%s", watch.Table, watch.Key, key), Count: 1,
					Details: map[string]string{"watch": watch.Name},
				})
			}
		}
	}
	c.saveState(current)
}

// snapshot reads the requested columns of the table.
func (c *ColumnWatcher) snapshot(watch ColumnWatch) (map[string]string, error) {
	if err := validateIdentifiers(watch); err != nil {
		return nil, err
	}
	limit := watch.MaxRows
	if limit <= 0 {
		limit = 10000
	}
	quotedColumns := make([]string, 0, len(watch.Columns))
	for _, column := range watch.Columns {
		quotedColumns = append(quotedColumns, c.quoted(column))
	}
	columns := strings.Join(quotedColumns, ", ")
	// #nosec G201 -- table and column names cannot be passed as query values;
	// they are checked by validateIdentifiers above and quoted here, and no
	// values are inlined.
	query := fmt.Sprintf("SELECT %s, %s FROM %s", c.quoted(watch.Key), columns, c.quoted(watch.Table))
	if strings.TrimSpace(watch.Where) != "" {
		query += " WHERE " + watch.Where
	}
	query += fmt.Sprintf(" LIMIT %d", limit)

	rows, err := c.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]string{}
	holders := make([]any, len(watch.Columns)+1)
	values := make([]sql.NullString, len(watch.Columns)+1)
	for i := range values {
		holders[i] = &values[i]
	}
	for rows.Next() {
		if err := rows.Scan(holders...); err != nil {
			return nil, err
		}
		key := values[0].String
		parts := make([]string, 0, len(watch.Columns))
		for i, column := range watch.Columns {
			parts = append(parts, column+"="+values[i+1].String)
		}
		out[key] = strings.Join(parts, " ")
	}
	return out, rows.Err()
}

// validateIdentifiers checks the table and column names: letters, digits and
// underscore only. The names are inlined into the query as they are, because
// they cannot be passed as parameters.
func validateIdentifiers(watch ColumnWatch) error {
	check := func(name string) error {
		if name == "" {
			return fmt.Errorf("empty name")
		}
		for _, symbol := range name {
			isLetter := (symbol >= 'a' && symbol <= 'z') || (symbol >= 'A' && symbol <= 'Z')
			isDigit := symbol >= '0' && symbol <= '9'
			if !isLetter && !isDigit && symbol != '_' {
				return fmt.Errorf("disallowed name %q", name)
			}
		}
		return nil
	}
	if err := check(watch.Table); err != nil {
		return err
	}
	if err := check(watch.Key); err != nil {
		return err
	}
	if len(watch.Columns) == 0 {
		return fmt.Errorf("no columns specified")
	}
	for _, column := range watch.Columns {
		if err := check(column); err != nil {
			return err
		}
	}
	// The filter condition is written by the administrator, but it must not be
	// able to change data.
	lower := strings.ToLower(watch.Where)
	for _, forbidden := range []string{";", "--", "/*", "insert ", "update ", "delete ", "drop ", "into outfile"} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("disallowed filter condition")
		}
	}
	return nil
}

// loadState reads the previous snapshot.
func (c *ColumnWatcher) loadState() map[string]map[string]string {
	state := map[string]map[string]string{}
	loadJSONState(c.statePath, &state)
	return state
}

// saveState writes the snapshot.
func (c *ColumnWatcher) saveState(state map[string]map[string]string) {
	saveJSONState(c.statePath, state, 0o600)
}
