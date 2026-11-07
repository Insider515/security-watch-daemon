// Criticality grades: how bad an event is for whoever reads the messages.
//
// Severity says how sure a watcher is that something happened - info, warn,
// alert. It does not say how bad it is. A changed file is "alert" whether it was
// a deploy or a break-in, and at thirty thousand such events a day the messages
// stop being read at all. The grade answers the other question: what this means
// for the server. The bot filters by the grade, not by severity.
package watch

import "strings"

// Grade - the criticality of an event.
type Grade string

const (
	// GradeNotice - the service's own doings and ordinary life: watching
	// started, an address was blocked on request, the digest went out.
	GradeNotice Grade = "notice"
	// GradeMinor - reconnaissance and brute force: visible from outside,
	// stopped by itself, nothing changed inside.
	GradeMinor Grade = "minor"
	// GradeMajor - a deliberate attempt at the application: an injection, a
	// privileged field in a request, an address that crossed the score.
	GradeMajor Grade = "major"
	// GradeCritical - a sign that someone is already inside: a trap went off, a
	// bait key was used, application code changed, a new service is listening.
	GradeCritical Grade = "critical"
	// GradeSystem - the server's own trouble with nobody behind it: memory ran
	// out, the disk is full, a watcher itself failed. Kept apart from the scale
	// above because it is a different kind of trouble, not a lesser one.
	GradeSystem Grade = "system"
)

// gradeRank orders the grades so that a minimum can be compared against. System
// trouble is outside the order: it is switched on and off on its own.
func gradeRank(g Grade) int {
	switch g {
	case GradeCritical:
		return 4
	case GradeMajor:
		return 3
	case GradeMinor:
		return 2
	case GradeNotice:
		return 1
	default:
		return 0
	}
}

// GradeNames are the grades as the operator names them, for messages and for
// checking the configuration.
var GradeNames = map[Grade]string{
	GradeNotice:   "warning",
	GradeMinor:    "minor",
	GradeMajor:    "significant",
	GradeCritical: "critical",
	GradeSystem:   "system",
}

// kindGrades is the grade of each event kind the service produces.
//
// The division is by what the event means for the server, not by how loud it
// is. Everything that proves a presence inside is critical; a deliberate but
// repelled attempt is significant; looking around from outside is minor; our
// own actions are warnings; a failure of the service or of the machine itself
// is system trouble.
var kindGrades = map[string]Grade{
	// Someone is inside, or one step away from it.
	"trap_hit":          GradeCritical,
	"canary_used":       GradeCritical,
	"canary_file_read":  GradeCritical,
	"custom_backdoor":   GradeCritical,
	"deleted_binary":    GradeCritical,
	"process_from_temp": GradeCritical,
	"own_file_changed":  GradeCritical,
	"own_file_missing":  GradeCritical,
	"listening_port":    GradeCritical,
	"ssh_login":         GradeCritical,
	"sudo":              GradeCritical,
	"column_changed":    GradeCritical,
	"row_added":         GradeCritical,
	"row_removed":       GradeCritical,
	// A file of the application changed. The scheduled scan and the realtime
	// watcher name it differently, so both spellings are listed.
	"file_changed":          GradeCritical,
	"file_changed_realtime": GradeCritical,

	// A deliberate attempt at the application. Repelled or unconfirmed, but
	// aimed at us on purpose.
	"mass_assignment_attempt": GradeMajor,
	"sqli_union":              GradeMajor,
	"sqli_stacked":            GradeMajor,
	"sqli_file":               GradeMajor,
	"sqli_schema":             GradeMajor,
	"sqli_sleep":              GradeMajor,
	"sqli_tautology":          GradeMajor,
	"sqli_comment":            GradeMajor,
	"shell_injection":         GradeMajor,
	"template_injection":      GradeMajor,
	"path_traversal":          GradeMajor,
	"custom_pattern":          GradeMajor,
	"custom_signature":        GradeMajor,
	"actor_threshold":         GradeMajor,
	"threshold_exceeded":      GradeMajor,
	"outbound_connection":     GradeMajor,
	"probe":                   GradeMajor,

	// Looking around from outside.
	"path_scan":                  GradeMinor,
	"suspicious_path":            GradeMinor,
	"honeypot_hit":               GradeMinor,
	"ssh_bruteforce":             GradeMinor,
	"file_added":                 GradeMinor,
	"file_added_realtime":        GradeMinor,
	"file_removed":               GradeMinor,
	"file_removed_realtime":      GradeMinor,
	"file_mode_changed":          GradeMinor,
	"file_mode_changed_realtime": GradeMinor,
	"port_gone":                  GradeMinor,

	// Our own doings and ordinary life.
	"resource_recovered":  GradeNotice,
	"watch_started":       GradeNotice,
	"watch_stopped":       GradeNotice,
	"heartbeat":           GradeNotice,
	"digest":              GradeNotice,
	"archive_done":        GradeNotice,
	"ip_blocked":          GradeNotice,
	"ip_unblocked":        GradeNotice,
	"ip_auto_blocked":     GradeNotice,
	"auto_block_proposed": GradeNotice,
	"action_done":         GradeNotice,

	// The service or the machine is in trouble, with nobody behind it.
	"db_error":            GradeSystem,
	"scan_error":          GradeSystem,
	"check_failed":        GradeSystem,
	"check_rejected":      GradeSystem,
	"column_watch_failed": GradeSystem,
	"auto_block_failed":   GradeSystem,
	"archive_failed":      GradeSystem,
	"memory_low":          GradeSystem,
	"disk_low":            GradeSystem,
	"inodes_low":          GradeSystem,
	"load_high":           GradeSystem,
	"oom_kill":            GradeSystem,
	"service_failed":      GradeSystem,
}

// GradeOf works out the grade of an event.
//
// The configuration may override the grade of any kind: what counts as serious
// differs from server to server, and the operator should not have to rebuild the
// service to say so.
func GradeOf(event Event, overrides map[string]Grade) Grade {
	if grade, has := overrides[event.Kind]; has && grade != "" {
		return grade
	}
	if grade, has := kindGrades[event.Kind]; has {
		return grade
	}
	// The learning watcher builds its kind names at runtime: first_time_country,
	// first_time_agent and the rest of that family.
	if strings.HasPrefix(event.Kind, "first_time_") {
		return GradeMinor
	}
	// An unknown kind is treated as reconnaissance when an address is behind it
	// and as system trouble when there is none: an event with no address comes
	// from our own machinery, not from outside.
	if event.IP == "" {
		return GradeSystem
	}
	return GradeMinor
}

// gradeOrDerive returns the grade the service worked out, or works it out from
// the kind when the event carries none.
//
// An event always leaves the service with its grade filled in; one can be
// missing only if it was written to the on-disk queue by an earlier version and
// read back after an update. Having this in one place keeps the sink from
// judging the same event by two different rules.
func gradeOrDerive(event Event) Grade {
	if event.Grade != "" {
		return event.Grade
	}
	return GradeOf(event, nil)
}

// EscalateByScore raises the grade when a lot has piled up from one address.
//
// A single repelled scan means nothing; the same address at a score of fifty is
// working on us on purpose, and the grade has to say that even though each
// separate event stays minor.
func EscalateByScore(grade Grade, score, threshold int) Grade {
	if threshold <= 0 || score < threshold || grade == GradeSystem {
		return grade
	}
	switch grade {
	case GradeNotice, GradeMinor:
		return GradeMajor
	case GradeMajor:
		// Twice the threshold from one address is no longer an attempt but a
		// break-in in progress.
		if score >= threshold*2 {
			return GradeCritical
		}
	}
	return grade
}
