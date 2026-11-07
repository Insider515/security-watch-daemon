# security-watch - specification

Document version: 2026-11-02 (second revision, after the defect fixes). It describes what is in the code and covered by
tests; the limitations are listed at the end. The detailed description of the
settings and capabilities is in [README.md](README.md).

## 1. Purpose

A server monitoring service. It reads logs, files, ports, processes and the
database, finds signs of an attack and reports them off the host. By default it
changes nothing and blocks nobody.

There is no tie to any application: everything application-specific is set in
the configuration. It installs on any Linux server.

## 2. Composition

| | |
|---|---|
| Language | Go 1.25, 6753 lines of production code and 3548 lines of tests, 141 checks (plus 2 that run on Linux only), 76.7% coverage |
| Layout | `cmd/security-watch` - command-line parsing, `internal/watch` - all the work |
| Dependencies | the `go-sql-driver/mysql` and `lib/pq` drivers; everything else is the standard library |
| Delivery | a single executable of 7.8 MB (`-ldflags='-s -w'`), a systemd service, `install.sh` |
| Resource use | 14.3-14.6 MB of memory; one pass over files, ports, processes and the database takes 2.4 s |

## 3. Observation sources

| Source | Setting | What it finds |
|---|---|---|
| Web server log | `access_log` | path scanning (404 spike), access guessing (401/403), request floods, 5xx spikes, requests to foreign paths, trap paths, injection attempts in the request |
| Auth log | `auth_log` | SSH password guessing, successful login (an alarm from an unknown address), sudo |
| Application log | `app_log` | database messages about a failed query parse, custom signatures, canary tokens |
| auditd log | `audit` | program execution with the full command line, working directory, user and parent (the lines of one event are collected by their shared id), **reading** of a canary file |
| Files | `files`, `files_realtime` | replacement (SHA-256), creation, deletion, permission changes; scheduled scanning plus a subscription to kernel events (inotify, reported within 0.3 s) |
| Ports | `ports` | a listening port appearing outside the expected list |
| Processes | `processes` | a start from a temporary directory, a program with a deleted file, an outbound connection to an undeclared port |
| Database | `db` | threshold checks with arbitrary queries; column watches on tables (what changed, from which value to which) |
| nginx mirror | `mirror` | injection in a POST body and in headers, privileged field injection, canary tokens |
| Trap | `trap` | a request to an address nothing links to; a bait token issued per visitor |
| The service itself | `self_guard` | replacement of its own files, start, shutdown, heartbeat |

### Aggregation and learning

| | Setting | What it does |
|---|---|---|
| Resources | `resources` | the machine's own trouble: memory, free space and free file slots on the mount points, load per processor. The only source with nobody on the other side, so its events get the `system` grade and are switched on apart from the reports about attacks |
| Actors | `actors` | groups events by whoever caused them: a score from per-kind weights, one report when the threshold is crossed instead of a stream, a periodic "who did what" digest |
| Learning | `baseline` | spends the configured number of days silently remembering what is normal (countries, clients, fingerprints), then reports a value that was not there before |

## 4. Events

One record shape: time, source, kind, severity (`info`/`warn`/`alert`),
**criticality grade**, address, subject, repeat count, details, **the sequence
number and the hash of the previous event**.

Severity says how sure the watcher is; the grade says what the event means for
the server: `notice` (our own doings), `minor` (looking around from outside),
`major` (a deliberate attempt at the application), `critical` (somebody is
inside) and `system`, kept apart from the scale for the machine's own trouble.
The grade is worked out once by the service, reaches every sink, is raised by the
score piled up from the address, can be overridden per kind through
`grade_overrides`, and stays out of the chain hash, so earlier event files still
verify.

There are 69 event kinds, plus the `first_time_<feature>` family from learning.
Among them: `path_scan`, `access_denied_burst`, `request_flood`,
`server_error_burst`, `suspicious_path`, `honeypot_hit`, `trap_hit`,
`canary_used`, `canary_file_read`, `sqli_union`, `sqli_tautology`, `sqli_sleep`,
`sqli_schema`, `sqli_file`, `sqli_stacked`, `sqli_comment`, `shell_injection`,
`path_traversal`, `template_injection`, `mass_assignment_attempt`, `db_error`,
`ssh_login`, `ssh_bruteforce`, `sudo`, `file_changed`, `file_added`,
`file_removed`, `file_mode_changed`, the same four with the `_realtime` suffix,
`process_exec`, `process_exec_from_temp`, `process_from_temp`,
`deleted_binary`, `outbound_connection`, `listening_port`, `port_gone`,
`threshold_exceeded`, `column_changed`, `row_added`, `row_removed`,
`own_file_changed`, `own_file_missing`, `watch_started`, `watch_stopped`,
`heartbeat`, `ip_blocked`, `ip_unblocked`, `ip_auto_blocked`,
`auto_block_proposed`.

Repeats are merged: the first event goes out at once, the following ones inside
the window pile up and arrive as a single event with the repeat count. For the
sources in `dedup_ignore_subject` (by default `access`, `trap`, `mirror`) the
subject is left out of the merge key, because during path scanning the path
changes with every request: 50 scanned paths give 3 events instead of about a
hundred.

The events pass through a queue and are processed one at a time, so the chain
numbering in the file matches the order of the records even for an event born
while another one is being processed.

## 5. Where it reports

A line-based JSON file; an HTTP receiver (a POST with an array of events);
Telegram; email over SMTP. All network sinks, email included, are wrapped in an
on-disk queue: when the link goes down the events are not lost and go out later.
A failed delivery is counted in `sink_errors`; on shutdown the service sends what
the email sink was holding back for its throttle period.

The Telegram sink filters by grade rather than by severity, writes to named
people in private when no chat is set, caps the messages per hour and holds
same-kind events together, so that a deploy touching thousands of files becomes
one message instead of burying a break-in. It can also take commands - the
service asks Telegram for updates itself, so nothing is opened up on the server -
and answers only the numeric identifiers listed in `allowed_user_ids`, with
silence to everyone else. The commands show the same actors, proposals, dossiers
and blocking as the command-line flags.

## 6. Protecting the watcher itself

1. events go off the host immediately - what has left cannot be erased;
2. the chain: a sequence number and the hash of the previous event, so cutting
   or replacing a record is visible;
3. the service watches its own executable, configuration and systemd unit;
4. a heartbeat on schedule; a shutdown is an event of the highest severity;
5. the heartbeat carries the **head of the chain** - the number of the last
   event and its hash. The number can only grow: if after state tampering it
   went down or the hash does not match what arrived earlier, the tampering is
   visible to the receiving side. State files are written with mode 0600;
6. the same message carries **the service's own counters**: arrived, delivered,
   suppressed, merged, failed deliveries, with a breakdown by source and
   severity. A service that keeps sending heartbeats with a zero count of
   arrivals has gone blind - the web server log may have moved, for instance.
   The counters are printed by `-stats`.

## 5a. Event log rotation

The service rotates `events.jsonl` itself by size (`sinks.file_max_mb`, 50 MB by
default) and keeps the configured number of previous pieces (`file_keep`, 7).
For uniformity with the rest of the server logs a `logrotate` file is shipped as
well.

## 6a. Chain verification and shipping

```
security-watch -verify events.jsonl      # on your own machine, over a copy you received
security-watch -stats                    # the service's own counters
security-watch -version                  # version, platform, Go version
```

It checks that the numbers run consecutively and the hashes match; for a record
that was cut out or replaced it names its number. The `archive` section runs the
configured command once a day to ship the log to another machine (`rsync`,
`scp`, anything).

## 7. Blocking

By default **only on a human command**:

```
security-watch -candidates           # proposals with evidence
security-watch -dossier <address>    # the dossier: paths, clients, headers, fingerprint, tokens
security-watch -block <address>      # run the command set in the configuration
security-watch -unblock <address>
```

Self-directed blocking (`blocking.auto`) is off by default and fires only when
every condition is met: the number of hits, the number of distinct reasons, the
required event kinds, the allowlist, the hourly limit, the report-only mode.

The address is validated before being substituted into the command: digits,
dots, colons and hexadecimal letters only.

## 7a. Response actions

Named commands at the application level - revoke access keys, close an account,
rotate an API key:

```
security-watch -action revoke-tokens -arg 2648
```

The service never calls them on its own. The value is validated (letters,
digits, dot, underscore, dash, at sign, colon only) and the commands are defined
in the `actions` section.

## 7b. Configuration check

```
security-watch -check
```

Before startup it checks that the named logs and directories exist, that what is
enabled has everything it needs (paths for the trap, recipients for email, a
command for blocking), that the database queries are read-only, that the table
and column names are safe and that the patterns from the configuration compile.
Anything that prevents work is printed as a problem and exits with a non-zero
status; the rest is printed as a note.

## 8. Configuration

One JSON file, 29 sections: `host`, `state_dir`, `dedup_window`,
`dedup_ignore_subject`, `logging`,
`sinks`, `access_log`, `auth_log`, `files`, `files_realtime`, `ports`,
`processes`, `resources`, `app_log`, `audit`, `mirror`, `trap`, `canary`,
`enrich`, `db`, `self_guard`, `blocking`, `actors`, `baseline`, `archive`,
`actions`, `ignore`, `severity_overrides`, `grade_overrides`.

Among the things that can be configured: the log format through a custom
pattern, name patterns for logs with a date in the file name, custom and
disabled injection signatures, the privileged fields and the admin sections, the
tables and columns under watch, the database kind (MySQL or PostgreSQL),
suppression rules, severity by kind, the merge key (`dedup_ignore_subject`), the
field holding the real client address behind a reverse proxy
(`access_log.real_ip_field`), known login networks in CIDR form
(`auth_log.known_ips`), and the format and level of the service's own log
(`logging`: `text` for the eye, `json` for collectors).

## 9. Where it stores things

| Path | What |
|---|---|
| `/opt/security-watch/` | the executable |
| `/etc/security-watch/config.json` | the configuration |
| `/var/lib/security-watch/` | log read marks, snapshots of files and columns, the chain, dossiers, block proposals, the queue of undelivered events, the counters |
| `/var/log/security-watch/events.jsonl` | the event log (about 470 bytes per event) |

## 10. What the service does not do

It does not block without permission; it does not parse network packets and does
not hook into the kernel (it uses what nginx and auditd write); it does not send
file contents anywhere - only their hashes; it does not try to break into the
attacker's machine and does not uncover their identity through third-party
services.

## 11. Limitations

The six defects found on a running server are fixed and covered by tests
(repeat merging during path scanning, the chain order with nested events,
quoting of database identifiers, networks in `known_ips`, counting sink
failures together with the email queue, and the real client address behind a
reverse proxy). What is left:

- A merged event carries the last subject seen plus the repeat count; the full
  list of paths is in the web server log and in the dossier.
- The event queue holds 10000 items; when it is full the watchers wait instead
  of dropping events.
- `internal/watch` is one package of about 6600 lines.
- Coverage is 76.7% for the engine and 28.8% for the command-line wrapper.
- The service has about a day of real operation on one server.
- Email delivery is covered by tests with a substituted sender; the one live
  attempt failed on the mail provider's side.

### About the thresholds

The thresholds in the example configuration come from parsing 34,724 lines of
one server's log: in an ordinary minute one address sends 1 request, in 99 cases
out of 100 no more than 17, and the maximum was 149. The thresholds are set to
twice the 99.9th value: 86 requests, 20 404 responses, 10 401/403 responses, 5
5xx responses.

For your own server they have to be computed anew:

```
security-watch -tune /var/log/nginx/access.log
```

If the site works behind a reverse proxy (Cloudflare and the like), the log
contains the addresses of the proxy nodes, each serving many visitors, and the
per-visitor thresholds come out inflated. To count honestly, add
`$http_cf_connecting_ip` to `log_format` (see
[docs-nginx-ja3.md](docs-nginx-ja3.md)) and recompute.
