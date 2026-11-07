# security-watch

![security-watch: log files, listening ports, processes and the database on the left; a single Go executable in the middle; Telegram, email, an HTTP API and file reports on the right](assets/banner.png)

A server monitoring service for Linux. It reads logs, watches files, ports,
processes and the database, and reports what it notices to a file, to Telegram,
to an HTTP receiver or by email. It changes nothing in the system until it is
asked to.

A single Go executable with no external dependencies beyond the database
drivers. Configured by one JSON file. Installs as a systemd service. There is no
tie to a particular application: everything server-specific is set in the
configuration.

Documentation in other languages: [Українська](README.uk.md).

- [What it does](#what-it-does)
- [What it does not do](#what-it-does-not-do)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Observation sources](#observation-sources)
  - [Web server log](#web-server-log)
  - [Auth log](#auth-log)
  - [Application log](#application-log)
  - [Files](#files)
  - [Listening ports](#listening-ports)
  - [Processes and outbound connections](#processes-and-outbound-connections)
  - [Database](#database)
  - [auditd log](#auditd-log)
  - [Request mirror](#request-mirror)
  - [Trap](#trap)
  - [Canary tokens](#canary-tokens)
- [Event kinds](#event-kinds)
- [Injection signatures](#injection-signatures)
- [Sinks](#sinks)
- [The event chain](#the-event-chain)
- [Actors and scoring](#actors-and-scoring)
- [Learning normal behaviour](#learning-normal-behaviour)
- [Blocking](#blocking)
- [Response actions](#response-actions)
- [Shipping the log to another server](#shipping-the-log-to-another-server)
- [Protecting the service itself](#protecting-the-service-itself)
- [Suppressing noise](#suppressing-noise)
- [Deriving thresholds from your own traffic](#deriving-thresholds-from-your-own-traffic)
- [Commands](#commands)
- [All settings](#all-settings)
- [Files and directories](#files-and-directories)
- [Resource use](#resource-use)
- [Compatibility](#compatibility)
- [Building and checks](#building-and-checks)
- [Known limitations](#known-limitations)

## What it does

| Source | What it notices |
|---|---|
| Web server log | path scanning, access guessing, request floods, requests to trap paths, injection signatures in the request |
| Auth log | SSH password guessing, successful logins (separately - from an unknown address), sudo usage |
| Application log | database messages about a malformed query, custom signatures, injection signatures in the request body |
| Files | replacement, creation, deletion, permission changes; by scheduled scanning and the moment they happen through inotify |
| Listening ports | a port appearing that is not on the declared list; a declared port disappearing |
| Processes | a start from a temporary directory, a running process whose file was deleted, an outbound connection to an undeclared port |
| Database | a threshold exceeded by your own query, changes to columns the application must not change |
| auditd | program execution with the full command line, reading of a canary file |
| nginx request mirror | injection and privileged field injection in the POST body and in headers |
| Trap | a request to an address nothing links to |
| Canary tokens | a fake key appearing in any watched log |
| The machine's resources | memory, free space and free file slots on the mount points, load per processor |
| The service itself | shutdown, replacement of its own files, heartbeat, its own counters |

Beyond watching, the service can merge repeats, obtain facts about an address
(reverse name, network owner through RDAP, membership in the Tor network), keep
a score per address, learn what is normal for the server and report deviations,
number the events in a hash chain, collect block proposals with evidence, serve
an attacker a fake key and link it to a later login attempt.

## What it does not do

- It does not block and does not change the system on its own. Blocking is a
  separate command; self-directed blocking is off by default and is enabled with
  conditions.
- It does not parse network packets and does not hook into the kernel.
  Kernel-level facts come ready-made from the auditd log.
- It does not send the contents of watched files anywhere - it only computes
  SHA-256 hashes.
- It does not reach into the attacker's machine. Only what they sent themselves
  is collected, plus open registry data (RDAP, reverse DNS).
- It is not a replacement for a WAF or an antivirus. This is a watcher, not a
  perimeter defence.
- The bot does nothing beyond the commands listed below: it does not take
  arbitrary text, does not run shell commands and does not change the
  configuration. Blocking from the chat runs the same command from the
  configuration that `-block` runs, and nothing else.

## Requirements

- Linux. Parsing `/proc/net/tcp`, `/proc` and inotify are Linux-specific; on
  other systems real-time watching is disabled and the rest keeps working.
- Go 1.25 or newer to build. Go is not needed on the server.
- Root privileges: to read `/var/log/auth.log`, other users' directories and
  `/proc`.
- Optional: `auditd` (kernel-level facts), nginx with the `mirror` directive
  (request body inspection), MySQL/MariaDB or PostgreSQL (database checks).

## Installation

Build and install on the server itself:

```bash
git clone https://github.com/Insider515/security-watch-daemon.git
cd security-watch-daemon
sudo ./install.sh
```

`install.sh` builds the executable, puts it into place, installs the systemd
service and the logrotate rule and, if there is no configuration file yet, drops
in the example. Running it again only updates the executable and restarts the
service, leaving the configuration alone.

If the server has no Go, build on your own machine and copy a single file:

```bash
GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o security-watch ./cmd/security-watch
scp security-watch root@server:/tmp/
scp systemd/security-watch.service root@server:/etc/systemd/system/
scp config.example.json root@server:/tmp/
ssh root@server '
  mkdir -p /opt/security-watch /etc/security-watch /var/lib/security-watch /var/log/security-watch
  chmod 750 /var/lib/security-watch /var/log/security-watch
  install -m 0755 /tmp/security-watch /opt/security-watch/security-watch
  install -m 0640 /tmp/config.example.json /etc/security-watch/config.json
  systemctl daemon-reload && systemctl enable --now security-watch
'
```

The systemd unit ships with hardening: `NoNewPrivileges`,
`ProtectSystem=strict`, `ProtectHome=read-only`, `ProtectKernelTunables`,
`ProtectKernelModules`, `MemoryDenyWriteExecute`; writing is allowed only to the
state directory and the event log directory.

## Quick start

The shortest working configuration file - the web server log and the event file:

```json
{
  "host": "my-server",
  "sinks": { "file": "/var/log/security-watch/events.jsonl" },
  "access_log": {
    "enabled": true,
    "path": "/var/log/nginx/access.log",
    "not_found_per_minute": 60,
    "requests_per_minute": 600,
    "detect_injection": true,
    "suspicious_paths": ["/.env", "/.git", "/wp-login.php", "/phpmyadmin"]
  }
}
```

Everything that is not set comes from the defaults. Check the configuration
before startup:

```bash
security-watch -config /etc/security-watch/config.json -check
```

The command tells you which of the named files and directories do not exist and
what the enabled sections are missing. Anything that does not prevent work is
printed as a note rather than an error.

One pass over files, ports, processes and the database, without continuous
watching:

```bash
security-watch -config /etc/security-watch/config.json -once
```

The first pass only remembers the current state: there is nothing to compare
against yet, so it produces no events.

## How it works

Every event takes one path:

```
observation source
  -> suppression by the ignore rules, severity correction by severity_overrides
  -> merging repeats inside dedup_window
  -> facts about the address (reverse DNS, RDAP, Tor)
  -> the sequence number and the hash of the previous event (the chain)
  -> a block proposal, if the event kind is in propose_on
  -> the actor score, learning
  -> the service log
  -> the sinks: file, Telegram, HTTP, email
```

The order is chosen by cost: what is superfluous is dropped before any outside
queries or chain writes are spent on the event.

Every watcher runs in its own goroutine: log reading is continuous, scans follow
the schedule from the configuration. The read marks are kept on disk, so a
restart loses no lines and does not re-read old ones.

## Observation sources

### Web server log

The `access_log` section. It reads the log line by line and understands the
standard combined format:

```
1.2.3.4 - - [30/Oct/2026:22:13:00 +0100] "POST /api/pay HTTP/2.0" 404 153 "-" "UA"
```

Threshold events are counted per address in one-minute windows; the count
restarts with every new minute, so the thresholds catch bursts rather than daily
totals.

| Setting | Default | Event when exceeded |
|---|---|---|
| `not_found_per_minute` | 60 | `path_scan` - path scanning |
| `denied_per_minute` | 30 | `access_denied_burst` - access guessing (401, 403) |
| `errors_per_minute` | 10 | `server_error_burst` - a stream of 5xx responses |
| `requests_per_minute` | 600 | `request_flood` - a request flood |

Besides the thresholds, every line is checked for:

- `suspicious_paths` - paths that are suspicious to request in themselves
  (`/.env`, `/.git`, `/wp-login.php`), the `suspicious_path` event;
- `honeypot_paths` - paths that do not and must not exist on this server, the
  `honeypot_hit` event with the highest severity;
- `detect_injection` - injection signatures in the request, see
  [Injection signatures](#injection-signatures);
- the tokens from the `canary` section, the `canary_used` event.

A non-standard log format is handled with a custom pattern:

```json
"access_log": {
  "regexp": "^(?P<ip>\\S+) \\S+ \\[(?P<time>[^\\]]+)\\] \"(?P<method>\\S+) (?P<path>\\S+)[^\"]*\" (?P<status>\\d{3})",
  "extra_fields": ["ja3", "cf_ip"]
}
```

The group names understood are `ip`, `time`, `method`, `path`, `status`,
`agent`; the rest land in the event details. `extra_fields` are the names of the
fields appended to `log_format` at the end of the line, in order: that is how
the TLS fingerprint, for instance, gets into the event.

If the site works behind Cloudflare or another reverse proxy, the log will
contain the proxy addresses rather than the clients'. Add the real address to
`log_format`:

```nginx
log_format combined_real '$http_cf_connecting_ip - $remote_user [$time_local] '
                         '"$request" $status $body_bytes_sent '
                         '"$http_referer" "$http_user_agent"';
access_log /var/log/nginx/access.log combined_real;
```

Then name that field in `extra_fields` and point `real_ip_field` at it, and the
events will carry the client address rather than the proxy one:

```json
"access_log": { "extra_fields": ["ja3", "cf_ip"], "real_ip_field": "cf_ip" }
```

An empty field value or an unparsable one is ignored, and the address from the
first field of the line is used. If the proxy writes a list, the first address of
the list is taken.

The path may be a pattern: `"/var/log/nginx/access-*.log"`. The reader picks the
most recent matching file - that is how logs that start a new file with the date
every day are handled.

### Auth log

The `auth_log` section, `/var/log/auth.log` by default (`/var/log/secure` on
RHEL and derivatives).

- Failed attempts pile up and produce `ssh_bruteforce` when
  `failures_per_minute` (default 5) is exceeded within a minute from one
  address.
- A successful login produces `ssh_login`. If the address is in `known_ips` the
  severity is informational, otherwise it is an alarm. This is what tells "they
  are knocking" apart from "they are already in".
- A sudo invocation produces `sudo` with the user and the command.

`known_ips` holds exact addresses and networks in CIDR form: `203.0.113.9`,
`188.129.64.0/18`, `2001:db8::/32`. With a provider address that changes inside
one network, listing the network keeps your own login from raising an alarm every
time.

Custom patterns for other ways in (a control panel, a VPN, mail):

```json
"auth_log": { "extra_failure_patterns": ["authentication failure for (\\S+) from (\\S+)"] }
```

The first group is the user name, the second one is the address.

### Application log

The `app_log` section. Injection more often arrives in a POST body, which is not
in the web server log at all. The database, however, on receiving a malformed
query writes a recognizable parse error into the application log - a sign that
the injected value reached the database. The event is `db_error`, with the
highest severity.

The messages of MySQL/MariaDB and PostgreSQL are built in; a separate pattern
catches the sign that the query did run and returned system tables. The built-in
set can be disabled (`disable_builtin_patterns`) and custom substrings added:

```json
"app_log": {
  "enabled": true,
  "path": "/var/log/myapp/app.log",
  "extra_patterns": ["mass_assignment", "guard_field"],
  "detect_injection": true
}
```

Looking for injection signatures in the application log is enabled separately:
in some logs such lines appear as a matter of course.

### Files

The `files` section. It compares the current state of the paths with the
previous snapshot: contents by SHA-256, permissions, modification time. The
snapshot lives on disk, so a replacement that happened while the service was
down is noticed too.

```json
"files": {
  "enabled": true,
  "paths": ["/etc/nginx", "/etc/systemd/system", "/root/.ssh", "/etc/cron.d", "/opt/myapp/.env"],
  "interval": "5m",
  "max_depth": 6,
  "skip": ["node_modules", "/tmp/", ".git/"]
},
"files_realtime": true
```

`files_realtime` adds watching through inotify: the event arrives within 0.3
seconds rather than on the next scan (the descriptor is polled with that
interval so the service still stops on a signal within a second). Scheduled scanning stays in place - it
survives a service restart and sees what happened while the service was down.
Real-time events have their own kinds with the `_realtime` suffix.

A path that names a directory is watched whole, down to `max_depth`. A path that
names a single file - `/opt/myapp/.env` above - is watched as that file alone:
inotify can only subscribe to directories, so the service subscribes to the
file's directory and reports nothing else inside it. That matters on a deployed
application, where the file sits in the application's own directory: watching
the tree around it would mean hundreds of directories and tens of thousands of
events from every deployment. To watch the whole directory, name the directory.

### Listening ports

The `ports` section. It reads `/proc/net/tcp` and `/proc/net/tcp6` directly,
without `ss` or `netstat`. A port that is not in `expected` produces
`listening_port`; a declared port disappearing produces `port_gone`.

```json
"ports": { "enabled": true, "interval": "1m", "expected": [22, 80, 443, 3306] }
```

On the first pass undeclared ports are reported as a warning (this is an
inventory), afterwards as an alarm.

### Processes and outbound connections

The `processes` section. It walks `/proc` and looks for:

- `process_from_temp` - a program started from `/tmp`, `/dev/shm`, `/var/tmp`,
  `/run/user` (the list is in `suspicious_dirs`);
- `deleted_binary` - the process runs while its file has been deleted from disk;
- `outbound_connection` - an outbound connection to a port that is not in
  `allowed_outbound_ports`; connections to private addresses are skipped.

```json
"processes": {
  "enabled": true,
  "interval": "1m",
  "suspicious_dirs": ["/tmp", "/dev/shm", "/var/tmp", "/run/user"],
  "allowed_outbound_ports": [25, 53, 80, 443, 587, 3306]
}
```

If the server legitimately connects to arbitrary ports (proxy checking, polling
third-party APIs), it is better to silence the outbound check with a rule and
keep the other two kinds:

```json
"ignore": [{ "source": "process", "kind": "outbound_connection" }]
```

### The machine's resources

The `resources` section. The only watcher with nobody on the other side:
everything else reports what somebody did to the server, this one reports that
the server is running out of something. Such events get the `system` grade and
are switched on apart from the reports about attacks.

- `memory_low` - less than `memory_free_percent` of memory is left.
  `MemAvailable` is taken rather than `MemFree`: the kernel gives free memory
  away to caches, so `MemFree` on a healthy server is small at all times and a
  report built on it would be false every hour of the day.
- `disk_low` - less than `disk_free_percent` of space is left on one of
  `paths`. Space available to an ordinary user is counted, not the part
  reserved for root.
- `inodes_low` - less than `inodes_free_percent` of file slots is left. A disk
  with no slots left refuses to create files although the space is there, which
  looks like an unexplained failure of everything at once.
- `load_high` - the one-minute load average per processor is above
  `load_per_cpu`. Per processor, because the same figure means different things
  on a machine with two cores and on one with thirty-two.
- `resource_recovered` - the trouble is over. Reported so that the operator
  knows the server pulled through without having to go and look.

```json
"resources": {
  "enabled": true,
  "interval": "1m",
  "memory_free_percent": 10,
  "paths": ["/", "/var"],
  "disk_free_percent": 10,
  "inodes_free_percent": 10,
  "load_per_cpu": 4,
  "repeat": "1h"
}
```

Trouble that has not gone away is not reported at every pass: a full disk stays
full, and `repeat` says how long to wait before saying it again. The figures
live in `/proc`, so this watcher works on Linux only; elsewhere the service
runs with it idle.

### Database

The `db` section. Two different kinds of checks, both described in the
configuration - there are no queries in the code.

**Query checks** (`checks`). The query must return a single row with a single
number; if the number exceeds `threshold`, `threshold_exceeded` is emitted. The
query is checked for being read-only: it must start with `SELECT` or `WITH`, and
words that change data are forbidden; a rejected query produces
`check_rejected`.

```json
"db": {
  "enabled": true,
  "driver": "mysql",
  "dsn": "watch:password@tcp(127.0.0.1:3306)/mydb?parseTime=true",
  "interval": "5m",
  "checks": [
    {
      "name": "registrations per hour",
      "query": "SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL 1 HOUR",
      "threshold": 10,
      "severity": "warn",
      "description": "A spike in registrations is a sign of a bot flood"
    }
  ]
}
```

**Column watches** (`column_watches`). The service keeps a snapshot of the
selected columns and reports an added row (`row_added`), a disappeared one
(`row_removed`) and a changed value (`column_changed`) - with the old and the
new value.

```json
"column_watches": [
  {
    "name": "user roles",
    "table": "users",
    "key": "id",
    "columns": ["role_id", "is_admin"],
    "where": "role_id IN (1,3,4)",
    "severity": "alert",
    "max_rows": 5000
  }
]
```

This is the case that is visible neither in the web server log nor in the
application log: a value written into the database bypassing the form -
privileged field injection, an edit through someone else's access, an edit
straight in the database console. Pick columns that change rarely: role,
administrator flag, API key, settings. A frequently changed column raises an
alarm on every edit.

`where` narrows the watch. A condition such as `role_id <= 2` on a server where
an ordinary user's role equals 2 will raise an alarm on every registration.

Read-only access is enough for the service. A separate MySQL user:

```sql
CREATE USER 'watch'@'localhost' IDENTIFIED BY 'your-password';
GRANT SELECT ON `mydb`.`users` TO 'watch'@'localhost';
GRANT SELECT ON `mydb`.`settings` TO 'watch'@'localhost';
FLUSH PRIVILEGES;
```

For PostgreSQL: `"driver": "postgres"` and a connection string such as
`postgres://watch:password@127.0.0.1:5432/mydb?sslmode=disable`.

The table and column names are inlined into the query as they are (they cannot
be passed as parameters), so they are validated: letters, digits and underscore
only.

### auditd log

The `audit` section. It provides what neither walking `/proc` nor inotify can
show: the kernel reports every program start with its full command line and
every file open. The service does not install auditd rules - that is done
separately (see `docs-auditd.md`):

```bash
auditctl -a always,exit -F arch=b64 -S execve -k sw_exec
auditctl -w /opt/myapp/.env.backup -p r -k sw_canary
```

The rule keys are set in `exec_keys` and `canary_keys`. The kernel writes the
records of one event as several lines sharing an id, and the service collects
them together: the user and the program from SYSCALL, the command line from
EXECVE, the file from PATH.

Events: `process_exec` (informational), `process_exec_from_temp` (alarm),
`canary_file_read` (alarm, someone read the canary file).

### Request mirror

The `mirror` section. The web server writes only the request line into the log,
so injection in a POST body or in a header is invisible there. nginx can send a
copy of the request to an internal location - the service receives it, parses it
and answers immediately, without delaying the visitor's request.

```json
"mirror": {
  "enabled": true,
  "addr": "127.0.0.1:9777",
  "max_body_bytes": 65536,
  "privileged_fields": ["role_id", "is_admin", "balance", "status_id", "price"],
  "allow_paths": ["/admin/", "/api/admin/"]
}
```

nginx configuration:

```nginx
location / {
    mirror /_watch;
    mirror_request_body on;
    proxy_pass http://app_backend;
}

location = /_watch {
    internal;
    proxy_pass http://127.0.0.1:9777/mirror$request_uri;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Real-IP $remote_addr;
}
```

What is looked for in the copy of the request:

- `mass_assignment_attempt` - a privileged field arrived in the body of a
  request to a path that is not in `allow_paths`. The field name is searched for
  as it arrives: `"role_id":` in JSON and `role_id=` in a form;
- injection signatures in the body and in the headers;
- canary tokens.

Setup details and passing the TLS fingerprint (JA3) are in
`docs-nginx-ja3.md`.

### Trap

The `trap` section. The service brings up a small server and answers addresses
that no link points to - not in the markup, not in the sitemap, not in
`robots.txt`. They cannot be reached by accident, so the request itself means
scanning.

```json
"trap": {
  "enabled": true,
  "addr": "127.0.0.1:9778",
  "paths": ["/.env.bak", "/admin-old", "/backup.sql"],
  "serve_bait": true,
  "bait_template": "APP_ENV=production\nDB_PASSWORD=%s\nAPI_KEY=%s\n"
}
```

nginx configuration:

```nginx
location ~ ^/(\.env\.bak|admin-old|backup\.sql)$ {
    proxy_pass http://127.0.0.1:9778;
    proxy_set_header X-Real-IP $remote_addr;
}
```

The `trap_hit` event contains everything the visitor sent themselves: address,
headers, client, scanned paths. With `serve_bait` they are served a plausible
configuration file with a fake key, unique for every address. The key
automatically becomes a canary token: if someone later tries to log in with it,
the event gains a `bait_issued_to` field - the link between whoever poked around
and whoever is trying to log in is proven, not guessed.

Without `serve_bait` the trap answers like any missing address and gives nothing
away. What has been collected per address is shown by the `-dossier` command.
Details are in `docs-trap.md`.

### Canary tokens

The `canary` section. A canary token is a value that cannot exist in normal
life. Fake credentials are placed in a decoy configuration file on the server:

```bash
cat > /opt/myapp/.env.backup <<'EOF'
DB_PASSWORD=CANARY_4F2A91C7E55B0D13
API_KEY=CANARY_4F2A91C7E55B0D13
EOF
```

```json
"canary": { "enabled": true, "tokens": ["CANARY_4F2A91C7E55B0D13"] }
```

Such a value can be obtained nowhere else, so its appearance in a request, in
the application log or in a request copy from the mirror means the files on the
server have already been read and what was found is being tried. The event is
`canary_used`, with the highest severity. A value shorter than 8 characters is
ignored.

## Event kinds

Severity: `info`, `warn` - a warning, `alert` - an alarm. Any of them can be
overridden through `severity_overrides`. Every event also carries a
[criticality grade](#criticality-grades) - what it means for the server - which
can be overridden through `grade_overrides`.

| Source | Kind | Severity | When |
|---|---|---|---|
| access | `honeypot_hit` | alert | a request to a path from `honeypot_paths` |
| access | `canary_used` | alert | a canary token found in the request |
| access | `suspicious_path` | warn | a request to a path from `suspicious_paths` |
| access | `path_scan` | warn | `not_found_per_minute` exceeded |
| access | `access_denied_burst` | warn | `denied_per_minute` exceeded |
| access | `server_error_burst` | alert | `errors_per_minute` exceeded |
| access | `request_flood` | warn | `requests_per_minute` exceeded |
| access | injection signatures | alert, warn | see [Injection signatures](#injection-signatures) |
| auth | `ssh_bruteforce` | warn | `failures_per_minute` exceeded |
| auth | `ssh_login` | alert, info | a successful login; info if the address is in `known_ips` |
| auth | `sudo` | info | a command run through sudo |
| app | `db_error` | alert | a database message about a malformed query |
| app | `canary_used` | alert | a canary token in the application log |
| app | `custom_pattern` | warn | a match with `extra_patterns` |
| files | `file_added` | alert | a file appeared in a watched path |
| files | `file_changed` | alert | the contents changed (SHA-256) |
| files | `file_removed` | alert | the file disappeared |
| files | `file_mode_changed` | warn | the permissions changed |
| files | `scan_error` | warn | the path could not be read |
| files | `*_realtime`, `file_touched` | alert, warn | the same from inotify, the moment it happens |
| ports | `listening_port` | alert, warn | a port not in `expected`; warn on the first pass |
| ports | `port_gone` | warn | a declared port no longer listens |
| process | `process_from_temp` | alert | a program started from a temporary directory |
| process | `deleted_binary` | alert | the process runs, the file is deleted |
| process | `outbound_connection` | warn | a connection to an undeclared port |
| db | `threshold_exceeded` | per configuration | the query returned a number above the threshold |
| db | `row_added`, `row_removed` | per configuration | a row appeared in or disappeared from the watch |
| db | `column_changed` | per configuration | the value of a watched column changed |
| db | `check_failed` | warn | the query did not run |
| db | `check_rejected` | warn | the query changes data and was not run |
| db | `column_watch_failed` | warn | the column watch did not run |
| audit | `process_exec` | info | the kernel reported a program start |
| audit | `process_exec_from_temp` | alert | a start from a temporary directory |
| audit | `canary_file_read` | alert | the canary file was read |
| mirror | `mass_assignment_attempt` | alert | a privileged field in a request to an ordinary path |
| mirror | `canary_used` | alert | a canary token in the body or a header |
| trap | `trap_hit` | alert | a request to the trap |
| baseline | `first_time_<feature>` | per configuration | a feature value (`country`, `agent`, `owner`, `tls_fingerprint`, `ip`, `subject`) was met for the first time after learning |
| actor | `actor_threshold` | alert | the address score reached `alert_score` |
| actor | `digest` | info | the digest for `digest_interval` |
| self | `watch_started` | info | the service started |
| self | `watch_stopped` | alert | the service is shutting down |
| self | `heartbeat` | info | the heartbeat with the counters and the chain head |
| self | `own_file_changed` | alert | a file of the service itself was replaced |
| self | `own_file_missing` | alert | a file of the service itself disappeared |
| self | `archive_done`, `archive_failed` | info, warn | shipping the log off the host |
| action | `ip_blocked`, `ip_unblocked` | info | blocking on the operator's command |
| action | `ip_auto_blocked` | alert | self-directed blocking by the conditions |
| action | `auto_block_proposed` | warn | the conditions were met but `dry_run` is on |
| action | `auto_block_failed` | warn | the blocking command did not run |
| action | `action_done` | info | an action from the `actions` section was executed |
| resources | `memory_low` | alert | less than `memory_free_percent` of memory is left |
| resources | `disk_low` | alert | less than `disk_free_percent` of space is left on a mount point |
| resources | `inodes_low` | alert | less than `inodes_free_percent` of file slots is left |
| resources | `load_high` | alert | the load per processor is above `load_per_cpu` |
| resources | `resource_recovered` | info | the trouble is over |

An event in the file looks like this:

```json
{"at":"2026-11-01T12:22:14+01:00","source":"access","kind":"honeypot_hit","severity":"alert",
 "grade":"minor","ip":"203.0.113.77","subject":"/.env","count":1,"host":"my-server","seq":729,
 "prev_hash":"a61312f8...","hash":"59001ca0...",
 "details":{"agent":"curl/8.5.0","method":"GET","status":"404","country":"NL","owner":"Example BV"}}
```

## Injection signatures

They are enabled by `detect_injection` in the `access_log` and `app_log`
sections and always work in the request mirror. Before matching, the string is
percent-decoded twice (scanners write `%2527` instead of `%27`), plus signs
become spaces and the case is folded to lower.

| Kind | Severity | What it looks for |
|---|---|---|
| `sqli_union` | alert | `union select`, `union all select` |
| `sqli_tautology` | alert | `' or 1=1`, `") and 1=1` |
| `sqli_comment` | warn | cutting the query short with a comment: `-- `, `#`, `/*!`, `; --` |
| `sqli_sleep` | alert | `sleep(`, `benchmark(`, `pg_sleep(`, `waitfor delay` |
| `sqli_schema` | alert | `information_schema`, `sysobjects`, `pg_catalog` |
| `sqli_file` | alert | `load_file`, `into outfile`, `into dumpfile`, `xp_cmdshell` |
| `sqli_stacked` | alert | `; drop`, `; insert`, `; update`, `; delete`, `; alter`, `; create` |
| `shell_injection` | alert | `;wget`, `curl` after a separator, `; /bin/bash -c`, `$(...)`, backticks, `() { :; }` |
| `path_traversal` | alert | `../../`, `..\..\`, `/etc/passwd`, `/proc/self/environ` |
| `template_injection` | warn | `{{...}}`, `${jndi:` |

The set is extended and narrowed by configuration, with no code changes:

```json
"access_log": {
  "extra_injection_patterns": [
    { "kind": "custom_backdoor", "pattern": "/cgi-bin/\\w+\\.cgi\\?cmd=", "severity": "alert" }
  ],
  "disabled_signatures": ["sqli_comment"]
}
```

An invalid pattern from the configuration is skipped: a typo does not keep the
service from starting.

## Sinks

Several can be enabled at once; a failure of one does not get in the way of the
others.

```json
"sinks": {
  "file": "/var/log/security-watch/events.jsonl",
  "file_max_mb": 50,
  "file_keep": 7,
  "telegram": {
    "enabled": true, "token": "token",
    "allowed_user_ids": ["111111111", "222222222"],
    "min_grade": "major", "system_errors": true, "commands": true,
    "max_per_hour": 20, "group_window": "2m"
  },
  "email": {
    "enabled": true, "host": "smtp.example.com", "port": 587,
    "user": "watch@example.com", "pass": "password",
    "from": "watch@example.com", "to": ["admin@example.com"],
    "min_severity": "alert", "throttle": "15m"
  },
  "webhook": { "enabled": true, "url": "https://example.com/api/security-events", "headers": { "X-Token": "..." } },
  "outbox_max": 5000,
  "outbox_retry": "1m"
}
```

- **File** - one event per line as JSON. Works without the network. The service
  rotates the file itself by `file_max_mb` and keeps `file_keep` previous
  pieces, instead of relying on an external logrotate; the shipped
  `logrotate.conf` is only needed where logs are rotated uniformly.
- **Telegram** - a message through the bot API, needing no configured mail
  server. Messages longer than 4096 characters are truncated. With no `chat_id`
  the bot writes to the people in `allowed_user_ids` in private, which is the
  usual case: there is then no group whose membership has to be watched. The
  bot filters by [criticality grade](#criticality-grades) rather than by
  severity and can take commands - see [The bot](#the-bot).
- **Email** - SMTP through the standard library, with STARTTLS. Events pile up
  and go out in a single message no more often than `throttle`: during a flood
  that is the difference between one message and a hundred.
- **HTTP receiver** - a POST with JSON and your own headers; convenient for
  accepting events into your own dashboard.

`min_severity` cuts off the small stuff: `alert` - alarms only, `warn` - alarms
and warnings, empty - everything.

All network sinks (Telegram, HTTP, email) are wrapped in an on-disk queue: if a
sink is unreachable, the events land in `outbox.<sink>.jsonl` and go out at the
first opportunity, no more often than `outbox_retry`. The queue length is
limited by `outbox_max`, and on overflow the earliest events are kept. On
shutdown the service sends what the email sink was holding back for its throttle
period, so the last batch is not lost on restart.

A failed delivery is counted in `sink_errors` and shown by `-stats`.

A sink failure is visible in the service's own log:

```
WARN sink did not accept the events sink=email events=1 error="535 5.7.8 Authentication Failed"
```

## The event chain

Every event carries a sequence number (`seq`), the hash of the previous event
(`prev_hash`) and its own hash (`hash`), computed over the time, source, kind,
address, subject and repeat count. Deleting or editing a record breaks the
chain:

```bash
security-watch -verify /var/log/security-watch/events.jsonl
```

The command either confirms integrity or names the number of the first corrupted
record. It needs no configuration file, so the check is convenient to run on
your own machine over a copy of the log you received - then it does not depend
on the server.

The number and hash of the last event go off the host with the heartbeat. The
number can only grow: a number that went down, or a hash that does not match
what arrived earlier, means the state on the server was tampered with.

Events from the watchers go through a queue and are processed one at a time, so
the numbering in the file always matches the order of the records - including an
event born while another one is being processed, such as an actor report. The
queue holds 10000 events; when it is full the watchers wait, because slowing down
log reading is better than dropping events.

## Actors and scoring

The `actors` section. A stream of individual events does not answer the question
"who is doing what". The service groups the events by address: kinds and number
of events, country, network owner, clients, TLS fingerprint, scanned paths, and
computes a score.

```json
"actors": {
  "enabled": true,
  "weights": { "honeypot_hit": 5, "trap_hit": 10, "sqli_union": 10, "ssh_login": 8 },
  "alert_score": 50,
  "digest_interval": "1h",
  "forget": "168h"
}
```

The weight of an event kind is set in the configuration; anything not listed
weighs 1. On reaching `alert_score` an `actor_threshold` event is emitted with
everything known about the address. A digest goes out every
`digest_interval`. An address with no new events is forgotten after `forget`.

```bash
security-watch -config /etc/security-watch/config.json -actors
```

```
address              score  events last seen            what it did
203.0.113.77          1087     471 2026-11-01 09:53:57  honeypot_hit×68, request_flood×1, suspicious_path×402
198.51.100.82          598     193 2026-11-01 06:01:19  (BG Example-EOOD) honeypot_hit×43, path_traversal×1
```

## Criticality grades

Severity says how sure a watcher is that something happened. It does not say how
bad it is: a changed application file is `alert` whether it was a deploy or a
break-in. On a server that is deployed to with rsync that is thirty-five
thousand `alert` events a day, and messages at that rate stop being read.

The grade answers the other question - what the event means for the server:

| grade | what it means | examples |
|---|---|---|
| `critical` | somebody is inside, or one step away | a trap went off, a bait key was used, application code changed, a new service is listening, a database column changed |
| `major` | a deliberate attempt at the application, repelled or unconfirmed | an injection, a privileged field in a request, an address that crossed the score |
| `minor` | looking around from outside | path scanning, brute force, a file added |
| `notice` | our own doings and ordinary life | watching started, an address was blocked on request, the digest |
| `system` | the machine's own trouble, with nobody behind it | memory ran out, the disk is full, a watcher failed |

`system` is kept apart from the scale above because it is a different kind of
trouble, not a lesser one: a full disk is not "worse than a scan" or "better
than a break-in", and it is switched on and off on its own with
`sinks.telegram.system_errors`.

The grade of an event is raised by what has piled up from its address. At the
`actors.alert_score` threshold reconnaissance becomes an attempt; at twice the
threshold an attempt becomes a break-in in progress. A single repelled scan
means nothing, the same address at fifty is working on the server on purpose,
and the grade says so even though each separate event stays minor.

Which kind gets which grade:

| grade | kinds |
|---|---|
| `critical` | `canary_file_read`, `canary_used`, `column_changed`, `custom_backdoor`, `deleted_binary`, `file_changed`, `file_changed_realtime`, `listening_port`, `own_file_changed`, `own_file_missing`, `process_from_temp`, `row_added`, `row_removed`, `ssh_login`, `sudo`, `trap_hit` |
| `major` | `actor_threshold`, `custom_pattern`, `custom_signature`, `mass_assignment_attempt`, `outbound_connection`, `path_traversal`, `probe`, `shell_injection`, `sqli_comment`, `sqli_file`, `sqli_schema`, `sqli_sleep`, `sqli_stacked`, `sqli_tautology`, `sqli_union`, `template_injection`, `threshold_exceeded` |
| `minor` | `file_added`, `file_added_realtime`, `file_mode_changed`, `file_mode_changed_realtime`, `file_removed`, `file_removed_realtime`, `honeypot_hit`, `path_scan`, `port_gone`, `ssh_bruteforce`, `suspicious_path` |
| `notice` | `action_done`, `archive_done`, `auto_block_proposed`, `digest`, `heartbeat`, `ip_auto_blocked`, `ip_blocked`, `ip_unblocked`, `resource_recovered`, `watch_started`, `watch_stopped` |
| `system` | `archive_failed`, `auto_block_failed`, `check_failed`, `check_rejected`, `column_watch_failed`, `db_error`, `disk_low`, `inodes_low`, `load_high`, `memory_low`, `oom_kill`, `scan_error`, `service_failed` |

The `first_time_<feature>` family from learning is minor. A kind the service does
not know - one that appeared in a newer version, or one written by hand into the
configuration - is minor when an address is behind it and system trouble when
there is none: an event with no address comes from our own machinery rather than
from outside.

The grade of any kind can be set in the configuration - what counts as serious
differs from server to server:

```json
"grade_overrides": {
  "file_added_realtime": "notice",
  "file_mode_changed_realtime": "notice"
}
```

The grade is worked out once, by the service, and reaches every sink: it is the
`grade` field of each event in the log and in the HTTP receiver's payload. It
stays out of the chain hash, so event files written by earlier versions still
verify.

## The bot

The Telegram sink can also take commands. The service asks Telegram for updates
itself, so nothing has to be opened up on the server: no address reachable from
outside, no certificate, no webhook.

```json
"telegram": {
  "enabled": true,
  "token": "bot token",
  "allowed_user_ids": ["111111111", "222222222"],
  "min_grade": "major",
  "system_errors": true,
  "intrusions_only": false,
  "commands": true,
  "max_per_hour": 20,
  "group_window": "2m"
}
```

Who may use it is decided by person, not by chat. Commands are answered only for
the numeric identifiers in `allowed_user_ids`; to anyone else the bot does not
reply at all, so the silence does not even reveal that the commands exist. With
`chat_id` left empty the bot writes to those same people in private - then there
is no group whose membership has to be watched either.

What it reports:

- `min_grade` - the lowest grade worth a message. The default is `major`:
  reconnaissance from outside goes on around the clock and says nothing on its
  own.
- `system_errors` - whether to report the machine's own trouble. Separate from
  the scale, because wanting to know about a full disk is not the same as
  wanting to know about every scanner.
- `intrusions_only` - leave out the service's own doings even when their grade
  would pass.
- `max_per_hour` and `group_window` - the cap on messages and how long same-kind
  events are held together. A deploy touches thousands of files; held together
  they become one message that names the worst event in full and counts the rest
  by kind. Nothing critical is ever held: the window and the cap are there to
  quiet the noise, not to delay a break-in.

In a message the grade is shown by a coloured dot and by the word next to it:
red for `critical`, orange for `major`, yellow for `minor`, blue for `system`
and white for `notice`. The dot is there so that the grade is seen before the
message is read; the word stays because colour is lost wherever the text is
copied as plain characters.

```
security-watch geekproxy.io: 🔴 critical

🔴 critical auth / ssh_login
address: 91.200.12.7 (score 40)
subject: root
country: RU

🟠 significant access / sqli_union
address: 91.200.12.7 (score 40)
subject: /api/users?id=1 UNION SELECT
repeats: 4
```

Commands:

| command | what it does |
|---|---|
| `/status` | the service's counters, the most persistent addresses, whether silence is on |
| `/actors` | addresses ranked by score |
| `/candidates` | what the service proposes to block, and why |
| `/ip ADDRESS` | everything known about an address: score, kinds, country, owner, dossier |
| `/block ADDRESS`, `/unblock ADDRESS` | the same blocking as `-block` on the command line |
| `/mute HOURS` | stay silent (one hour by default, a day at most); critical events still get through, and a restart does not undo the silence |
| `/unmute` | report again |
| `/settings` | what the bot is set to report |
| `/help` | the list of commands |

The bot works over what the service already keeps - the same actors, the same
block list - so the chat and the command line show one and the same state.

## Learning normal behaviour

The `baseline` section. Part of what happens has no ready-made signature: "the
administrator logged in from a country they have never logged in from", "an API
key was used by an unfamiliar client". The service spends the configured number
of days silently remembering the normal feature values and then reports a value
it has not seen before.

```json
"baseline": {
  "enabled": true,
  "learn_days": 14,
  "features": ["country", "owner", "agent", "tls_fingerprint"],
  "kinds": ["ssh_login", "trap_hit", "mass_assignment_attempt", "canary_used"],
  "severity": "warn"
}
```

`features` are taken from the event details (`country`, `agent`, `ptr`, `owner`,
`tls_fingerprint`) and from the event itself (`ip`, `subject`). `kinds` limits
the event kinds learning is based on. While learning is in progress the service
reports at startup how many days are left.

## Blocking

By default the service blocks nobody. It collects proposals with evidence for
the event kinds listed in `propose_on`:

```json
"blocking": {
  "enabled": true,
  "command": "ufw deny from %s",
  "unblock_command": "ufw delete deny from %s",
  "propose_on": ["trap_hit", "canary_used", "sqli_union", "path_traversal", "shell_injection", "mass_assignment_attempt"],
  "auto": { "enabled": false }
}
```

```bash
security-watch -config /etc/security-watch/config.json -candidates
security-watch -config /etc/security-watch/config.json -block 203.0.113.77
security-watch -config /etc/security-watch/config.json -unblock 203.0.113.77
```

`%s` in the command is replaced with the address; the address is validated as
IPv4 or IPv6 before substitution. The command can be anything: `ufw`, `nft`, a
Cloudflare API call via `curl`.

**Self-directed blocking** is enabled separately and with conditions:

```json
"auto": {
  "enabled": true,
  "min_hits": 3,
  "min_reasons": 2,
  "require_kinds": ["trap_hit", "canary_used"],
  "allowlist": ["203.0.113.5", "198.51.100.0/24"],
  "max_per_hour": 10,
  "dry_run": true
}
```

The conditions are needed because a trap hit does not always mean an attack:
anyone can put a link to a trap path on their own page, and the browser of
everyone who opens it will come from their own address. One visit and one reason
is an accident; several reasons and several visits are scanning. `allowlist`
understands addresses and networks, `max_per_hour` limits the number of blocks
per hour, and `dry_run` prints the decision (`auto_block_proposed`) without
doing anything - that is how new conditions are run in without risk.

## Response actions

The `actions` section holds named commands the service never calls on its own.
The point is to have the response to an incident be a single command:

```json
"actions": {
  "enabled": true,
  "commands": {
    "revoke-tokens": "mysql -u app -ppassword mydb -e \"DELETE FROM auth_access_tokens WHERE tokenable_id = %s\"",
    "ban-user": "mysql -u app -ppassword mydb -e \"UPDATE users SET is_banned = 1 WHERE id = %s\""
  }
}
```

```bash
security-watch -config /etc/security-watch/config.json -action revoke-tokens -arg 2648
```

The value is substituted in place of `%s` and validated: letters, digits, dot,
dash, underscore and colon are allowed. Running an action produces an
`action_done` event.

## Shipping the log to another server

The `archive` section. Every `interval` it runs your command over the event
file:

```json
"archive": {
  "enabled": true,
  "command": "rsync -az %s backup@another-server:/archive/security-watch/",
  "interval": "24h"
}
```

`%s` is replaced with the path to the event file. The result produces
`archive_done` or `archive_failed`.

## Protecting the service itself

The `self_guard` section. Whoever breaks in with root privileges first kills the
watcher or cleans its log. Five things work against that:

1. **Events go off the host immediately** - what has left cannot be erased.
2. **The event chain** - a record cut out or replaced is visible on verification.
3. **The service watches its own files** - the executable, the configuration, the
   systemd unit (`own_file_changed`, `own_file_missing`).
4. **A heartbeat** every `heartbeat_interval`. Its absence on the receiving side
   means the service was stopped or the server was cut off. The shutdown, if the
   service gets the chance, is reported by a `watch_stopped` event with the
   highest severity.
5. **Its own counters** in that same heartbeat: how many events arrived from the
   watchers, how many were suppressed by rules, merged, delivered, and how many
   deliveries failed. Without them "the server is quiet" and "the service has
   gone blind" look identical.

```bash
security-watch -config /etc/security-watch/config.json -stats
```

```
last change 2026-11-01 12:08:34
arrived 1140, delivered 715, suppressed 42, merged 396, failed deliveries 0
by severity:
  alert        135
  warn         577
by source:
  access       702
  auth         3
```

What this does not give: full invulnerability. Someone with root can stop the
service before it sends anything, forge the whole chain or cut the network off.
The point is to make a quiet cleanup of the traces impossible - any of those
actions becomes a noticeable event in itself.

State files are written with mode 0600, the configuration file with 0640.

## Suppressing noise

**Suppression rules.** An event matching every field set in a rule is not
emitted at all; empty fields are not checked.

```json
"ignore": [
  { "source": "process", "kind": "outbound_connection" },
  { "ip": "203.0.113.5" },
  { "source": "access", "kind": "path_scan", "ip": "198.51.100.10" },
  { "source": "files", "subject_contains": "/var/cache/" }
]
```

**Severity overrides** by event kind - for when a kind of event means more or
less than usual on this server:

```json
"severity_overrides": { "sudo": "warn", "outbound_connection": "info", "ssh_login": "alert" }
```

**Merging repeats** always works: the same event inside `dedup_window` is sent
once, and after the window one event goes out with the number of accumulated
repeats in the `count` field.

For the sources listed in `dedup_ignore_subject` the subject is left out of the
merge key. That matters for path scanning: the path is different with every
request, so with the subject in the key a scanner that walked 50 paths used to
produce about a hundred events. With the default (`access`, `trap`, `mirror`) the
same scan gives three: one `honeypot_hit`, one `suspicious_path` and one
`path_scan`, with the repeat count in `count`. For `files`, `db`, `ports` and
`process` the subject stays in the key - two changed files are two different
events, not a repeat.

The resulting event carries the last subject seen plus the repeat count; the
full list of paths is in the web server log, and for trap hits also in the
dossier.

## Deriving thresholds from your own traffic

Thresholds taken "from general considerations" stay silent on one server and
flood another with alarms. The command computes them from a real log:

```bash
security-watch -tune /var/log/nginx/access.log
```

It takes the distribution of requests per minute and per address and places the
threshold above the 99.9th value but below rare outliers. No configuration file
is needed, so the command can also be run on your own machine over a copy of the
log you received.

## Commands

| Command | What it does |
|---|---|
| `-config PATH` | the configuration file (default `/etc/security-watch/config.json`) |
| `-check` | check the configuration and exit |
| `-once` | one pass over files, ports, processes and the database |
| `-stats` | print the service's own counters |
| `-version` | print the version, platform and Go version |
| `-actors` | print the actors ranked by score |
| `-candidates` | print the block proposals with their reasons |
| `-dossier ADDRESS` | print the dossier for an address (`*` for the list) |
| `-block ADDRESS` | block an address with the command from the configuration |
| `-unblock ADDRESS` | remove a block |
| `-action NAME -arg VALUE` | run an action from the `actions` section |
| `-verify FILE` | verify the chain in an event file (no configuration file needed) |
| `-tune FILE` | derive thresholds from a web server log (no configuration file needed) |

Control commands run and exit: watching is not started, so two copies of the
service never read the same logs.

The same actors, proposals, dossiers and blocking are available in Telegram
without a session on the server - see [The bot](#the-bot).

## All settings

One JSON file. Any section may be omitted: a disabled source does not start. The
full example with every section is `config.example.json`. Durations are written
as Go strings: `30s`, `5m`, `12h`, `168h`.

### General

| Field | Default | Meaning |
|---|---|---|
| `host` | the machine hostname | the server name used in messages |
| `state_dir` | `/var/lib/security-watch` | where to keep read marks and snapshots |
| `dedup_window` | `10m` | the merge window for repeats |
| `dedup_ignore_subject` | `access`, `trap`, `mirror` | sources (or `source/kind` pairs) whose subject is left out of the merge key |
| `files_realtime` | no | watch files through inotify |
| `ignore` | - | suppression rules |
| `severity_overrides` | - | severity correction by event kind |

### `grade_overrides`

| Field | Default | Meaning |
|---|---|---|
| `grade_overrides` | - | event kind -> `notice`, `minor`, `major`, `critical` or `system` |

### `resources`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `interval` | `1m` | how often to look |
| `memory_free_percent` | 10 | report below this share of free memory |
| `paths` | `["/"]` | mount points to watch for free space |
| `disk_free_percent` | 10 | report below this share of free space |
| `inodes_free_percent` | 10 | report below this share of free file slots |
| `load_per_cpu` | 4 | report above this load per processor |
| `repeat` | `1h` | how long before repeating a report about trouble that remains |

### `logging`

| Field | Default | Meaning |
|---|---|---|
| `format` | `text` | `text` for reading by eye, `json` for log collectors |
| `level` | `info` | `debug`, `info`, `warn`, `error` |

The service log goes to the error stream, from where journald picks it up. In
the `json` format every observation event becomes a record with the fields
`source`, `kind`, `severity`, `ip`, `subject`, `count`, `seq`, and the event
severity becomes the record level.

### `sinks`

| Field | Default | Meaning |
|---|---|---|
| `file` | - | path to the line-based event log |
| `file_max_mb` | 50 | the size at which the log is rotated |
| `file_keep` | 7 | how many previous pieces to keep |
| `outbox_max` | 5000 | the length limit of the undelivered queue |
| `outbox_retry` | `1m` | how often to retry what was deferred |
| `webhook.enabled` | no | |
| `webhook.url` | - | where to send the POST with JSON |
| `webhook.headers` | - | your own headers, an access key for instance |
| `webhook.timeout` | `10s` | how long to wait for the answer |
| `email.enabled` | no | |
| `email.host`, `email.port` | -, `587` | the SMTP server |
| `email.user`, `email.pass` | - | login to the SMTP server |
| `email.from`, `email.to` | - | sender and recipients (a list) |
| `email.min_severity` | `alert` | severity threshold |
| `email.throttle` | `15m` | at most one message per this period |
| `telegram.enabled` | no | |
| `telegram.token` | - | the bot token |
| `telegram.chat_id` | - | the chat to write to; empty means the allowed people in private |
| `telegram.allowed_user_ids` | - | numeric identifiers of the people who may use the bot |
| `telegram.min_severity` | `warn` | severity threshold |
| `telegram.min_grade` | `major` | the lowest [criticality grade](#criticality-grades) worth a message |
| `telegram.system_errors` | no | report the machine's own trouble (memory, disk, a failed watcher) |
| `telegram.intrusions_only` | no | leave out the service's own doings |
| `telegram.commands` | no | take commands from the allowed people |
| `telegram.max_per_hour` | 20 | the cap on messages per hour |
| `telegram.group_window` | `2m` | how long same-kind events are held together |
| `telegram.timeout` | `10s` | how long to wait for the answer |

### `access_log`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `path` | - | path to the log, a `*` pattern is allowed |
| `not_found_per_minute` | 60 | threshold of 404 responses per minute from one address |
| `denied_per_minute` | 30 | threshold of 401 and 403 responses |
| `requests_per_minute` | 600 | threshold of the request count |
| `errors_per_minute` | 10 | threshold of 5xx responses |
| `suspicious_paths` | - | paths that are suspicious to request |
| `honeypot_paths` | - | paths that do not exist on the server at all |
| `detect_injection` | no | look for injection signatures |
| `extra_fields` | - | names of extra fields at the end of the line |
| `real_ip_field` | - | which extra field holds the real client address |
| `regexp` | - | a custom line parsing pattern |
| `extra_injection_patterns` | - | custom injection signatures |
| `disabled_signatures` | - | which built-in signatures to turn off |

### `auth_log`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `path` | `/var/log/auth.log` | path to the auth log |
| `failures_per_minute` | 5 | threshold of failed attempts per minute |
| `known_ips` | - | known login addresses (exact) |
| `extra_failure_patterns` | - | custom patterns for failed attempts |

### `app_log`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `path` | - | path to the application log, a pattern is allowed |
| `extra_patterns` | - | custom substrings to treat as signatures |
| `disable_builtin_patterns` | no | turn off the built-in database messages |
| `detect_injection` | no | look for injection signatures |

### `files`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `paths` | - | files and directories under watch |
| `interval` | `5m` | how often to scan |
| `max_depth` | 6 | directory traversal depth |
| `skip` | - | path fragments to skip |

### `ports`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `interval` | `1m` | how often to compare |
| `expected` | - | the declared ports |

### `processes`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `interval` | `1m` | how often to walk `/proc` |
| `suspicious_dirs` | `/tmp`, `/dev/shm`, `/var/tmp`, `/run/user` | where starting a program is suspicious |
| `allowed_outbound_ports` | - | ports the server legitimately connects out to |

### `db`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `driver` | `mysql` | `mysql` or `postgres` |
| `dsn` | - | the connection string |
| `interval` | `5m` | how often to run the checks |
| `checks[].name` | - | the check name in the event |
| `checks[].query` | - | a query returning a single number |
| `checks[].threshold` | - | the threshold |
| `checks[].severity` | `alert` | the event severity |
| `checks[].description` | - | an explanation inside the event |
| `column_watches[].table`, `.key`, `.columns` | - | table, key, watched columns |
| `column_watches[].where` | - | a narrowing condition |
| `column_watches[].max_rows` | 10000 | the row limit of the snapshot |

### `audit`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `path` | `/var/log/audit/audit.log` | the auditd log |
| `exec_keys` | `sw_exec` | rule keys for program execution |
| `canary_keys` | `sw_canary` | rule keys for reading canary files |

### `mirror`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `addr` | - | the receiver address, `127.0.0.1:9777` for instance |
| `max_body_bytes` | - | how many bytes of the body to parse |
| `privileged_fields` | - | fields that must not appear in a request from an outsider |
| `allow_paths` | - | paths where these fields are legitimate |

### `trap`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `addr` | - | the trap address, `127.0.0.1:9778` for instance |
| `paths` | - | the trap paths |
| `serve_bait` | no | serve a fake configuration file |
| `bait_template` | a fake `.env` | the answer template, `%s` is replaced with the token |

### `canary`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `tokens` | - | the canary values, 8 characters and up |

### `enrich`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `reverse_dns` | no | the reverse name of the address |
| `rdap` | no | the network owner and the abuse contact |
| `tor_list_url` | - | the URL of the Tor exit node list |
| `timeout` | - | how long to wait for a lookup |
| `cache_ttl` | - | how long to remember an answer |

### `self_guard`

| Field | Default | Meaning |
|---|---|---|
| `enabled` | no | |
| `heartbeat_interval` | `15m` | how often to send the heartbeat |
| `check_interval` | `1m` | how often to re-check its own files |
| `watch_paths` | the service unit | what else counts as its own files |

### `blocking`, `actors`, `baseline`, `archive`, `actions`

Described in [Blocking](#blocking), [Actors and scoring](#actors-and-scoring),
[Learning normal behaviour](#learning-normal-behaviour), [Shipping the log to
another server](#shipping-the-log-to-another-server) and [Response
actions](#response-actions).

## Files and directories

| Path | What |
|---|---|
| `/opt/security-watch/security-watch` | the executable |
| `/etc/security-watch/config.json` | the configuration, mode 0640 |
| `/var/lib/security-watch/` | log read marks, snapshots of files and columns, the chain, dossiers, block proposals, the queues of undelivered events, the counters, the bot's state (`bot.state.json`: the silence asked for and the last update taken); mode 0600 |
| `/var/log/security-watch/events.jsonl` | the event log |
| `/etc/systemd/system/security-watch.service` | the service |
| `/etc/logrotate.d/security-watch` | event log rotation by an external logrotate |

The state can be deleted entirely: the service will take the snapshots again and
carry on. The first pass after that produces no events.

## Resource use

Measurements on a server with nginx, a Node.js application, MariaDB and a dozen
services, with 2170 lines in the web server log per day:

| What | How much |
|---|---|
| Memory | 14.3-14.6 MB |
| CPU time | 3 s to parse the accumulated log at startup, idle afterwards |
| One `-once` pass over files, ports, processes and the database | 2.4 s |
| Real-time watching | 469 directories under inotify |
| Size of one event in the log | about 470 bytes |
| The executable | 7.8 MB with `-ldflags='-s -w'`, 11.1 MB without |
| The bot taking commands | one HTTP request per 30 s of waiting, held open by Telegram until an update arrives |

## Compatibility

- **OS**: Linux - Ubuntu, Debian, RHEL and derivatives. Building for other
  systems is possible; real-time watching and `/proc` reading are then disabled.
- **Web servers**: nginx, apache and any other. The combined format is
  understood out of the box, the rest through `regexp`. Request body mirroring
  requires nginx with the `mirror` directive.
- **Applications**: the service knows nothing about the framework. For the
  application log only a path to the file is needed; privileged field injection
  is caught by the field names you provide, so it works the same with Laravel,
  AdonisJS, Django and Rails.
- **Databases**: MySQL, MariaDB, PostgreSQL.
- **Delivery**: Telegram, SMTP, your own HTTP receiver, a file.

## Building and checks

```bash
go build -o security-watch ./cmd/security-watch   # build
go build -ldflags="-X main.version=1.0.0" -o security-watch ./cmd/security-watch   # build with a version
go test ./...                                     # tests
go test -race ./...                               # tests with the race detector
go test -cover ./internal/watch                   # coverage
go vet ./...                                      # the built-in analyzer
staticcheck ./...                                 # an external analyzer
gosec ./...                                       # a scan for unsafe patterns
```

Layout: `cmd/security-watch` parses the command line, `internal/watch` does all
the work. Dependencies: the `go-sql-driver/mysql` and `lib/pq` drivers;
everything else is the standard library.

## Known limitations

Listed here is what has been verified. The six defects found on a running server
are fixed and covered by tests; what is left is the honest remainder.

1. **A merged event carries only the last subject.** For the sources in
   `dedup_ignore_subject` the event holds the last path seen and the repeat
   count; the full list of paths has to be looked up in the web server log, or in
   the dossier for trap hits.
2. **A full queue slows the watchers down.** The event queue holds 10000 items.
   If the sinks cannot keep up (a slow SMTP server, for example), log reading
   waits. That is a deliberate choice: back-pressure instead of dropped events.
   Verified: a pass over 12000 changed files produces 12000 events with the
   chain intact, and takes 11 seconds instead of 1.
3. **`internal/watch` is one package of about 8100 lines.** The internal
   dependencies are not split into separate packages.
4. **Coverage is 80.0%** for the engine and 28.8% for the command-line wrapper.
5. **The service has about a day of real operation** on one server. The
   thresholds come from a real log, but only running it can confirm them.
6. **Email delivery is proven by tests, not by a letter.** The SMTP sink is
   covered by tests with a substituted sender; the live attempts fail on the mail
   provider's side (`535 Authentication Failed`), which is outside the service.
   Such events wait in `outbox.email.jsonl` and are retried no more often than
   the throttle period, so a wrong password delays the retry by that period.
7. **Reading the real client address requires an nginx change.** `real_ip_field`
   only works once the address is added to `log_format`; without that the service
   sees the proxy addresses.
8. **Watching resources works on Linux only.** The figures come from
   `/proc/meminfo` and `/proc/loadavg`, which exist nowhere else. On other
   systems the service runs with that watcher idle, and its reading is the one
   part of it that tests cannot cover off Linux.
9. **The bot cannot write to someone first.** Telegram refuses a message to a
   person who has not started the conversation with the bot, so everyone in
   `allowed_user_ids` has to send it `/start` once. Until then delivery to that
   person fails and the events wait in `outbox.telegram.jsonl`.
10. **The grade is worked out from the kind and the score, not from intent.** A
    file changed by a deploy and a file changed by an intruder are the same event
    to the service; it says that the code changed, not who changed it. On a
    server deployed to with rsync that means a batch of critical events at every
    deploy, which is why `grade_overrides` exists.
