# auditd rules for security-watch

`auditd` is a standard Linux kernel subsystem: it reports program execution and
file access. The service does **not** install these rules itself - changing
kernel settings from a watcher is wrong, and it does not need the privileges for
it either. The rules are installed once, by hand.

## Installation

```bash
apt install auditd audispd-plugins        # Debian/Ubuntu
```

## Rules

The file `/etc/audit/rules.d/security-watch.rules`:

```
# Execution of any program (key sw_exec).
-a always,exit -F arch=b64 -S execve -k sw_exec
-a always,exit -F arch=b32 -S execve -k sw_exec

# Reading the canary: a file nobody has any reason to open (key sw_canary).
-w /opt/myapp/.env.backup -p r -k sw_canary

# Useful additions: changes to access keys, schedules and services.
-w /root/.ssh/authorized_keys -p wa -k sw_canary
-w /etc/crontab -p wa -k sw_exec
-w /etc/systemd/system -p wa -k sw_exec
```

Apply them:

```bash
augenrules --load && systemctl restart auditd
auditctl -l        # check that the rules are in place
```

## Service configuration

```json
"audit": {
  "enabled": true,
  "path": "/var/log/audit/audit.log",
  "exec_keys": ["sw_exec"],
  "canary_keys": ["sw_canary"]
}
```

## What this adds to what is already there

- **Every** program start, including one that lived for a fraction of a second -
  polling `/proc` once a minute misses those;
- the full command line, not just the path to the program;
- **reading** the canary file. Neither file scanning nor change subscriptions see
  reads: the kernel reports them only through auditd. Before this the canary
  fired only when someone tried to use what they had found.

## The cost

A rule on `execve` produces a noticeable stream of records on a busy server:
check the size of `/var/log/audit/` after a day and narrow the rule if needed
(for example, only for users with `auid>=1000`, or only for certain
directories).
