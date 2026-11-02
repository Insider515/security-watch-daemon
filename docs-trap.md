# The trap and blocking on your decision

## How it works

The trap is a handful of addresses that appear nowhere on the site - not in a
link, not in the sitemap, not in `robots.txt`. An ordinary visitor will never
end up there: the only way to get there is by scanning. That is why **the
request itself is already the signal**, and no thresholds are needed.

How the trap differs from the `honeypot_paths` list in the `access_log` section:
that list merely notices the request in the log after the fact. The trap answers
by itself and can therefore collect more and serve the bait.

## What is collected

Only what the attacker sent themselves:

- the real address (through `CF-Connecting-IP` from Cloudflare);
- the `User-Agent` and every other header, their set and their order;
- the TLS fingerprint, if nginx or Cloudflare adds one;
- which paths they scanned and how many times they came;
- which bait token they got and whether they tried to use it.

The contents of `Cookie` and `Authorization` are **not stored** - only the fact
that they were presented is recorded. The service cannot and will not break into
the attacker's machine, plant code on it or uncover their identity through
third-party services: that would be a crime on your side.

Everything goes into a per-address dossier:
`/var/lib/security-watch/dossier.json`.

## The bait

When `serve_bait` is on, the trap serves a plausible configuration file with
fake credentials, **unique for every visitor**:

```
APP_ENV=production
DB_USER=app
DB_PASSWORD=SWBAIT_9f2c71a4e8b3
API_KEY=SWBAIT_9f2c71a4e8b3
```

That key is taken under watch immediately. If it surfaces anywhere - in a
request, in a POST body, in the application log - the link is proven: whoever
poked at the trap is now trying to log in. Not a guess but evidence, with a
timestamp and an address.

## nginx configuration

The trap paths must lead to the trap, not to the application:

```nginx
location ~ ^/(\.env\.bak|\.env\.old|backup\.sql|config\.bak\.json)$ {
    proxy_pass http://127.0.0.1:9778;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
    proxy_set_header X-JA3 $http_x_ja3;   # if a fingerprint is available
}
```

Important: do not add these paths to `robots.txt`, to the sitemap or to any
link. A disallow entry in `robots.txt` in fact attracts those who read it
looking for something interesting - the trap must only be findable by scanning.

## Blocking happens on your decision only

The service **never blocks on its own**. It collects proposals with evidence:

```bash
security-watch -config /etc/security-watch/config.json -candidates
```

```
address               hits last seen            reasons
203.0.113.9              4 2026-10-31 18:20:11  trap/trap_hit: /.env.bak; access/sqli_union: /news?id=1
```

To see the whole dossier:

```bash
security-watch -dossier 203.0.113.9
```

Blocking is a separate command, that is, your decision:

```bash
security-watch -block 203.0.113.9
security-watch -unblock 203.0.113.9
```

What exactly is executed is set in the configuration (`blocking.command`): `ufw
deny from %s`, a Cloudflare API call via `curl`, an nftables entry - anything.
While `blocking.enabled` is `false` the blocking command will not run at all,
even if it is invoked.

The address is validated strictly before being substituted into the command:
digits, dots, colons and hexadecimal letters only. Otherwise an entry such as
`1.2.3.4; rm -rf /` would turn the watcher into a hole.

## Self-directed blocking

It is enabled separately and is off by default:

```json
"blocking": {
  "enabled": true,
  "command": "ufw deny from %s",
  "auto": {
    "enabled": true,
    "min_hits": 3,
    "min_reasons": 2,
    "require_kinds": ["trap_hit"],
    "allowlist": ["127.0.0.1", "95.87."],
    "max_per_hour": 10,
    "dry_run": true
  }
}
```

### Why not "hit the trap, get shut out"

An innocent party can reach us too, in two ways.

**First, someone else's page.** Anyone can post an image like
`<img src="https://your-site/.env.bak">` on a forum, and the browser of everyone
who opens that page will come to us from that person's address. Without
conditions, self-directed blocking would become a weapon against your own
customers, and one that an outsider can fire. The protection: such a browser
load comes **once and to a single path**, while a scanner comes many times and
to different ones - hence `min_hits` and `min_reasons`, while `require_kinds`
lets you require that besides the trap there is also path scanning or an
injection attempt.

**Second, shared addresses.** Behind one address there may be an office, a hotel
or a whole mobile network; shutting it out shuts out everyone. There is no full
protection from this, but `max_per_hour` keeps one mistake from becoming a mass
one, and `allowlist` protects your own networks.

### How to turn it on

1. Set `dry_run: true` and leave it for a week. The service will report with
   `auto_block_proposed` events whom it would have shut out.
2. Look through that list. If it contains none of your people and none of your
   monitoring services, turn `dry_run` off.
3. Put your own addresses on the `allowlist` in advance, home and office alike.
   A spare way in (SSH on a separate port) must remain in any case.

## Why the decision stays with you

Any self-directed blocker one day shuts out either a real customer or the owner.
If the site sits behind Cloudflare, one CF node serves thousands of people: a
mistaken block of such an address cuts off many at once. That is why the service
shows the evidence and you press the button.
