# The client fingerprint in the nginx log

A TLS fingerprint (JA3/JA4) is a snapshot of how a client opens a secure
connection: the set and order of the ciphers and extensions it supports. An
ordinary browser has one, while `curl`, `python-requests`, `sqlmap` and other
tools have another, and it does not change when the address changes. It shows
that yesterday's and today's attacker are the same one, even from different
addresses.

nginx does not compute the fingerprint itself. There are two ways to get it.

## 1. Through Cloudflare (simpler, nothing to build)

Cloudflare adds the `CF-Connecting-IP` header, and on paid plans also
`cf-bot-score` and the fingerprint. It is enough to pass them into the log:

```nginx
log_format watch '$remote_addr - - [$time_local] "$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent" "$http_cf_ray" "$http_cf_connecting_ip"';

access_log /var/log/nginx/access.log watch;
```

List the added fields in the service configuration, in order:

```json
"access_log": { "extra_fields": ["cf_ray", "cf_ip"] }
```

## 2. On your own

The fingerprint is computed by a third-party nginx module (`ngx_ssl_ja3` and
similar); it requires rebuilding nginx with the module. After the build the
variable goes into `log_format` the same way:

```nginx
log_format watch '$remote_addr - - [$time_local] "$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent" "$http_ssl_ja3" "$http_cf_connecting_ip"';
```

```json
"access_log": { "extra_fields": ["ja3", "cf_ip"] }
```

The service picks the fields up from the end of the line in order and puts them
into the event details - no code changes are required.

## An important limitation

The fingerprint identifies a tool, not a person. It is good for tying the
requests of one attacker together and for telling a browser from a script. The
conclusion "this is the same person" does not follow from it: a fingerprint can
be forged, and millions of ordinary users of the same browser share one.
