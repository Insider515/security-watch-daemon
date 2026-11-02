# Request body inspection and blocking: Coraza/ModSecurity and CrowdSec

This service watches and does not block. Below are two ready-made layers that
cover what it must not do.

## 1. The request body: the nginx mirror (no module builds)

The cheapest way to see a POST body is to hand its copy to the service with the
`mirror` directive. It does not delay the visitor: nginx sends the copy in
parallel and does not wait for the mirror's response.

```nginx
# Inside the server block:
location / {
    mirror /_watch_mirror;          # a copy of the request goes to the watcher
    mirror_request_body on;
    proxy_pass http://app_backend;
    # ... the other proxy_set_header lines as usual
}

location = /_watch_mirror {
    internal;
    proxy_pass http://127.0.0.1:9777$request_uri;
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
    proxy_set_header Content-Type $http_content_type;
}
```

Service configuration:

```json
"mirror": { "enabled": true, "addr": "127.0.0.1:9777", "max_body_bytes": 65536 }
```

The service matches the body and the headers with the same signatures it uses
for the request line and emits `mirror/sqli_*`, `mirror/shell_injection` and
`mirror/canary_used` events.

**Limitation:** the mirror only watches. It cannot block - the visitor's
response has already been sent.

## 2. Blocking in place: Coraza or ModSecurity

If you need to actually stop a request, install a full web application firewall
with the OWASP CRS rule set:

- **ModSecurity 3** + `ModSecurity-nginx` - requires building the module for
  your nginx version;
- **Coraza** - the same logic in Go, plugged in through `coraza-caddy` (if you
  move to Caddy) or through `coraza-spoa` with nginx/HAProxy.

Start in detection-only mode (`SecRuleEngine DetectionOnly`), collect the false
positives on your own traffic and only then turn blocking on. On an application
service CRS out of the box usually cuts off some legitimate requests - the admin
area, exports, the API.

## 3. CrowdSec: blocking by behaviour and shared reputation

CrowdSec reads the same logs as this service, recognizes known techniques and
blocks addresses through a bouncer. The main difference from fail2ban is the
shared database: an address caught at other participants is blocked at your
place in advance.

```bash
curl -s https://install.crowdsec.net | sudo sh
apt install crowdsec
apt install crowdsec-firewall-bouncer-iptables   # or cs-cloudflare-bouncer
cscli collections install crowdsecurity/nginx
systemctl restart crowdsec
```

Inspection and control:

```bash
cscli metrics            # what was parsed and how much
cscli decisions list     # who was blocked
cscli decisions delete --ip 1.2.3.4   # remove a block
```

For a site behind Cloudflare `cs-cloudflare-bouncer` makes more sense: it shuts
the address out at the Cloudflare side, so the traffic never reaches the server.

**A warning:** any blocker will one day shut you out as well. Put your own
addresses on the allowlist (`cscli allowlists`) and keep a spare way in - SSH on
a separate port, for instance.

## How this fits together with security-watch

| Layer | What it does |
|---|---|
| Cloudflare | cuts floods and bots off before the server |
| CrowdSec | blocks by behaviour and shared reputation |
| Coraza/ModSecurity | stops a request carrying injection on the spot |
| **security-watch** | sees all of it together, keeps a tamper-evident log and reports to you |

The watcher stays the only one that breaks nothing and can therefore run all the
time.
