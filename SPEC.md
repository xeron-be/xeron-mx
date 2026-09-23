# Product specification: XeronMX

## 1. Vision

**XeronMX is the modern equivalent of a Postfix configured as a backup MX, shipped as a Docker appliance with a UI, metrics, and five minutes of setup.**

One promise: "Your mail server goes down, but you lose no mail. And you can see what is happening."

## 2. Scope

### 2.1 In scope

- Inbound SMTP (port 25) for configured domains
- Persistent queue (messages held on disk, encrypted at rest)
- Automatic detection of the primary's state (SMTP health check)
- Automatic forwarding with exponential backoff once the primary returns
- Ceilings: maximum message size, maximum queue depth, maximum retention
- Web UI: live queue, upstream state, logs, metrics, configuration
- REST API plus a Server-Sent Events stream for the live queue
- Admin authentication (email and password, optionally OIDC)
- Configuration through the UI **or** a YAML file (immutable-infrastructure friendly)
- Automatic TLS (Let's Encrypt) for both SMTP and the UI
- SPF / DKIM / DMARC passthrough (the primary's signatures are never broken)
- Structured logs (JSON), exportable
- Prometheus metrics

Added to the scope during development, and shipped in v1.0:

- Authenticated outbound submission (port 587) with DKIM signing and
  per-destination routing, for primaries that can receive but cannot send
- ARC sealing of mail forwarded to the primary, and a DMARC helper
- Inbound perimeter checks: DNSBL at connection time, ClamAV body scanning,
  regex content filters with quarantine, and the rspamd sidecar
- Alerting (email and webhook) and event webhooks
- Roles (`admin`, `operator`, `viewer`) with optional per-domain scoping, and
  API tokens
- Spool disk guard and a maintenance drain mode
- Several independent nodes reporting to one another, with configuration drift
  detection (the queue itself is not replicated)
- A companion CLI (`xeronmxctl`) and a Helm chart

### 2.2 Out of scope (for v1.x at least)

- Hosting mailboxes (XeronMX stores no mailboxes; it is a relay)
- Webmail
- IMAP / POP3
- Advanced spam filtering: content scoring is delegated to the optional rspamd
  sidecar. XeronMX itself only runs checks that need no training data (DNSBL,
  ClamAV, regex filters)
- Outbound IP reputation management (warm-up, feedback loops, IP pools)
- Heavyweight multi-tenancy. Domain-scoped roles let one operator delegate some
  domains to someone else, but there is no tenant isolation, self-service
  sign-up or billing: one deployment is still run by one organisation
- Queue replication between nodes

## 3. User flow

### 3.1 Installation

```bash
mkdir xeronmx && cd xeronmx
curl -O https://raw.githubusercontent.com/xeron-be/xeron-mx/main/docker-compose.yml
docker compose up -d
```

First boot opens a web wizard at `http://<host>:8080`:

1. Create the administrator account
2. Add a first domain and the address of the primary mail server
3. Show the DNS records to create (secondary MX plus an A record)
4. Test connectivity to the primary
5. Dashboard

### 3.2 Day to day

- Nothing happens while the primary is healthy; XeronMX is only reached as a fallback
- When the primary goes down, XeronMX starts receiving, and raises a UI notification plus an email or webhook
- When the primary returns, XeronMX drains the queue automatically, with backoff
- The dashboard shows queue depth, the last successful delivery, the primary's state, and recent events

### 3.3 Failure cases

- Primary down for longer than `alerts.primary_down_after` → alert
- Queue past `queue.max_messages` or `queue.max_bytes` → alert, and
  `452 4.3.1` so the sender retries
- A domain past its own `max_queue_messages` → `452 4.3.1` for that domain
  only (no alert: the rest of the node is still accepting)
- Free space on the spool volume below `queue.min_free_disk_bytes` → alert,
  and `452 4.3.1` at `MAIL FROM`
- Node in drain mode → `421 4.3.2`, so the sender defers or tries another MX
- Message over the size ceiling → `552 5.3.4`
- Unconfigured or disabled domain → `550 5.7.1`
- Client listed on a configured DNSBL → `554 5.7.1` before any data is accepted

## 4. Technical architecture

### 4.1 Components

```
┌──────────────────────────────────────────────────────┐
│                    XeronMX (Docker)                   │
├──────────────────────────────────────────────────────┤
│                                                       │
│  ┌────────────┐    ┌─────────────┐    ┌───────────┐ │
│  │ SMTP Server │───▶│   Queue     │───▶│  Sender   │ │
│  │  (port 25)  │    │  (SQLite +  │    │ (delivers │ │
│  │             │    │   fs blobs) │    │ to primary)│ │
│  └────────────┘    └─────────────┘    └───────────┘ │
│         ▲                  ▲                  │       │
│         │                  │                  ▼       │
│  ┌────────────┐    ┌─────────────┐    ┌───────────┐ │
│  │  Auth +    │◀───│   REST API  │───▶│ Primary   │ │
│  │   TLS      │    │  + SSE      │    │ Health    │ │
│  └────────────┘    └─────────────┘    └───────────┘ │
│                            ▲                          │
└────────────────────────────┼──────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Web UI (Vite)  │
                    │     React       │
                    └─────────────────┘
```

### 4.2 Stack: architectural decisions

| Component | Choice | Alternative considered | Reason |
|-----------|--------|------------------------|--------|
| Frontend | **Vite + React** | Next.js | No SSR needed, simple deployment, no second runtime |
| Backend | **Go** (go-smtp / emersion) | Node.js (Haraka) | Static binary, performance, low memory |
| Queue metadata | **SQLite** (modernc, pure Go) | PostgreSQL | Enough for 99% of self-hosted installs, and keeps the binary CGO-free |
| Message bodies | **Filesystem** (one encrypted file per message) | Everything in the database | Keeps SQLite small, and the spool easy to back up |
| TLS | **Let's Encrypt** built in (autocert, from `x/crypto`) | lego, or an external reverse proxy | Zero configuration, no extra module |
| UI auth | Argon2id plus an httpOnly session cookie, optional OIDC | JWT | Simpler, and safer by default |
| Live updates | Server-Sent Events | WebSocket | Everything flows one way; plain HTTP with native reconnection |
| Metrics | Prometheus exporter | None | The standard in self-hosted infrastructure |
| Logs | Structured JSON on stdout, live tail in the UI | None | The Docker standard |
| Spam filtering (v0.3+) | rspamd sidecar | Built-in greylisting | Do not reinvent it |

### 4.3 Data model (initial sketch)

> This is the model as first drafted. The schema actually shipped lives in
> [`internal/store/schema.sql`](internal/store/schema.sql) and the numbered
> migrations beside it, and it has moved on: it stores no `blob_path`, since the
> spool is addressed by message id, and it has since gained submission accounts
> and spam verdicts (v2), content filters and quarantine (v3), DKIM keys and
> outbound routes (v4), API tokens, webhook subscriptions with their delivery
> outbox, cluster peers and OIDC identities (v5), and the `operator` role with
> per-user `allowed_domains` (v6). Secrets in those tables (private keys, relay passwords, signing secrets)
> are sealed with the same
> master key the spool uses, so reading the database alone yields nothing usable.

```sql
-- Configured domains
CREATE TABLE domains (
  id          INTEGER PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  primary_host TEXT NOT NULL,         -- e.g. mail.example.com
  primary_port INTEGER NOT NULL DEFAULT 25,
  primary_tls  TEXT NOT NULL DEFAULT 'starttls',  -- none | starttls | tls
  max_queue_size INTEGER,
  max_retention_hours INTEGER DEFAULT 168,  -- 7 days
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Queued messages
CREATE TABLE queue (
  id          TEXT PRIMARY KEY,        -- UUID
  domain_id   INTEGER REFERENCES domains(id),
  envelope_from TEXT NOT NULL,
  envelope_to   TEXT NOT NULL,         -- JSON array
  subject     TEXT,                    -- pulled from the header, for display
  size_bytes  INTEGER NOT NULL,
  blob_path   TEXT NOT NULL,           -- path to the encrypted .eml file
  received_at DATETIME NOT NULL,
  status      TEXT NOT NULL,           -- queued | delivering | delivered | failed | expired
  attempts    INTEGER NOT NULL DEFAULT 0,
  next_retry_at DATETIME,
  last_error  TEXT,
  delivered_at DATETIME
);

-- Cached health of each primary
CREATE TABLE primary_status (
  domain_id   INTEGER PRIMARY KEY REFERENCES domains(id),
  is_up       BOOLEAN NOT NULL,
  last_check  DATETIME NOT NULL,
  last_up     DATETIME,
  last_down   DATETIME,
  consecutive_failures INTEGER DEFAULT 0
);

-- Administrators
CREATE TABLE users (
  id          INTEGER PRIMARY KEY,
  email       TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role        TEXT NOT NULL DEFAULT 'admin',
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Events, for the audit trail and the UI timeline
CREATE TABLE events (
  id          INTEGER PRIMARY KEY,
  type        TEXT NOT NULL,           -- mail_received | mail_delivered | primary_down | ...
  domain_id   INTEGER,
  queue_id    TEXT,
  data        TEXT,                    -- JSON
  created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### 4.4 Public API

The complete route table lives in `internal/api/api.go`. The role in brackets is
the least one required; routes without one need only a signed-in session or a
token (any role), and `operator` routes are further limited to the caller's
`allowed_domains` when that list is set.

```
# Setup and sessions
GET    /api/v1/setup                  → whether the first administrator exists yet
POST   /api/v1/setup                  → create it (refused once one exists)
POST   /api/v1/auth/login             → start a session
POST   /api/v1/auth/logout            → end it
GET    /api/v1/auth/me                → the signed-in account and its role
GET    /api/v1/auth/oidc/login        → begin single sign-on (302 to the provider)
GET    /api/v1/auth/oidc/callback     → finish it, and start a session

# State
GET    /api/v1/status                 → overall state (primaries, queue, disk, TLS, drain, version)
GET    /api/v1/events?limit=100       → timeline
GET    /api/v1/live                   → live events over SSE (queue, status)
GET    /healthz                       → liveness, unauthenticated
GET    /metrics                       → Prometheus (optional bearer token)

# Domains
GET    /api/v1/domains                → list domains
POST   /api/v1/domains                → add one                                  [admin]
GET    /api/v1/domains/:id            → one domain
PATCH  /api/v1/domains/:id            → update it                                [admin]
DELETE /api/v1/domains/:id            → remove it                                [admin]
GET    /api/v1/domains/:id/dns        → the DNS records to publish
POST   /api/v1/domains/:id/test       → test connectivity to the primary         [operator]
GET    /api/v1/domains/:id/dkim       → the signing key's DNS record and state
POST   /api/v1/domains/:id/dkim       → generate one (starts disabled)           [admin]
PATCH  /api/v1/domains/:id/dkim       → enable signing (checks DNS first unless forced), or disable it [admin]
DELETE /api/v1/domains/:id/dkim       → delete the key                           [admin]
GET    /api/v1/domains/:id/dkim/check → does the published record match the key (also POST)
GET    /api/v1/domains/:id/dmarc      → DMARC guidance for the domain
POST   /api/v1/domains/:id/dmarc/check → query the live record over DoH

# Queue
GET    /api/v1/queue?status=queued    → queued mail (paginated)
GET    /api/v1/queue/:id              → one message, without its body
GET    /api/v1/queue/:id/raw          → raw .eml body (audit logged)             [operator]
POST   /api/v1/queue/:id/retry        → force a retry now                        [operator]
POST   /api/v1/queue/:id/release      → release a message from quarantine        [operator]
DELETE /api/v1/queue/:id              → delete it                                [operator]

# Outbound
GET    /api/v1/smtp-users             → submission accounts
POST   /api/v1/smtp-users             → add one                                  [admin]
PATCH  /api/v1/smtp-users/:id         → update it                                [admin]
DELETE /api/v1/smtp-users/:id         → remove it                                [admin]
GET    /api/v1/routes                 → per-destination outbound routes
POST   /api/v1/routes                 → add one                                  [admin]
PATCH  /api/v1/routes/:id             → update it                                [admin]
DELETE /api/v1/routes/:id             → remove it                                [admin]
GET    /api/v1/routes/test            → which path a destination would take

# Inbound protection
GET    /api/v1/filters                → list the content filters
POST   /api/v1/filters                → add one                                  [admin]
PATCH  /api/v1/filters/:id            → update it                                [admin]
DELETE /api/v1/filters/:id            → remove it                                [admin]
POST   /api/v1/filters/test           → try a pattern, or the saved rules, on a sample [admin]
GET    /api/v1/security/status        → DNSBL and ClamAV configuration and health
POST   /api/v1/security/dnsbl/test    → look an address up on the configured lists

# Administration
GET    /api/v1/config                 → export domains and accounts as YAML      [admin]
POST   /api/v1/config                 → apply a YAML document (?dry_run=true)    [admin]
GET    /api/v1/users                  → operators                                [admin]
POST   /api/v1/users                  → pre-provision one                        [admin]
PATCH  /api/v1/users/:id              → change role or allowed domains           [admin]
DELETE /api/v1/users/:id              → remove one (never the last admin)        [admin]
GET    /api/v1/tokens                 → API tokens, by prefix; never the secret  [admin]
POST   /api/v1/tokens                 → mint one (the secret is shown exactly once) [admin]
DELETE /api/v1/tokens/:id             → revoke one                               [admin]
GET    /api/v1/webhooks               → event subscriptions
POST   /api/v1/webhooks               → add one (signing secret generated by default) [admin]
PATCH  /api/v1/webhooks/:id           → update it                                [admin]
DELETE /api/v1/webhooks/:id           → remove it                                [admin]
POST   /api/v1/webhooks/:id/test      → send one synthetic event now             [admin]
GET    /api/v1/webhooks/deliveries    → the delivery log, with attempts and errors
GET    /api/v1/webhooks/events        → the catalogue of subscribable event types
GET    /api/v1/maintenance/drain      → drain mode state and remaining queue     [operator]
POST   /api/v1/maintenance/drain      → enter or leave drain mode                [operator]

# Cluster
GET    /api/v1/cluster                → the fleet, with per-node config drift
DELETE /api/v1/cluster/nodes/:id      → forget a node that is gone for good      [admin]
```

Two further endpoints exist for node-to-node traffic and are not part of the
browser or token API. They are authenticated by an HMAC over the cluster secret
rather than by a session, and answer 404 when clustering is off:

```
POST   /api/v1/cluster/heartbeat    → a peer reports itself; the answer is ours
GET    /api/v1/cluster/config       → the primary's configuration, for a follower
```

### 4.5 Security

- Passwords: Argon2id
- Sessions: httpOnly cookie with SameSite=Lax, rotated at login
- TLS for the UI and the API: HTTPS-only when ACME is on (port 80 then only
  answers the HTTP-01 challenge and redirects everything else to HTTPS), or
  with a static certificate (`http.tls_cert`). Without either, the panel listens
  in plain HTTP on 8080 for first setup and belongs behind a TLS proxy. HSTS is
  only sent over TLS
- Messages encrypted at rest with AES-256-GCM, the key in a 0600 file
  (`<data_dir>/master.key`). Loading it from an environment variable or a KMS
  is not implemented
- SMTP rate limiting per source address
- No open relay: mail is accepted only for configured domains
- Audit log of every admin action (reading a message, deleting one, forcing a retry)
- Standard security headers (strict CSP, HSTS)
- API tokens for non-browser clients, stored as SHA-256 rather than Argon2id:
  256 bits of `rand.Read` has nothing to guess, and stretching it on every call
  would only be a way to attack ourselves. A token acts as the account that
  created it, with the narrower of the two roles, so revoking or demoting the
  person does the same to the token
- Optional OIDC for the panel, with PKCE, a nonce bound to the browser that
  started the sign-in, and accounts matched on the `sub` claim rather than on an
  email address that can be reassigned. An address the provider will not vouch
  for is refused
- Every cluster call is signed over its timestamp, method, path and body, inside
  a five-minute window. There is no unauthenticated mode: those endpoints hand
  out the configuration document
- Webhook payloads are signed with the same HMAC-SHA256 construction the alert
  webhook uses. One scheme, so a receiver cannot implement the wrong one
