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

### 2.2 Out of scope (for v1.x at least)

- Hosting mailboxes (XeronMX stores no user accounts; it is a relay)
- Webmail
- Advanced spam filtering (delegated to an optional rspamd sidecar)
- IMAP / POP3
- IP and reputation management
- Heavyweight multi-tenancy (one deployment = one operator, managing their own domains)

## 3. User flow (v0.1)

### 3.1 Installation

```bash
mkdir xeronmx && cd xeronmx
curl -o docker-compose.yml https://xeronmx.io/install
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

- Primary down for more than X hours → alert
- Queue past N messages or X GB → alert, and refuse new mail with an SMTP code that makes the sender retry
- Message over the size ceiling → SMTP 552
- Unconfigured domain → SMTP 550

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
| TLS | **Let's Encrypt** built in (lego or autocert) | External reverse proxy | Zero configuration |
| UI auth | Argon2 plus an httpOnly session cookie | JWT | Simpler, and safer by default |
| Metrics | Prometheus exporter | None | The standard in self-hosted infrastructure |
| Logs | Structured JSON on stdout, live tail in the UI | None | The Docker standard |
| Spam filtering (v0.3+) | rspamd sidecar | Built-in greylisting | Do not reinvent it |

### 4.3 Data model (initial sketch)

> This is the model as first drafted. The schema actually shipped lives in
> [`internal/store/schema.sql`](internal/store/schema.sql) and the numbered
> migrations beside it, and it has moved on: it stores no `blob_path`, since the
> spool is addressed by message id, and it has since gained submission accounts
> and spam verdicts (v2), content filters and quarantine (v3), DKIM keys and
> outbound routes (v4), and API tokens, webhook subscriptions with their delivery
> outbox, cluster peers and OIDC identities (v5). Secrets in those tables (private keys, relay passwords, signing secrets)
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

### 4.4 Public API (extract)

```
GET    /api/v1/status               → overall state (primaries, queue depth, version)
GET    /api/v1/domains              → list domains
POST   /api/v1/domains              → add a domain
GET    /api/v1/queue?status=queued  → queued mail (paginated)
GET    /api/v1/queue/:id            → one message, without its body
GET    /api/v1/queue/:id/raw        → raw .eml body (admin only, audit logged)
POST   /api/v1/queue/:id/retry      → force a retry now
DELETE /api/v1/queue/:id            → delete (with confirmation)
GET    /api/v1/events?limit=100     → timeline
GET    /api/v1/domains/:id/dkim     → the signing key's DNS record and state
POST   /api/v1/domains/:id/dkim     → generate one (starts disabled)
GET    /api/v1/routes               → per-destination outbound routes
GET    /api/v1/routes/test          → which path a destination would take
GET    /api/v1/filters              → list the content filters
POST   /api/v1/filters              → add one
POST   /api/v1/filters/test         → try a pattern, or the saved rules, on a sample
POST   /api/v1/queue/:id/release    → release a message from quarantine
GET    /api/v1/config               → export domains and accounts as YAML
POST   /api/v1/config               → apply a YAML document (?dry_run=true)
GET    /api/v1/tokens               → API tokens, by prefix; never the secret
POST   /api/v1/tokens               → mint one (the secret is shown exactly once)
GET    /api/v1/webhooks             → event subscriptions
POST   /api/v1/webhooks             → add one (signing secret generated by default)
POST   /api/v1/webhooks/:id/test    → send one synthetic event now
GET    /api/v1/webhooks/deliveries  → the delivery log, with attempts and errors
GET    /api/v1/webhooks/events      → the catalogue of subscribable event types
GET    /api/v1/auth/oidc/login      → begin single sign-on (302 to the provider)
GET    /api/v1/auth/oidc/callback   → finish it, and start a session
GET    /api/v1/cluster              → the fleet, with per-node config drift
DELETE /api/v1/cluster/nodes/:id    → forget a node that is gone for good
GET    /api/v1/live                 → live events over SSE (queue, status)
GET    /metrics                     → Prometheus
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
- TLS required for the UI and the API (HTTP redirects to HTTPS)
- Messages encrypted at rest with AES-256-GCM, the key in a 0600 file (or an environment variable, or a KMS later)
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
