# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Initial implementation. Fully drivable over the REST API; the browser UI in
front of it is still to come.

### Added

- SMTP intake on port 25, accepting mail only for configured, enabled domains
- Encrypted spool: AES-256-GCM in a streaming construction, per-file keys derived
  with HKDF-SHA256, with truncation and tampering detection
- SQLite persistence with embedded schema and `user_version` migrations
- Queue with atomic multi-worker claim, exponential backoff with jitter,
  retention expiry, and recovery of claims orphaned by a crash
- Primary health checking over a real SMTP handshake, with separate failure and
  success thresholds to prevent flapping
- Delivery workers that forward the spool once the primary answers, pulling the
  queue forward immediately on recovery
- Configuration from YAML with environment overrides, and working defaults for
  every field
- Structured JSON logging, graceful shutdown, and an append-only event timeline
  that doubles as the admin audit log
- Automatic TLS certificate issuance and renewal via Let's Encrypt (ACME),
  validated live against staging and production CAs for HTTPS (port 443) and
  SMTP STARTTLS (port 25)

- REST API over net/http's own router, with Argon2id passwords, hashed session
  tokens, admin and viewer roles, per-address login throttling, and a strict set
  of security headers
- Setup wizard that creates the first administrator, then closes permanently
- Primary connectivity test and generated DNS records with a deployment checklist
- Live event stream over Server-Sent Events
- Audit trail on every admin action, and a hard refusal to show a spooled message
  when the audit entry cannot be written
- Managed OIDC identity provider support verified live against Google Identity /
  Google Cloud OAuth 2.0, with support for Google Workspace `hosted_domain` (`hd`
  parameter and claim validation) and Microsoft Entra ID `skip_email_verified`,
  along with `preferred_username` and `upn` fallbacks.
- Operator management in the Settings tab and REST API (`/api/v1/users`):
  administrators can list operators, pre-provision allowed email addresses with
  assigned roles (`admin` or `viewer`), update roles, and delete operators while
  safeguarding the last remaining administrator from deletion or demotion.
  Combined with `auto_provision: false`, this enforces strict whitelist-based
  access control for SSO.
- Real DKIM deliverability verified in anger by both Google (Gmail) and Microsoft
  (Outlook / Hotmail): outbound emails signed with RSA-2048 keys generated and sealed
  by XeronMX delivered and verified with `dkim=pass` across both major providers
  (`header.s=xeronmx` on Google MX and `dkim=pass (signature was verified)` on Microsoft
  Exchange Online Protection).
- Optimized default signed DKIM headers set (`From`, `To`, `Subject`, `Date`,
  `Message-ID`, `MIME-Version`) for strict RFC 5322 compliance, keeping the `h=` tag
  line length under 78 characters to prevent intermediate MTAs (such as Exim) from
  erroneously wrapping and applying RFC 2047 quoted-printable encoding to the
  `DKIM-Signature` header.
- DMARC compliance helper and DNS guidance in the admin UI and REST API
  (`GET /api/v1/domains/{id}/dmarc` and `POST /api/v1/domains/{id}/dmarc/check`),
  featuring live DNS-over-HTTPS queries against Google DNS (`dns.google`) and Cloudflare
  DNS (`1.1.1.1`), policy validation (`none`, `quarantine`, `reject`), and alignment checking.
- ARC (Authenticated Received Chain, RFC 8617) cryptographic sealing engine (`internal/arc`):
  relayed messages forwarded to the primary mail server are automatically sealed with
  `ARC-Authentication-Results`, `ARC-Message-Signature`, and `ARC-Seal` using the domain's
  sealed DKIM key, preserving origin authentication and preventing SPF penalties on the primary.
- Inbound Perimeter Protection (Milestone v0.8):
  - DNSBL reputation checking at connection time (`internal/dnsbl`): real-time concurrent queries against reputable blocklists (`zen.spamhaus.org`, `bl.spamcop.net`) rejecting botnets and open relays with `554 5.7.1` before spooling or processing data, with automatic bypass for loopback and RFC 1918 private ranges, support for IPv4/IPv6 address reversal, and filtering of Spamhaus open resolver queries (`127.255.255.x`).
  - ClamAV antivirus body scanning (`internal/clamav`): native `zINSTREAM` streaming scanner over TCP (`clamav:3310`) or local UNIX socket (`unix:///path/to/clamd.sock`), supporting configurable action (`quarantine` or `reject`), fail-open on scanner unavailability, and daemon health ping.
  - Security status API and interactive IP reputation testing (`/api/v1/security/status` and `/api/v1/security/dnsbl/test`) integrated into the web UI (`Filters.tsx`), with 100% synchronized multi-language translation parity across EN, FR, DE, ES, and NL.
- Multi-Tenancy & Domain-Scoped RBAC for Operators (Milestone v0.9):
  - Intermediate `operator` role between `admin` and `viewer` for day-to-day operations and domain administration.
  - Domain isolation via `allowed_domains`: operators and viewers can be restricted to designated domains across queue inspection, retry, release, delete, metrics, and timeline events.
  - Dynamic OIDC role mapping: maps external token claims (`roles`, `groups`) to `admin`, `operator`, or `viewer`.
  - Database schema v6 migration with `allowed_domains` JSON list and role constraint.
  - Frontend operator management modal with domain selector pills, inline domain editor, and full multi-language support (EN, FR, DE, ES, NL).
- Spool Disk Guard & Quota Protection (Milestone v1.0):
  - Proactive disk space verification before spooling inbound mail (`internal/diskguard`) with Windows (`windows.GetDiskFreeSpaceEx`) and Unix (`unix.Statfs`) support.
  - Returns polite SMTP error `452 4.3.1 (Insufficient system storage)` at `MAIL FROM` whenever available disk drops below `queue.min_free_disk_bytes` (default 1 GiB), ensuring remote servers retry later without spool corruption.
  - Disk capacity and threshold monitoring integrated into `GET /api/v1/status` (`disk.free_bytes`, `disk.total_bytes`, `disk.min_free_bytes`, `disk.guard_enabled`).
- Graceful Maintenance Drain Mode (Milestone v1.0):
  - Dynamic maintenance drain manager (`internal/maintenance`) to prepare nodes for zero-loss server restarts or host upgrades.
  - Temporarily rejects incoming SMTP traffic on intake and submission ports with `421 4.3.2 Service temporarily unavailable, server is draining for maintenance`, signaling senders to defer or fall back to an alternate MX.
  - Outbound delivery workers remain active to flush existing spool down to zero messages.
  - Managed via CLI `xeronmxctl drain` (with flags `--status`, `--cancel`, `--wait`, `--json`) and REST endpoints `GET /api/v1/maintenance/drain` / `POST /api/v1/maintenance/drain`.
  - Amber warning banner displayed in the web dashboard when drain mode is active, with instant one-click termination.

### Changed

- REST API error responses now return stable error codes in `{"error": "<error_code>"}` with the HTTP status set in the response header (`w.WriteHeader(status)`). The web UI localizes these error codes into EN, FR, ES, NL, and DE, falling back to the raw code if untranslated.
- `GET /api/v1/events` now returns snake_case fields (`id`, `type`, `domain_id`,
  `queue_id`, `user_id`, `data`, `created_at`). It was the one endpoint still
  serialising Go field names, so a client scripting against the API got
  `received_at` from the queue and `CreatedAt` from the timeline
- `primary_tls` gained an `opportunistic` mode, now the default: STARTTLS when
  the primary offers it, plaintext when it does not, as RFC 7435 describes and
  as Postfix does. `starttls` remains available as the strict mode that refuses
  to deliver without TLS. The previous default would have silently stopped
  delivery to any primary without STARTTLS.

- Admin web interface: overview with live queue depth and primary state, domain
  management with a connectivity test and generated DNS records, a filterable
  queue with per-message detail, and the timeline. Built with Vite and React,
  compiled into the binary with `go:embed`, ~54 kB gzipped, no external assets
- Live updates over Server-Sent Events, rather than the WebSocket the spec
  sketched: everything flows one way, and SSE is plain HTTP with browser-native
  reconnection and no dependency
- Automatic certificates from Let's Encrypt via `autocert`, already available
  through `x/crypto` so no new module. The same certificate serves the admin
  panel and STARTTLS on port 25, with the missing SNI that most SMTP clients
  omit filled in from the primary domain
- Prometheus metrics at `/metrics`, with an optional bearer token. The exposition
  format is written directly rather than pulling in `client_golang` and protobuf
  for a handful of gauges

- Outbound submission on port 587: authenticated SMTP relaying for when the
  primary can receive but cannot send. Credentials are separate from the admin
  accounts, hashed with Argon2id, optionally restricted to named sender domains,
  and AUTH is refused before TLS. Delivery routes through a configured smarthost
  or resolves MX records directly
- Spam filtering through an rspamd sidecar, failing open on every error path.
  Verdicts are recorded on the queue row and rendered as `X-Spam-*` headers at
  delivery, so the encrypted body is never rewritten. Rejecting is opt-in
- Schema v2: message direction, spam verdicts, and submission accounts

### Added (v0.4)

- Optional DKIM signing for outbound mail, per domain. `POST
  /api/v1/domains/{id}/dkim` generates a key and returns the TXT record to
  publish. A new key starts **disabled**: signing before the record resolves
  makes every message fail verification, which is worse for the domain than not
  signing. RSA-2048 by default, ed25519 on request
- The private half never leaves the server and is never returned by the API. It
  is sealed with the master key the spool already uses, so a stolen database on
  its own yields nothing that can sign as the domain. Unlike the password
  hashes beside it, a signing key is a live credential
- Signatures use relaxed canonicalization and cover the headers a recipient
  assumes are the sender's. The `X-Spam-*` headers added at delivery are
  deliberately outside the signature: signing them would break it as soon as
  another hop did the same. An unreadable key sends unsigned rather than holding
  the mail
- Per-destination outbound routing. A route overrides the global outbound path
  for one destination, with a leading dot matching subdomains. The most specific
  match wins, and anything unmatched falls through, so a deployment that never
  configures a route behaves exactly as before. `GET /api/v1/routes/test`
  answers which path a destination would actually take. Relay passwords are
  sealed and never returned
- Schema v4

### Added (v0.3)

- Content filters: a regular expression matched against the envelope sender, a
  recipient, or the subject, with one of three actions. Reject refuses with a
  5xx; quarantine accepts the message and holds it out of delivery; allow stops
  evaluation, which is what lets a narrow exception sit above a broad rule.
  Patterns are RE2, so a pathological expression is linear rather than a way to
  stop the server with one email, and they are compiled once on load rather than
  per message. A rule that will not compile is dropped loudly instead of
  silently matching nothing
- Quarantine: held mail keeps its real lifecycle state rather than getting a new
  status, is never claimed for delivery, and never expires out from under an
  operator who has not looked at it yet. Releasing it makes it due immediately,
  so nobody waits out a backoff that was not running. Both the hold and the
  release are on the timeline
- `POST /api/v1/filters/test` tries a pattern, or the whole saved rule set,
  against a sample message without touching the queue. The UI wires it to a
  "Try it" button next to the pattern field
- Saving a filter reloads the running set immediately. The set refreshes on a
  timer too, but a reject rule that quietly does nothing for the first half
  minute reads as the feature being broken
- Schema v3

### Added (v0.2)

- Alerting over webhook and email. Three conditions raise an alert: a primary that has
  stayed down past `alerts.primary_down_after`, a spool that has filled and is
  refusing mail, or a message given up on before delivery, plus the recovery
  when a primary comes back, but only if the outage was announced. Routine
  traffic raises nothing. A webhook body is signed with HMAC-SHA256 when a secret
  is set. Repeats of the same condition are throttled by `alerts.min_interval`,
  and a short outage inside the grace period never alerts at all
- Configuration as a file: `GET /api/v1/config` exports the domains and
  submission accounts as YAML, `POST /api/v1/config` applies one, and
  `?dry_run=true` reports what would change without touching anything. An import
  creates and updates but never deletes (removing a domain would destroy the mail
  queued for it) and never carries a password, since only the Argon2id hash is
  stored. A document that fails validation is applied in full or not at all
- Automatic backups: a consistent snapshot of the database on a schedule, via
  SQLite's `VACUUM INTO`, with retention. Copying a live SQLite file can produce
  a corrupt one; this makes an ordinary volume backup restorable. It covers the
  database, not the message bodies or the master key, which a file-level backup
  already captures correctly
- The admin UI speaks English, French, Spanish, Dutch and German. The language
  is chosen in the browser (saved in `localStorage` or taken from
  `navigator.languages`), with a picker in the sidebar. No i18n library: the
  whole mechanism is one file, and English is the fallback for a missing string
  rather than the key, so a gap reads as slightly wrong rather than as machinery
  leaking into the page. `en.ts` is the typed source of truth and the other four
  catalogues are checked against it at compile time, so a missing or stray key
  fails the build instead of shipping
- `queue_full` now reaches the live event stream. It was written to the database
  and nowhere else, so the one condition where mail is actively being refused was
  invisible to both the dashboard and, once it existed, to alerting

### Security

- Dependencies raised past two advisories that were reachable from the ACME
  code path: an infinite loop on invalid input in `golang.org/x/text`
  (GO-2026-5970) and a Punycode validation failure in `golang.org/x/net/idna`
  (GO-2026-5026). The fixed releases require Go 1.25, so the toolchain moved
  with them. `go-smtp` and `modernc.org/sqlite` were brought current at the
  same time
- `smtp.max_connections` is now enforced. It was documented and defaulted to
  200 but never applied, so both SMTP listeners accepted connections without
  any ceiling, each holding a goroutine and up to 64 KiB of peeked
  headers. Sessions past the limit are answered 421 and closed. `outbound`
  gained the same setting, defaulting to 100
- SMTP AUTH on the submission listener is throttled per source address, the way
  the admin login form already was. Every attempt runs Argon2id over 19 MiB, so
  an unthrottled endpoint was a cheaper way to exhaust the server's memory than
  to guess the password it protects
- Argon2id runs under a concurrency limit, and every entry point now refuses an
  oversized password before hashing it rather than only at account creation
- The setup wizard creates the first administrator in a single statement that
  re-tests emptiness. Checking and inserting separately let two requests
  carrying different addresses both pass the check, which during the window
  between first boot and first login would leave a stranger holding an admin
  account alongside the operator's
- State-changing requests that declare a cross-site `Origin` are refused, behind
  the `SameSite=Lax` session cookie. Requests with no `Origin` (such as curl or
  install scripts) are unaffected
- A successful sign-in clears its address's attempt budget, so the throttle can
  no longer lock an operator out of their own panel

### Fixed

- The container never started on a fresh install. `docker compose up -d`, the
  first command in the README, created a named volume owned by root while the
  image runs as uid 65532, so the daemon could not create its database and exited
  immediately. The data directory is now built into the image already owned by
  that uid, and the volume inherits it
- A delivered message left its encrypted body on disk on Windows. The spool file
  was still open when it was deleted: POSIX unlinks an open file happily, Windows
  refuses, so every delivery leaked a body that nothing later cleaned up once the
  queue row was purged. The handle is closed before the delete on both the
  delivered and the permanently-rejected path
- The data directory is now chmodded to 0700 rather than only being created that
  way. When it already existed (as under Docker), the mode was
  never applied, leaving the SQLite database, and the password and session hashes
  in it, readable by any other uid in the container
- A primary that was never reachable is now reported. `RecordProbe` only
  signalled transitions, and a new domain is seeded down so nothing is delivered
  to a primary that has not answered yet. Consequently, a host that was
  unreachable from the moment it was configured never transitioned, and produced
  no event and no alert. A typo in `primary_host` looked exactly like silence
- A missing certificate no longer breaks the things it protects. The SMTP
  listener advertises STARTTLS whenever a TLS config is set, so between first
  boot and the first issued certificate it offered STARTTLS and then failed the
  handshake (which go-smtp answers with `550`), turning a missing certificate
  into refused mail. The admin panel, HTTPS-only under ACME, was unreachable for
  the same reason, setup wizard included. A self-signed certificate is now served
  in the interim: mail flows encrypted, the panel opens behind a browser warning,
  and the real certificate replaces it without a restart
- Issuance moved off the serving path into a background loop with backoff.
  autocert clears a failed attempt after a minute, so every inbound connection
  that tried STARTTLS started a fresh ACME order, generating enough traffic to cross Let's
  Encrypt's failed-validation limit within minutes and lock issuance out for an
  hour, including after the underlying problem was fixed. TLS-ALPN-01 is still
  answered from the handshake, since that challenge has to be
- The interim certificate is surfaced rather than silent: a dashboard banner, a
  `tls` object in `GET /api/v1/status`, and the last failure in the log
- The Compose file never published port 80, which automatic TLS cannot work
  without: Let's Encrypt connects there by name for the HTTP-01 challenge. The
  challenge listener started inside the container and logged that it had, so the
  failure looked like success until no certificate ever appeared; with ACME
  on, the panel serves HTTPS only, leaving it unreachable. The mapping is now in
  the Compose file, the README says to uncomment it, and the warning logged when
  issuance fails names the port
- Prometheus label values were escaped twice, once by `escapeLabel` and again by
  `%q`, so a domain name containing a backslash rendered with doubled ones. The
  formatting verb is gone and the escaping is now done once, to the exposition
  format's rules rather than Go's

### Added (v0.5)

- Clustering between independent nodes. Peers gossip their queue depth, domain
  count, version and a fingerprint of their configuration; the fleet, and any
  drift between nodes, is visible in the panel and from the CLI. A follower can
  pull the primary's domains and submission accounts when the fingerprints
  disagree, through the same import `POST /api/v1/config` uses.

  The queue is **not** replicated, and the feature says so in the API payload,
  the UI, the CLI and the chart's values file. Two backup MX nodes behind
  equal-priority MX records are already a cluster; each accepts what DNS hands
  it and drains its own spool. What that arrangement lacked was visibility and a
  guarantee against configuration drift: a domain present on one node and missing on another
  is a backup MX answering `550` to whichever senders land on it
- `cluster.primary_node_id` names the primary instead of assigning a role per
  node, so one configuration file serves the whole fleet. It is what makes the
  Kubernetes case work at all (a StatefulSet's pods share a ConfigMap and
  cannot be given different roles), and it removes the split-brain where two
  nodes both believe they are primary
- Event webhooks: any subset of the timeline POSTed to any number of endpoints,
  with exponential backoff, a bounded attempt count, and a persisted delivery
  log. The outbox is a table, not a channel, so a restart mid-retry resumes
  instead of dropping the notification, matching the guarantee of the mail queue.
  Payloads carry the event's id, stable across retries, for receivers that must
  act exactly once
- The dispatcher tails the event log rather than intercepting call sites, so a
  subscriber sees exactly what the timeline shows, including admin actions, and
  an event recorded while it was down is still delivered. A first run starts at
  the head of the log: switching webhooks on does not replay months of history
- OIDC sign-in for the panel, with PKCE and a nonce bound to the browser that
  started the flow. Accounts are matched on the `sub` claim rather than on an
  email address, and an address the provider will not assert as verified is
  refused. Discovery retries in the background rather than blocking startup: an
  identity provider being down must not stop a mail server from coming up
- API tokens for non-browser clients. Stored as SHA-256: a 256-bit random token
  cannot be guessed, and running Argon2id on every API call would create
  excessive CPU overhead. A token acts as the account that made it, with the narrower
  of the two roles, so the audit trail names a person and revoking them revokes
  their tokens
- `xeronmxctl`, a companion CLI covering status, domains, the queue, filters,
  webhooks, tokens, the cluster and config import/export, with `--json` on every
  command. It ships in the container image, which is `FROM scratch` and has no
  shell, so `kubectl exec -- /xeronmxctl status` is the only way to question a
  running node without a browser
- A Kubernetes Helm chart. A StatefulSet rather than a Deployment, because each
  replica needs its own spool and two pods on one ReadWriteOnce volume is
  corruption; port 25 mapped by the Service onto a high container port, so no
  ambient capability or sysctl is needed; `externalTrafficPolicy: Local`, so the
  sender's address survives and per-source rate limiting still means something.
  Cluster peer addresses and the primary's node id are generated from the
  StatefulSet, so nothing has to be listed by hand
- Panel pages for the fleet and settings (event subscriptions,
  delivery log, and API tokens) in all five languages

### Changed (v0.5)

- Configuration export and import moved out of the HTTP handlers into methods
  the cluster also calls, so "what you download" and "what gets replicated" are
  the same document rendered by the same code. `ConfigHash` fingerprints it,
  which is what makes drift detectable in one string
- Database transactions now begin as `BEGIN IMMEDIATE` (see Fixed), and
  `busy_timeout` was raised from 5s to 10s

### Fixed (v0.5)

- Concurrent writers could fail outright with `database is locked`. A
  transaction that reads and then writes (such as the health probe) began
  deferred, so it started as a reader and had to upgrade; if anything wrote in
  between, SQLite answered `SQLITE_BUSY_SNAPSHOT` and failed the transaction.
  `busy_timeout` cannot help there, because there is nothing to wait for.

  The fault was latent from the start and surfaced only when v0.5 added two more
  background writers to a database the health checker and the sender already
  shared: it appeared in the logs of a live two-node run, not in any test.
  Transactions now take the write lock up front, which turns an unrecoverable
  error back into an ordinary wait. A regression test reproduces the contention
  and fails without the fix
- `xeronmxctl` dropped flags written after positional arguments. Go's `flag`
  package stops parsing at the first non-flag argument, so
  `domains add example.com mail.example.com --port 25` silently ignored the port
  and then failed on the argument count, despite parsing earlier arguments. Flags
  and positionals are now accepted in either order
- Certificates shorter than the renewal window were renewed without pause.
  autocert replaces a certificate as soon as less than `RenewBefore` is left and
  applies no floor to that, so a certificate whose whole lifetime is shorter
  than the window is renewed the instant renewal finishes. Against a CA issuing
  ten-minute certificates that measured **3022 issuances in four minutes**
  (about twelve per second), while the log said "certificate ready" once and
  nothing after. Let's Encrypt's per-domain limit would be gone in under five
  seconds and the account blocked.

  Short-lived certificates are not exotic: step-ca issues day-long ones by
  default and Let's Encrypt's short-lived profile is six days, against a
  `RenewBefore` that was hard-coded to thirty. It is now `http.acme.renew_before`
  and documented as needing to be shorter than what the CA issues. A rate guard
  sits on the ACME transport as well, so a misconfiguration costs a warning
  rather than an account: the same runaway now reaches the CA twice in four
  minutes instead of three thousand times, and says why. Found by pointing the
  daemon at a CA configured to issue ten-minute certificates
- No certificate could be obtained when TLS-ALPN-01 was unavailable. autocert
  settles which challenge types an attempt may use once, at the start of that
  attempt, and it only counts HTTP-01 as available after its handler has been
  registered. That registration happened in the listener goroutine, which raced
  the obtain loop and frequently lost, leaving autocert with TLS-ALPN-01 as its
  only option and, when port 443 was not reachable, `no viable challenge type
  found` followed by an hour of backoff having never tried the challenge that
  would have worked. The handler is now built before anything can start
- The HTTP-01 challenge was refused with a 403 when the validator named a port.
  autocert compares the `Host` header verbatim against the configured names, so
  `example.com:80` did not match `example.com`. The refusal goes to the CA
  rather than to the log, so the operator saw only a challenge that never
  passed. Both of these were found by pointing the daemon at Pebble, the Let's
  Encrypt team's own test CA
- An ACME server that omits the optional `Location` header on a finalize
  response is now named as incompatible instead of producing
  `Post "": unsupported protocol scheme ""` once an hour. RFC 8555 does not
  require the header, but `golang.org/x/crypto/acme` reads the order's URL from
  it; Let's Encrypt sends it, Pebble does not. Worth saying out loud because the
  CA has already issued a certificate by that point and every retry issues
  another
- A message rspamd rejected was accepted anyway. rspamd sets `is_skipped` when
  it did not run its whole filter chain, and that covers two opposite outcomes:
  a message it declined to scan, and a passthrough rule reaching a verdict on
  its own and short-circuiting the rest. The second comes back skipped *and*
  rejected (GTUBE, `force_actions`, multimap blocklist, ratelimit), which
  is standard configuration for a hard reject. Reading the flag alone threw
  the strongest verdict rspamd can give straight in the bin and answered 250.

  This was invisible to the test suite because the stub only ever returned what
  a test put in it. It took a real rspamd container to surface, and the real
  payload is now pinned in a regression test that fails without the fix
- Ten CSS classes used by the panel since v0.2 (`section-head`, `inline-form`,
  `grid-2`, `mono-sm`, `right`, `break`, `checkbox`, `checkbox-grid`, `secret`,
  `auth-divider`) had no rules at all. They rendered as browser defaults, which
  reads as a deliberately plain form rather than as a missing stylesheet
- Checkboxes were stretched across their grid cell by the global
  `input { width: 100% }` rule meant for text fields, pushing each label far from
  its box and breaking event names down the middle of a word

### Not yet built

Every feature on the roadmap through v0.5 is built. One optional item remains:
localising the API's own error messages, which needs stable error codes rather
than English prose (v0.2).

Seven things that used to be listed here as unverified have since been run
against the real implementation: a real rspamd (which found the passthrough bug
above), two independent DKIM verifiers, Keycloak 26 for the whole OIDC flow,
Google Cloud OAuth 2.0 / Google Identity for managed OIDC, the Helm chart
installed on Kubernetes 1.32, and the complete ACME path against a production CA
(which found the two certificate bugs above).

What remains genuinely cannot be done on a development machine:

- no certificate has been issued by the live Let's Encrypt CA; that needs a
  publicly resolvable domain with port 80 or 443 open, and it is the only way to
  exercise rate limits, CAA checks and the real chain
- no receiving provider has judged a signature; three implementations agreeing
  is strong evidence, Gmail accepting a message is the thing itself
- kind is a real Kubernetes, but it is one node with no cloud provider, so a
  `LoadBalancer` Service was never satisfied and nothing was learned about a
  real external load balancer
