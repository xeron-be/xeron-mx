# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Two-step verification for panel accounts: TOTP codes from any authenticator
  app (RFC 6238), turned on from Settings with a QR code, with ten single-use
  recovery codes shown once. The secret is sealed with the master key, a code
  is refused once used, and codes go through the login rate limit. Admins can
  reset another account's second factor, not their own. OIDC accounts and API
  tokens are unaffected
- Password change for the signed-in account, in Settings. It needs the current
  password and ends the account's other sessions. Settings now opens for every
  role, showing non-admins their own account only
- Database schema v9 (three columns on `users`, table `totp_recovery_codes`),
  applied automatically on start

### Security

- Domain scoping leaked across tenants. An account restricted with
  `allowed_domains` received every other domain's traffic on the live stream
  (`/api/v1/live` carried the domain and subject of each message received, for
  all domains), and could read the node-wide settings: submission accounts,
  outbound routes, content filters, webhooks and their delivery log, and the
  cluster. The live stream is now filtered per account, and those listings
  answer such an account with 403 `domain_scoped`. The panel hides the
  matching tabs. Admins, and accounts without `allowed_domains`, are unaffected
- A primary could point inside the host. Whoever creates a domain chooses its
  primary, so `127.0.0.1`, a private address or `169.254.169.254` made delivery,
  health probes and the connectivity test talk SMTP to services on the host or
  its network; in direct mode, a sender's MX could do the same for bounces.
  These destinations are now refused, on the address actually dialled after DNS
  resolution, so a public name later pointed inside is caught too. Relays and
  alert sinks, which only the admin sets, are unaffected
- Drain mode is admin-only. Any operator could enter it, including one scoped
  to a single domain, and drain refuses mail for every domain on the node.
  Reading the drain state stays open to operators

### Fixed

- `docker-compose.yml` pulled rspamd from `ghcr.io/rspamd/rspamd`, which the
  registry refuses, so `--profile spam` never started. It now uses the official
  `rspamd/rspamd` image from Docker Hub

### Changed

- A node whose primary is on a private network (LAN, VPN, the same Kubernetes
  cluster) must now set `queue.allow_private_destinations: true`
  (`XERONMX_QUEUE_ALLOW_PRIVATE_DESTINATIONS`, Helm
  `queue.allowPrivateDestinations`). Until then its messages stay queued with
  an error naming the setting, and the connectivity test says the same

## [1.0.0] - 2026-09-23

First public release. XeronMX was built over a series of internal milestones
that were never published on their own, so everything they produced is listed
here. The Changed, Security and Fixed sections record decisions and defects from
those milestones: they are kept because they explain behaviour a reader might
otherwise take for an accident.

### Added

#### Backup MX core

- SMTP intake on port 25, accepting mail only for configured, enabled domains
- Encrypted spool: AES-256-GCM in a streaming construction, per-file keys derived
  with HKDF-SHA256, with truncation and tampering detection
- SQLite persistence with embedded schema and `user_version` migrations, from
  the initial schema through v8
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

#### TLS

- Automatic certificates from Let's Encrypt via `autocert`, already available
  through `x/crypto` so no new module. The same certificate serves the admin
  panel and STARTTLS on port 25, with the missing SNI that most SMTP clients
  omit filled in from the primary domain
- Issuance and renewal validated live against the Let's Encrypt staging and
  production CAs, for both HTTPS (port 443) and SMTP STARTTLS (port 25)

#### Admin panel and API

- REST API over net/http's own router, with Argon2id passwords, hashed session
  tokens, per-address login throttling, and a strict set of security headers
- Setup wizard that creates the first administrator, then closes permanently
- Primary connectivity test and generated DNS records with a deployment checklist
- Live updates over Server-Sent Events, rather than the WebSocket the spec
  sketched: everything flows one way, and SSE is plain HTTP with browser-native
  reconnection and no dependency
- Audit trail on every admin action, and a hard refusal to show a spooled message
  when the audit entry cannot be written
- Admin web interface: overview with live queue depth and primary state, domain
  management with a connectivity test and generated DNS records, a filterable
  queue with per-message detail, the timeline, filters, the fleet and settings.
  Built with Vite and React, compiled into the binary with `go:embed`, with no
  external assets
- The admin UI speaks English, French, Spanish, Dutch and German. The language
  is chosen in the browser (saved in `localStorage` or taken from
  `navigator.languages`), with a picker in the sidebar. No i18n library: the
  whole mechanism is one file, and English is the fallback for a missing string
  rather than the key, so a gap reads as slightly wrong rather than as machinery
  leaking into the page. `en.ts` is the typed source of truth and the other four
  catalogues are checked against it at compile time, so a missing or stray key
  fails the build instead of shipping
- Prometheus metrics at `/metrics`, with an optional bearer token. The exposition
  format is written directly rather than pulling in `client_golang` and protobuf
  for a handful of gauges
- Configuration as a file: `GET /api/v1/config` exports the domains and
  submission accounts as YAML, `POST /api/v1/config` applies one, and
  `?dry_run=true` reports what would change without touching anything. An import
  creates and updates but never deletes (removing a domain would destroy the mail
  queued for it) and never carries a password, since only the Argon2id hash is
  stored. A document that fails validation is applied in full or not at all
- API tokens for non-browser clients. Stored as SHA-256: a 256-bit random token
  cannot be guessed, and running Argon2id on every API call would create
  excessive CPU overhead. A token acts as the account that made it, with the narrower
  of the two roles, so the audit trail names a person and revoking them revokes
  their tokens
- `xeronmxctl`, a companion CLI covering status, domains, the queue, filters,
  webhooks, tokens, the cluster, config import/export and drain mode, with
  `--json` on every command. It ships in the container image, which is
  `FROM scratch` and has no shell, so `kubectl exec -- /xeronmxctl status` is the
  only way to question a running node without a browser

#### Alerting and webhooks

- Alerting over webhook and email. Four conditions raise an alert: a primary that has
  stayed down past `alerts.primary_down_after`, a spool that has filled and is
  refusing mail, a message given up on before delivery, or a message or
  recipient refused for good by the primary (critical when the body could not
  be read back from the spool, since that is data lost here), plus the recovery
  when a primary comes back, but only if the outage was announced. Routine
  traffic raises nothing. A webhook body is signed with HMAC-SHA256 when a secret
  is set. Repeats of the same condition are throttled by `alerts.min_interval`,
  and a short outage inside the grace period never alerts at all
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

#### Identity and access

- OIDC sign-in for the panel, with PKCE and a nonce bound to the browser that
  started the flow. Accounts are matched on the `sub` claim rather than on an
  email address, and an address the provider will not assert as verified is
  refused. Discovery retries in the background rather than blocking startup: an
  identity provider being down must not stop a mail server from coming up
- Managed OIDC providers: Google Workspace `hosted_domain` (`hd` parameter and
  claim validation), Microsoft Entra ID `skip_email_verified`, and
  `preferred_username` and `upn` fallbacks. Verified live against Keycloak 26 and
  Google Identity
- Three roles: `admin`, `operator` for day-to-day operations and domain
  administration, and `viewer`
- Domain isolation via `allowed_domains`: operators and viewers can be restricted
  to designated domains across queue inspection, retry, release, delete, metrics,
  and timeline events
- OIDC role mapping from token claims (`roles`, `groups`) to `admin`, `operator`,
  or `viewer`
- Operator management in the Settings tab and REST API (`/api/v1/users`):
  administrators can list operators, pre-provision allowed email addresses with a
  role and a domain scope, update them, and delete operators, while the last
  remaining administrator can be neither deleted nor demoted. Combined with
  `auto_provision: false`, this enforces whitelist-based access control for SSO

#### Outbound mail

- Outbound submission on port 587: authenticated SMTP relaying for when the
  primary can receive but cannot send. Credentials are separate from the admin
  accounts, hashed with Argon2id, optionally restricted to named sender domains,
  and AUTH is refused before TLS. Delivery routes through a configured smarthost
  or resolves MX records directly
- Optional DKIM signing for outbound mail, per domain. `POST
  /api/v1/domains/{id}/dkim` generates a key and returns the TXT record to
  publish. A new key starts **disabled**: signing before the record resolves
  makes every message fail verification, which is worse for the domain than not
  signing. RSA-2048 by default, ed25519 on request
- The private half never leaves the server and is never returned by the API. It
  is sealed with the master key the spool already uses, so a stolen database on
  its own yields nothing that can sign as the domain. Unlike the password
  hashes beside it, a signing key is a live credential
- Signatures use relaxed canonicalization and cover `From`, `To`, `Subject`,
  `Date`, `Message-ID` and `MIME-Version`, which keeps the `h=` tag under 78
  characters so that intermediate MTAs (such as Exim) do not wrap it and apply
  RFC 2047 encoding to the `DKIM-Signature` header. The `X-Spam-*` headers added
  at delivery are deliberately outside the signature: signing them would break it
  as soon as another hop did the same. An unreadable key sends unsigned rather
  than holding the mail
- DKIM verified by real receivers: messages signed with RSA-2048 keys generated
  by XeronMX were delivered with `dkim=pass` by both Google (Gmail) and Microsoft
  (Outlook / Exchange Online Protection)
- Per-destination outbound routing. A route overrides the global outbound path
  for one destination, with a leading dot matching subdomains. The most specific
  match wins, and anything unmatched falls through, so a deployment that never
  configures a route behaves exactly as before. `GET /api/v1/routes/test`
  answers which path a destination would actually take. Relay passwords are
  sealed and never returned
- DMARC compliance helper in the admin UI and REST API
  (`GET /api/v1/domains/{id}/dmarc` and `POST /api/v1/domains/{id}/dmarc/check`),
  with live DNS-over-HTTPS queries against Google DNS (`dns.google`) and
  Cloudflare DNS (`1.1.1.1`), policy validation (`none`, `quarantine`, `reject`),
  and alignment checking
- ARC (Authenticated Received Chain, RFC 8617) sealing (`internal/arc`): mail
  forwarded to the primary is sealed with `ARC-Authentication-Results`,
  `ARC-Message-Signature` and `ARC-Seal` using the domain's DKIM key, carrying
  the SPF and DKIM results checked at intake across the extra hop. A chain the
  message already carries (Gmail and Microsoft 365 add one to everything they
  send) is validated at intake, recorded as `arc=pass`, `arc=fail` or
  `arc=none`, and extended with a new set whose `cv` states that result. RSA
  and Ed25519 keys both seal. Checked against dkimpy's independent verifier,
  including a live Gmail chain extended to `i=2`
- `Received:` trace header on every accepted message, inbound and submitted
  (RFC 5321 §4.4), naming the sending host's greeting and address, so the
  primary's own filtering sees the original hop rather than only the backup
  MX. A message that already carries 50 of them is refused with `554 5.4.6`
  as a mail loop
- Delivery status notifications (RFC 3464, `internal/dsn`). When the primary
  refuses a recipient or a whole message for good, or a message outlives its
  retention, the sender receives a standard report naming each failed
  recipient, its status code and the primary's answer, with the original
  headers attached. Only senders authenticated at intake receive one (SPF pass
  for the envelope domain, or a passing DKIM signature aligned with it), never
  the null sender, and the report itself is sent from the null sender:
  a backup MX cannot check recipients while the primary is down, and bouncing
  forged spam would make it a source of backscatter. Reports go through the
  outbound module when it is enabled, straight to the sender's MX otherwise.
  `queue.bounces: off` turns them off
- The message detail, in the panel and in `GET /api/v1/queue/{id}`, shows the
  authentication results recorded at intake and whether the sender counts as
  authenticated, so an operator can tell why a bounce was or was not sent

#### Inbound protection

- Spam filtering through an rspamd sidecar, failing open on every error path.
  Verdicts are recorded on the queue row and rendered as `X-Spam-*` headers at
  delivery, so the encrypted body is never rewritten. Rejecting is opt-in.
  Verified against a real rspamd container
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
- DNSBL reputation checking at connection time (`internal/dnsbl`): concurrent
  queries against configurable blocklists (`zen.spamhaus.org`, `bl.spamcop.net`
  by default), rejecting listed addresses with `554 5.7.1` before any data is
  accepted. Loopback and RFC 1918 ranges are bypassed, IPv4 and IPv6 are both
  reversed, and Spamhaus's "open resolver" answers (`127.255.255.x`) are not
  mistaken for a listing
- ClamAV body scanning (`internal/clamav`) over `zINSTREAM`, on TCP
  (`clamav:3310`) or a UNIX socket (`unix:///path/to/clamd.sock`), with a
  configurable action (`quarantine` or `reject`), fail-open when the scanner is
  unavailable, and a daemon health ping
- `GET /api/v1/security/status` and `POST /api/v1/security/dnsbl/test`, with an
  interactive IP reputation test on the Filters page
- SPF and DKIM checked for every accepted message (`internal/authres`,
  `smtp.sender_auth`, on by default). SPF uses `blitiri.com.ar/go/spf`, which
  passes the RFC 7208 test suite and is what chasquid and maddy use; DKIM uses
  `go-msgauth`, already a dependency. Both run under a ten-second limit and
  fail open: the result is recorded on the message and never refuses mail,
  which stays the primary's decision
- Known recipients, optional per domain: when a domain has a list, any other
  address is refused at `RCPT TO` with `550 5.1.1`, so the sender learns at once
  instead of through a bounce, and spam to invented addresses is never
  accepted. Addresses are compared case-insensitively. Managed from the
  Domains page, `GET`/`PUT /api/v1/domains/{id}/recipients` (admin),
  `xeronmxctl domains recipients` and the `recipients:` key of the configuration
  document, where leaving the key out leaves the list alone

#### Operations

- Container images for `linux/amd64` and `linux/arm64`, and standalone
  binaries on every release: the daemon for Linux, `xeronmxctl` for Linux,
  macOS and Windows. `:latest` is the newest stable release; `:edge` follows
  `main`
- Automatic backups: a consistent snapshot of the database on a schedule, via
  SQLite's `VACUUM INTO`, with retention. Copying a live SQLite file can produce
  a corrupt one; this makes an ordinary volume backup restorable. It covers the
  database, not the message bodies or the master key, which a file-level backup
  already captures correctly
- Spool disk guard (`internal/diskguard`): free space on the spool volume is
  checked before accepting mail, on both Unix (`statfs`) and Windows
  (`GetDiskFreeSpaceEx`). Below `queue.min_free_disk_bytes` (default 1 GiB),
  intake and submission answer `452 4.3.1 Insufficient system storage` at
  `MAIL FROM`, so senders retry later instead of the spool or the database
  filling up. `GET /api/v1/status` reports `disk.free_bytes`,
  `disk.total_bytes`, `disk.min_free_bytes` and `disk.guard_enabled`
- Maintenance drain mode (`internal/maintenance`): intake and submission refuse
  new sessions with `421 4.3.2 Service temporarily unavailable, server is
  draining for maintenance`, so senders defer or fall back to another MX, while
  delivery workers keep flushing the spool down to zero. Driven by
  `xeronmxctl drain` (`--status`, `--cancel`, `--wait`, `--json`) and
  `GET`/`POST /api/v1/maintenance/drain`; the dashboard shows a banner with a
  one-click cancel while it is active
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
- A Kubernetes Helm chart, installed and exercised on Kubernetes 1.32. A
  StatefulSet rather than a Deployment, because each
  replica needs its own spool and two pods on one ReadWriteOnce volume is
  corruption; port 25 mapped by the Service onto a high container port, so no
  ambient capability or sysctl is needed; `externalTrafficPolicy: Local`, so the
  sender's address survives and per-source rate limiting still means something.
  Cluster peer addresses and the primary's node id are generated from the
  StatefulSet, so nothing has to be listed by hand
- Outage drill in CI (`test/drill`, `make drill`): a real Postfix in a
  container is taken down, 20 messages and a 25 MB attachment are held, XeronMX
  is killed with SIGKILL once with the queue full and once mid-delivery, and
  every message is checked byte for byte at the primary, with no loss and no
  duplicate
- An alert when a domain reaches its `max_queue_messages` ceiling: a warning
  scoped to that domain (`queue_full:<domain>`), and the refusal on the domain's
  timeline. The ceiling used to answer `452` silently
- Helm values `smtp.senderAuth` and `queue.bounces`
- PROXY protocol v1 and v2 on ports 25 and 587 (`smtp.proxy_protocol_trusted`,
  Helm `smtp.proxyProtocolTrusted`), so a sender's own address survives a
  load balancer that proxies the connection. Only the listed ranges may send
  the header and they must; from anyone else it is an invalid command, never
  a way to claim another address. Tested behind HAProxy (v1 and v2), directly,
  and with a forged header
- The malware scan outcome is recorded on every message (schema v8,
  `malware_scan`): `clean`, `infected: <name>`, `skipped: larger than N bytes`
  or `failed: <reason>`, shown in the message detail and on the timeline.
  `clamav.max_size_bytes` (25 MiB, clamd's default `StreamMaxLength`) skips
  larger messages without streaming them. A message that was never scanned
  used to look exactly like a clean one

### Changed

- Webhook and alert signatures cover a timestamp: every request carries
  `X-XeronMX-Timestamp`, and `X-XeronMX-Signature` is the HMAC-SHA256 of
  `<timestamp>.<body>`. Receivers reject anything more than five minutes old,
  so a captured request can no longer be replayed. The README shows the check
- Drain mode set at runtime still ends with the process, now documented as
  deliberate: `maintenance.drain: true` keeps a node drained across restarts
- GitHub Actions moved to their current majors (checkout v7, setup-go v7,
  setup-node v7, upload-artifact v7, download-artifact v8, setup-helm v5 and the
  Docker actions), all on Node 24
- The Helm chart is marked beta until it has run behind a real cloud load
  balancer
- REST API errors are stable codes, `{"error": "<error_code>"}`, with the
  meaning carried by the HTTP status. The web UI translates them into all five
  languages and falls back to the raw code when a translation is missing
- `GET /api/v1/events` now returns snake_case fields (`id`, `type`, `domain_id`,
  `queue_id`, `user_id`, `data`, `created_at`). It was the one endpoint still
  serialising Go field names, so a client scripting against the API got
  `received_at` from the queue and `CreatedAt` from the timeline
- `primary_tls` gained an `opportunistic` mode, now the default: STARTTLS when
  the primary offers it, plaintext when it does not, as RFC 7435 describes and
  as Postfix does. `starttls` remains available as the strict mode that refuses
  to deliver without TLS. The previous default would have silently stopped
  delivery to any primary without STARTTLS.
- Configuration export and import moved out of the HTTP handlers into methods
  the cluster also calls, so "what you download" and "what gets replicated" are
  the same document rendered by the same code. `ConfigHash` fingerprints it,
  which is what makes drift detectable in one string
- Database transactions now begin as `BEGIN IMMEDIATE` (see Fixed), and
  `busy_timeout` was raised from 5s to 10s

### Security

- The ARC seal vouched for checks that never ran. With a DKIM key enabled on a
  domain, every message forwarded to the primary carried a signed
  `spf=pass; dkim=pass; dmarc=pass`, written as a constant, and a message that
  arrived with an ARC chain was sealed `cv=pass` without the chain being
  looked at. A primary configured to trust XeronMX as an ARC sealer, which is
  what the seal is for, would have let forged mail through its own checks.
  The seal now carries the results actually checked at intake, `none` when
  nothing was, and an existing chain is sealed only after it has been
  validated, with the `cv` the validation produced
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

- A restart during an outage lost the alerts. The primary's state is kept in
  the database but the alert was only armed when it changed, so after an
  upgrade, a crash or a reboot inside the grace period no "primary down" alert
  was ever sent, and after one the "answering again" notice was not. At
  startup the alerter now reads the primaries already down and arms the grace
  period from when the outage began (checked on AWS: restarted 11 seconds
  into an outage, alerted at the minute, recovery announced)
- Wrong relay credentials failed every outgoing message for good. A `535`
  from the relay was taken as a permanent refusal of the message, so a typo in
  `outbound.relay_password` bounced all outbound mail. It is now a temporary
  failure, logged as an error, and the mail waits for the credentials to be
  fixed, as Postfix does
- Direct outbound delivery (`outbound.mode: direct`, and every bounce when the
  outbound module is off) never delivered a message addressed to more than one
  domain: each attempt failed with "direct mode delivers one domain per
  message" until the message expired. Each domain now gets its own
  transaction, and a domain that cannot be reached holds back only its own
  recipients. A failed MX lookup (timeout, SERVFAIL) no longer falls back to
  the domain's address record, which could deliver to a web server; it is
  retried. A null MX (RFC 7505) and a domain with neither MX nor address now
  fail at once (`556 5.1.10`, `550 5.1.2`) instead of being retried for the
  whole retention
- A bounce sent through a relay that refuses the null sender was lost. Amazon
  SES answers `MAIL FROM:<>` with `501 Invalid MAIL FROM address provided`, so
  the notification failed at once and, being a bounce, was never reported
  anywhere. A bounce refused at `MAIL FROM` by a relay is now sent again in
  the same session from `MAILER-DAEMON@<smtp.hostname>`, the address its
  `From:` already shows. Direct delivery still uses the null sender. Log lines
  for refused outbound mail no longer say "rejected by primary"
- ARC seals failed verification whenever the body had an indented line: the
  relaxed body canonicalization dropped leading whitespace instead of
  reducing it to one space. Earlier sets were also hashed in header order
  rather than instance order, and a domain with an Ed25519 key never sealed
  at all
- The submission listener announced itself as `localhost`: it now uses
  `smtp.hostname`
- `PATCH /api/v1/domains/:id`, `POST /api/v1/domains` and
  `POST /api/v1/domains/:id/dkim` answered with a `created_at` of
  `0001-01-01T00:00:00Z`: they now return the stored row
- A primary with a self-signed, expired or mismatched certificate received no
  mail at all under the default `opportunistic` TLS mode. The handshake
  failure surfaced after the point where the connection could fall back to
  plaintext, so every delivery failed, the primary was reported down, and the
  queue held until messages expired. Opportunistic TLS now encrypts without
  verifying the certificate, as Postfix's `may` level does, and falls back to
  plaintext when the handshake itself fails. `starttls` still requires a
  valid certificate
- The DKIM DNS check listed a published key twice when its record was longer
  than 255 characters: Cloudflare's resolver returns it split into quoted
  strings and Google's joined, and the two were compared before being
  cleaned
- One refused recipient cost every other recipient of the same message. A
  single `550` to `RCPT TO` (a mistyped or deleted mailbox) aborted the whole
  transaction and was taken as a permanent rejection of the message: it was
  marked failed and its body deleted, so the recipients the primary would have
  accepted never received it. A `4xx` for one recipient (a full mailbox) held
  back all the others until it cleared, or until the message expired with
  everyone still waiting. Recipients are now settled one by one: the accepted
  ones are delivered, the refused ones are recorded on the timeline, and a
  message waits only for the recipients that were deferred. This covers mail
  forwarded to the primary and outbound mail alike
- A primary that accepted the connection and then stopped answering held the
  health probe, the "test connection" button and a delivery attempt for up to
  five minutes per SMTP command, whatever `health.timeout` or
  `queue.delivery_timeout` said. go-smtp sets its own deadline on every command,
  replacing the one derived from the context. Because the checker waits for
  every domain before starting the next round, one stalled primary also delayed
  outage detection for all the others. The context now closes the connection
  when it expires, and the error names the expired deadline
- Refusing to delete or demote the last administrator showed the raw code
  `cannot_remove_last_admin` instead of a message: the translations were filed
  under a different key. The UI's tests now check every error code and event
  type the daemon emits against the translations
- Operator changes (`user_created`, `user_updated`, `user_deleted`) and drain
  mode changes (`maintenance_drain`) appeared on the timeline in English
  whatever the panel's language
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
- `queue_full` now reaches the live event stream. It was written to the database
  and nowhere else, so the one condition where mail is actively being refused was
  invisible to both the dashboard and to alerting
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
- Concurrent writers could fail outright with `database is locked`. A
  transaction that reads and then writes (such as the health probe) began
  deferred, so it started as a reader and had to upgrade; if anything wrote in
  between, SQLite answered `SQLITE_BUSY_SNAPSHOT` and failed the transaction.
  `busy_timeout` cannot help there, because there is nothing to wait for.

  The fault was latent from the start and surfaced only when clustering and
  webhooks added two more background writers to a database the health checker
  and the sender already shared: it appeared in the logs of a live two-node run,
  not in any test. Transactions now take the write lock up front, which turns an
  unrecoverable error back into an ordinary wait. A regression test reproduces
  the contention and fails without the fix
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
- Ten CSS classes used by the panel (`section-head`, `inline-form`,
  `grid-2`, `mono-sm`, `right`, `break`, `checkbox`, `checkbox-grid`, `secret`,
  `auth-divider`) had no rules at all. They rendered as browser defaults, which
  reads as a deliberately plain form rather than as a missing stylesheet
- Checkboxes were stretched across their grid cell by the global
  `input { width: 100% }` rule meant for text fields, pushing each label far from
  its box and breaking event names down the middle of a word

### Known limitations

- The Helm chart has run on kind with cloud-provider-kind (install, the
  `LoadBalancer` Service, mail through it, persistence across pod deletion,
  `helm upgrade`), not behind a cloud provider's load balancer. Behind a
  load balancer that proxies connections, as cloud-provider-kind's does, the
  client address is lost despite `externalTrafficPolicy: Local`: XeronMX sees
  the load balancer's address for every sender; configure the PROXY protocol
  (`smtp.proxyProtocolTrusted`) with such a balancer

[Unreleased]: https://github.com/xeron-be/xeron-mx/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/xeron-be/xeron-mx/releases/tag/v1.0.0
