<div align="center">

# XeronMX

**Your mail server goes down. You do not lose a single email.**

*A resilient backup MX appliance with real-time visibility, encrypted spool, and full operational control.*

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
[![Built with](https://img.shields.io/badge/built%20with-Go-00add8.svg)](https://go.dev)
[![Release](https://img.shields.io/badge/release-v1.0.0-green.svg)](https://github.com/xeron-be/xeron-mx/releases)

</div>

---

## Overview

When you self-host your email (Mailcow, Mail-in-a-Box, Stalwart, or standalone Postfix), unexpected downtime can happen: power outages, network hiccups, kernel updates, or maintenance windows. While remote mail servers are supposed to retry delivering deferred mail, retry intervals vary widely, and aggressive senders may bounce messages after only an hour.

The proven solution is a **backup MX**: a secondary mail server that queues incoming messages during an outage and delivers them reliably once the primary returns. 

Traditional backup MX setups relying on handwritten Postfix configurations are often black boxes. When an outage occurs, operators have little insight into queue health, spool state, or delivery progress.

**XeronMX solves this problem.** It is a single, self-contained Docker appliance built for transparency and security:
- **Receives** inbound mail for configured domains on port 25 when your primary server is unreachable.
- **Holds** messages in an encrypted streaming spool (AES-256-GCM) on disk.
- **Monitors** your primary server using real SMTP handshakes, not simple ICMP pings.
- **Drains** the queue automatically with exponential backoff and jitter as soon as the primary recovers.
- **Displays** live queue depth, primary health, and audit logs via an embedded web UI and Server-Sent Events (SSE).
- **Protects** against storage saturation (Spool Disk Guard) and enables smooth server maintenance (Graceful Drain Mode).
- **Secures** communications with automatic Let's Encrypt certificates for both SMTP STARTTLS and the web dashboard.
- **Relays** outbound mail over port 587 with DKIM signing (RSA-2048 and ed25519) and destination-based routing.

XeronMX focuses strictly on its core job: it stores no user mailboxes and requires no complex database cluster. It acts as the resilient perimeter safeguard standing in front of your mail infrastructure.

---

## Architectural Principles

1. **Strictly Non-Open Relay**: Mail is accepted exclusively for domains explicitly configured and enabled by the administrator. There are no wildcard routes or open relay mechanisms.
2. **Graceful Deferral (4xx over 5xx)**: If disk space drops below safety thresholds, or if the server enters maintenance mode, XeronMX returns polite temporary SMTP codes (`452` or `421`). Senders back off and retry later without bouncing.
3. **At-Least-Once Delivery**: Messages are deleted from the local spool only after the destination mail server returns an explicit `250 OK`. No email is lost.

---

## How It Works

```
                    ┌──────────────────────────┐
   Internet ───────▶│  MX 10   mail.you.com    │   Primary Server
                    └──────────────────────────┘
                                 ▲
                                 │  Forwards when back online
                    ┌────────────┴─────────────┐
   Internet ───────▶│  MX 20   mx2.you.com     │   XeronMX Backup
                    └──────────────────────────┘
```

DNS configuration requires only two MX records. Sending servers always target priority 10 first and route to priority 20 only when the primary server is unreachable:

```dns
you.com.   IN  MX  10  mail.you.com.
you.com.   IN  MX  20  mx2.you.com.
```

---

## Quick Start

### 1. Run with Docker Compose

Download the official `docker-compose.yml` file and launch the service:

```bash
mkdir xeronmx && cd xeronmx
curl -O https://raw.githubusercontent.com/xeron-be/xeron-mx/main/docker-compose.yml
docker compose up -d
```

Open `http://your-host:8080` in your browser. The setup wizard guides you through:
1. Creating your initial administrator account.
2. Registering your first domain and primary server address.
3. Testing live connectivity to the primary mail server.
4. Viewing the exact DNS records to publish.

Once an administrator account is registered, the setup wizard locks permanently.

**Image tags.** The image is published for `linux/amd64` and `linux/arm64`:

| Tag | What it is |
|-----|------------|
| `latest` | The newest stable release. This is what `docker-compose.yml` pulls. |
| `1.2.0`, `1.2` | A specific release, or the newest patch of a minor version. Pin one of these in production. |
| `edge`, `sha-<commit>` | The current `main` branch, rebuilt on every push. For testing only. |

### 2. Scripting with the REST API

All web dashboard capabilities are accessible through the REST API. You can use a session cookie jar or an API token:

```bash
API=localhost:8080/api/v1
JSON="Content-Type: application/json"

# First-time initialization only:
curl -X POST $API/setup -H "$JSON" -c jar -d '{"email":"admin@you.com","password":"a long secure passphrase"}'

# Add a domain:
curl -X POST $API/domains -b jar -H "$JSON" -d '{"name":"you.com","primary_host":"mail.you.com"}'

# Test connectivity to primary:
curl -X POST $API/domains/1/test -b jar

# Inspect queue and primary state:
curl $API/status -b jar
```

---

## Key Capabilities

### Encrypted Spool at Rest
Every spooled message body is encrypted with AES-256-GCM before writing to disk, using the streaming construction popularized by `age`. Attachments of any size are processed in constant memory. Tampered or truncated spool files fail authentication upon decryption. The encryption key is generated at first boot with restrictive permissions (`0600`) at `<data_dir>/master.key`.

### Spool Disk Guard (Storage Quota Protection)
To prevent disk exhaustion and protect SQLite database integrity, XeronMX actively monitors available storage on the spool volume. If available space drops below `queue.min_free_disk_bytes` (default: 1 GiB), incoming SMTP transactions on ports 25 and 587 are refused at `MAIL FROM` with:
```text
452 4.3.1 Insufficient system storage
```
Sending servers temporarily defer delivery, allowing time to clear disk space or drain the queue.

### Graceful Maintenance Drain Mode
Before restarting the host for OS updates or maintenance, administrators can place the node into drain mode via the CLI or web dashboard:
```bash
xeronmxctl drain --wait
```
In drain mode, inbound intake rejects new connections with:
```text
421 4.3.2 Service temporarily unavailable, server is draining for maintenance
```
Upstream servers immediately fail over to alternate secondary MX nodes or defer. Meanwhile, background delivery workers continue flushing queued messages to the primary until the spool reaches zero.

Drain mode set from the panel, the API or the CLI lasts until the process restarts, deliberately: the usual sequence is drain, stop, update, start, and a backup MX that silently kept refusing mail after that would be worse than one that resumes. To keep a node drained across restarts, set `maintenance.drain: true` (or `XERONMX_MAINTENANCE_DRAIN=true`).

### Inbound Perimeter Protection (DNSBL & ClamAV)
- **DNSBL IP Reputation**: Real-time concurrent checks against configurable blocklists (such as `zen.spamhaus.org` and `bl.spamcop.net`). Listed IPs are rejected at connection with `554 5.7.1` before accepting message data. Private RFC 1918 and loopback addresses are automatically bypassed.
- **ClamAV Streaming Antivirus**: Scans incoming message bodies via `zINSTREAM` over TCP or UNIX sockets. Detected threats can be quarantined or rejected. The scanner fails open if ClamAV is temporarily offline, and messages larger than `clamav.max_size_bytes` (25 MiB by default, clamd's own `StreamMaxLength`) are not sent to it. Every message records the outcome (`clean`, `infected: <name>`, `skipped: larger than ...`, `failed: ...`), shown in the message detail in the panel and on the timeline, so an unscanned message is never mistaken for a clean one. Raise both limits together to scan everything.

### Authenticated Outbound Submission (Port 587)
For environments where the primary server can receive but cannot send directly (for example, residential IP blocks or untrusted subnets), XeronMX accepts authenticated SMTP submissions:
- Dedicated submission accounts with Argon2id password hashing.
- Mandatory TLS before credentials can be transmitted.
- Restrictable to authorized sender domains.
- Direct delivery via recipient MX lookup or forwarding through an upstream smarthost.

### Cryptographic Signatures: DKIM & ARC
- **DKIM Signing**: Generates and manages RSA-2048 and ed25519 signing keys per domain. Private keys are sealed with the master key. Signatures cover From, Reply-To, Subject, Date, To, Cc, Message-ID, In-Reply-To, References, MIME-Version, Content-Type and Content-Transfer-Encoding with relaxed canonicalization, and were verified end to end with dkimpy through a Postfix relay.
- **ARC (Authenticated Received Chain, RFC 8617)**: Attaches `ARC-Seal`, `ARC-Message-Signature`, and `ARC-Authentication-Results` when forwarding mail to your primary server, carrying the SPF and DKIM results XeronMX checked when it received the message. Nothing is claimed that was not checked: with `smtp.sender_auth` off the seal records `none`. A message that already carries an ARC chain (Gmail and Microsoft 365 add one to everything they send) has that chain validated when it arrives, and the new set states the result (`cv=pass` or `cv=fail`); a chain that was already marked failed is not extended. Every accepted message also gets a `Received:` header naming the host that sent it, so the primary's own filters see the original hop.
- **DMARC Compliance Helper**: Queries live DNS records over HTTPS (Google and Cloudflare DoH) to evaluate alignment and recommend publication tags (`p=quarantine` or `p=reject`).

### Sender Authentication, Bounces & Known Recipients
- **SPF and DKIM at intake**: every accepted message is checked (`smtp.sender_auth`, on by default). The check never refuses mail, it records who the sender really is.
- **Bounces only to real senders**: when a recipient or a message is refused by the primary, or a message outlives its retention, XeronMX sends a standard delivery status notification (RFC 3464), but only when the sender was authenticated (SPF pass, or a DKIM signature aligned with the sender's domain). Forged senders of spam get nothing, so the backup MX never becomes a source of backscatter. Set `queue.bounces: off` to disable.
- **How bounces leave**: straight to the sender's MX when the outbound module is off (port 25 must be open outbound, with a PTR and an SPF record for `smtp.hostname`), through the configured relay otherwise. Bounces use the null sender `<>`; a relay that refuses it (Amazon SES does) gets the bounce from `MAILER-DAEMON@<smtp.hostname>` instead, so verify that domain with the relay. Tested end to end through SES: the bounce reached the inbox at Gmail and at Outlook.com with SPF, DKIM and DMARC passing (Microsoft's spam score 1), and Outlook displayed it as a native non-delivery report, reading the reporting host, the recipient and the `5.1.1` status from the machine-readable part. SES also replaces the `Message-ID` header, which breaks XeronMX's own DKIM signature on everything sent through it; with SES, publish SES's Easy DKIM records for your domain so its signature carries DMARC.
- **Known recipients (optional, per domain)**: give a domain its list of valid addresses and any other address is refused at `RCPT TO` with `550 5.1.1`, so the sender is told at once instead of by a bounce. An empty list accepts every address. Managed from the panel, the API, `xeronmxctl domains recipients` or the YAML configuration.

### Behind a Load Balancer (PROXY Protocol)
A load balancer that proxies connections (AWS Classic ELB, an NLB with proxy protocol, HAProxy, Envoy, Kubernetes ingress controllers for TCP) hides every sender behind its own address, and SPF, blocklists, per-source limits and the `Received:` header then all see the balancer. List the balancer's addresses in `smtp.proxy_protocol_trusted` and turn on the PROXY protocol (v1 or v2) on its side: XeronMX then reads each sender's real address from the header, on ports 25 and 587. Only the listed ranges may send the header, and they must; anyone else is served normally and cannot use one to claim another address. Tested behind HAProxy with both versions.

### Setting Up the Primary to Receive from XeronMX
Mail held by XeronMX reaches your primary from XeronMX's address, not the original sender's, so the sender's SPF fails there unless the primary knows XeronMX is a relay it trusts. XeronMX gives it what it needs: a `Received:` header naming the original sending host and address, and an ARC seal carrying the SPF, DKIM and ARC results checked when the message arrived. Some ways to use them:
- **Never** add XeronMX's address to the primary's list of networks allowed to relay (`mynetworks` in Postfix): that lets it send anywhere through your primary. Trust it for filtering only.
- **SpamAssassin** (and filters built on it): list XeronMX in `trusted_networks` and `internal_networks`, so SPF and DNS blocklists are evaluated against the host before it, read from the `Received:` header.
- **Microsoft 365 / Exchange Online**: add XeronMX's host name as a trusted ARC sealer, or turn on Enhanced Filtering for the inbound connector and skip XeronMX's address.
- **rspamd** (Mailcow and similar): treat XeronMX as a trusted relay or trust its ARC seal; check your version's documentation for the exact setting.
- DKIM signatures survive the extra hop unchanged, so DMARC passes on DKIM alone for senders that sign, which is most of them.

### Verifying Webhooks and Alerts
Event webhooks and the alert webhook are signed the same way when a secret is set. Each request carries `X-XeronMX-Timestamp` (Unix seconds) and `X-XeronMX-Signature: sha256=<hex>`, the HMAC-SHA256 of the timestamp, a dot, and the raw body. Check both, and reject anything more than five minutes old, so a captured request cannot be replayed later. Event webhooks also carry `X-XeronMX-Delivery`, to drop the duplicates that retries can produce.

```python
import hashlib, hmac, time

def verify(secret: bytes, headers, body: bytes) -> bool:
    ts = headers["X-XeronMX-Timestamp"]
    if abs(time.time() - int(ts)) > 300:
        return False
    expected = "sha256=" + hmac.new(secret, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, headers["X-XeronMX-Signature"])
```

### Multi-Tenancy & Domain-Scoped RBAC
- Roles: `admin` (full system control), `operator` (queue inspection, retries, quarantine release, domain connectivity tests), and `viewer` (read-only telemetry).
- Domain Scoping: Operators and viewers can be restricted to designated domains (`allowed_domains`), isolating queue entries, metrics, and timeline events.
- Dynamic OIDC Mapping: Maps external SSO group and role claims from identity providers (Google Workspace, Microsoft Entra ID, Keycloak, Okta) directly to local roles.

### High Availability & Clustering
Multiple XeronMX nodes operate in a shared-nothing model behind equal-priority MX records. Nodes gossip operational telemetry (queue depth, primary state, config fingerprints) over peer-to-peer HTTPS. With `sync_config: true`, followers synchronize domain configurations from the primary node to prevent configuration drift.

---

## Command Line Client (`xeronmxctl`)

The companion binary `xeronmxctl` ships alongside the daemon and is embedded in the Docker container image. Standalone builds for Linux, macOS and Windows (amd64 and arm64) are attached to every [release](https://github.com/xeron-be/xeron-mx/releases):

```bash
# Authenticate:
xeronmxctl login --url https://mx2.you.com --token xmx_...

# Check status:
xeronmxctl status

# Inspect and manage queue:
xeronmxctl queue list --status queued --limit 20
xeronmxctl queue retry 01J8Z...

# Replace a domain's known recipients (one address per line):
xeronmxctl domains recipients 1 --file recipients.txt

# Trigger graceful maintenance drain:
xeronmxctl drain --wait

# Cancel drain mode:
xeronmxctl drain --cancel

# Configuration export / import:
xeronmxctl config export > backup.yaml
xeronmxctl config import backup.yaml --dry-run
```

Append `--json` to any command for clean machine-readable output in scripts and automated pipelines.

---

## Configuration Reference

Settings can be specified via YAML (`xeronmx.yaml`) or mapped directly through environment variables (`XERONMX_SMTP_HOSTNAME`, `XERONMX_QUEUE_RETENTION`, etc.):

```yaml
data_dir: /var/lib/xeronmx

smtp:
  addr: ":25"
  hostname: mx2.you.com
  max_message_bytes: 52428800    # 50 MiB

queue:
  max_messages: 100000
  max_bytes: 21474836480        # 20 GiB
  min_free_disk_bytes: 1073741824 # 1 GiB disk guard threshold
  retention: 168h               # 7 days
  workers: 4
  retry_base: 1m
  retry_max: 2h

health:
  interval: 30s
  failure_threshold: 3
  success_threshold: 2

maintenance:
  drain: false                  # Start in drain mode if needed

http:
  addr: ":8080"
  acme:
    enabled: false
    domains: ["mx2.you.com"]
    email: admin@you.com
    terms_agreed: true
    challenge_addr: ":80"

clamav:
  enabled: false
  addr: "tcp://clamav:3310"
  action: quarantine

dnsbl:
  enabled: false
  zones:
    - zen.spamhaus.org
    - bl.spamcop.net

metrics:
  enabled: true

log:
  level: info
  format: json
```

---

## Kubernetes Helm Chart

A Helm chart is available in `deploy/helm/xeronmx`. It is **beta**: rendered and checked in CI, not yet run behind a real cloud `LoadBalancer` (see the chart's README).

```bash
helm install xeronmx ./deploy/helm/xeronmx \
  --set hostname=mx2.you.com \
  --set ui.ingress.enabled=true \
  --set ui.ingress.host=mx2.you.com
```

The chart deploys a `StatefulSet` ensuring dedicated persistent volumes per replica, integrates with `cert-manager` for automated TLS secrets, and sets `externalTrafficPolicy: Local` on the SMTP Service to preserve client IP addresses.

---

## Building from Source

Requirements: Go 1.25 or newer, Node.js 22 (for UI assets). No CGO is required.

```bash
git clone https://github.com/xeron-be/xeron-mx.git
cd xeron-mx

# Build admin UI:
cd web && npm ci && npm run build && cd ..

# Build static Go binaries:
make build      # Outputs bin/xeronmx and bin/xeronmxctl

# Run test suite with race detector:
make check
```

---

## Licence

Licensed under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE). You are free to run, study, modify, and self-host XeronMX. If you provide modifications as a network service, source code must be made available under the same license terms.
