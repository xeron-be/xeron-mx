# Security policy

XeronMX handles mail delivery and exposes public network ports. Security reports are reviewed promptly and treated with high priority.

## Reporting a vulnerability

**Please do not open a public issue.**

Use GitHub's [private vulnerability reporting](https://github.com/xeron-be/xeron-mx/security/advisories/new) on this repository, which opens a confidential channel visible only to the maintainers.

Please provide as much context as possible:
- Affected version or commit hash.
- Step-by-step reproduction instructions or proof of concept.
- Potential impact and threat assessment.

You can expect an initial acknowledgement within 72 hours and a detailed assessment with remediation timelines within 7 days. Responsible disclosure credits will be included in the advisory unless you request anonymity.

## Supported versions

| Version | Supported |
| :--- | :--- |
| **1.0.x** | **Yes** |
| < 1.0 | No |

## What is in scope

Vulnerabilities with direct security impact on deployments:

- **Relaying**: Any mechanism allowing an external client to route mail through XeronMX for unconfigured or disabled domains.
- **Mail disclosure**: Unauthorized access to queued message bodies, plaintext recovery from the spool without the master encryption key, or cross-tenant visibility.
- **Mail loss**: Any path where an accepted message (2xx response) is dropped without delivery, recording, or expiration.
- **Authentication & session handling**: Flaws in the admin dashboard, session cookies, API tokens, or OIDC single sign-on flows (forged callbacks, replayed authorization codes, or improper claim binding).
- **Remote crashes & DoS**: Exploits causing process termination over SMTP, or memory exhaustion bypassing configured queue ceilings.
- **Container escape & privilege escalation**: Escapes from the non-root container or daemon privilege escalation.
- **Cluster endpoints**: Unauthorized access to peer gossip endpoints or unauthorized configuration injection without the shared cluster secret.
- **Credential leakage**: Exposure of sealed DKIM private keys, relay passwords, webhook HMAC secrets, or API token hashes in API responses.

## What is not in scope

- Rate limiting on authenticated administrative endpoints where access is already restricted.
- Spam or phishing classification: XeronMX acts as an infrastructure relay. Inbound content filtering belongs on the primary server, or via the optional rspamd sidecar.
- Attacks requiring local root filesystem access or physical possession of the host's `master.key`.
- Generic volumetric denial of service: queue ceilings actively protect the host, responding with SMTP 452 by design when full.
- Vulnerabilities in upstream third-party dependencies without a reachable code path in XeronMX.

## Design commitments

These architectural guarantees apply across all releases:

1. Mail is accepted only for configured, enabled domains. No authenticated bypass and no wildcards.
2. Non-permanent failures return 4xx (never 5xx), directing senders to retry rather than bounce.
3. Message bodies are purged from disk only after the destination mail server accepts delivery.
4. Spool bodies are encrypted at rest with AES-256-GCM streaming encryption prior to disk write.
5. All sensitive credentials (DKIM keys, relay passwords, webhook secrets) are sealed with the master key. Admin passwords use Argon2id. Tokens are stored as one-way SHA-256 hashes.
6. Generated secrets and tokens are displayed exactly once upon creation and cannot be retrieved later.
7. Clustering adheres to a shared-nothing model without queue replication, preventing peer compromise from polluting other nodes.
