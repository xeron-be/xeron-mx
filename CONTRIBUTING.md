# Contributing to XeronMX

Thanks for your interest. Issues, bug reports, and pull requests are welcome.

## Sign your commits (DCO)

Every commit must carry a `Signed-off-by` line. This line confirms that you wrote the patch or hold the right to submit it under the project's licence, following the [Developer Certificate of Origin](https://developercertificate.org/) used by the Linux kernel.

Git adds this line automatically when using the `-s` flag:

```bash
git commit -s -m "fix retry backoff on first attempt"
```

There is no CLA to sign, no copyright assignment, and no third-party account required.

## Before opening a pull request

Run the automated test suite locally:

```bash
make check     # runs gofmt, go vet, and the full test suite with -race
```

Key guidelines for contributions:

- **Comments explain why, not what.** The code demonstrates what it does. A comment earns its place by recording a non-obvious design decision, a protocol constraint, or a pitfall.
- **New behavior requires tests.** Provide thorough unit and integration coverage, especially in `internal/smtpd`, `internal/store`, and `internal/blob`.
- **No unnecessary dependencies.** Dependencies introduce maintenance overhead and security attack surface for mail infrastructure.
- **Use `modernc.org/sqlite`, not `mattn/go-sqlite3`.** The pure-Go driver keeps the binary static and the container image minimal. Avoid introducing CGO dependencies.

## Three non-negotiable design principles

These properties define the safety guarantees of XeronMX:

1. **Never become an open relay.** Mail is accepted only for domains explicitly configured and enabled. This enforcement lives in `session.Rcpt` with no bypass: no authenticated exceptions, no wildcards, and no test flags.
2. **When unsure, return 4xx, never 5xx.** A 4xx response instructs the sending server to retain the message and retry later. A 5xx causes an immediate bounce. Any non-permanent failure (such as full storage, I/O errors, or temporary lock) returns 4xx.
3. **Delete a message only after the primary accepts it.** Delivery is at-least-once. A duplicate message is an inconvenience; a lost message is a critical failure.

## Security

Do not report security vulnerabilities through public GitHub issues. Please follow the instructions in [SECURITY.md](SECURITY.md).

## Licence

XeronMX is licensed under the AGPL-3.0. All contributions are accepted under this license.
