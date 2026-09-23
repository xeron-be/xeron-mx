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
make ui-test   # the admin UI's tests (needs Node and `npm ci` in web/)
```

`make ui-test` also checks that every API error code and event type the Go code emits has a label in the UI, so run it after adding either.

Key guidelines for contributions:

- **Comments explain why, not what.** The code demonstrates what it does. A comment earns its place by recording a non-obvious design decision, a protocol constraint, or a pitfall.
- **New behavior requires tests.** Provide thorough unit and integration coverage, especially in `internal/smtpd`, `internal/store`, and `internal/blob`.
- **No unnecessary dependencies.** Dependencies introduce maintenance overhead and security attack surface for mail infrastructure.
- **Use `modernc.org/sqlite`, not `mattn/go-sqlite3`.** The pure-Go driver keeps the binary static and the container image minimal. Avoid introducing CGO dependencies.

## Releases

Nothing is tagged by hand. `.github/workflows/release.yml` does it all, from `main` only:

- **Every push to `main`** runs the full CI, then replaces the `edge` pre-release (binaries attached) and pushes the image as `:edge` and `:sha-<commit>`. Commits that only touch Markdown are skipped.
- **A versioned release** is started from the Actions tab: *Release* → *Run workflow*, with the version (for example `1.2.0`). Before that, on `main`:
  1. rename `## [Unreleased]` in `CHANGELOG.md` to `## [1.2.0] - <date>`, open a new empty `## [Unreleased]` above it, and update the link references at the bottom;
  2. set `version` and `appVersion` in `deploy/helm/xeronmx/Chart.yaml` to `1.2.0`.

  The workflow refuses to run if the tag already exists, if the changelog has no section for that version, or if the chart still points at another one. It then tags the exact commit it tested, publishes the release with that changelog section as its notes, and pushes `:1.2.0`, `:1.2` and `:latest`.
- **A pre-release** is the same, with *pre-release* ticked or a version such as `1.2.0-rc.1`. It gets only its own image tag: `:latest` stays on the last stable release. The chart check is skipped.

## Three non-negotiable design principles

These properties define the safety guarantees of XeronMX:

1. **Never become an open relay.** Mail is accepted only for domains explicitly configured and enabled. This enforcement lives in `session.Rcpt` with no bypass: no authenticated exceptions, no wildcards, and no test flags.
2. **When unsure, return 4xx, never 5xx.** A 4xx response instructs the sending server to retain the message and retry later. A 5xx causes an immediate bounce. Any non-permanent failure (such as full storage, I/O errors, or temporary lock) returns 4xx.
3. **Delete a message only after the primary accepts it.** Delivery is at-least-once. A duplicate message is an inconvenience; a lost message is a critical failure.

## Security

Do not report security vulnerabilities through public GitHub issues. Please follow the instructions in [SECURITY.md](SECURITY.md).

## Licence

XeronMX is licensed under the AGPL-3.0. All contributions are accepted under this license.
