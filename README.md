# Maumap Fixer

`fixer` is a local evidence engine for Debian and adjacent ecosystems. It inventories what is actually running, watches configured repos, ingests crashes and warnings, ranks fix opportunities, and can hand a bounded evidence bundle to Codex for a reviewed patch proposal.

The current tree also includes a client/server federation model:

- `fixerd` stays the local collector and SQLite store
- `fixer-server` aggregates opted-in findings in Postgres
- hosts without Codex can submit findings
- opted-in Codex-capable hosts can volunteer as workers, pull promoted issues, and either produce a patch proposal or explain why a patch is not currently possible

## What this MVP includes

- Rust workspace with a shared library and two binaries: `fixer` and `fixerd`
- SQLite-backed inventory of capabilities, artifacts, findings, opportunities, validations, and proposals
- Collectors for process/package usage, watched repos, `coredumpctl`, warning logs, kernel warnings, optional `perf`, and optional `bpftrace`
- PostgreSQL collation mismatch detection for local clusters, with deterministic remediation proposals that start with `pg_amcheck`, then target only the affected indexes before refreshing the recorded collation version
- Crash ingestion now requires an actual stack trace, then runs a best-effort symbolization pass with local binaries and debug-package hints before ranking the result
- If a package has no patchable source workspace, deterministic proposals fall back to a precise external bug report with package versions, update availability, vendor/support routing, environment details, crash evidence, and a share-safe redacted command line
- Pluggable repo adapters for Debian, npm, pip, and PGXN metadata/validation
- Automatic workspace hydration for Debian-backed opportunities: use an existing repo when present, try `apt-get source` when `deb-src` is configured, otherwise fall back to cloning the package homepage when it is a cloneable upstream repo
- Debian packaging for a local `.deb` install with a systemd service and default config
- A new `fixer-server` binary for central or siloed deployments
- Public deployment assets for `https://fixer.maumap.com`, including a landing page, a light public issues UI, a signed APT repository publisher, and deploy scripts for the canonical server
- Explicit participation modes: `local-only`, `submitter`, and `submitter+worker`
- Anonymous install identity, proof-of-work, quarantine, rate limits, and issue clustering for basic anti-spam and anti-abuse handling

## Quick start

1. Build the binaries:

```bash
cargo build
```

2. Copy the example config and edit watched repos or logs:

```bash
cp examples/fixer.toml ./fixer.toml
```

3. Collect one snapshot:

```bash
cargo run -p fixer -- --config ./fixer.toml collect
```

4. Inspect the data:

```bash
cargo run -p fixer -- --config ./fixer.toml status
cargo run -p fixer -- --config ./fixer.toml opportunities
```

5. Run the daemon loop:

```bash
cargo run -p fixer --bin fixerd -- --config ./fixer.toml run
```

6. Opt in to federation if you want this host to upload findings:

```bash
cargo run -p fixer -- --config ./fixer.toml opt-in --mode submitter
```

7. Push findings to a server:

```bash
cargo run -p fixer -- --config ./fixer.toml sync
```

8. On a Codex-capable host, opt in as a worker and pull one lease:

```bash
cargo run -p fixer -- --config ./fixer.toml opt-in --mode submitter-worker
cargo run -p fixer -- --config ./fixer.toml worker run
```

9. Run the server:

```bash
cargo run -p fixer --bin fixer-server -- --config ./fixer.toml serve
```

10. Build and publish release packages into a signed APT repo:

```bash
scripts/build-release-debs.sh
scripts/publish-apt-repo.sh dist/packages/*/*/fixer_*_*.deb
```

## Packaging

Build an installable Debian package from the repo root:

```bash
dpkg-buildpackage -us -uc -b
```

For the simplest user install, prefer APT over `dpkg -i` so recommended
helper tools are pulled in automatically:

```bash
sudo apt install ../fixer_*.deb
```

The resulting package installs:

- `/usr/bin/fixer`
- `/usr/bin/fixerd`
- `/usr/bin/fixer-server`
- `/etc/fixer/fixer.toml`
- `/usr/lib/systemd/system/fixer.service`
- `/usr/lib/systemd/system/fixer-server.service`

The canonical public endpoint is `https://fixer.maumap.com`, and the public APT repository is expected at `https://fixer.maumap.com/apt/`.

## Privacy and participation

Network participation is opt-in. Until you explicitly run `fixer opt-in`, the daemon stays local-only.

When you opt in, Fixer warns that it may unintentionally collect private data such as:

- local paths
- command lines
- warning text
- stack traces
- package metadata

Uploads go through best-effort secret redaction first, but redaction is not perfect. High-risk artifacts such as raw coredumps or whole repositories are not auto-uploaded; the intended model is a second explicit approval before richer evidence is shared.

The public/no-config path is:

- client binaries default to a baked-in server URL
- each install creates an anonymous install ID locally
- submissions and worker pulls require proof-of-work
- new installs and new issue clusters stay quarantined until corroborated or trusted

## Documentation

- [Architecture notes](./doc/architecture.md)
- [Design decisions](./doc/design-decisions.md)
- [Original product brief](./doc/requirements.md)

## Notes

- Debian-available helper tools now ship as package recommendations, so a normal `apt install ./fixer...deb` will usually pull in `perf`, `bpftrace`, `cargo`, `nodejs`, `npm`, `python3-pip`, and `postgresql-client`.
- `pip-audit` is still not bundled through Debian packaging here because there is no native Debian package for it in this environment.
- Optional tools are detected at runtime. Missing `npm`, `pip-audit`, `perf`, or `bpftrace` reduce features but do not block startup.
- Automated Debian source retrieval prefers `apt-get source`, but if the machine has no `deb-src` entries configured, Fixer now falls back to cloning a package homepage when it points at a real upstream repository.
- The packaged service currently runs as root so it can access system-wide telemetry. Hardening and privilege separation are the next major step.
- The new federation mode uses SQLite on clients and Postgres on the server. The same server binary is meant to work both for a public central deployment and for a siloed corporate/local deployment with a config override for `network.server_url`.
