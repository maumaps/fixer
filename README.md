# Maumap Fixer

`fixer` is a local evidence engine for Debian and adjacent ecosystems. It inventories what is actually running, watches configured repos, ingests crashes and warnings, ranks fix opportunities, and can hand a bounded evidence bundle to Codex for a reviewed patch proposal.

## What this MVP includes

- Rust workspace with a shared library and two binaries: `fixer` and `fixerd`
- SQLite-backed inventory of capabilities, artifacts, findings, opportunities, validations, and proposals
- Collectors for process/package usage, watched repos, `coredumpctl`, warning logs, kernel warnings, optional `perf`, and optional `bpftrace`
- Crash ingestion now requires an actual stack trace, then runs a best-effort symbolization pass with local binaries and debug-package hints before ranking the result
- If a package has no patchable source workspace, deterministic proposals fall back to a precise external bug report with package versions, update availability, vendor/support routing, environment details, crash evidence, and a share-safe redacted command line
- Pluggable repo adapters for Debian, npm, pip, and PGXN metadata/validation
- Automatic workspace hydration for Debian-backed opportunities: use an existing repo when present, try `apt-get source` when `deb-src` is configured, otherwise fall back to cloning the package homepage when it is a cloneable upstream repo
- Debian packaging for a local `.deb` install with a systemd service and default config

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

## Packaging

Build an installable Debian package from the repo root:

```bash
dpkg-buildpackage -us -uc -b
```

For the simplest user install, prefer APT over `dpkg -i` so recommended
helper tools are pulled in automatically:

```bash
sudo apt install ../fixer_0.1.0-1_amd64.deb
```

The resulting package installs:

- `/usr/bin/fixer`
- `/usr/bin/fixerd`
- `/etc/fixer/fixer.toml`
- `/usr/lib/systemd/system/fixer.service`

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
