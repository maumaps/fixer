# Fixer Architecture

This document describes the architecture of the current MVP implementation in this repository. It is intentionally grounded in the code that exists today, not the longer-term product vision from `doc/requirements.md`.

## System shape

Fixer is split into three layers:

1. Collection and normalization
   - `fixerd` runs collection cycles.
   - Collectors inventory local machine activity and normalize it into a small set of persisted records.
2. Persistence and ranking
   - SQLite stores capabilities, artifacts, findings, opportunities, validation runs, and patch proposals.
   - A simple scoring function turns findings into ranked opportunities.
3. Operator workflows
   - `fixer` exposes commands for collection, inspection, validation, and proposal generation.
   - Codex is only used at the proposal stage and only on a bounded evidence bundle.

## Main binaries

- `fixer`
  - Operator-facing CLI.
  - Commands include `collect`, `status`, `capabilities`, `crashes`, `warnings`, `hotspots`, `owners`, `opportunities`, `inspect`, `validate`, `propose-fix`, and `prepare-submit`.
- `fixerd`
  - Long-running daemon wrapper around the same collection pipeline.
  - Reads config, performs a collection cycle, sleeps, and repeats.

## Module layout

The shared application logic lives in `crates/fixer/src/`.

- `app.rs`
  - Top-level orchestration for loading config, opening the store, running collection, validating, and preparing proposals.
- `config.rs`
  - TOML-backed runtime configuration.
  - Holds service settings, watched repos, log paths, sampling toggles, and Codex settings.
- `capabilities.rs`
  - Detects optional helper tools at runtime.
  - This lets the package stay installable even when optional integrations are absent.
- `collectors.rs`
  - Collects process/package usage, watched repos, crashes, warning logs, kernel warnings, optional perf hotspots, and optional `bpftrace` output.
  - Crash collection only keeps coredumps that include stack frames, chooses the most informative thread when multiple thread stacks are present, and runs a best-effort local symbolization pass on unresolved frames.
- `adapters.rs`
  - Repo-level ecosystem detection and metadata/validation lookup for Debian, Cargo, npm, pip, and PGXN.
- `storage.rs`
  - SQLite schema creation and all read/write operations.
- `proposal.rs`
  - Creates proposal bundles, writes evidence files, and optionally invokes `codex exec`.
  - Deterministic proposals can also generate external bug-report bundles when Fixer cannot acquire a patchable workspace, including package/update metadata and a redacted report-safe command line.
- `workspace.rs`
  - Resolves a patchable workspace for an opportunity.
  - Uses an attached repo when one exists, then tries `apt-get source` for Debian packages, then falls back to cloning a package homepage when it looks like a real upstream repository.
- `models.rs`
  - Shared record types for capabilities, findings, opportunities, validation runs, proposals, and repo insights.

## Data model

The current pipeline uses these record types:

- Capabilities
  - Runtime view of which helper binaries are available.
  - Example: `perf`, `bpftrace`, `coredumpctl`, `npm`, `codex`.
- Artifacts
  - Things observed on the system or in configured repos.
  - Examples: a running binary, a watched repo.
- Findings
  - Normalized observations worth tracking.
  - Examples: a crash, a warning, a hotspot, missing repo metadata.
- Opportunities
  - Ranked findings ready for operator action.
  - One opportunity is derived from one finding in the MVP.
- Validation runs
  - Results of ecosystem-specific validation commands for an opportunity.
- Proposals
  - Output bundles for deterministic or Codex-backed patch proposals.
  - Proposal bundles now also record the prepared workspace that Fixer resolved for patching.

## Collection flow

Each collection cycle follows this order:

1. Detect runtime capabilities and persist them.
2. Inventory currently running executables from `/proc`.
3. Map executable paths to Debian packages with `dpkg-query -S` when possible.
4. Inspect configured watched repos and enrich them through an ecosystem adapter.
5. Ingest recent crashes from `coredumpctl`.
   - Reject coredumps with no stack frames at all.
   - Prefer the thread with the highest number of useful frames for summaries and evidence.
   - Try to improve `n/a (object + offset)` frames through local symbolizers and package/debug-symbol hints before storing the crash.
6. Ingest warning lines from configured logs and kernel warnings from `journalctl`.
7. Optionally sample hotspots with `perf`.
8. Optionally capture a short `bpftrace` run.
9. Normalize each observation into a finding fingerprint.
10. Upsert or refresh the corresponding opportunity.

When an operator later validates or proposes a fix for an opportunity, Fixer resolves a workspace in this order:

1. use the repo already attached to the opportunity
2. fetch Debian source with `apt-get source` if `deb-src` is configured
3. clone the package homepage if it points at a cloneable upstream repo

If none of those work and the operator asks for a deterministic proposal, Fixer falls back to an external bug-report bundle instead of failing outright. That bundle includes installed and candidate package versions, upgrade guidance, host details, crash metadata, the locally symbolized stack, a redacted command line suitable for sharing with a vendor, and any vendor/support URL discoverable from package metadata.

## Scoring model

The scoring model is intentionally simple in v1. It prioritizes:

- crashes over hotspots
- hotspots over warnings
- warnings over repo hygiene findings
- higher severity over lower severity
- opportunities that already have a repo root or ecosystem hint

This is a placeholder for a more evidence-rich opportunity engine later. The current version is deliberately easy to understand and debug.

## Repo and ecosystem resolution

Repo inspection uses deterministic adapters instead of AI:

- Debian
  - looks at `debian/control` and related packaging metadata
- Cargo
  - looks at `Cargo.toml`
- npm
  - looks at `package.json`
- pip
  - looks at `pyproject.toml`, `requirements.txt`, or `setup.cfg`
- PGXN
  - looks at `META.json`

Each adapter can provide:

- a display name
- upstream and bug tracker URLs
- a small owner list
- validation commands
- raw metadata for storage

Owner detection currently uses `git shortlog` as a pragmatic fallback.

## Proposal flow

Proposal generation is intentionally bounded:

1. Read the selected opportunity from SQLite.
2. Write an evidence bundle into the state directory.
3. Write a prompt that points Codex at that evidence bundle.
4. Either:
   - create a deterministic summary artifact, or
   - run `codex exec` inside the opportunity's repo root.
5. Persist the proposal bundle, output paths, and workspace metadata.

The system does not auto-submit patches upstream. `prepare-submit` creates a handoff artifact for manual review and publication.

## Packaging and runtime layout

The Debian package installs:

- `/usr/bin/fixer`
- `/usr/bin/fixerd`
- `/etc/fixer/fixer.toml`
- `/usr/lib/systemd/system/fixer.service`
- `/usr/lib/tmpfiles.d/fixer.conf`

Default runtime paths:

- database: `/var/lib/fixer/fixer.sqlite3`
- state directory: `/var/lib/fixer`

The service runs as root in the current package because the MVP needs broad visibility into system telemetry. This is a practical choice, not the desired end state.

## Current limitations

The MVP intentionally stops short of the full product vision:

- no TUI or web UI yet
- no background job queue beyond the daemon loop
- no source package graph beyond basic package/path mapping
- no automatic `deb-src` enablement or build-dependency installation yet
- no upstream issue search or maintainer routing beyond local metadata and `git shortlog`
- no raw eBPF integration library yet; optional eBPF support shells out to `bpftrace`
- no automatic branch creation, PR creation, or issue submission
- no privilege separation between collection and proposal execution

## Near-term extensions

The next meaningful architecture steps are:

- split privileged collection from unprivileged validation and patch generation
- enrich artifact ownership from package metadata to source package and upstream trackers
- add Debian source-index management and build-dependency bootstrap for fully hands-off package rebuilds
- add better finding deduplication for warnings and crashes
- improve hotspot collection so it is less expensive and more targeted
- add validation profiles for each ecosystem beyond the current generic commands
- expand proposal bundles with adjacent-code slicing instead of only opportunity metadata
