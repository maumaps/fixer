# Fixer Architecture

This document describes the architecture of the current MVP implementation in this repository. It is intentionally grounded in the code that exists today, not the longer-term product vision from `doc/requirements.md`.

## System shape

Fixer is now split into four layers:

1. Collection and normalization
   - `fixerd` runs collection cycles.
   - Collectors inventory local machine activity and normalize it into a small set of persisted records.
2. Persistence and ranking
   - SQLite stores capabilities, artifacts, findings, opportunities, validation runs, and patch proposals.
   - A simple scoring function turns findings into ranked opportunities.
3. Federation and aggregation
   - Opted-in clients can upload structured finding bundles to a Fixer server.
   - `fixer-server` stores anonymous submissions in Postgres, clusters repeated findings into issues, keeps new installs and new issues quarantined by default, and leases promoted issues to trusted workers.
   - Basic anti-spam and anti-abuse controls are proof-of-work, per-install and per-IP rate limits, duplicate-content suppression, quarantine, and install trust scores.
4. Operator and worker workflows
   - `fixer` exposes commands for collection, inspection, validation, and proposal generation.
   - It also exposes explicit participation commands: `opt-in`, `opt-out`, `sync`, `worker run`, and `participation`.
   - Codex is only used at the proposal stage and only on a bounded evidence bundle, whether that proposal is local-only or comes from a leased server issue.

## Main binaries

- `fixer`
  - Operator-facing CLI.
  - Commands include `collect`, `status`, `capabilities`, `crashes`, `warnings`, `hotspots`, `owners`, `opportunities`, `inspect`, `validate`, `propose-fix`, and `prepare-submit`.
- `fixerd`
  - Long-running daemon wrapper around the same collection pipeline.
  - Reads config, performs a collection cycle, sleeps, and repeats.
- `fixer-server`
  - Aggregation server for opted-in clients.
  - Stores submissions in Postgres, clusters issues, exposes promoted issues, and accepts worker results.

## Module layout

The shared application logic lives in `crates/fixer/src/`.

- `app.rs`
  - Top-level orchestration for loading config, opening the store, running collection, validating, and preparing proposals.
- `config.rs`
  - TOML-backed runtime configuration.
  - Holds service settings, watched repos, log paths, sampling toggles, Codex settings, client network defaults, privacy policy versioning, participation defaults, and server settings.
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
  - Shared record types for local findings and proposals plus the wire format for client/server federation.
- `privacy.rs`
  - Participation policy text plus best-effort secret redaction for outbound bundles.
- `pow.rs`
  - Hashcash-style proof-of-work helpers used by submissions and worker pulls.
- `network.rs`
  - Client-side participation state, submission bundle building, sync, and worker execution.
- `server.rs`
  - Axum HTTP server plus Postgres-backed clustering, quarantine, leasing, and worker result handling.

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
- Participation state
  - Local opt-in state, consent policy version/digest, richer-evidence opt-in, and anonymous install identity.
- Submission bundles
  - Structured uploads containing capabilities, status, redactions, and a set of ranked opportunities plus their underlying findings.
- Issue clusters
  - Server-side aggregation records keyed by normalized finding fingerprints and stack/module signatures.
- Worker leases and patch attempts
  - Server-side records for volunteer workers that try to patch promoted issues or explain why a safe patch is not currently possible.

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

If the host is opted in as a submitter, the same local opportunity graph can also be serialized into a submission bundle. Before upload, Fixer applies best-effort secret redaction to known high-risk string classes such as passwords, query tokens, and bearer headers. The explicit participation policy warns that redaction is not perfect and that private data may still be present unintentionally.

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

In the federated flow:

1. A submitter uploads a redacted finding bundle after explicit opt-in.
2. The server stores the raw bundle, normalizes issue clusters, and keeps them quarantined until corroborated or trusted.
3. A trusted worker host with Codex can pull a promoted issue lease.
4. The worker reuses the normal workspace-acquisition and proposal pipeline locally.
5. The worker sends back either:
   - a patch attempt with local bundle/output paths and a “review and submit upstream” summary
   - an impossibility reason explaining why a safe patch could not be produced
   - an optional request for richer evidence

## Packaging and runtime layout

The Debian package installs:

- `/usr/bin/fixer`
- `/usr/bin/fixerd`
- `/usr/bin/fixer-server`
- `/etc/fixer/fixer.toml`
- `/usr/lib/systemd/system/fixer.service`
- `/usr/lib/tmpfiles.d/fixer.conf`

Default runtime paths:

- database: `/var/lib/fixer/fixer.sqlite3`
- state directory: `/var/lib/fixer`
- default public server URL: `https://fixer.maumaps.org`

The service runs as root in the current package because the MVP needs broad visibility into system telemetry. This is a practical choice, not the desired end state.

## Current limitations

The MVP intentionally stops short of the full product vision:

- no TUI or web UI yet
- no admin UI for siloed server promotion or moderation yet
- no source package graph beyond basic package/path mapping
- no automatic `deb-src` enablement or build-dependency installation yet
- no upstream issue search or maintainer routing beyond local metadata and `git shortlog`
- no raw eBPF integration library yet; optional eBPF support shells out to `bpftrace`
- no automatic branch creation, PR creation, or issue submission
- no privilege separation between collection and proposal execution
- no richer-evidence approval path implemented yet beyond the policy/config shape

## Near-term extensions

The next meaningful architecture steps are:

- split privileged collection from unprivileged validation and patch generation
- enrich artifact ownership from package metadata to source package and upstream trackers
- add Debian source-index management and build-dependency bootstrap for fully hands-off package rebuilds
- add better finding deduplication for warnings and crashes
- improve hotspot collection so it is less expensive and more targeted
- add validation profiles for each ecosystem beyond the current generic commands
- expand proposal bundles with adjacent-code slicing instead of only opportunity metadata
