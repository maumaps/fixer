# Fixer Architecture

This document explains the architecture that exists in this repository today.

It is intentionally practical. The goal is to help someone new to the codebase understand how evidence moves through the system, where responsibilities live, and what Fixer is trying to protect.

## The short version

Fixer has one job: turn real machine problems into small, reviewable maintenance tasks.

In practice that means:

1. collect deterministic evidence locally
2. normalize it into findings
3. rank those findings into opportunities
4. optionally federate sanitized opportunities to a server
5. let workers try to turn promoted issues into either a patch or an honest triage handoff

The collection side is deliberately boring. The patch side is deliberately bounded.

## Runtime pieces

The current system is made of three binaries:

- `fixer`
  - the operator-facing CLI
  - used for collection, inspection, validation, proposal generation, participation, sync, and worker runs
- `fixerd`
  - the long-running daemon wrapper around the same collection pipeline
  - performs a collection cycle, sleeps, and repeats
- `fixer-server`
  - the aggregation server for opted-in hosts
  - accepts submissions, clusters issues, promotes corroborated work, and accepts worker results

## System shape

It helps to think about Fixer as four layers.

### 1. Collection and normalization

`fixerd` and `fixer collect` gather evidence from the local machine:

- running processes and binaries
- Debian package ownership
- watched repositories
- crashes from `coredumpctl`
- warnings and kernel messages
- targeted `perf` profiles
- optional `bpftrace`
- runaway CPU loops and stuck `D`-state processes

The output of this layer is not “AI insight.” It is a normalized set of findings that are stable enough to compare over time.

### 2. Local persistence and ranking

The local store is SQLite.

It keeps:

- capabilities
- artifacts
- findings
- opportunities
- validation runs
- proposals
- participation state

The ranking model is intentionally simple. It prefers obvious, actionable pain over cleverness:

- crashes over hotspots
- hotspots over warnings
- warnings over hygiene findings
- higher severity over lower severity
- findings with ownership or workspace hints over findings with none

### 3. Federation and aggregation

Opted-in clients can upload sanitized bundles to a Fixer server.

The server:

- stores submissions
- clusters repeated findings into issues
- keeps new installs and new issue clusters quarantined by default
- promotes corroborated or trusted issues
- leases promoted work to volunteer workers

The same protocol is used for local, siloed, and public installs. The public deployment is not a separate product line.

### 4. Worker and proposal flow

Workers reuse the same local proposal pipeline. The only difference is where the work item came from.

A worker:

1. pulls a promoted issue lease
2. resolves or prepares a workspace
3. builds a bounded evidence bundle
4. runs deterministic helpers and, when allowed, Codex
5. returns one of three honest outcomes

Those outcomes are:

- patch
- successful triage
- report or impossibility result

Fixer tries hard not to fake a patch when the real answer is “this belongs in a different tree.”

## Module layout

The shared logic lives in `crates/fixer/src/`.

- `app.rs`
  - top-level command orchestration
- `config.rs`
  - TOML-backed runtime configuration
- `capabilities.rs`
  - runtime detection of optional helper tools
- `collectors.rs`
  - local evidence gathering and normalization
- `adapters.rs`
  - ecosystem-specific repo inspection and validation metadata
- `storage.rs`
  - local SQLite schema and persistence
- `proposal.rs`
  - proposal bundles, evidence files, and Codex-facing artifacts
- `workspace.rs`
  - workspace acquisition and hydration
- `models.rs`
  - shared local and wire-format record types
- `privacy.rs`
  - consent text and best-effort redaction
- `pow.rs`
  - proof-of-work helpers for anonymous network endpoints
- `network.rs`
  - client-side participation, sync, and worker execution
- `server.rs`
  - Axum server plus clustering, moderation, leasing, and public rendering

## Data model

The most important records are:

- Capabilities
  - what helper tools are available on this host
- Artifacts
  - concrete things observed on the system or in a repo
- Findings
  - normalized observations such as crashes, warnings, hotspots, or stuck processes
- Opportunities
  - ranked findings that look worth acting on
- Validation runs
  - ecosystem-aware checks for an opportunity
- Proposals
  - local bundles containing evidence, prompt, output, and workspace metadata
- Participation state
  - local opt-in status, consent version, richer-evidence preference, and install identity
- Submission bundles
  - the upload payload for opted-in hosts
- Issue clusters
  - server-side aggregation of repeated findings
- Worker leases
  - the server-side record that a worker is actively handling an issue
- Patch attempts
  - worker results, including successful triage and report-only outcomes

## Collection flow

Each collection cycle is intentionally predictable:

1. detect capabilities
2. inventory running executables from `/proc`
3. map binaries and libraries to Debian packages when possible
4. inspect watched repositories
5. ingest recent crashes from `coredumpctl`
6. ingest warnings and kernel messages
7. sample hot paths with `perf` when available
8. optionally run short `bpftrace` captures
9. normalize observations into finding fingerprints
10. upsert or refresh the corresponding opportunities

The important boundary here is that collection stays deterministic. We want it to be debuggable when it gets something wrong.

## Workspace acquisition

When Fixer wants to validate or propose a fix, it tries to find a real workspace in this order:

1. use the repo already attached to the opportunity
2. fetch Debian source with `apt-get source`
3. clone the package homepage when it looks like a real upstream repository

If none of those work, Fixer should not bluff. It falls back to a triage or bug-report path rather than pretending a patch exists.

## Proposal flow

Proposal generation is deliberately narrow:

1. read the selected opportunity
2. write an evidence bundle into the state directory
3. write the prompt and supporting files
4. resolve the workspace
5. run deterministic helpers and, when enabled, Codex
6. persist the resulting bundle and metadata

The system does not silently submit patches upstream. The output is designed for review and handoff.

## Federation flow

In the networked path:

1. a submitter uploads a redacted finding bundle after explicit opt-in
2. the server stores the bundle and clusters issues
3. new installs and new issues stay quarantined until corroborated or trusted
4. a worker host pulls a promoted issue lease
5. the worker runs the normal local investigation and proposal flow
6. the worker publishes a patch, a successful triage handoff, or a report-only result

Public pages only show sanitized summaries and published worker output that is safe to expose.

## Packaging and runtime layout

The Debian packaging installs:

- `/usr/bin/fixer`
- `/usr/bin/fixerd`
- `/usr/bin/fixer-server`
- `/etc/fixer/fixer.toml`
- `/etc/fixer/fixer-server.toml`
- systemd units for the collector and server

Typical runtime paths are:

- local database: `/var/lib/fixer/fixer.sqlite3`
- local state directory: `/var/lib/fixer`
- standalone server database: `/var/lib/fixer-server/fixer-server.sqlite3`
- public site: `https://fixer.maumap.com`

The current packaged collector still runs as root because it needs broad telemetry access. That is a pragmatic choice, not the desired end state.

## What the architecture is trying to protect

A lot of the shape above is there to protect a few important boundaries:

- collection should be inspectable and deterministic
- private machine evidence should stay local unless a user opts in
- public output should be sanitized
- worker output should be reviewable
- “no honest local fix” should be treated as a valid result, not as failure

That last point matters more than it sounds. Fixer gets healthier when it can say, in public, “this is a real problem, but the fix belongs elsewhere.”

## Current rough edges

A few things are still in motion:

- privilege separation is improving but not finished
- workspace acquisition is much stronger for Debian-backed issues than for everything else
- clustering still needs periodic refinement as new finding types are added
- richer-evidence approval exists in the model, but the UX around it is still maturing
- public boards and worker routing are intentionally conservative, which can make progress feel slower than a looser system

If you are reading the code for the first time, the most useful mental model is this: Fixer is trying to make system maintenance legible. Everything else is in service of that.
