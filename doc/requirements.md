# Fixer Product Brief

This document is the cleaned-up product brief for Fixer.

It comes from the original brainstorming that started the project, but it is written here as a working brief rather than a transcript.

## Problem

Modern Linux machines accumulate a lot of friction:

- packages crash
- background services spin
- warnings pile up
- hot paths stay hot for months
- the real owner of a problem is often unclear
- even when the code is open, the path from “something is wrong” to “here is a patch or report” is still manual and scattered

Fixer exists to close that gap.

The goal is not “an AI that rewrites your machine.” The goal is a local maintenance system that knows what is actually happening, which problems matter, who likely owns them, and how to hand a small, reviewable job to a coding agent.

## Core idea

Fixer should combine two halves:

### 1. A non-AI evidence engine

This side stays deterministic and local.

It should:

- observe package-level and repo-level activity
- profile hot code paths
- collect warnings and crashes
- map binaries and files back to packages, source trees, and upstream metadata
- rank the problems that are actually worth attention

### 2. A bounded fix engine

This side can use Codex, but only after the evidence bundle is small and explicit.

It should:

- receive a sharply scoped task
- work inside a real workspace
- produce either a patch or a credible explanation of why the patch belongs elsewhere
- validate before publication whenever possible

## Product principles

These are the non-negotiable parts of the design.

### Deterministic first

Collection, normalization, and ranking should be understandable without invoking a model.

### Local by default

Fixer should be useful on a single machine even when the network is disabled.

### Honest outputs

If the right answer is “this does not belong in this source tree,” Fixer should say that clearly instead of forcing a fake patch flow.

### Reviewable results

Patches, triage handoffs, and bug-report bundles should all be inspectable by a human.

### Humane operator experience

The system should explain what it knows, what it does not know, and why it made a recommendation.

## What success looks like

A good Fixer session should let a user go from “my machine is acting up” to something concrete:

- a ready-to-review patch
- a successful triage handoff with next steps
- a vendor-ready bug report
- a clear understanding of which package, repo, or maintainer path is involved

The real win is not just automatic code changes. The real win is making maintenance legible and easier to finish.

## Evidence sources

The first versions should lean on mature Linux tooling instead of inventing a new telemetry stack.

Priority inputs:

- `/proc` for process and executable visibility
- `dpkg-query` for package ownership
- watched Git repositories for repo-level context
- `coredumpctl` for crashes
- `journalctl` and configured logs for warnings
- `perf` for hot paths
- optional `bpftrace` for deeper targeted traces

Fixer should prefer executed binaries, loaded libraries, active worktrees, builds, tests, and profiler samples over weak signals like file access time.

## Ownership graph

One of the most important product jobs is building a trustworthy ownership chain:

`process or file -> package or repo -> source package -> upstream project -> likely maintainer path`

That should come from deterministic metadata first:

- Debian package metadata
- npm `repository` and `bugs`
- Python project URLs
- PGXN metadata
- repo-local ownership files and recent Git history

This graph is the moat. Everyone can call a model. Far fewer systems know what is actually worth fixing on one real machine and where that fix should go.

## Opportunity engine

Fixer should rank work using evidence, not vibes.

A useful mental model is:

`score = frequency * pain * confidence * fixability * upstreamability`

Where:

- frequency means how often the issue appears
- pain means crash severity, CPU cost, latency, or user interruption
- confidence means how clearly the system understands the owner and scope
- fixability means whether a bounded patch or deterministic repair is realistic
- upstreamability means whether the result can be handed to the right place

The exact math can evolve. The idea should stay simple.

## Proposal engine

Fixer should try deterministic repair paths before asking an LLM to reason over code.

Examples of deterministic work:

- dependency bumps
- manifest edits
- structural rewrites
- packaging metadata cleanup
- external bug-report generation

When Codex is used, the model should see:

- the smallest useful evidence bundle
- the nearby code it actually needs
- validation expectations
- the likely owner or publication target

It should not see an entire machine snapshot or whole repositories by default.

## Validation and publication

A good fix pipeline should end in evidence-backed output, not silent mutation.

Preferred publication targets:

- a local patch queue
- a local branch
- a draft PR
- a draft bug report
- a mail-ready patch for patch-based communities

Validation should be ecosystem-aware where possible:

- package builds and Debian tooling for Debian-backed work
- project tests for language ecosystems
- regression or extension tests for PGXN and Postgres extensions
- before-and-after profiles for performance work

## Federation

Fixer should work in two modes:

- local-only
- opt-in federation

Federation should let:

- hosts without Codex submit findings
- Codex-capable hosts volunteer as workers
- repeated issues corroborate across machines
- successful patches and successful triage become visible to others

The public deployment should not be a separate product concept. It should be the same protocol and the same mental model, with tighter privacy and abuse controls.

## Privacy stance

Fixer must assume that machine evidence can be sensitive.

That means:

- no uploads before explicit opt-in
- best-effort redaction before upload
- no public raw evidence bundles
- no raw coredumps to the model
- public pages should expose sanitized summaries, not machine gossip

Privacy is not a footnote here. It is one of the reasons the evidence engine should be deterministic and local-first.

## Target ecosystems

The product should support multiple ecosystems, but in a realistic order.

### Debian first

Debian is the strongest starting point because package ownership, source metadata, and machine integration are clear.

### npm next

npm is valuable because repo and bug metadata are often explicit and dependency maintenance workflows are well established.

### pip after that

Python support matters, but environment shape is less standardized, so reproduction discipline matters more.

### PGXN as a focused later target

PGXN is smaller, but strategically interesting because extension metadata and test culture are often clearer than in larger ecosystems.

## Non-goals for the early versions

To stay honest, Fixer should explicitly avoid a few traps:

- no “AI decides everything” pipeline
- no whole-machine autonomous patching
- no raw coredump upload
- no pretending every successful investigation should produce a diff
- no in-place patching of installed distro binaries
- no silent upstream submission without review

## MVP shape

The first useful version should provide:

- a Rust daemon and CLI
- a local SQLite event and proposal store
- package and repo ownership mapping
- crash, warning, hotspot, and stuck-process collection
- a ranked opportunity view
- deterministic proposal paths
- Codex-backed proposal mode for sharply scoped tasks
- a server for opt-in federation
- public issue, patch, and triage boards

If that works well, the next layer can focus on stronger validation, better ownership routing, and tighter privilege separation.

## The plain-English summary

Fixer is trying to be local source maintenance infrastructure for real Linux machines.

The model is important, but it is not the product. The product is the combination of:

- local ground truth
- clear ranking
- good ownership mapping
- humane outputs

If Fixer gets those right, the patches get better too.
