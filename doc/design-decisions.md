# Design Decisions

This document records the major implementation choices behind the current MVP and why they were made.

## 1. Rust for the core service and CLI

Decision:
- Build both the daemon and CLI in Rust.

Why:
- Good fit for a local long-running service.
- Easy to ship as static-ish binaries with predictable runtime behavior.
- Strong ecosystem for CLI tooling, SQLite, and process management.
- Keeps the implementation aligned with Codex CLI's environment and the Debian packaging target.

Tradeoff:
- Slower iteration than a scripting language for quick experiments.
- Some integrations still shell out to external tools instead of using native Rust libraries.

## 2. SQLite as the local system of record

Decision:
- Use a single local SQLite database instead of a separate service.

Why:
- Zero extra deployment surface.
- Works well for a single-machine daemon.
- Simple to back up, inspect, and package.
- Enough structure for capabilities, artifacts, findings, opportunities, validations, and proposals.

Tradeoff:
- Not designed for distributed or multi-writer deployments.
- Some richer analytics will eventually want materialized views or a more explicit event log.

Related choice:
- The new federation server uses Postgres instead of SQLite.
- Clients stay on SQLite; only the central or siloed server takes on the multi-host aggregation problem.

## 3. Non-AI collection, AI only at the patch boundary

Decision:
- Keep all observation, normalization, ranking, and ownership inference deterministic.
- Use Codex only for bounded patch proposal generation.

Why:
- Makes the trust boundary obvious.
- Keeps raw crashes and system telemetry local.
- Avoids spending model tokens on work the machine can do deterministically.
- Matches the product thesis from the original brief: AI is a plug-in, not the operating system.

Tradeoff:
- The system does less autonomous "magic" in v1.
- Some contextual triage that an AI could help with is postponed until the evidence bundle is richer.

## 4. System service by default

Decision:
- Package the daemon as a systemd system service and currently run it as root.

Why:
- The product goal is machine-wide visibility.
- Systemd packaging and lifecycle control are natural on Debian and Ubuntu.
- Access to `coredumpctl`, kernel logs, and process telemetry is simpler from a system service.

Tradeoff:
- Root is broader than we want long term.
- A future version should split privileged collectors from unprivileged proposal generation and validation.

## 5. Explicit opt-in before any upload

Decision:
- Keep network participation disabled until the operator explicitly opts in.
- Ship an explicit warning that Fixer may unintentionally collect private data.

Why:
- The system gathers command lines, file paths, warning text, stack traces, and other machine evidence.
- Even with best-effort redaction, some private data can still slip through.
- Opt-in makes the privacy boundary concrete instead of buried in packaging defaults.

Tradeoff:
- The zero-config experience starts in local-only mode, so users who want federation must take one explicit action.

## 6. Anonymous install identity instead of user accounts

Decision:
- Use a generated anonymous install ID with no human login, tokens, or registration flow.

Why:
- Matches the “just works” requirement.
- Keeps public and siloed deployments simple.
- Still gives the server enough continuity to rate-limit, quarantine, and build trust over time.

Tradeoff:
- Install identity is weaker than real authentication.
- Abuse defenses need proof-of-work, rate limits, quarantine, and trust heuristics to compensate.

## 7. Capability detection instead of hard dependency sprawl

Decision:
- Detect optional helper tools at runtime.
- Keep only a small hard dependency set in the Debian package.

Why:
- The package should install on a clean machine even if npm, Python auditing tools, or eBPF tools are absent.
- The CLI can report what is available instead of failing at startup.
- Debian packaging stays simpler and more shareable.

Tradeoff:
- The feature surface varies by host.
- Operator docs have to explain that missing tools reduce capability rather than break the package.

## 8. External observability tools first

Decision:
- Use `coredumpctl`, `journalctl`, `perf`, `dpkg-query`, and optional `bpftrace` by shelling out to system tools.

Why:
- These are the source-of-truth tools already expected on the target systems.
- Faster path to a working MVP than writing or embedding custom tracing stacks.
- Keeps the code close to the operational reality of Debian machines.
- `coredumpctl info` already exposes stack frames, and local symbolizers can often improve unresolved offsets enough to keep evidence useful even when full debug info is missing.

Tradeoff:
- Output parsing is less elegant than tight library integration.
- Tool availability and output format differences need defensive handling.

## 9. Simple finding-to-opportunity mapping in v1

Decision:
- Model one opportunity per finding with an easily explainable score.

Why:
- Easy to reason about and debug.
- Enough to prove the data flow end to end.
- Avoids a premature complex ranking engine while the collectors are still evolving.

Tradeoff:
- Related findings are not yet clustered into a single higher-level issue.
- Scoring is intentionally coarse and will need to become more evidence-driven later.

## 10. Adapter-based ecosystem support

Decision:
- Represent Debian, Cargo, npm, pip, and PGXN support as ecosystem adapters.

Why:
- Keeps metadata discovery and validation logic out of the collector core.
- Makes it easier to add or deepen ecosystems later.
- Lets a watched repo expose validation commands and upstream metadata in a consistent shape.

Tradeoff:
- Current adapters are intentionally thin and focus on repo metadata, not full dependency graph resolution.

## 11. Automatic workspace hydration for Debian-backed findings

Decision:
- When an opportunity has no repo attached but does have a Debian package name, resolve a workspace automatically.
- Prefer Debian source via `apt-get source`, then fall back to cloning the package homepage when it points at a real upstream repository.

Why:
- Matches the product goal of not requiring the user to hand over repos manually.
- Lets machine-level crash and warning findings become patchable workspaces.
- Works even on systems where `deb-src` is not configured, as long as the package exposes a usable upstream homepage.

Tradeoff:
- A homepage clone is not the same thing as the Debian packaging repo.
- Rebuilding the exact Debian package still needs source indexes and package-specific build dependencies.
- Validation time can become large for upstream projects, especially big Cargo workspaces.

## 12. External bug reports for non-patchable packages

Decision:
- When Fixer cannot acquire a patchable workspace for a package-backed finding, deterministic proposals become precise external bug reports instead of patch attempts.

Why:
- Closed-source and binary-only packages like Zoom are still important maintenance targets.
- A precise vendor-ready report is more useful than a fake patch flow when no source tree is available.
- Package version, candidate version, upgrade availability, OS details, and the symbolized stack are often enough to move vendor support conversations forward.
- Shareable reports should not leak meeting links, tokens, or similar command-line secrets, so the rendered report redacts URL query values even though the local evidence bundle remains intact.
- When package metadata exposes a support or bug-report URL, the report should surface that target directly so the automated path does not stop at "someone should file this somewhere."

Tradeoff:
- This path does not validate a code change because there is no code workspace to validate.
- Vendor bug trackers and support flows are less standardized than upstream source repos.

## 13. Proposal bundles as filesystem artifacts

Decision:
- Materialize each patch proposal as a directory containing evidence, prompt, and output files.

Why:
- Easy to inspect and debug manually.
- Good audit trail for what was sent to Codex and what came back.
- Makes submission handoff straightforward.

Tradeoff:
- Bundle cleanup and retention are not automated yet.
- The current evidence bundle contains opportunity data, but not yet rich adjacent-code slices.

## 14. Client/server federation with the same protocol for public and siloed installs

Decision:
- Add a `fixer-server` binary and use the same client protocol for a public central deployment and for siloed/corporate installs.
- Public builds use a baked-in default server URL; siloed installs override it in config or packaging.

Why:
- Keeps the client simple and zero-config.
- Avoids maintaining separate “cloud” and “enterprise” client code paths.
- Lets hosts without Codex still contribute findings while Codex-capable volunteers do the patch attempts.

Tradeoff:
- The server becomes another product surface to operate and package.
- The default public server URL is opinionated and must be override-friendly.

## 15. Proof-of-work plus quarantine as the first anti-spam layer

Decision:
- Protect anonymous submission and worker-pull endpoints with proof-of-work, per-install and per-IP rate limits, duplicate suppression, quarantine, and trust scores.

Why:
- The system deliberately avoids user accounts and manual auth.
- We still need a cheap way to make abuse expensive and keep spam out of the worker queue.
- Quarantine lets us accept submissions without immediately turning them into globally leased work.

Tradeoff:
- Proof-of-work adds client CPU time.
- The current trust model is intentionally simple and will need refinement if the public network grows.

## 16. Single Debian binary package in the MVP

Decision:
- Ship one `fixer` Debian package containing both the CLI and daemon.

Why:
- Simplest install story for early users.
- Avoids splitting packages before the runtime boundary is stable.
- Keeps service, config, and CLI in one shareable artifact.

Tradeoff:
- Collector-only deployments still receive the CLI.
- If privilege separation becomes stronger, splitting packages may become the better design.

## 17. Deliberate non-goals in this version

These are intentionally not implemented yet:

- autonomous upstream submissions
- patching distro binaries in place
- shipping raw coredumps or entire repos to an LLM
- a kernel module or deep in-kernel policy engine
- a desktop UI
- mandatory user accounts or manual API key setup

These omissions are part of the design, not missing polish. The MVP favors a narrow, reviewable system over maximum automation.

## 18. What should change next

If we keep building on this implementation, the next decisions worth revisiting are:

- whether to introduce a separate unprivileged worker for validation and Codex execution
- whether to add a richer event log alongside the current normalized tables
- whether to split packaging into `fixer` and `fixerd`
- whether to bootstrap Debian source indexes and package build-dependencies automatically
- whether to replace generic validation commands with per-ecosystem policy packs
- whether to add structured adjacent-code bundles before asking Codex for patches
- whether to add richer evidence requests with explicit second approval in the CLI
- whether to add admin and moderation tools for siloed servers
