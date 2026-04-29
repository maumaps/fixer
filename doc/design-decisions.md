# Design Decisions

This document records the main choices behind the current Fixer implementation.

The tone here is intentionally plain: what we chose, why we chose it, and what it costs us.

## 1. Rust for the core

What we chose:

- the CLI, daemon, and server are written in Rust

Why:

- long-running local services benefit from predictable resource use
- Rust fits well with CLI tooling, SQLite, HTTP, and Debian packaging
- it keeps the core stable while still letting us shell out to proven system tools

What it costs:

- quick experiments are slower than they would be in a scripting language
- some integrations are still wrappers around external tools rather than native Rust libraries

## 2. SQLite on the client, Postgres on the server

What we chose:

- every client keeps a local SQLite database
- the aggregation server can use SQLite locally and Postgres for shared deployments

Why:

- local installs should be simple and self-contained
- the public and shared server needs stronger multi-writer behavior
- this keeps the client lightweight while giving the server room to grow

What it costs:

- some logic exists in both local and server persistence paths
- richer server-side analytics will eventually want more explicit migration and reporting support

## 3. Deterministic collection, bounded AI at the edge

What we chose:

- evidence gathering, normalization, ranking, and most ownership inference stay deterministic
- Codex is used only at the proposal stage

Why:

- it keeps the trust boundary easy to explain
- it is cheaper, easier to debug, and safer for private telemetry
- the model sees a small, purpose-built bundle instead of an undifferentiated machine state

What it costs:

- the system feels less magical than a fully agentic toy demo
- some nuanced triage still depends on improving the evidence bundle first

## 4. A system service by default

What we chose:

- the packaged collector runs as a systemd system service
- it currently runs as root

Why:

- machine-wide visibility is the whole point
- access to `/proc`, kernel logs, `coredumpctl`, and similar telemetry is much simpler there

What it costs:

- root is broader than we want long term
- we have to be deliberate about how proposal execution and worker actions are separated

## 5. Explicit opt-in before network participation

What we chose:

- nothing is uploaded until the user opts in
- the policy text is intentionally blunt about privacy risk

Why:

- crash data, command lines, paths, and logs can contain private information
- even best-effort redaction is not a promise
- consent should be a real product boundary, not hidden in defaults

What it costs:

- federation is not zero-click
- the happiest path for privacy is slightly slower than the happiest path for growth

## 6. Anonymous install identity instead of accounts

What we chose:

- installs identify themselves with a generated install ID, not a human login

Why:

- it keeps setup light
- it works for public and siloed installs without account infrastructure
- it still gives the server enough continuity for rate limits, trust, and quarantine

What it costs:

- identity is weaker than a real auth system
- the server has to lean on proof-of-work, duplicate suppression, and trust heuristics

## 7. Capability detection instead of hard dependency sprawl

What we chose:

- optional helper tools are discovered at runtime

Why:

- Fixer should install on a plain machine without dragging in every optional tool
- operators can still get value from a partial setup
- this keeps packaging humane

What it costs:

- feature depth varies by host
- docs have to explain missing capability as graceful degradation, not silent failure

## 8. Real system tools first

What we chose:

- Fixer shells out to tools like `coredumpctl`, `journalctl`, `perf`, `dpkg-query`, and optional `bpftrace`

Why:

- those tools are already the source of truth on the target systems
- it is the fastest way to build something honest and useful
- it keeps Fixer close to the operational reality of Debian machines

What it costs:

- output parsing is never as tidy as a native API
- tool availability and output shape need defensive handling

## 9. One finding becomes one opportunity in the MVP

What we chose:

- the first version keeps the mapping simple: one finding, one opportunity

Why:

- it makes the data flow easy to inspect and debug
- collector quality matters more than a fancy ranking engine right now

What it costs:

- some related signals are not grouped as elegantly as they should be
- clustering work has to happen later, especially on the server side

## 10. Adapter-based ecosystem support

What we chose:

- ecosystem-specific logic lives behind adapters

Why:

- Debian, Cargo, npm, pip, and PGXN each expose metadata differently
- adapters keep that complexity out of the collector core
- it gives us one consistent shape for validation and ownership hints

What it costs:

- adapters are intentionally thin today
- deep ecosystem support is still uneven

## 11. Automatic workspace hydration

What we chose:

- when an opportunity has no attached repo, Fixer tries to fetch one automatically

Why:

- machine-level failures are only patchable if they can be connected to code
- users should not have to hand-feed the obvious source tree in every case

Current order:

1. attached repo
2. `apt-get source`
3. download and unpack source files listed by `apt-cache showsrc`
4. clone Debian `Vcs-Git` or `Vcs-Browser` metadata when it points at a real git repo
5. clone the package homepage if it looks like a real upstream repo

What it costs:

- a homepage clone is not always the same thing as the distro packaging tree
- buildability and validation can still be messy

## 12. Honest triage is a success state

What we chose:

- workers can succeed by publishing a clear triage handoff, not only by producing a diff

Why:

- some real issues do not belong in the current source tree
- pretending every successful investigation should end in a patch trains the system to lie
- a strong handoff is often more valuable than a speculative patch

What it costs:

- public and internal result types are a little more complex
- the UI has to distinguish patch success from triage success clearly

## 13. Proposal bundles as filesystem artifacts

What we chose:

- every proposal is materialized as a directory with evidence, prompt, output, and metadata

Why:

- it makes debugging and review much easier
- it creates an audit trail
- it gives the submission and publication paths something concrete to point at

What it costs:

- cleanup and retention need ongoing attention
- the bundle format is now part of the product surface

## 14. One protocol for local, siloed, and public deployments

What we chose:

- the same client protocol is used everywhere

Why:

- the client stays simple
- local and public installs feel like the same product
- override paths are easier than maintaining separate “cloud” and “enterprise” stacks

What it costs:

- the server becomes a more serious product surface
- backwards compatibility matters sooner

## 15. Proof-of-work plus quarantine as the first anti-abuse layer

What we chose:

- anonymous endpoints use proof-of-work, rate limits, duplicate suppression, quarantine, and trust scores

Why:

- we do not want account friction
- we still need the worker queue to stay usable
- quarantine gives new data somewhere safe to land before it becomes global work

What it costs:

- clients spend CPU time to participate
- the trust model is intentionally simple and will need refinement over time

## 16. User-leased Codex auth instead of root-owned Codex auth

What we chose:

- the collector service stays root-owned
- Codex proposal work is leased from a real user and runs with that user's existing auth

Why:

- it is much safer than copying a Codex login into root
- it respects the fact that patch generation is higher-risk than collection
- it creates a natural budget and supervision point

What it costs:

- worker setup is a little more involved
- unattended workers depend on a working user systemd manager and lease state

## 17. Public pages should be useful, not voyeuristic

What we chose:

- public pages expose sanitized summaries, published sessions, patches, and triage handoffs
- they do not expose raw host details or internal evidence bundles

Why:

- the point of public visibility is shared maintenance, not machine gossip
- useful public output needs enough detail to act on, but not enough to leak local context

What it costs:

- sanitization and public rendering need active maintenance
- some rich local evidence cannot be shown directly even when it would be informative

## The through-line

Most of these choices are really the same choice repeated in different forms:

- keep the evidence path boring
- keep the trust boundary obvious
- prefer a smaller honest system over a bigger theatrical one

That does not make Fixer less ambitious. It just means the ambition is aimed at real maintenance work rather than at looking autonomous in a demo.
