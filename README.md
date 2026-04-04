# Maumap Fixer

`fixer` is a local evidence engine for Linux machines.

It watches what is actually happening on a host, turns that into a small set of ranked problems, and helps turn those problems into one of two honest outcomes:

- a diff-backed patch proposal
- a clear triage handoff explaining why the fix belongs somewhere else

The important boundary is that collection stays deterministic and local. AI only enters at the patch-and-explanation stage, after Fixer has already done the boring but important work of gathering evidence, mapping ownership, and shrinking the task.

## What Fixer does today

Fixer currently includes:

- a local collector daemon, `fixerd`
- a CLI, `fixer`
- a standalone aggregation server, `fixer-server`
- a local SQLite store for findings, opportunities, validations, and proposals
- opt-in federation so machines can share sanitized findings
- volunteer worker flow so Codex-capable hosts can investigate promoted issues
- a public site and APT repository at `https://fixer.maumap.com`

On a single machine, Fixer can already:

- inventory running binaries and map them to packages
- inspect watched repositories and detect ecosystems
- ingest crashes, warnings, hotspot profiles, runaway CPU loops, and stuck `D`-state processes
- score and rank fix opportunities
- hydrate a workspace automatically for many Debian-backed issues
- generate either a patch proposal or a report-ready triage bundle

In federation mode, opted-in hosts can:

- upload structured findings
- corroborate the same issue across machines
- pull promoted issues as workers
- publish a patch attempt or a successful triage result back to the server
- sync a ready local Codex proposal with its issue so the public patch or triage artifact appears immediately after upload

## How to think about it

Fixer is easiest to understand as five steps:

1. Observe the machine.
2. Normalize what it found into stable findings.
3. Rank those findings into opportunities worth attention.
4. Resolve a real workspace when possible.
5. Produce a patch or a clear explanation of why a patch would be dishonest.

That means Fixer is not trying to be “an AI daemon that rewrites your machine.” It is much closer to maintenance infrastructure: a local evidence engine with an AI plug-in at the very edge.

## Quick start

1. Build the binaries:

```bash
cargo build
```

2. Copy the example config:

```bash
cp examples/fixer.toml ./fixer.toml
```

3. Run one collection pass:

```bash
cargo run -p fixer -- --config ./fixer.toml collect
```

4. Inspect what Fixer found:

```bash
cargo run -p fixer -- --config ./fixer.toml status
cargo run -p fixer -- --config ./fixer.toml opportunities
```

5. If you want the background daemon:

```bash
cargo run -p fixer --bin fixerd -- --config ./fixer.toml run
```

6. If something feels wrong before Fixer has a crisp finding yet, you can describe it in plain language and let it build a local triage plan:

```bash
cargo run -p fixer -- --config ./fixer.toml complain "chrome is slow when opening tabs"
```

Or open a free-form complaint draft in your editor:

```bash
cargo run -p fixer -- --config ./fixer.toml complain
```

## Federation quick start

Until you opt in, Fixer stays local-only.

To let one host submit findings:

```bash
cargo run -p fixer -- --config ./fixer.toml opt-in --mode submitter
cargo run -p fixer -- --config ./fixer.toml sync
```

If a submitted opportunity already has a ready local Codex proposal, `sync` now includes a sanitized published session for that proposal by default. The server stores it as the issue's latest patch or triage attempt immediately, so `best.patch` and the public issue detail no longer wait for a separate worker lease just to publish an already-reviewed local result.

To let a Codex-capable host volunteer as a worker:

```bash
cargo run -p fixer -- --config ./fixer.toml opt-in --mode submitter-worker
cargo run -p fixer -- --config ./fixer.toml worker run
```

To run the server locally:

```bash
cargo run -p fixer --bin fixer-server -- --config ./fixer-server.toml serve
```

The public deployment uses the same protocol and binaries. Local and public installs are meant to feel like the same system, just with different trust and visibility.

## Packaging

Build Debian packages from the repo root:

```bash
dpkg-buildpackage -us -uc -b
```

The two main packages are:

- `fixer`: the CLI plus local collector daemon
- `fixer-server`: the aggregation server

For the collector package, prefer APT over raw `dpkg -i` so helper tools are pulled in automatically:

```bash
sudo apt install ../fixer_*.deb
```

For a local standalone server, plain `dpkg -i` is fine on a normal Debian machine:

```bash
sudo dpkg -i ../fixer-server_*.deb
systemctl status fixer-server.service
curl http://127.0.0.1:8080/healthz
```

The packaged server defaults to:

- bind address: `127.0.0.1:8080`
- local state: `/var/lib/fixer-server/fixer-server.sqlite3`

Shared or public deployments can switch to Postgres through `/etc/fixer/fixer-server.env` with `FIXER_SERVER_POSTGRES_URL=...`.

## Worker auth and safety

The packaged worker path defaults to `patch.auth_mode = "user-lease"`.

That means:

- the root-owned service keeps responsibility for collection, leasing, and the SQLite state
- Codex runs as a real user with that user's existing login
- root does not need a copied Codex credential

Typical setup looks like this:

```bash
sudo fixer auth lease bootstrap <user>
sudo fixer auth lease grant <user> --ttl 8h --budget conservative
sudo fixer auth lease status
```

Worker jobs run in isolated per-job workspace snapshots under `/var/lib/fixer/proposals/...`. The goal is not perfect sandboxing yet, but a much more supervised path than “run Codex as root and hope for the best.”

For `desktop-input-config` investigations such as Plasma keyboard-layout complaints, Fixer keeps the full Codex path by default:

- it respects `patch.plan_before_patch`, so multi-step repairs still get a plan pass
- it prefers the primary Codex model when available
- when the installed Codex CLI supports it, it defaults reasoning effort to `xhigh` for this subsystem unless you override it
- it keeps Spark available as a fallback when rate limits or usage pressure make that the better tradeoff
- it still keeps the normal review pass enabled, with at least two refinement chances for this subsystem

## Privacy and participation

Fixer is intentionally cautious here.

Before opt-in, nothing is uploaded. After opt-in, Fixer still warns that it may collect sensitive machine evidence such as:

- local paths
- command lines
- warning text
- stack traces
- package metadata

Uploads go through best-effort redaction first, but redaction is not perfect. Public pages only expose sanitized aggregate summaries, not raw evidence bundles, hostnames, install IDs, or richer artifacts.

`fixer complain` always starts with local triage. On `local-only` hosts it stays private in a per-user complaint workspace under `~/.local/state/fixer/complaints/`. On hosts already opted into federation, the resulting complaint opportunity can join the next sync after local triage, but complaint text still goes through the same best-effort redaction and is not published as a public issue card by default.

## Public deployment

The canonical public endpoints are:

- site: `https://fixer.maumap.com`
- issues: `https://fixer.maumap.com/issues`
- patches: `https://fixer.maumap.com/patches`
- triage: `https://fixer.maumap.com/triage`
- APT repo: `https://fixer.maumap.com/apt/`

The canonical runbook lives in [doc/service-actions.md](./doc/service-actions.md). It covers each service action in a strict Markdown format that is both human-readable and linted by `scripts/validate-service-actions.py`.

The main release path is:

```bash
scripts/release-public.sh
```

That wrapper validates non-local deployment readiness, builds the Debian packages, deploys the public server, republishes the hosted APT repository on the server, and then runs post-release verification.

Fleet-wide client upgrades intentionally use a local-only inventory file:

- inventory template: [doc/host-inventory-template.md](./doc/host-inventory-template.md)
- real local inventory: `doc/local/host-inventory.md`
- fleet upgrade command: `scripts/upgrade-all-hosts.sh`

## Documentation

- [Architecture notes](./doc/architecture.md)
- [Design decisions](./doc/design-decisions.md)
- [Product brief](./doc/requirements.md)
- [Service action runbook](./doc/service-actions.md)
- [Host inventory template](./doc/host-inventory-template.md)
- [Debian packaging notes](./debian/README.Debian)

## Current limits

Fixer is already useful, but it is still early. A few boundaries are worth being explicit about:

- optional tools like `perf`, `bpftrace`, `npm`, and `pip-audit` expand capability, but missing them should not block startup
- workspace hydration is strongest for Debian-backed issues and still imperfect for everything else
- some findings are best handled as successful triage rather than patches, especially when the real owner lives outside the current source tree
- the system service still runs as root for telemetry access; privilege separation is improving, not finished
- the public network is intentionally conservative, with quarantine, proof-of-work, and trust gating to keep the queue honest

If you want the one-sentence summary: Fixer is trying to make real machine breakage legible, patchable, and shareable without pretending every problem deserves an instant AI patch.
