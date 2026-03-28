let's think about a product/daemon in AI/code improvement sphere. I want something (a daemon?) run on my linux machine, trace what I use (on package level but also on code/repo level), review the hot paths and adjacent code, find out upstream repositories and existing tickets/people behind them, implement improvements. also should look at warnings and crashes and fix them. I am thinking of using OpenAI Codex for that, but main collecting harness needs to be non-AI. find prior art for this and existing systems, success and failures overview design the system. rust? kernel level something? target debian, npm, pip, pgxn?



Yes. This is a real product category.

The good version is not "an AI daemon that rewrites my machine". The good version is a local evidence engine that knows what you actually use, what is hot, what is noisy, what is crashing, which package or repo owns it, and who upstream is. Then it hands only small, well-evidenced jobs to a coding agent. OpenAI Codex fits that second half pretty well: Codex CLI runs locally in the terminal, is built in Rust, supports approval modes and OS-enforced sandboxing, has network off by default in local mode, and also has a non-interactive `codex exec` path plus reusable "skills" for repeatable workflows. ([developers.openai.com][1])

I do not see a mature single product that already combines all of the pieces you described on one Linux box. What exists today is a pile of specialized systems: `perf` and eBPF tools for observation, coredump and crash systems for triage, package metadata systems for finding upstream, dependency bots for updates, structural codemod tools for mechanical fixes, and repair bots for narrow autonomous patching. The gap is the glue, not the existence of parts. ([kernel.org][2])

## Prior art worth stealing from

* For hot paths and usage, the serious baseline is `perf`, not magic AI. Linux `perf` is the kernel subsystem for performance analysis, and `bpftrace` gives a higher-level way to do user-space and kernel tracing on top of eBPF. On the optimization side, AutoFDO and LLVM BOLT are proof that profile-guided improvements based on real execution are very effective when the evidence is good. ([kernel.org][2])

* For crash capture and triage, Linux already has systemd-native coredump handling through `systemd-coredump` and `coredumpctl`. Ubuntu had Apport, and Red Hat has ABRT, which can detect crashes, deduplicate them, and in ABRT's case even point to an existing bug or package update. Browser and desktop app ecosystems solved a related problem with Crashpad and Sentry-style minidumps. ([Systemd][3])

* For discovering where code lives and who owns it, the metadata is already there more often than people realize. Debian packages can expose `Homepage`, `Vcs-*`, `Vcs-Browser`, and DEP-12 upstream metadata. npm packages can publish `repository` and `bugs`. PyPI projects can publish `[project.urls]`. PGXN `META.json` has `resources` for homepage, bug tracker, and repository. Inside repos, GitHub `CODEOWNERS` helps, Linux has `MAINTAINERS` plus `scripts/get_maintainer.pl`, and `git shortlog` is a good fallback for active humans. ([debian.org][4])

* For package and dependency maintenance, Dependabot and Renovate are the big success stories because the change space is bounded and validation is straightforward. `deps.dev` is useful as enrichment because it can return resolved dependency graphs across ecosystems like npm and PyPI. Security tooling such as `npm audit` and `pip-audit` is another ready-made signal source. ([GitHub Docs][5])

* For deterministic code repair, Coccinelle is the classic Linux answer for semantic patches, `ast-grep` is a fast polyglot structural search-and-rewrite tool written in Rust, Sorald automatically repairs 25+ Sonar rules, and Semgrep supports both rule-defined autofix and AI-backed Autofix PRs. GitHub Copilot Autofix is another example of an LLM being useful when it is given a very specific alert and bounded context, not a whole undifferentiated codebase. ([Coccinelle][6])

* For autonomous repair, the useful references are Repairnator, SapFix, and syzbot. Repairnator monitored test failures, reproduced bugs, ran repair tools, and reported patches. SapFix combined bug finding, patch generation, and retesting at Meta, but its mutation-based fixing was initially narrow, for example focused on NPE crashes. syzbot is maybe the strongest example of what success looks like in the wild: it continuously fuzzes Linux kernel branches, deduplicates, assigns subsystem tags, reports to kernel mailing lists, and tracks fixes against real reproducers. ([arXiv][7])

## What worked, what failed

* The winners are narrow, evidence-heavy, and reviewable. Dependabot and Renovate work because dependency upgrades are constrained and CI can validate them. Coccinelle works because the transformations are structural and explicit. syzbot works because it has reproducers, routing, and a fix-tracking loop. ([GitHub Docs][5])

* The losers, or at least the disappointing cases, are the ones that try to do broad repair without strong reproduction and validation. Repairnator is the classic signal here: it studied 11,317 test failures across 1,609 GitHub projects and produced patches for 17 bugs. That is not failure in a scientific sense, but it is a warning that unconstrained repair pipelines have bad economics. Flaky tests make this even worse, because they distort localization and patch validation. ([arXiv][7])

* AI autofix systems themselves also tell the same story. Copilot Autofix says it operates on a best-effort basis and may fail on complex multi-file logic or subtle data-flow cases. Semgrep Autofix explicitly keeps the human in control by opening a draft PR rather than silently merging anything. This is the right pattern. ([GitHub Docs][8])

* Crash data is gold, but it is also toxic waste. Ubuntu disables Apport by default in stable partly because crash reports can contain core dumps, stack traces, and logs with sensitive data. There was also a recent information-disclosure issue in `systemd-coredump`, which is a healthy reminder not to spray raw cores around. Keep crash handling local, symbolized, minimized, and hashed before any AI sees it. ([wiki.ubuntu.com][9])

* Simple package-usage signals are weaker than they look. Debian Popularity Contest reports installed packages and uses file access time as one input, but `noatime` breaks that model. So for your daemon, do not copy popcon literally. Infer usage from executed binaries, loaded libraries, open source trees, build invocations, and profiler samples, not from `atime`. ([popcon.debian.org][10])

## The system I would build

### 1. Non-AI sensor plane

This part should be boring, deterministic, and local.

* Process and package usage:

  * Record `exec` activity, loaded ELF objects, and optionally selected `open` events.
  * Map executable and library paths to Debian packages, then to source packages and upstream metadata.
  * Record repo activity for paths under watched Git worktrees.
  * Treat editor saves, builds, test runs, and shell invocations as stronger repo-level signals than raw file access time.

* Performance:

  * Use sampled `perf` first for CPU hot paths.
  * Add targeted eBPF probes only where you need latency histograms, syscall distributions, or low-overhead correlation that `perf` alone does not give.
  * For binaries you can rebuild, later feed profile data into AutoFDO or BOLT-style optimization passes. ([kernel.org][2])

* Warnings:

  * Wrap compiler, linter, and test commands, or scrape build logs from watched repos.
  * Normalize warnings into signatures: tool, rule/code, symbol, file, line, commit, package.

* Crashes:

  * Integrate with `coredumpctl` and optionally ABRT-like problem directories.
  * Symbolize locally.
  * Store hashes of stack traces and a minimized crash fingerprint.
  * Do not upload raw coredumps to any model. ([Systemd][3])

### 2. Artifact and ownership graph

This is the actual moat.

For every observed thing, build a chain like this:

`process/binary/file/symbol -> package or repo -> source package -> upstream repo -> issue tracker -> owners/maintainers/recent humans`

Use distro and ecosystem metadata first, then repo metadata, then heuristics. Debian `Vcs-*` and DEP-12 should beat regex guessing. npm `repository` and `bugs`, PyPI project URLs, and PGXN `resources` should beat web search. Then enrich with `CODEOWNERS`, Linux `get_maintainer.pl`, recent `git shortlog`, and blame-based author density. `deps.dev` is useful for adding resolved transitive dependency context for npm and PyPI projects. ([debian.org][4])

### 3. Opportunity engine

Do not ask AI "what should I fix?" Compute that.

I would score opportunities roughly as:

`score = frequency * pain * confidence * fixability * upstreamability`

Where:

* frequency = how often the path, warning, or crash occurs
* pain = CPU cost, wall time, crash severity, or user interruption
* confidence = how clear the owner, reproducer, and affected files are
* fixability = whether deterministic or localized patch strategies exist
* upstreamability = chance a maintainer will actually take it

Examples of high-score items:

* a repeated crash with a stable stack signature and a clear upstream repo
* a hot function in your own repo or a clean upstream fork with benchmark coverage
* a noisy linter/compiler warning in a repo with tests
* a vulnerable dependency with a known fix version from `npm audit` or `pip-audit` and passing tests afterward ([docs.npmjs.com][11])

### 4. Adjacent-code slicer

This is where most agent systems get stupid. They hand the model too much code.

For each task, slice context to:

* the hot function or crashing frame
* direct callers and callees
* same module or package
* tests touching those symbols
* recent changes around those files
* open issues with matching symbols or stack fragments
* owners for those paths

That "adjacent code" bundle is what Codex sees, not the whole repository. This is also where structural tools like `ast-grep` and semantic patch tools like Coccinelle become very useful, because they let you localize and transform code by structure rather than by giant prompt. ([ast-grep.github.io][12])

### 5. Fix engine, deterministic first, AI second

This is the central trust boundary.

First try non-AI fixers:

* dependency bumps and manifest edits, Dependabot or Renovate style
* rule-defined rewrites with Coccinelle, `ast-grep`, or Semgrep rule-defined autofix
* packaging metadata cleanups
* suppressions only when policy allows and you can justify them
* issue drafts that include repro, stack, owner, and suspected component ([GitHub Docs][5])

Only then call Codex for patches that need actual reasoning. Run it through `codex exec` or the CLI with approval-gated sandboxing, give it the minimal evidence bundle, and encode ecosystem workflows as reusable skills. This is exactly where Codex is better than a giant homegrown agent framework. ([developers.openai.com][13])

### 6. Validation and publication

Never merge from the agent straight into reality.

Validation should be ecosystem-aware:

* Debian: package build, Lintian, and `autopkgtest` on an installed-package testbed. Salsa CI also exists as a quality pipeline around these ideas. ([lintian.debian.org][14])
* npm: project tests plus `npm audit` status before and after. ([docs.npmjs.com][11])
* Python: project tests plus `pip-audit`. ([PyPI][15])
* PGXN and Postgres extensions: PostgreSQL regression tests and pgTAP. ([PostgreSQL][16])
* Performance work: before/after perf profiles and microbenchmarks. ([kernel.org][2])

Publication should default to one of these, in order of safety:

* local patch queue
* local git branch
* draft PR
* draft issue with suggested patch
* mail-ready patch for mailing-list projects

## Rust, kernel level, or both?

Rust for the daemon core: yes.

Reasons:

* long-running local service
* lots of concurrent event ingestion
* filesystem and process interaction
* easy integration with SQLite, Git, HTTP, and structured logs
* good fit with optional eBPF in Rust through Aya or `libbpf-rs`
* Codex CLI itself is already Rust-based, so the ecosystem fit is nice ([aya-rs.dev][17])

Kernel level for observation only, not for policy.

My recommendation:

* Start in user space.
* Use `perf` for hot-path ranking.
* Add optional eBPF probes for targeted telemetry.
* Do not write a kernel module.
* Do not put scheduling, scoring, or AI policy into the kernel.
* Do not use `ptrace` as the normal data plane.

That gives you most of the value without turning the product into a fragile rootkit-shaped science project. `perf` plus selective eBPF gets you very far. ([kernel.org][2])

## Targets: Debian, npm, pip, PGXN?

Yes, and I would support them in this order.

* Debian first. The machine-level story is strongest there because package ownership is explicit, source-package metadata is rich, `systemd-coredump` is standard, and Debian packaging quality gates like Lintian and `autopkgtest` already exist. ([debian.org][4])

* npm second. The metadata is unusually cooperative: `repository`, `bugs`, lockfiles, monorepo hints via `repository.directory`, and there is direct supply-chain feedback through `npm audit`. Renovate is also especially strong in monorepo and schedule-heavy setups. ([docs.npmjs.com][18])

* pip/PyPI third. `[project.urls]` is useful, `pip-audit` gives a clear security signal, and `deps.dev` can enrich the dependency graph. The weakness is that Python environments can be messier and more dynamic than npm lockfile worlds, so reproduction discipline matters more. ([docs.pypi.org][19])

* PGXN fourth, but actually strategically interesting. The ecosystem is smaller, metadata is explicit, regression testing culture is strong, and many extensions have clearer maintainer lines than giant JavaScript forests. If your user base overlaps Postgres-heavy shops, this can become a very nice wedge. ([PGXN: PostgreSQL Extension Network][20])

## What I would not do

* I would not base package usage on `atime`.
* I would not let the agent decide ownership or upstream mapping without metadata and heuristics first.
* I would not auto-submit issues or PRs before deduplication and local validation.
* I would not send raw coredumps or whole repositories to an LLM.
* I would not patch distro-installed binaries in place. Rebuild from source package or patch an upstream/local fork instead.
* I would not aim for "autonomous machine-wide fixing" in v1. That is how you get an expensive chaos monkey. ([GitHub][21])

## The MVP I would actually ship

* A Rust daemon with:

  * local event store
  * repo/package ownership graph
  * `perf`-based hot-path sampler
  * crash and warning ingestion
  * ecosystem adapters for Debian, npm, pip, PGXN
  * deterministic fixers
  * Codex-backed patch mode for localized edits only

* A CLI and TUI that show:

  * top hot packages and repos
  * repeating crashes and warnings
  * fix opportunities ranked by evidence
  * maintainers and issue trackers
  * one-click actions: open draft issue, create patch branch, run Codex fix, run validation

* Codex workflow:

  * bundle evidence
  * run `codex exec`
  * produce patch
  * run tests and benchmarks
  * leave a draft branch or draft PR, never silent merge ([developers.openai.com][13])

The real moat is not the model. The moat is that your daemon has local ground truth about usage, crashes, hot paths, owner routing, and reproducibility. Everyone can rent an LLM. Very few systems know what is actually worth fixing on one specific Linux machine.

The contrarian take: this should be sold less as "autonomous coding" and more as "local source maintenance infrastructure". The AI is a plug-in. The hard part is evidence, ranking, and maintainer-compatible output.

I can also sketch a concrete internal architecture for the daemon, with process model, event schema, and a first-pass Rust crate layout.

[1]: https://developers.openai.com/codex/cli/?utm_source=chatgpt.com "Codex CLI"
[2]: https://www.kernel.org/doc/man-pages/online/pages/man1/perf.1.html "https://www.kernel.org/doc/man-pages/online/pages/man1/perf.1.html"
[3]: https://systemd.io/COREDUMP/ "https://systemd.io/COREDUMP/"
[4]: https://www.debian.org/doc/manuals/developers-reference/best-pkging-practices.en.html "https://www.debian.org/doc/manuals/developers-reference/best-pkging-practices.en.html"
[5]: https://docs.github.com/en/code-security/concepts/supply-chain-security/about-dependabot-version-updates "https://docs.github.com/en/code-security/concepts/supply-chain-security/about-dependabot-version-updates"
[6]: https://coccinelle.gitlabpages.inria.fr/website/ "https://coccinelle.gitlabpages.inria.fr/website/"
[7]: https://arxiv.org/abs/1811.09852 "https://arxiv.org/abs/1811.09852"
[8]: https://docs.github.com/en/code-security/responsible-use/responsible-use-autofix-code-scanning "https://docs.github.com/en/code-security/responsible-use/responsible-use-autofix-code-scanning"
[9]: https://wiki.ubuntu.com/Apport "https://wiki.ubuntu.com/Apport"
[10]: https://popcon.debian.org/ "https://popcon.debian.org/"
[11]: https://docs.npmjs.com/cli/v9/commands/npm-audit "https://docs.npmjs.com/cli/v9/commands/npm-audit"
[12]: https://ast-grep.github.io/ "https://ast-grep.github.io/"
[13]: https://developers.openai.com/codex/noninteractive/ "https://developers.openai.com/codex/noninteractive/"
[14]: https://lintian.debian.org/manual/index.html "https://lintian.debian.org/manual/index.html"
[15]: https://pypi.org/project/pip-audit/ "https://pypi.org/project/pip-audit/"
[16]: https://www.postgresql.org/docs/current/regress.html "https://www.postgresql.org/docs/current/regress.html"
[17]: https://aya-rs.dev/book/ "https://aya-rs.dev/book/"
[18]: https://docs.npmjs.com/cli/v11/configuring-npm/package-json/ "https://docs.npmjs.com/cli/v11/configuring-npm/package-json/"
[19]: https://docs.pypi.org/project_metadata/ "https://docs.pypi.org/project_metadata/"
[20]: https://pgxn.org/spec/ "https://pgxn.org/spec/"
[21]: https://github.com/xsuchy/popularity-contest/blob/master/FAQ "https://github.com/xsuchy/popularity-contest/blob/master/FAQ"
<!--  -->
