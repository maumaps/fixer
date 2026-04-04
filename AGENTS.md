# AGENTS

## Deployment Discipline

- Before any non-local deployment, bump the minor version.
- Before any non-local deployment, make sure the deployment state is captured in a git commit.
- Before any non-local deployment, make sure the git worktree is clean, including generated Debian build artifacts such as `debian/fixer-server/` and `*.debhelper.log`.
- Do not rebuild or republish an already-published version. If the APT repo already has that version, verify the deployed hosts against the published package instead of trying to overwrite it with a different build.
- Treat the current machine as local even if it also has an SSH hostname. Upgrade it locally instead of routing the upgrade through `ssh`.

## Repair Discipline

- No hacks. Do not ship or recommend local wrappers, launcher overrides, environment-variable shims, or other band-aids as a substitute for a proper system-wide fix when the underlying issue belongs in packages, services, or distro configuration.
- For Codex usage, treat `gpt-5.3-codex-spark` as a good fallback and a good fit for one-liner or narrowly bounded fixes.
- For fuller multi-step patches, prefer normal Codex with a planning pass and high reasoning effort when usage limits are not the gating factor.
