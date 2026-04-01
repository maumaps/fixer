# AGENTS

## Deployment Discipline

- Before any non-local deployment, bump the minor version.
- Before any non-local deployment, make sure the deployment state is captured in a git commit.
- Before any non-local deployment, make sure the git worktree is clean, including generated Debian build artifacts such as `debian/fixer-server/` and `*.debhelper.log`.
- Do not rebuild or republish an already-published version. If the APT repo already has that version, verify the deployed hosts against the published package instead of trying to overwrite it with a different build.
- Treat the current machine as local even if it also has an SSH hostname. Upgrade it locally instead of routing the upgrade through `ssh`.
