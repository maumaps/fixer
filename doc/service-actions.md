# Service Actions

This runbook is the canonical action catalog for operating the public Fixer service and the enrolled client fleet.

It is written for both people and automation:

- humans should use it as the primary runbook
- automation should lint it with `scripts/validate-service-actions.py`

Non-local deployment discipline applies to every action that changes a remote machine or the public service:

- bump the minor version before the deployment
- capture the deployment state in git before the deployment

## Local Inventory

Fleet-wide host actions intentionally use a local-only inventory file so private hostnames do not need to live in git.

- template: `doc/host-inventory-template.md`
- real local file: `doc/local/host-inventory.md`
- parser: `scripts/upgrade-all-hosts.sh`

The local inventory file must keep the same Markdown table columns as the template.

## Action: publish-version

Action ID: `publish-version`

### Purpose

Prepare a new non-local deployment version by bumping the workspace version and Debian package version together.

### When To Use

Use this before any non-local deployment, release, public package publication, or remote host upgrade.

### Implementation

- Type: `manual`
- Validator: `scripts/validate-service-actions.py`

### Prerequisites

- Minor version bump recorded in both `Cargo.toml` and `debian/changelog`.
- Deployment state committed to git before any non-local deployment.
- The next changelog entry should stay ahead of the previous released minor version.

### Inputs

- new semver version, typically `major.(previous_minor + 1).0`
- Debian changelog entry matching that version as `<version>-1`

### Commands

```bash
$EDITOR Cargo.toml
$EDITOR debian/changelog
python3 scripts/validate-service-actions.py
```

### Verification

```bash
grep -n '^version = "' Cargo.toml
dpkg-parsechangelog -SVersion
python3 scripts/check-nonlocal-deploy.py
```

### Failure / Rollback

- If the versions do not match, fix `Cargo.toml` and `debian/changelog` before building packages.
- If `scripts/check-nonlocal-deploy.py` reports that the version did not advance by a minor bump, correct the version before continuing.

## Action: build-release-packages

Action ID: `build-release-packages`

### Purpose

Build release `.deb` artifacts for the current Fixer version.

### When To Use

Use this before publishing packages, deploying the public server, or testing a release locally.

### Implementation

- Type: `script`
- Script: `scripts/build-release-debs.sh`

### Prerequisites

- `debian/changelog` already reflects the intended release version.
- `dpkg-buildpackage` and Debian packaging dependencies are available locally.

### Inputs

- optional `OUTPUT_DIR` override for the package output root

### Commands

```bash
scripts/build-release-debs.sh
```

### Verification

```bash
VERSION=$(dpkg-parsechangelog -SVersion)
ARCH=$(dpkg --print-architecture)
ls -1 ../dist/packages/"$VERSION"/"$ARCH"/fixer_"$VERSION"_"$ARCH".deb
ls -1 ../dist/packages/"$VERSION"/"$ARCH"/fixer-server_"$VERSION"_"$ARCH".deb
```

### Failure / Rollback

- If package build fails, fix the packaging or source issue and rerun the build.
- If you need a different output root, rerun with `OUTPUT_DIR=/path/to/packages`.

## Action: publish-apt-repo

Action ID: `publish-apt-repo`

### Purpose

Publish built `.deb` packages into the Fixer APT repository metadata and public package pool.

### When To Use

Use this when updating an APT repository that client hosts install from.

### Implementation

- Type: `script`
- Script: `scripts/publish-apt-repo.sh`

### Prerequisites

- Minor version bump recorded in both `Cargo.toml` and `debian/changelog` before any non-local deployment.
- Deployment state committed to git before any non-local deployment.
- Built package paths are available and the repo config exists.
- The target machine has `reprepro`, `gpg`, and `rsync`.

### Inputs

- one or more package paths, typically `fixer_*.deb` and `fixer-server_*.deb`
- optional `FIXER_APT_CONFIG` override

### Commands

```bash
VERSION=$(dpkg-parsechangelog -SVersion)
ARCH=$(dpkg --print-architecture)
scripts/publish-apt-repo.sh \
  ../dist/packages/"$VERSION"/"$ARCH"/fixer_"$VERSION"_"$ARCH".deb \
  ../dist/packages/"$VERSION"/"$ARCH"/fixer-server_"$VERSION"_"$ARCH".deb
```

### Verification

```bash
curl -fsS https://fixer.maumap.com/apt/dists/stable/Release >/dev/null
curl -fsS https://fixer.maumap.com/apt/fixer-archive-keyring.gpg >/dev/null
```

### Failure / Rollback

- If repository metadata generation fails, fix the package input or repo config and rerun publication.
- If publication is partially updated, rerun the same command with the intended package set to regenerate the public metadata.

## Action: deploy-public-server

Action ID: `deploy-public-server`

### Purpose

Deploy the public Fixer server package set, config, and APT repository content to the public host.

### When To Use

Use this when rolling out a new public service version or refreshing the public server configuration.

### Implementation

- Type: `script`
- Script: `scripts/deploy-fixer-server.sh`

### Prerequisites

- Minor version bump recorded in both `Cargo.toml` and `debian/changelog` before any non-local deployment.
- Deployment state committed to git before any non-local deployment.
- Packages already exist locally or can be built from the current checkout.
- SSH access to the deployment host is available.
- `deploy/Caddyfile`, `deploy/fixer-server.toml`, and `deploy/apt/repo.env` contain the intended deployment config.

### Inputs

- optional `FIXER_DEPLOY_HOST`
- optional `FIXER_SITE_NAME`
- optional `FIXER_PACKAGE_PATH`
- optional `FIXER_SERVER_PACKAGE_PATH`

### Commands

```bash
python3 scripts/check-nonlocal-deploy.py
scripts/deploy-fixer-server.sh
```

### Verification

```bash
scripts/verify-public-services.sh
```

### Failure / Rollback

- If the remote package install or service restart fails, fix the remote issue and rerun the deploy script.
- If the public host is healthy but the site still serves stale content, rerun `scripts/verify-public-services.sh` and inspect `systemctl status` on the remote host.

## Action: release-public

Action ID: `release-public`

### Purpose

Run the canonical non-local release flow for the public Fixer service.

### When To Use

Use this when shipping a new public Fixer version end to end.

### Implementation

- Type: `script`
- Script: `scripts/release-public.sh`

### Prerequisites

- Minor version bump recorded in both `Cargo.toml` and `debian/changelog` before any non-local deployment.
- Deployment state committed to git before any non-local deployment.
- Working tree is clean enough for `scripts/check-nonlocal-deploy.py` to pass.
- SSH access to the deployment host is available.

### Inputs

- optional `FIXER_DEPLOY_HOST`
- optional `FIXER_SITE_NAME`

### Commands

```bash
scripts/release-public.sh
```

### Verification

```bash
scripts/verify-public-services.sh
```

### Failure / Rollback

- If release validation fails locally, fix the versioning or git state first.
- If deployment fails after package build, rerun `scripts/deploy-fixer-server.sh` once the host issue is corrected.

## Action: enroll-client-host

Action ID: `enroll-client-host`

### Purpose

Install `fixer` on a remote client machine, point it at the Fixer APT repository, and opt it into the selected participation mode.

### When To Use

Use this for first-time setup of a new client host.

### Implementation

- Type: `script`
- Script: `scripts/enroll-client-host.sh`

### Prerequisites

- Minor version bump recorded in both `Cargo.toml` and `debian/changelog` before any non-local deployment.
- Deployment state committed to git before any non-local deployment.
- The public APT repository and server are already reachable from the target host.
- SSH access with passwordless `sudo -n` is available on the target host.

### Inputs

- remote SSH target
- participation mode: `submitter`, `submitter-worker`, or `local-only`
- optional `FIXER_APT_URL`
- optional `FIXER_SERVER_URL`

### Commands

```bash
scripts/enroll-client-host.sh user@host submitter
```

### Verification

```bash
ssh user@host 'systemctl is-active fixer.service'
ssh user@host 'fixer --config /etc/fixer/fixer.toml participation'
ssh user@host 'fixer --config /etc/fixer/fixer.toml status'
```

### Failure / Rollback

- If enrollment fails before package install, fix connectivity or `sudo` access and rerun.
- If the host should leave the network later, switch it with `fixer opt-in --mode local-only` on that host.

## Action: upgrade-host

Action ID: `upgrade-host`

### Purpose

Upgrade the `fixer` package on one already-enrolled client host and verify the service afterward.

### When To Use

Use this for a targeted client rollout or to recover one host before a fleet-wide upgrade.

### Implementation

- Type: `script`
- Script: `scripts/upgrade-host.sh`

### Prerequisites

- Minor version bump recorded in both `Cargo.toml` and `debian/changelog` before any non-local deployment.
- Deployment state committed to git before any non-local deployment.
- The host is already enrolled and has the Fixer APT repository configured.
- SSH access with passwordless `sudo -n` is available on the target host.

### Inputs

- remote SSH target
- optional `FIXER_POST_UPGRADE_SYNC=1` if you want a best-effort sync after upgrade

### Commands

```bash
scripts/upgrade-host.sh user@host
```

### Verification

```bash
ssh user@host 'dpkg-query -W fixer'
ssh user@host 'systemctl is-active fixer.service'
ssh user@host 'fixer --config /etc/fixer/fixer.toml status'
```

### Failure / Rollback

- If the host cannot upgrade from APT, fix the host's package source or network path and rerun the action.
- If the service fails after the package upgrade, inspect `journalctl -u fixer.service` on the host before retrying.

## Action: upgrade-all-hosts

Action ID: `upgrade-all-hosts`

### Purpose

Upgrade every enabled client host listed in the local-only fleet inventory.

### When To Use

Use this after the public release is already available in the APT repository and you want to roll out the client fleet.

### Implementation

- Type: `script`
- Script: `scripts/upgrade-all-hosts.sh`

### Prerequisites

- Minor version bump recorded in both `Cargo.toml` and `debian/changelog` before any non-local deployment.
- Deployment state committed to git before any non-local deployment.
- `doc/local/host-inventory.md` exists locally and follows `doc/host-inventory-template.md`.
- Each enabled host in the inventory is already enrolled and reachable over SSH with passwordless `sudo -n`.

### Inputs

- optional `FIXER_HOST_INVENTORY` path override
- optional `FIXER_UPGRADE_CONTINUE_ON_ERROR=1` if you want best-effort fleet progress

### Commands

```bash
scripts/upgrade-all-hosts.sh
```

### Verification

```bash
scripts/upgrade-all-hosts.sh
```

### Failure / Rollback

- By default the script stops on the first host failure so you can fix the issue before continuing.
- If you intentionally want best-effort fleet progress, rerun with `FIXER_UPGRADE_CONTINUE_ON_ERROR=1`.

## Action: verify-public-services

Action ID: `verify-public-services`

### Purpose

Check that the public Fixer site, server health endpoint, APT repository metadata, and key system services are healthy after a rollout.

### When To Use

Use this after public deployment, after a server repair, or as a quick production sanity check.

### Implementation

- Type: `script`
- Script: `scripts/verify-public-services.sh`

### Prerequisites

- SSH access to the deployment host is available if you want remote `systemctl` verification.
- The public site URL resolves from the machine running the check.

### Inputs

- optional `FIXER_DEPLOY_HOST`
- optional `FIXER_SITE_NAME`

### Commands

```bash
scripts/verify-public-services.sh
```

### Verification

```bash
scripts/verify-public-services.sh
```

### Failure / Rollback

- If a public HTTP check fails, inspect the remote services and rerun once the dependency is restored.
- If only the APT metadata check fails, republish the repository and rerun the verification action.
