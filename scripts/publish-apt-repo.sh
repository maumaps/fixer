#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
CONFIG_FILE=${FIXER_APT_CONFIG:-"$REPO_ROOT/deploy/apt/repo.env"}

if [ ! -f "$CONFIG_FILE" ]; then
    echo "missing APT repo config: $CONFIG_FILE" >&2
    exit 1
fi

# shellcheck disable=SC1090
. "$CONFIG_FILE"

ARCHIVE_DIR=${APT_REPO_ARCHIVE_DIR:-/srv/fixer/reprepro}
PUBLIC_DIR=${APT_REPO_PUBLIC_DIR:-/srv/fixer/public/apt}
GNUPG_HOME=${APT_REPO_GNUPG_HOME:-/srv/fixer/gnupg}
SIGNING_NAME=${APT_REPO_SIGNING_NAME:-"Fixer Archive Signing Key <packages@maumap.com>"}
ORIGIN=${APT_REPO_ORIGIN:-Fixer}
LABEL=${APT_REPO_LABEL:-Fixer}
DESCRIPTION=${APT_REPO_DESCRIPTION:-Fixer package repository}
COMPONENT=${APT_REPO_COMPONENT:-main}
ARCHITECTURES=${APT_REPO_ARCHITECTURES:-"amd64 arm64 source"}
SUITES=${APT_REPO_SUITES:-}

derive_suites() {
    suites=""
    if command -v debian-distro-info >/dev/null 2>&1; then
        oldstable=$(debian-distro-info --oldstable 2>/dev/null || true)
        stable=$(debian-distro-info --stable 2>/dev/null || true)
        if [ -n "$oldstable" ]; then
            suites="$suites oldstable $oldstable"
        fi
        if [ -n "$stable" ]; then
            suites="$suites stable $stable"
        fi
        suites="$suites unstable sid"
    else
        suites="$suites stable unstable"
    fi

    if command -v ubuntu-distro-info >/dev/null 2>&1; then
        lts_list=$(ubuntu-distro-info --supported 2>/dev/null | awk '$3 == "LTS" {print $1}')
        latest_supported=$(ubuntu-distro-info --supported 2>/dev/null | awk 'END {print $1}')
        for suite in $lts_list; do
            suites="$suites $suite"
        done
        if [ -n "$latest_supported" ]; then
            suites="$suites $latest_supported"
        fi
    fi

    printf '%s\n' "$suites" | tr ' ' '\n' | awk 'NF && !seen[$0]++'
}

if [ -z "$SUITES" ]; then
    SUITES=$(derive_suites)
fi

if [ $# -eq 0 ]; then
    echo "usage: $0 path/to/package.deb [...]" >&2
    exit 1
fi

mkdir -p "$ARCHIVE_DIR/conf" "$PUBLIC_DIR" "$GNUPG_HOME"
chmod 700 "$GNUPG_HOME"
export GNUPGHOME="$GNUPG_HOME"

if ! gpg --batch --list-secret-keys "$SIGNING_NAME" >/dev/null 2>&1; then
    gpg --batch --pinentry-mode loopback --passphrase '' \
        --quick-generate-key "$SIGNING_NAME" rsa4096 sign 0
fi

SIGNING_KEY=$(gpg --batch --with-colons --list-secret-keys "$SIGNING_NAME" | awk -F: '/^fpr:/ {print $10; exit}')
if [ -z "$SIGNING_KEY" ]; then
    echo "failed to resolve APT signing key fingerprint" >&2
    exit 1
fi

{
    for suite in $SUITES; do
        cat <<EOF
Origin: $ORIGIN
Label: $LABEL
Suite: $suite
Codename: $suite
Architectures: $ARCHITECTURES
Components: $COMPONENT
Description: $DESCRIPTION
SignWith: $SIGNING_KEY

EOF
    done
} >"$ARCHIVE_DIR/conf/distributions"

for package in "$@"; do
    if [ ! -f "$package" ]; then
        echo "package not found: $package" >&2
        exit 1
    fi
    for suite in $SUITES; do
        reprepro -b "$ARCHIVE_DIR" includedeb "$suite" "$package"
    done
done

mkdir -p "$PUBLIC_DIR"
if [ -d "$ARCHIVE_DIR/dists" ]; then
    rsync -a --delete "$ARCHIVE_DIR/dists/" "$PUBLIC_DIR/dists/"
fi
if [ -d "$ARCHIVE_DIR/pool" ]; then
    rsync -a --delete "$ARCHIVE_DIR/pool/" "$PUBLIC_DIR/pool/"
fi

gpg --batch --yes --export "$SIGNING_KEY" >"$PUBLIC_DIR/fixer-archive-keyring.gpg"
gpg --batch --yes --armor --export "$SIGNING_KEY" >"$PUBLIC_DIR/KEY.gpg.asc"
find "$PUBLIC_DIR" -type d -exec chmod 755 {} +
find "$PUBLIC_DIR" -type f -exec chmod 644 {} +

printf 'published suites:\n%s\n' "$SUITES"
