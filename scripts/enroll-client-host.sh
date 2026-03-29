#!/bin/sh
set -eu

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
    echo "usage: $0 host [submitter|submitter-worker|local-only]" >&2
    exit 1
fi

HOST=$1
MODE=${2:-submitter}
APT_URL=${FIXER_APT_URL:-https://fixer.maumap.com/apt}
SERVER_URL=${FIXER_SERVER_URL:-https://fixer.maumap.com}
SUITE=${FIXER_APT_SUITE:-stable}
COMPONENT=${FIXER_APT_COMPONENT:-main}
KEYRING_PATH=${FIXER_KEYRING_PATH:-/usr/share/keyrings/fixer-archive-keyring.gpg}
LIST_PATH=${FIXER_LIST_PATH:-/etc/apt/sources.list.d/fixer.list}

case "$MODE" in
    submitter|submitter-worker|local-only)
        ;;
    *)
        echo "unsupported mode: $MODE" >&2
        exit 1
        ;;
esac

ssh "$HOST" \
    "sudo -n env FIXER_APT_URL='$APT_URL' FIXER_SERVER_URL='$SERVER_URL' FIXER_APT_SUITE='$SUITE' FIXER_APT_COMPONENT='$COMPONENT' FIXER_KEYRING_PATH='$KEYRING_PATH' FIXER_LIST_PATH='$LIST_PATH' FIXER_MODE='$MODE' /bin/sh -s" <<'EOF'
set -eu

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y ca-certificates curl gnupg

mkdir -p "$(dirname "$FIXER_KEYRING_PATH")" "$(dirname "$FIXER_LIST_PATH")"
curl -fsSL "$FIXER_APT_URL/fixer-archive-keyring.gpg" -o "$FIXER_KEYRING_PATH"
chmod 0644 "$FIXER_KEYRING_PATH"
printf 'deb [signed-by=%s] %s %s %s\n' \
    "$FIXER_KEYRING_PATH" \
    "$FIXER_APT_URL" \
    "$FIXER_APT_SUITE" \
    "$FIXER_APT_COMPONENT" >"$FIXER_LIST_PATH"

apt-get update
apt-get install -y fixer

systemctl disable --now fixer-server.service >/dev/null 2>&1 || true
systemctl enable --now fixer.service

/usr/bin/fixer --config /etc/fixer/fixer.toml opt-in --mode "$FIXER_MODE" >/dev/null
/usr/bin/fixerd --config /etc/fixer/fixer.toml collect-once >/dev/null
/usr/bin/fixer --config /etc/fixer/fixer.toml sync
echo
/usr/bin/fixer --config /etc/fixer/fixer.toml participation
echo
/usr/bin/fixer --config /etc/fixer/fixer.toml status
EOF
