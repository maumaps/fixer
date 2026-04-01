#!/bin/sh
set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 host" >&2
    exit 1
fi

HOST=$1
POST_UPGRADE_SYNC=${FIXER_POST_UPGRADE_SYNC:-0}

ssh "$HOST" \
    "sudo -n env FIXER_POST_UPGRADE_SYNC='$POST_UPGRADE_SYNC' /bin/sh -s" <<'EOF'
set -eu

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y fixer
systemctl enable --now fixer.service

/usr/bin/fixerd --config /etc/fixer/fixer.toml collect-once >/dev/null
if [ "$FIXER_POST_UPGRADE_SYNC" = "1" ]; then
    /usr/bin/fixer --config /etc/fixer/fixer.toml sync >/dev/null || true
fi

echo
/usr/bin/fixer --config /etc/fixer/fixer.toml participation
echo
/usr/bin/fixer --config /etc/fixer/fixer.toml status
echo
dpkg-query -W fixer
echo
systemctl --no-pager --full --lines=20 status fixer.service
EOF
