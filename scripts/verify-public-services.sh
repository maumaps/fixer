#!/bin/sh
set -eu

HOST=${FIXER_DEPLOY_HOST:-root@fixer.maumap.com}
SITE=${FIXER_SITE_NAME:-fixer.maumap.com}

curl -fsS "https://$SITE/healthz" >/dev/null
curl -fsS "https://$SITE/issues" >/dev/null
curl -fsS "https://$SITE/apt/dists/stable/Release" >/dev/null

ssh "$HOST" \
    "systemctl --no-pager --full --lines=20 status fixer.service fixer-server.service caddy.service"
