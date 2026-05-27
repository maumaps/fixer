#!/bin/sh
set -eu

HOST=${FIXER_DEPLOY_HOST:-root@fixer.maumap.com}
SITE=${FIXER_SITE_NAME:-fixer.maumap.com}

if curl -fsS "https://$SITE/" | grep -q "Merged CPython event-driven subprocess wait optimization"; then
    echo "public claim audit failed: CPython external coverage is on the landing wins section" >&2
    exit 1
fi

ssh "$HOST" 'bash -s' <<'EOF'
set -eu
set -a
. /etc/fixer/fixer-server.env
set +a

legacy_count=$(psql "$FIXER_SERVER_POSTGRES_URL" -tAc \
    "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'upstream_patch_wins'")
if [ "$legacy_count" != "0" ]; then
    echo "public claim audit failed: legacy upstream_patch_wins table still exists" >&2
    exit 1
fi

cpython_credit=$(psql "$FIXER_SERVER_POSTGRES_URL" -tAc \
    "SELECT COALESCE((SELECT fixer_credit::text FROM upstream_reviews WHERE id = 'cpython-subprocess-pidfd-wait'), 'missing')")
if [ "$cpython_credit" != "false" ]; then
    echo "public claim audit failed: CPython #144047 must be uncredited external coverage, got $cpython_credit" >&2
    exit 1
fi

uncredited_landing_rows=$(psql "$FIXER_SERVER_POSTGRES_URL" -tAc \
    "SELECT count(*) FROM upstream_reviews WHERE state = 'merged' AND merged_at IS NOT NULL AND fixer_credit IS NOT TRUE AND id <> 'cpython-subprocess-pidfd-wait'")
if [ "$uncredited_landing_rows" != "0" ]; then
    echo "public claim audit warning: uncredited merged upstream coverage rows exist; verify public wording before calling them wins" >&2
fi
EOF
