#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
HOST=${FIXER_DEPLOY_HOST:-root@fixer.maumap.com}
SITE=${FIXER_SITE_NAME:-fixer.maumap.com}
VERSION=$(dpkg-parsechangelog -SVersion)
ARCH=$(dpkg --print-architecture)
PACKAGE=${FIXER_PACKAGE_PATH:-"$REPO_ROOT/dist/packages/$VERSION/$ARCH/fixer_${VERSION}_${ARCH}.deb"}
REMOTE_STAGE=/root/fixer-deploy

if [ ! -f "$PACKAGE" ]; then
    "$SCRIPT_DIR/build-release-debs.sh" >/dev/null
fi

if [ ! -f "$PACKAGE" ]; then
    echo "package not found: $PACKAGE" >&2
    exit 1
fi

STAGE_DIR=$(mktemp -d)
trap 'rm -rf "$STAGE_DIR"' EXIT

cp "$PACKAGE" "$STAGE_DIR/"
cp "$REPO_ROOT/deploy/Caddyfile" "$STAGE_DIR/Caddyfile"
cp "$REPO_ROOT/deploy/fixer-server.toml" "$STAGE_DIR/fixer-server.toml"
cp "$REPO_ROOT/deploy/apt/repo.env" "$STAGE_DIR/repo.env"
cp "$REPO_ROOT/scripts/publish-apt-repo.sh" "$STAGE_DIR/publish-apt-repo.sh"
cp "$REPO_ROOT/debian/fixer-server.service" "$STAGE_DIR/fixer-server.service"

ssh "$HOST" "mkdir -p '$REMOTE_STAGE'"
scp "$STAGE_DIR/"* "$HOST:$REMOTE_STAGE/"

ssh "$HOST" "SITE='$SITE' REMOTE_STAGE='$REMOTE_STAGE' VERSION='$VERSION' PACKAGE_NAME='$(basename "$PACKAGE")' sh -s" <<'EOF'
set -eu

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    caddy \
    postgresql \
    reprepro \
    gnupg \
    rsync \
    ca-certificates \
    curl \
    distro-info

mkdir -p "$REMOTE_STAGE"
DEBIAN_FRONTEND=noninteractive apt-get install -y "$REMOTE_STAGE/$PACKAGE_NAME"
systemctl disable --now fixer || true

DB_PASSWORD_FILE=/etc/fixer/fixer-server-db-password
if [ ! -f "$DB_PASSWORD_FILE" ]; then
    umask 077
    tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32 >"$DB_PASSWORD_FILE"
fi
DB_PASSWORD=$(cat "$DB_PASSWORD_FILE")

runuser -u postgres -- psql -v ON_ERROR_STOP=1 <<SQL
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'fixer_server') THEN
        CREATE ROLE fixer_server LOGIN PASSWORD '$DB_PASSWORD';
    ELSE
        ALTER ROLE fixer_server WITH LOGIN PASSWORD '$DB_PASSWORD';
    END IF;
END
\$\$;
SQL
runuser -u postgres -- psql -v ON_ERROR_STOP=1 -tAc "SELECT 1 FROM pg_database WHERE datname = 'fixer'" | grep -q 1 || \
    runuser -u postgres -- createdb -O fixer_server fixer

POSTGRES_URL="postgres://fixer_server:$DB_PASSWORD@127.0.0.1/fixer"
sed "s|__POSTGRES_URL__|$POSTGRES_URL|g" "$REMOTE_STAGE/fixer-server.toml" >/etc/fixer/fixer.toml

install -D -m 0644 "$REMOTE_STAGE/Caddyfile" /etc/caddy/Caddyfile
install -D -m 0644 "$REMOTE_STAGE/repo.env" /etc/fixer/apt-repo.env
install -D -m 0755 "$REMOTE_STAGE/publish-apt-repo.sh" /usr/local/bin/publish-fixer-apt-repo
install -D -m 0644 "$REMOTE_STAGE/fixer-server.service" /usr/lib/systemd/system/fixer-server.service

mkdir -p /srv/fixer/public/apt /srv/fixer/reprepro /srv/fixer/gnupg
FIXER_APT_CONFIG=/etc/fixer/apt-repo.env /usr/local/bin/publish-fixer-apt-repo "$REMOTE_STAGE/$PACKAGE_NAME"

systemctl daemon-reload
systemctl enable --now fixer-server.service
systemctl enable --now caddy.service
systemctl restart fixer-server.service
systemctl restart caddy.service
EOF
