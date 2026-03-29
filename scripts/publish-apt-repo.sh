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
SIGNING_NAME=${APT_REPO_SIGNING_NAME:-"Fixer Archive Signing Key <hello@maumap.com>"}
ORIGIN=${APT_REPO_ORIGIN:-Fixer}
LABEL=${APT_REPO_LABEL:-Fixer}
DESCRIPTION=${APT_REPO_DESCRIPTION:-Fixer package repository}
COMPONENT=${APT_REPO_COMPONENT:-main}
ARCHITECTURES=${APT_REPO_ARCHITECTURES:-"amd64 arm64 source"}
SUITES=${APT_REPO_SUITES:-}
PUBLIC_URL=${APT_REPO_PUBLIC_URL:-https://fixer.maumap.com/apt}
DEFAULT_SUITE=${APT_REPO_DEFAULT_SUITE:-stable}

write_repo_index() {
    public_url=${PUBLIC_URL%/}
    key_url="$public_url/fixer-archive-keyring.gpg"
    source_line="deb [signed-by=/usr/share/keyrings/fixer-archive-keyring.gpg] $public_url $DEFAULT_SUITE $COMPONENT"
    cat >"$PUBLIC_DIR/index.html" <<EOF
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Fixer APT Repository</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f6efe4;
      --panel: rgba(255, 251, 244, 0.92);
      --line: rgba(94, 70, 34, 0.18);
      --text: #2a2012;
      --muted: #6e5a3c;
      --accent: #095955;
      --code-bg: #211a12;
      --code-fg: #fef3db;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top left, rgba(11, 122, 117, 0.16), transparent 34%),
        linear-gradient(180deg, #faf6ef 0%, var(--bg) 100%);
    }
    main {
      width: min(980px, calc(100% - 2rem));
      margin: 0 auto;
      padding: 2rem 0 3rem;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 22px;
      padding: 1.35rem;
      box-shadow: 0 18px 40px rgba(66, 45, 15, 0.12);
      margin-top: 1rem;
    }
    h1, h2 { margin-top: 0; }
    p, li { color: var(--muted); }
    pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      padding: 1rem;
      border-radius: 16px;
      border: 1px solid var(--line);
      background: var(--code-bg);
      color: var(--code-fg);
      font-family: "Iosevka Term", "JetBrains Mono", "SFMono-Regular", monospace;
      font-size: 0.95rem;
    }
    code {
      font-family: "Iosevka Term", "JetBrains Mono", "SFMono-Regular", monospace;
    }
    ul {
      padding-left: 1.1rem;
    }
    a {
      color: var(--accent);
    }
    .topline {
      display: flex;
      flex-wrap: wrap;
      gap: 0.75rem;
      align-items: center;
    }
    .tag {
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      border: 1px solid var(--line);
      padding: 0.35rem 0.7rem;
      background: rgba(255, 255, 255, 0.55);
      color: var(--accent);
      text-decoration: none;
    }
  </style>
</head>
<body>
  <main>
    <section class="panel">
      <div class="topline">
        <span class="tag">Fixer APT repository</span>
        <a class="tag" href="/">Main site</a>
        <a class="tag" href="./dists/">Browse dists/</a>
        <a class="tag" href="./pool/">Browse pool/</a>
      </div>
      <h1>Install Fixer from APT</h1>
      <p>Add the public keyring, register the repository, then install <code>fixer</code> with normal APT tooling.</p>
      <pre><code>sudo install -d -m 0755 /usr/share/keyrings /etc/apt/sources.list.d
curl -fsSL $key_url -o /usr/share/keyrings/fixer-archive-keyring.gpg
echo "$source_line" | sudo tee /etc/apt/sources.list.d/fixer.list >/dev/null
sudo apt update
sudo apt install fixer</code></pre>
      <p>The default published suite is <code>$DEFAULT_SUITE</code> with component <code>$COMPONENT</code>.</p>
    </section>

    <section class="panel">
      <h2>Useful files</h2>
      <ul>
        <li>Binary keyring: <a href="./fixer-archive-keyring.gpg">fixer-archive-keyring.gpg</a></li>
        <li>ASCII armored key: <a href="./KEY.gpg.asc">KEY.gpg.asc</a></li>
        <li>Suite metadata: <a href="./dists/$DEFAULT_SUITE/Release">dists/$DEFAULT_SUITE/Release</a></li>
        <li>Raw package pool: <a href="./pool/">pool/</a></li>
      </ul>
      <p>If you are enrolling another host remotely, the repo URL is <code>$public_url</code>.</p>
    </section>
  </main>
</body>
</html>
EOF
}

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
write_repo_index
find "$PUBLIC_DIR" -type d -exec chmod 755 {} +
find "$PUBLIC_DIR" -type f -exec chmod 644 {} +

printf 'published suites:\n%s\n' "$SUITES"
