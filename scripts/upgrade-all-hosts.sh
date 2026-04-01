#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
INVENTORY_FILE=${FIXER_HOST_INVENTORY:-"$REPO_ROOT/doc/local/host-inventory.md"}
CONTINUE_ON_ERROR=${FIXER_UPGRADE_CONTINUE_ON_ERROR:-0}

if [ ! -f "$INVENTORY_FILE" ]; then
    echo "host inventory not found: $INVENTORY_FILE" >&2
    echo "copy doc/host-inventory-template.md to doc/local/host-inventory.md first" >&2
    exit 1
fi

parse_inventory() {
    awk -F'|' '
        function trim(value) {
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            return value
        }
        /^\|/ {
            name = trim($2)
            target = trim($3)
            role = trim($4)
            enabled = trim($5)
            if (name == "name" || name == "---" || name == "") {
                next
            }
            if (target == "" || role == "" || enabled == "") {
                next
            }
            if (role == "client" && enabled == "yes") {
                print name "\t" target
            }
        }
    ' "$INVENTORY_FILE"
}

HOSTS_FILE=$(mktemp)
trap 'rm -f "$HOSTS_FILE"' EXIT
parse_inventory >"$HOSTS_FILE"

if [ ! -s "$HOSTS_FILE" ]; then
    echo "no enabled client hosts found in $INVENTORY_FILE" >&2
    exit 1
fi

failures=0
while IFS="$(printf '\t')" read -r name target; do
    echo "==> upgrading $name ($target)"
    if "$SCRIPT_DIR/upgrade-host.sh" "$target"; then
        echo "==> upgraded $name"
    else
        failures=$((failures + 1))
        echo "==> failed to upgrade $name" >&2
        if [ "$CONTINUE_ON_ERROR" != "1" ]; then
            exit 1
        fi
    fi
done <"$HOSTS_FILE"

if [ "$failures" -ne 0 ]; then
    exit 1
fi
