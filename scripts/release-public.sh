#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

python3 "$SCRIPT_DIR/check-nonlocal-deploy.py"
"$SCRIPT_DIR/build-release-debs.sh"
"$SCRIPT_DIR/deploy-fixer-server.sh"
"$SCRIPT_DIR/verify-public-services.sh"
