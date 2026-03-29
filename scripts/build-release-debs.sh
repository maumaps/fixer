#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
OUTPUT_DIR=${OUTPUT_DIR:-"$REPO_ROOT/dist/packages"}
VERSION=$(dpkg-parsechangelog -SVersion)
ARCH=$(dpkg --print-architecture)
PARENT_DIR=$(CDPATH= cd -- "$REPO_ROOT/.." && pwd)

mkdir -p "$OUTPUT_DIR/$VERSION/$ARCH"

cd "$REPO_ROOT"
dpkg-buildpackage -us -uc -b

find "$PARENT_DIR" -maxdepth 1 -type f \
    \( -name "fixer_${VERSION}_${ARCH}.deb" -o -name "fixer-dbgsym_${VERSION}_${ARCH}.deb" \) \
    -exec cp -f {} "$OUTPUT_DIR/$VERSION/$ARCH/" \;

printf '%s\n' "$OUTPUT_DIR/$VERSION/$ARCH/fixer_${VERSION}_${ARCH}.deb"
