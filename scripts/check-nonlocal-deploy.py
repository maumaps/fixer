#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import re
import subprocess
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CHANGELOG = REPO_ROOT / "debian" / "changelog"
CARGO_TOML = REPO_ROOT / "Cargo.toml"


def run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, cwd=REPO_ROOT, text=True).strip()


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def parse_semver(text: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", text)
    if not match:
        fail(f"unsupported semver: {text}")
    return tuple(int(part) for part in match.groups())


def first_versions_from_changelog() -> tuple[str, str]:
    versions: list[str] = []
    for line in CHANGELOG.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^fixer \(([^)]+)\)", line)
        if not match:
            continue
        versions.append(match.group(1).split("-", 1)[0])
        if len(versions) == 2:
            return versions[0], versions[1]
    fail("expected at least two fixer versions in debian/changelog")


def cargo_version() -> str:
    match = re.search(
        r'^\[workspace\.package\]\n(?:.+\n)*?version = "([^"]+)"',
        CARGO_TOML.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not match:
        fail("could not find [workspace.package] version in Cargo.toml")
    return match.group(1)


def ensure_clean_git_state() -> None:
    run(["git", "rev-parse", "--verify", "HEAD"])
    status = run(["git", "status", "--porcelain"])
    if status:
        fail(
            "working tree is not clean; commit or stash changes before a non-local deployment"
        )


def ensure_minor_bump(current: str, previous: str) -> None:
    current_major, current_minor, current_patch = parse_semver(current)
    previous_major, previous_minor, _ = parse_semver(previous)
    if current_major != previous_major:
        fail(
            f"expected same major version for a minor bump, got {previous} -> {current}"
        )
    if current_minor != previous_minor + 1 or current_patch != 0:
        fail(
            "expected a minor version bump before non-local deployment; "
            f"got {previous} -> {current}"
        )


def main() -> None:
    ensure_clean_git_state()
    changelog_current, changelog_previous = first_versions_from_changelog()
    cargo_current = cargo_version()
    if cargo_current != changelog_current:
        fail(
            "Cargo.toml and debian/changelog disagree on the release version: "
            f"{cargo_current} vs {changelog_current}"
        )
    ensure_minor_bump(changelog_current, changelog_previous)
    print(
        "non-local deployment ready:",
        f"version={changelog_current}",
        f"previous={changelog_previous}",
    )


if __name__ == "__main__":
    main()
