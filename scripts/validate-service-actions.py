#!/usr/bin/env python3

from __future__ import annotations

import pathlib
import re
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC_PATH = REPO_ROOT / "doc" / "service-actions.md"
REQUIRED_ACTION_IDS = {
    "publish-version",
    "build-release-packages",
    "publish-apt-repo",
    "deploy-public-server",
    "release-public",
    "enroll-client-host",
    "upgrade-host",
    "upgrade-all-hosts",
    "verify-public-services",
}
REQUIRED_SECTIONS = (
    "Purpose",
    "When To Use",
    "Implementation",
    "Prerequisites",
    "Inputs",
    "Commands",
    "Verification",
    "Failure / Rollback",
)
DEPLOYMENT_ACTIONS = {
    "publish-apt-repo",
    "deploy-public-server",
    "release-public",
    "enroll-client-host",
    "upgrade-host",
    "upgrade-all-hosts",
}


def fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


def parse_actions(text: str) -> list[dict[str, object]]:
    matches = list(re.finditer(r"^## Action: .+$", text, re.MULTILINE))
    if not matches:
        fail("no action sections found in doc/service-actions.md")

    actions: list[dict[str, object]] = []
    for index, match in enumerate(matches):
        start = match.start()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        chunk = text[start:end]
        title = match.group(0).split(": ", 1)[1].strip()
        action_id_match = re.search(r"^Action ID: `([^`]+)`$", chunk, re.MULTILINE)
        if not action_id_match:
            fail(f"missing Action ID under action {title}")
        sections: dict[str, str] = {}
        section_matches = list(re.finditer(r"^### (.+)$", chunk, re.MULTILINE))
        for section_index, section_match in enumerate(section_matches):
            section_name = section_match.group(1).strip()
            section_start = section_match.end()
            section_end = (
                section_matches[section_index + 1].start()
                if section_index + 1 < len(section_matches)
                else len(chunk)
            )
            sections[section_name] = chunk[section_start:section_end].strip()
        actions.append(
            {
                "title": title,
                "id": action_id_match.group(1),
                "chunk": chunk,
                "sections": sections,
            }
        )
    return actions


def ensure_required_sections(action: dict[str, object]) -> None:
    sections = action["sections"]
    assert isinstance(sections, dict)
    for section_name in REQUIRED_SECTIONS:
        if section_name not in sections:
            fail(f"action {action['id']} is missing section: {section_name}")
        if not sections[section_name].strip():
            fail(f"action {action['id']} has an empty section: {section_name}")


def ensure_implementation_refs(action: dict[str, object]) -> None:
    sections = action["sections"]
    assert isinstance(sections, dict)
    implementation = sections["Implementation"]
    if "- Type: `manual`" in implementation:
        return
    scripts = re.findall(r"- Script: `([^`]+)`", implementation)
    if not scripts:
        fail(f"action {action['id']} needs a script reference or manual type")
    for script in scripts:
        if not (REPO_ROOT / script).exists():
            fail(f"action {action['id']} references missing script: {script}")


def ensure_command_blocks(action: dict[str, object]) -> None:
    sections = action["sections"]
    assert isinstance(sections, dict)
    for section_name in ("Commands", "Verification"):
        if "```" not in sections[section_name]:
            fail(f"action {action['id']} must include a fenced code block in {section_name}")


def ensure_deployment_policy(action: dict[str, object]) -> None:
    if action["id"] not in DEPLOYMENT_ACTIONS:
        return
    sections = action["sections"]
    assert isinstance(sections, dict)
    prerequisites = sections["Prerequisites"].lower()
    if "minor version" not in prerequisites:
        fail(f"deployment action {action['id']} must mention the minor version bump requirement")
    if "committed to git" not in prerequisites:
        fail(f"deployment action {action['id']} must mention the committed-state requirement")


def main() -> None:
    text = DOC_PATH.read_text(encoding="utf-8")
    actions = parse_actions(text)
    seen_ids = set()
    for action in actions:
        action_id = action["id"]
        if action_id in seen_ids:
            fail(f"duplicate action id: {action_id}")
        seen_ids.add(action_id)
        ensure_required_sections(action)
        ensure_implementation_refs(action)
        ensure_command_blocks(action)
        ensure_deployment_policy(action)

    missing = REQUIRED_ACTION_IDS - seen_ids
    if missing:
        fail("missing required actions: " + ", ".join(sorted(missing)))

    print(f"validated {len(actions)} service actions in {DOC_PATH}")


if __name__ == "__main__":
    main()
