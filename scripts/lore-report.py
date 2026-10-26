#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Post the result of a lore series test run to its tracking issue."""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

LABELS = {
    "pass": ("ci-pass", "0e8a16", "IPE CI: series applied and all tests passed"),
    "fail": ("ci-fail", "d73a4a", "IPE CI: series applied but tests failed"),
    "apply-failed": ("ci-apply-failed", "fbca04", "IPE CI: series could not be applied"),
    "error": ("ci-error", "cccccc", "IPE CI: run did not produce a verdict"),
}
SEVERITY = ("apply-failed", "fail", "error", "pass")
NOT_OK = re.compile(r"^\s*not ok\b(?!.*#\s*(TODO|SKIP)\b)", re.IGNORECASE)
MAX_LINES = 30


def read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def code_block(lines: list[str]) -> str:
    text = "\n".join(line.replace("```", "'''") for line in lines[:MAX_LINES])
    if len(lines) > MAX_LINES:
        text += f"\n... ({len(lines) - MAX_LINES} more)"
    return f"```\n{text}\n```"


def architecture_result(directory: Path) -> tuple[str, list[str]]:
    output = directory / "out"
    apply = read_json(output / "apply.json")
    if apply is None:
        return "error", ["the job ended before the series was applied"]
    if apply.get("status") != "applied":
        details = [f"Reason: {apply.get('reason', 'unknown')}"]
        for attempt in apply.get("attempts", []):
            details.append(f"Tried on {attempt.get('base_source')} `{attempt.get('base')}`:")
            details.append(code_block(str(attempt.get("output", "")).splitlines()[-MAX_LINES:]))
        return "apply-failed", details

    details = [
        f"Applied {len(apply.get('commits', []))} commit(s) on "
        f"{apply.get('base_source')} `{apply.get('base', '')[:12]}`"
    ]
    verdict = read_json(output / "verdict.json")
    if verdict is None:
        details.append("No verdict: the kernel build, image build or VM did not finish.")
        return "error", details
    if verdict.get("verdict") == "PASS":
        details.append("All TAP cases passed.")
        return "pass", details

    try:
        result = (output / "result.log").read_text(encoding="utf-8", errors="replace")
    except OSError:
        result = ""
    failed = [line.strip() for line in result.splitlines() if NOT_OK.match(line)]
    if failed:
        details.append("Failed TAP cases:")
        details.append(code_block(failed))
    details.append("Verdict reasons:")
    details.append(code_block([str(reason) for reason in verdict.get("reasons", [])]))
    return "fail", details


def gh(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["gh", *args], check=check, text=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    issue = os.environ.get("REPORT_ISSUE", "")
    if not issue.isdigit():
        print(f"invalid issue number: {issue!r}", file=sys.stderr)
        return 1
    run_url = os.environ.get("RUN_URL", "")
    message_id = os.environ.get("LORE_MESSAGE_ID", "")

    results = {}
    for directory in sorted(args.evidence.glob("test-evidence-*")):
        architecture = directory.name.removeprefix("test-evidence-")
        results[architecture] = architecture_result(directory)
    if not results:
        results["(all)"] = ("error", ["no test evidence was uploaded"])

    overall = next(
        state for state in SEVERITY if any(r[0] == state for r in results.values())
    )
    lines = [
        f"## IPE CI: {overall.upper()}",
        "",
        f"Message-ID: `{message_id.replace('`', '')}`",
        f"Run: {run_url}",
    ]
    for architecture, (state, details) in results.items():
        lines += ["", f"### {architecture}: {state}", "", *details]
    body = "\n".join(lines) + "\n"
    print(body)
    if args.dry_run:
        return 0

    for name, color, description in LABELS.values():
        gh("label", "create", name, "--force", "--color", color,
           "--description", description)
    gh("issue", "comment", issue, "--body", body)
    stale = [name for state, (name, _, _) in LABELS.items() if state != overall]
    gh("issue", "edit", issue, "--remove-label", ",".join(stale), check=False)
    gh("issue", "edit", issue, "--add-label", LABELS[overall][0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
