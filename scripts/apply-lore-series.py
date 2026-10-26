#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fetch a patch series from lore with b4 and apply it to a kernel tree.

The outcome is written to a JSON status file so that a series which does not
apply can be reported separately from a test failure.
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

BASE_COMMIT = re.compile(r"^base-commit:\s*([0-9a-f]{7,40})\b", re.MULTILINE)


def git(tree: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(tree), *args], check=check, text=True, capture_output=True
    )


def commit_exists(tree: Path, revision: str) -> bool:
    return git(tree, "cat-file", "-e", f"{revision}^{{commit}}", check=False).returncode == 0


def declared_base(directory: Path) -> str | None:
    for path in sorted(directory.glob("series.*")):
        match = BASE_COMMIT.search(path.read_text(encoding="utf-8", errors="replace"))
        if match:
            return match.group(1)
    return None


def apply(tree: Path, start: str, mbox: Path) -> tuple[bool, str]:
    git(tree, "checkout", "--quiet", "--detach", start)
    result = git(tree, "am", "-3", str(mbox), check=False)
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        git(tree, "am", "--abort", check=False)
    return result.returncode == 0, output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel_tree", type=Path)
    parser.add_argument("message_id")
    parser.add_argument("--status", type=Path, required=True)
    parser.add_argument(
        "--use-base-commit",
        action="store_true",
        help="apply on the series' base-commit first when the tree has it",
    )
    args = parser.parse_args(argv)

    tree = args.kernel_tree.resolve()
    status: dict = {"message_id": args.message_id, "status": "apply-failed"}

    def finish(code: int) -> int:
        args.status.parent.mkdir(parents=True, exist_ok=True)
        args.status.write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(status, indent=2))
        return code

    original = git(tree, "rev-parse", "HEAD").stdout.strip()
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        fetched = subprocess.run(
            ["b4", "am", "--outdir", str(directory), "--mbox-name", "series",
             "--", args.message_id],
            cwd=tree, text=True, capture_output=True, check=False,
        )
        print(fetched.stdout + fetched.stderr, flush=True)
        mbox = directory / "series.mbx"
        if fetched.returncode != 0 or not mbox.is_file() or not mbox.stat().st_size:
            status["reason"] = "b4 could not fetch the series"
            return finish(1)

        candidates = []
        base = declared_base(directory)
        status["declared_base"] = base
        if args.use_base_commit and base:
            if commit_exists(tree, base):
                candidates.append(("base-commit", base))
            else:
                print(f"base-commit {base} is not in the tree; using the default tree")
        candidates.append(("tree", original))

        for source, start in candidates:
            applied, output = apply(tree, start, mbox)
            print(output, flush=True)
            if applied:
                start_sha = git(tree, "rev-parse", start).stdout.strip()
                status.update(
                    status="applied",
                    base=start_sha,
                    base_source=source,
                    commits=git(
                        tree, "log", "--format=%h %s", f"{start_sha}..HEAD"
                    ).stdout.splitlines(),
                )
                return finish(0)
            print(f"series does not apply on {source} ({start})", flush=True)
            status.setdefault("attempts", []).append(
                {"base_source": source, "base": start, "output": output[-4000:]}
            )

    git(tree, "checkout", "--quiet", "--detach", original, check=False)
    status["reason"] = "the series does not apply"
    return finish(1)


if __name__ == "__main__":
    sys.exit(main())
