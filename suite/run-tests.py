#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import sys
from pathlib import Path

import runner


def main(argv: list[str] | None = None) -> int:
    """Run the suite, appending TAP to the requested result channel."""
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: run-tests.py <result-channel>", file=sys.stderr)
        return 2
    with Path(argv[0]).open("a", encoding="utf-8") as output:
        return runner.run(output)


if __name__ == "__main__":
    raise SystemExit(main())
