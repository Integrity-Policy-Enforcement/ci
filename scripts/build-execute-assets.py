#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the self-contained ELF target and the small static script interpreter."""

import subprocess

import layout


def main() -> int:
    for source, target in (
        (layout.source.EXECUTE_TARGET_SOURCE, layout.build.EXECUTE_TEST_BINARY),
        (layout.source.INTERPRETER_SOURCE, layout.build.INTERPRETER_TEST_BINARY),
    ):
        target.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "gcc", "-static", "-Os", "-Wall", "-Wextra", "-Werror",
                source, "-o", target,
            ],
            check=True,
        )
    print("    Prepared the static EXECUTE target and interpreter")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
