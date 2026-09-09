#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the self-contained ELF used by the execve tests."""

import subprocess

import layout


def main() -> int:
    layout.build.EXECUTE_TEST_BINARY.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "gcc", "-static", "-Os", "-Wall", "-Wextra", "-Werror",
            layout.source.EXECUTE_TARGET_SOURCE,
            "-o", layout.build.EXECUTE_TEST_BINARY,
        ],
        check=True,
    )
    print("    Prepared the static EXECUTE test binary")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
