#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the ELF targets, the small static script interpreter and the preload library."""

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
    # hugetlb-target.ld lays out the single 2 MiB segment. Omit the build-ID
    # note, which would push that segment past 2 MiB, and the symbol and
    # section tables after it, which exec never maps: the file is then exactly
    # one 2 MiB hugepage.
    subprocess.run(
        [
            "gcc", "-nostdlib", "-static",
            "-Wl,--build-id=none,--strip-all,-z,nosectionheader",
            f"-Wl,-T,{layout.source.HUGETLB_TARGET_LINKER_SCRIPT}",
            layout.source.HUGETLB_TARGET_SOURCE,
            "-o", layout.build.HUGETLB_TEST_BINARY,
        ],
        check=True,
    )
    # LD_PRELOAD cases load this shared library into /usr/bin/true.
    subprocess.run(
        [
            "gcc", "-shared", "-fPIC", "-Os", "-Wall", "-Wextra", "-Werror",
            layout.source.PRELOAD_LIBRARY_SOURCE, "-o", layout.build.PRELOAD_LIBRARY,
        ],
        check=True,
    )
    print("    Prepared the EXECUTE and hugetlb targets, interpreter and preload library")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
