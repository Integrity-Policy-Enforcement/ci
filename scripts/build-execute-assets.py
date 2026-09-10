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
    # A single hugepage-sized LOAD avoids libc/BSS/RELRO mappings whose offsets
    # and lengths cannot be used with a hugetlb memfd. The code only exits zero.
    subprocess.run(
        [
            "gcc", "-nostdlib", "-static",
            "-Wl,--build-id=none,-z,max-page-size=0x200000",
            f"-Wl,-T,{layout.source.MEMFD_TARGET_LINKER_SCRIPT}",
            layout.source.MEMFD_TARGET_SOURCE,
            "-o", layout.build.MEMFD_TEST_BINARY,
        ],
        check=True,
    )
    script = layout.build.SHEBANG_TEST_SCRIPT
    script.write_text(f"#!{layout.guest.FSVERITY_INTERPRETER_TEST_BINARY}\n+\n")
    script.chmod(0o755)
    print("    Prepared the static EXECUTE target, interpreter and shebang script")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
