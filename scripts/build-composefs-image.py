#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Use mkcomposefs to build a metadata image and its real content-addressed objects."""

import shutil
import subprocess
import tempfile
from pathlib import Path

import hashes
import layout


def main() -> int:
    shutil.rmtree(layout.build.COMPOSEFS_DIR, ignore_errors=True)
    layout.build.COMPOSEFS_DIR.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        shutil.copy(layout.build.EXECUTE_TEST_BINARY, root / "target")
        subprocess.run(
            ["mkcomposefs", "--use-epoch", "--min-version=1",
             f"--digest-store={layout.build.COMPOSEFS_OBJECTS}",
             root, layout.build.COMPOSEFS_IMAGE],
            check=True,
        )
    # The executable must be an external object, not inlined in the metadata.
    objects = subprocess.check_output(
        ["composefs-info", "objects", layout.build.COMPOSEFS_IMAGE], text=True,
    ).splitlines()
    if not objects:
        raise RuntimeError("Composefs fixture has no external data object")
    for algorithm in hashes.FSVERITY_ALGORITHMS:
        digest = subprocess.check_output(
            ["fsverity", "digest", layout.build.COMPOSEFS_IMAGE, f"--hash-alg={algorithm}", "--compact"],
            text=True,
        ).strip()
        layout.build.composefs_digest(algorithm).write_text(digest + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
