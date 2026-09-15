#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Pack the static executable into EROFS and measure the image itself."""

import shutil
import subprocess
import tempfile
from pathlib import Path

import hashes
import layout


def main() -> int:
    shutil.rmtree(layout.build.EROFS_DIR, ignore_errors=True)
    layout.build.EROFS_DIR.mkdir(parents=True)
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        shutil.copy(layout.build.EXECUTE_TEST_BINARY, root / "target")
        subprocess.run(
            ["mkfs.erofs", "-T", "0", "--all-root", layout.build.EROFS_IMAGE, root],
            check=True,
        )
    for algorithm in hashes.FSVERITY_ALGORITHMS:
        digest = subprocess.check_output(
            ["fsverity", "digest", layout.build.EROFS_IMAGE, f"--hash-alg={algorithm}", "--compact"],
            text=True,
        ).strip()
        layout.build.erofs_digest(algorithm).write_text(digest + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
