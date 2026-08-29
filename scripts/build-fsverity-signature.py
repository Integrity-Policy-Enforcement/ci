#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Sign the fs-verity digest of the test module.

    build/fsverity/
        ipe_test-sha256.digest    the digest, as ASCII hex
        ipe_test-sha256.p7s       that digest signed by the fs-verity key
        ipe_test-sha512.digest    the same pair, over the same module
        ipe_test-sha512.p7s

One pair per hash in hashes.ALGORITHMS.

The digest depends on the file alone, so it can be computed here, where
the key is, and the guest only has to enable fs-verity with the result.
"""

import shutil
import subprocess

import hashes
import layout
import signing


def main() -> int:
    if not signing.FSVERITY.key.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    if not layout.build.TEST_MODULE.is_file():
        raise SystemExit("the test module is missing; run build-kernel-module.py")
    shutil.rmtree(layout.build.FSVERITY_ASSETS, ignore_errors=True)
    layout.build.FSVERITY_ASSETS.mkdir(parents=True)

    for algorithm in hashes.ALGORITHMS:
        subprocess.run(
            [
                "fsverity", "sign", str(layout.build.TEST_MODULE),
                str(layout.build.fsverity_signature(algorithm)),
                f"--key={signing.FSVERITY.key}", f"--cert={signing.FSVERITY.certificate}",
                f"--hash-alg={algorithm}",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        reported = subprocess.run(
            ["fsverity", "digest", str(layout.build.TEST_MODULE), f"--hash-alg={algorithm}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()[0]
        _, _, digest = reported.partition(":")
        layout.build.fsverity_digest(algorithm).write_text(digest + "\n")

    relative = layout.build.FSVERITY_ASSETS.relative_to(layout.source.ROOT)
    print(f"    Prepared the fs-verity signature in {relative}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
