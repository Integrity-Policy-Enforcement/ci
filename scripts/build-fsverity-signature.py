#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Sign the fs-verity digest of the test module.

    build/fsverity/
        ipe_test-<hash>.digest    the digest, as ASCII hex
        ipe_test-<hash>.p7s       that digest signed by the fs-verity key

One pair per hash in layout.HASH_ALGORITHMS.

The digest depends on the file alone, so it can be computed here, where
the key is, and the guest only has to enable fs-verity with the result.
"""

import shutil
import subprocess

import layout
import signing


def main():
    if not signing.FSVERITY.key.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    if not layout.build.TEST_MODULE.is_file():
        raise SystemExit("the test module is missing; run build-kernel-module.py")
    shutil.rmtree(layout.build.FSVERITY_ASSETS, ignore_errors=True)
    layout.build.FSVERITY_ASSETS.mkdir(parents=True)

    for algorithm in layout.HASH_ALGORITHMS:
        subprocess.run(
            [
                "fsverity", "sign", str(layout.build.TEST_MODULE),
                str(layout.build.FSVERITY_ASSETS / layout.guest.fsverity_signature(algorithm)),
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
        (layout.build.FSVERITY_ASSETS / layout.guest.fsverity_digest(algorithm)).write_text(digest + "\n")

    print(f"    Prepared the fs-verity signature in {layout.build.FSVERITY_ASSETS.relative_to(layout.source.ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
