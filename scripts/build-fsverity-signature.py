#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Sign the fs-verity digest of the test module.

    build/fsverity/
        ipe_test-sha256.digest    sha256 digest of ipe_test.ko, as ASCII hex
        ipe_test-sha256.p7s       fsverity signature over the sha256 digest
        ipe_test-sha512.digest    sha512 digest of ipe_test.ko, as ASCII hex
        ipe_test-sha512.p7s       fsverity signature over the sha512 digest
        ipe_test.ko.gz            the compressed module used by the guest
        ipe_test-compressed-<hash>.digest  digest of the compressed file
        ipe_test-compressed-<hash>.p7s     signature over that digest

One pair per hash in hashes.FSVERITY_ALGORITHMS for each module format.

The digest depends on the file alone, so it can be computed here, where
the key is, and the guest only has to enable fs-verity with the result.
"""

import gzip
import shutil
import subprocess

import hashes
import layout
import signing


def main() -> int:
    if not signing.FSVERITY.key.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    if not layout.build.KMODULE_TEST_BINARY.is_file():
        raise SystemExit("the test module is missing; run build-kernel-modules.py")
    shutil.rmtree(layout.build.FSVERITY_ASSETS_DIR, ignore_errors=True)
    layout.build.FSVERITY_ASSETS_DIR.mkdir(parents=True)

    layout.build.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY.write_bytes(
        gzip.compress(layout.build.KMODULE_TEST_BINARY.read_bytes(), mtime=0)
    )
    for compressed, binary in (
        (False, layout.build.KMODULE_TEST_BINARY),
        (True, layout.build.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY),
    ):
        for algorithm in hashes.FSVERITY_ALGORITHMS:
            subprocess.run(
                [
                    "fsverity", "sign", str(binary),
                    str(layout.build.fsverity_signature(
                        algorithm=algorithm, compressed=compressed
                    )),
                    f"--key={signing.FSVERITY.key}", f"--cert={signing.FSVERITY.certificate}",
                    f"--hash-alg={algorithm}",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            digest = subprocess.run(
                [
                    "fsverity",
                    "digest",
                    str(binary),
                    f"--hash-alg={algorithm}",
                    "--compact",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            layout.build.fsverity_digest(
                algorithm=algorithm, compressed=compressed
            ).write_text(digest + "\n")

    relative = layout.build.FSVERITY_ASSETS_DIR.relative_to(layout.source.ROOT_DIR)
    print(f"    Prepared the fs-verity signature in {relative}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
