#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare fs-verity digests and signatures for the test inputs.

    build/fsverity/
        ipe_test-<hash>.digest             digest of ipe_test.ko
        ipe_test-<hash>.p7s                signature over that digest
        ipe_test.ko.gz                    compressed module used by the guest
        ipe_test-compressed-<hash>.digest  digest of the compressed file
        ipe_test-compressed-<hash>.p7s     signature over that digest
        firmware/ipe_test-<hash>.digest   digest of ipe_test.fw
        firmware/ipe_test-<hash>.p7s      signature over the firmware digest

Use hashes.FSVERITY_ALGORITHMS for every input. The digest depends on the
file bytes, so compute and sign it here; the guest enables fs-verity on
an exact copy of the same file.
"""

import gzip
import shutil
import subprocess
from pathlib import Path

import hashes
import layout
import signing


def prepare_input(
    *,
    binary: Path,
    algorithm: str,
    signature_path: Path,
    digest_path: Path,
) -> None:
    """Measure and sign one test input with one fs-verity hash."""
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "fsverity", "sign", str(binary), str(signature_path),
            f"--key={signing.FSVERITY.key}", f"--cert={signing.FSVERITY.certificate}",
            f"--hash-alg={algorithm}",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    digest = subprocess.run(
        ["fsverity", "digest", str(binary), f"--hash-alg={algorithm}", "--compact"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    digest_path.write_text(digest + "\n")


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
    for compressed in (False, True):
        binary = (
            layout.build.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY
            if compressed
            else layout.build.KMODULE_TEST_BINARY
        )
        for algorithm in hashes.FSVERITY_ALGORITHMS:
            prepare_input(
                binary=binary,
                algorithm=algorithm,
                signature_path=layout.build.fsverity_signature(
                    algorithm=algorithm, compressed=compressed
                ),
                digest_path=layout.build.fsverity_digest(
                    algorithm=algorithm, compressed=compressed
                ),
            )
    for algorithm in hashes.FSVERITY_ALGORITHMS:
        prepare_input(
            binary=layout.source.FIRMWARE_TEST_BINARY,
            algorithm=algorithm,
            signature_path=layout.build.fsverity_firmware_signature(algorithm=algorithm),
            digest_path=layout.build.fsverity_firmware_digest(algorithm=algorithm),
        )

    for algorithm in hashes.FSVERITY_ALGORITHMS:
        prepare_input(
            binary=layout.build.KEXEC_IMAGE_TEST_BINARY,
            algorithm=algorithm,
            signature_path=layout.build.fsverity_kexec_image_signature(algorithm=algorithm),
            digest_path=layout.build.fsverity_kexec_image_digest(algorithm=algorithm),
        )

    for algorithm in hashes.FSVERITY_ALGORITHMS:
        prepare_input(
            binary=layout.build.KEXEC_INITRAMFS_TEST_BINARY,
            algorithm=algorithm,
            signature_path=layout.build.fsverity_kexec_initramfs_signature(algorithm=algorithm),
            digest_path=layout.build.fsverity_kexec_initramfs_digest(algorithm=algorithm),
        )

    for algorithm in hashes.FSVERITY_ALGORITHMS:
        prepare_input(
            binary=layout.source.POLICY_OP_TEST_BINARY,
            algorithm=algorithm,
            signature_path=layout.build.fsverity_policy_op_signature(algorithm=algorithm),
            digest_path=layout.build.fsverity_policy_op_digest(algorithm=algorithm),
        )

    for algorithm in hashes.FSVERITY_ALGORITHMS:
        prepare_input(
            binary=layout.build.X509_TEST_BINARY,
            algorithm=algorithm,
            signature_path=layout.build.fsverity_x509_signature(algorithm=algorithm),
            digest_path=layout.build.fsverity_x509_digest(algorithm=algorithm),
        )

    for algorithm in hashes.FSVERITY_ALGORITHMS:
        prepare_input(
            binary=layout.build.EXECUTE_TEST_BINARY,
            algorithm=algorithm,
            signature_path=layout.build.fsverity_execute_signature(algorithm=algorithm),
            digest_path=layout.build.fsverity_execute_digest(algorithm=algorithm),
        )

    relative = layout.build.FSVERITY_ASSETS_DIR.relative_to(layout.source.ROOT_DIR)
    print(f"    Prepared the fs-verity signatures in {relative}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
