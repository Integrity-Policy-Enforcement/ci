#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the dm-verity image the tests open, signed and unsigned.

    build/dmverity/
        dmverity.squashfs     holds ipe_test.ko, nothing else
        dmverity-sha256.hash      sha256 Merkle tree over dmverity.squashfs
        dmverity-sha256.roothash  root of the sha256 tree, as ASCII hex
        dmverity-sha256.p7s       builtin signature over the sha256 root hash
        dmverity-sha512.hash      sha512 Merkle tree over dmverity.squashfs
        dmverity-sha512.roothash  root of the sha512 tree, as ASCII hex
        dmverity-sha512.p7s       builtin signature over the sha512 root hash

One set per hash in hashes.ALGORITHMS, all over the same image.

The guest opens the same image twice per hash, once passing that hash's
signature and once not, which is the only difference between the two
devices it gets.
"""

import shutil
import subprocess
from pathlib import Path

import hashes
import layout
import signing


def run(*command: object, **kwargs: object) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(part) for part in command], check=True, stdout=subprocess.DEVNULL, **kwargs
    )


def capture(*command: object) -> str:
    return subprocess.run(
        [str(part) for part in command], check=True, capture_output=True, text=True
    ).stdout


def build_squashfs(image: Path) -> None:
    staging = layout.build.DMVERITY_ASSETS / "tree"
    staging.mkdir()
    shutil.copy(layout.build.TEST_MODULE, staging / layout.build.TEST_MODULE.name)
    run("mksquashfs", staging, image, "-noappend", "-all-root")
    shutil.rmtree(staging)


def format_hash_tree(image: Path, hash_tree: Path, algorithm: str) -> str:
    formatted = capture("veritysetup", "format", image, hash_tree, f"--hash={algorithm}")
    for line in formatted.splitlines():
        if line.startswith("Root hash:"):
            return line.split()[-1]
    raise SystemExit("veritysetup printed no root hash")


def sign_root_hash(root_hash: str, signature: Path) -> None:
    plain = signature.with_suffix(".txt")
    plain.write_text(root_hash)
    run(
        "openssl", "cms", "-sign", "-binary", "-in", plain,
        "-signer", signing.BUILTIN.certificate, "-inkey", signing.BUILTIN.key,
        "-noattr", "-outform", "DER", "-out", signature,
    )
    plain.unlink()


def main() -> int:
    if not signing.BUILTIN.key.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    if not layout.build.TEST_MODULE.is_file():
        raise SystemExit("the test module is missing; run build-kernel-module.py")
    shutil.rmtree(layout.build.DMVERITY_ASSETS, ignore_errors=True)
    layout.build.DMVERITY_ASSETS.mkdir(parents=True)

    build_squashfs(layout.build.SQUASHFS)
    for algorithm in hashes.ALGORITHMS:
        root_hash = format_hash_tree(
            layout.build.SQUASHFS,
            layout.build.hash_tree(algorithm),
            algorithm,
        )
        layout.build.root_hash(algorithm).write_text(root_hash + "\n")
        sign_root_hash(root_hash, layout.build.root_hash_signature(algorithm))

    relative = layout.build.DMVERITY_ASSETS.relative_to(layout.source.ROOT)
    print(f"    Prepared the dm-verity image in {relative}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
