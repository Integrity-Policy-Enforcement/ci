#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the dm-verity test image, hash trees, root hashes, and signatures.

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
import tempfile
from pathlib import Path

import hashes
import layout
import signing


def run(*command: object, **kwargs: object) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(part) for part in command], check=True, stdout=subprocess.DEVNULL, **kwargs
    )


def build_squashfs(image: Path) -> None:
    """Assemble the squashfs root and pack it into an image."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        shutil.copy(layout.build.TEST_MODULE, root / layout.build.TEST_MODULE.name)
        run("mksquashfs", root, image, "-noappend", "-all-root")


def format_hash_tree(
    image: Path,
    hash_tree: Path,
    root_hash: Path,
    algorithm: str,
) -> None:
    """Build one Merkle tree and write its root hash to a file."""
    run(
        "veritysetup",
        "format",
        image,
        hash_tree,
        f"--hash={algorithm}",
        f"--root-hash-file={root_hash}",
    )


def sign_root_hash(root_hash: Path, signature: Path) -> None:
    run(
        "openssl", "cms", "-sign", "-binary", "-in", root_hash,
        "-signer", signing.BUILTIN.certificate, "-inkey", signing.BUILTIN.key,
        "-noattr", "-outform", "DER", "-out", signature,
    )


def main() -> int:
    if not signing.BUILTIN.key.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    if not layout.build.TEST_MODULE.is_file():
        raise SystemExit("the test module is missing; run build-kernel-module.py")
    shutil.rmtree(layout.build.DMVERITY_ASSETS, ignore_errors=True)
    layout.build.DMVERITY_ASSETS.mkdir(parents=True)

    build_squashfs(layout.build.SQUASHFS)
    for algorithm in hashes.ALGORITHMS:
        root_hash = layout.build.root_hash(algorithm)
        format_hash_tree(
            image=layout.build.SQUASHFS,
            hash_tree=layout.build.hash_tree(algorithm),
            root_hash=root_hash,
            algorithm=algorithm,
        )
        sign_root_hash(
            root_hash=root_hash,
            signature=layout.build.root_hash_signature(algorithm),
        )

    relative = layout.build.DMVERITY_ASSETS.relative_to(layout.source.ROOT)
    print(f"    Prepared the dm-verity image in {relative}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
