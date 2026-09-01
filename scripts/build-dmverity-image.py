#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the dm-verity test image, hash trees, root hashes, and signatures.

    build/dmverity/
        dmverity.squashfs         squashfs used by the dm-verity cases
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


def build_squashfs(*, content_dir: Path, image: Path) -> None:
    """Pack a prepared content directory into a squashfs image."""
    run("mksquashfs", content_dir, image, "-noappend", "-all-root")


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


def sign_root_hash(
    *,
    root_hash: Path,
    signature: Path,
    signer: signing.Identity,
) -> None:
    run(
        "openssl", "cms", "-sign", "-binary", "-in", root_hash,
        "-signer", signer.certificate, "-inkey", signer.key,
        "-noattr", "-outform", "DER", "-out", signature,
    )


def main() -> int:
    if not signing.BUILTIN.key.is_file():
        raise SystemExit("signing keys are missing; run prepare-keys.py")
    if not layout.build.KMODULE_TEST_BINARY.is_file():
        raise SystemExit("the test module is missing; run build-kernel-modules.py")
    shutil.rmtree(layout.build.DMVERITY_ASSETS_DIR, ignore_errors=True)
    layout.build.DMVERITY_ASSETS_DIR.mkdir(parents=True)

    with tempfile.TemporaryDirectory() as temporary:
        content_dir = Path(temporary)
        target = content_dir / layout.test_media.KMODULE_TEST_BINARY
        target.parent.mkdir(parents=True)
        shutil.copy(layout.build.KMODULE_TEST_BINARY, target)
        build_squashfs(content_dir=content_dir, image=layout.build.SQUASHFS)

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
            signer=signing.BUILTIN,
        )

    relative = layout.build.DMVERITY_ASSETS_DIR.relative_to(layout.source.ROOT_DIR)
    print(f"    Prepared the dm-verity image in {relative}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
