# SPDX-License-Identifier: GPL-2.0-only
"""Metadata-backing properties of files executed directly from file-backed EROFS."""

from functools import partial

import hashes
import ipe
import layout
from assets import policy
from model import Batch
from operations import execve
from resources import erofs, files, mounts


def build() -> tuple[Batch, ...]:
    return (
        Batch(
            id="erofs",
            cases=(
                # Policy: EXECUTE default DENY; ALLOW the EROFS image's fs-verity digest.
                # Input: static ELF inside EROFS; unsigned fs-verity is enabled on the image.
                # Match: the backing image digest matches -> explicit ALLOW, not the ELF digest.
                *(
                    execve.execve_case(
                        id=f"erofs_metadata_fsverity_digest_{algorithm}_match_ok",
                        policy=policy(
                            asset=f"erofs/metadata_digest_{algorithm}_allow",
                            name=f"ipe_test_erofs_metadata_digest_{algorithm}_allow",
                        ),
                        binary=erofs.MOUNT / algorithm / "target",
                        expected_errno=0,
                        expected_returncode=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
            ),
            setup=(
                partial(ipe.set_enforcement, enabled=False),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.EROFS_IMAGE,
                        target=erofs.fsverity_image(algorithm),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        mounts.mount,
                        erofs.fsverity_image(algorithm),
                        erofs.MOUNT / algorithm,
                        "-t", "erofs", "-o", "ro,X-mount.noloop",
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
            ),
            extra_scopes=(
                partial(files.directory_scope, directory=erofs.FILES),
                partial(mounts.mounted_scope, directory=erofs.MOUNT),
            ),
        ),
    )
