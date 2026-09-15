# SPDX-License-Identifier: GPL-2.0-only
"""Metadata-backing properties through real Composefs metadata and object layers."""

from functools import partial

import hashes
import ipe
import layout
from assets import policy
from model import Batch
from operations import execve
from resources import composefs, files, mounts


def build() -> tuple[Batch, ...]:
    return (
        Batch(
            id="composefs",
            cases=(
                # Policy: EXECUTE default DENY; ALLOW the metadata image's fs-verity digest.
                # Input: mkcomposefs image mounted with verity; data is a separate fs-verity object.
                # Match: verified data is bound to this metadata image -> explicit ALLOW.
                *(
                    execve.execve_case(
                        id=f"composefs_metadata_fsverity_digest_{algorithm}_match_ok",
                        policy=policy(
                            asset=f"composefs/metadata_digest_{algorithm}_allow",
                            name=f"ipe_test_composefs_metadata_digest_{algorithm}_allow",
                        ),
                        binary=composefs.MOUNT / f"{algorithm}-verity" / "target",
                        expected_errno=0,
                        expected_returncode=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
            ),
            setup=(
                partial(ipe.set_enforcement, enabled=False),
                composefs.prepare_objects,
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.COMPOSEFS_IMAGE,
                        target=composefs.fsverity_image(algorithm),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        composefs.mount,
                        image=composefs.fsverity_image(algorithm),
                        point=composefs.MOUNT / f"{algorithm}-verity",
                        verity=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
            ),
            extra_scopes=(
                partial(files.directory_scope, directory=composefs.FILES),
                partial(mounts.mounted_scope, directory=composefs.MOUNT),
            ),
        ),
    )
