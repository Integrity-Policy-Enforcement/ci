# SPDX-License-Identifier: GPL-2.0-only
"""Prepare Composefs objects and mount the official mkcomposefs image with its helper."""

from pathlib import Path

import layout
from command import run

from . import files

FILES = layout.guest.PAYLOAD_DIR / "fsverity-composefs"
OBJECTS = FILES / "objects"
MOUNT = layout.guest.MEDIA_DIR / "composefs"


def fsverity_image(algorithm: str) -> Path:
    """The metadata image digest is independent of its data object's digest."""
    return FILES / f"image-{algorithm}.cfs"


def prepare_objects() -> None:
    """Enable fs-verity on mkcomposefs's actual data objects, without recreating them."""
    for source in sorted(layout.guest.COMPOSEFS_OBJECTS.rglob("*")):
        if source.is_file():
            files.prepare_fsverity_test_binary(
                source=source,
                target=OBJECTS / source.relative_to(layout.guest.COMPOSEFS_OBJECTS),
                # Composefs v1 records SHA-256 fs-verity digests for its objects.
                algorithm="sha256",
            )


def mount(image: Path, point: Path, verity: bool) -> None:
    """Mount a view; the batch's existing mounted_scope owns cleanup."""
    options = f"ro,basedir={OBJECTS}" + (",verity" if verity else "")
    point.mkdir(parents=True, exist_ok=True)
    run("mount.composefs", "-o", options, image, point)
