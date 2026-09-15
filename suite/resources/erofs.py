# SPDX-License-Identifier: GPL-2.0-only
"""Paths for the file-backed EROFS test images and mount points."""

from pathlib import Path

import layout

FILES = layout.guest.PAYLOAD_DIR / "fsverity-erofs"
MOUNT = layout.guest.MEDIA_DIR / "erofs"


def fsverity_image(algorithm: str) -> Path:
    """The outer image has fs-verity, not the executable inside it."""
    return FILES / f"image-{algorithm}.erofs"
