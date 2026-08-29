# SPDX-License-Identifier: GPL-2.0-only

import shutil
from pathlib import Path

import layout
from command import run
from scope import Collection


def copies() -> set[str]:
    """The module copies a batch made, which outlive it on the payload."""
    if not layout.guest.FSVERITY_MODULES.is_dir():
        return set()
    return {str(path) for path in layout.guest.FSVERITY_MODULES.iterdir()}


def discard(copy: str) -> None:
    """Delete a module copy the batch made."""
    Path(copy).unlink()


def copy_module(target: Path) -> None:
    """Copy the test module from the payload to a new path."""
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(layout.guest.TEST_MODULE, target)


def verity_module(target: Path, algorithm: str, signature: Path | None = None) -> None:
    """Copy the module and enable fs-verity on the copy, optionally with a signature."""
    copy_module(target)
    signed = [f"--signature={signature}"] if signature else []
    run("fsverity", "enable", target, f"--hash-alg={algorithm}", *signed)


COPIES = Collection(members=copies, discard=discard)
