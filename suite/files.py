# SPDX-License-Identifier: GPL-2.0-only

import shutil
from contextlib import AbstractContextManager
from functools import partial
from pathlib import Path

import layout
from command import run
from scope import collection


def copies(directory: Path) -> set[Path]:
    """The files currently present directly under a directory."""
    if not directory.is_dir():
        return set()
    return {path for path in directory.iterdir() if path.is_file()}


def discard(copy: Path) -> None:
    """Delete a module copy the batch made."""
    copy.unlink()


def copy_kmodule_test_binary(target: Path) -> None:
    """Copy the KMODULE test binary to a new path."""
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(layout.guest.KMODULE_TEST_BINARY, target)


def verity_module(target: Path, algorithm: str, signature: Path | None = None) -> None:
    """Copy the module and enable fs-verity on the copy, optionally with a signature."""
    copy_kmodule_test_binary(target)
    signed = [f"--signature={signature}"] if signature else []
    run("fsverity", "enable", target, f"--hash-alg={algorithm}", *signed)


def copies_scope(*, directory: Path) -> AbstractContextManager[None]:
    """Track files created directly under a directory."""
    return collection(
        members=partial(copies, directory),
        discard=discard,
    )
