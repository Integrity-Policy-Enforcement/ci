# SPDX-License-Identifier: GPL-2.0-only

import shutil
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import layout
from command import run


def copy_kmodule_test_binary(
    target: Path,
    source: Path = layout.guest.KMODULE_TEST_BINARY,
) -> None:
    """Copy a KMODULE test binary to a new path."""
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(source, target)


def prepare_fsverity_kmodule_test_binary(
    target: Path,
    algorithm: str,
    signature: Path | None = None,
    source: Path = layout.guest.KMODULE_TEST_BINARY,
) -> None:
    """Copy a KMODULE test binary and enable fs-verity on it."""
    copy_kmodule_test_binary(target=target, source=source)
    signed = [f"--signature={signature}"] if signature else []
    run("fsverity", "enable", target, f"--hash-alg={algorithm}", *signed)


@contextmanager
def directory_scope(*, directory: Path) -> Generator[None, None, None]:
    """Remove a test-owned directory when the scope exits."""
    try:
        yield
    finally:
        try:
            shutil.rmtree(directory)
        except FileNotFoundError:
            pass
