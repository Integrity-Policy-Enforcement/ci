# SPDX-License-Identifier: GPL-2.0-only

import subprocess
from contextlib import AbstractContextManager
from functools import partial
from pathlib import Path

from command import capture, run
from scope import collection


def names() -> set[str]:
    """All module names reported by lsmod."""
    return {line.split()[0] for line in capture("lsmod").splitlines()[1:]}


def loaded(prefix: str) -> set[str]:
    """Loaded module names beginning with a caller-owned prefix."""
    return {name for name in names() if name.startswith(prefix)}


def is_loaded(name: str) -> bool:
    """Whether the exact module name is loaded."""
    return name in names()


def insert(path: Path) -> subprocess.CompletedProcess:
    """Run insmod; return the result without raising on failure."""
    return subprocess.run(["insmod", str(path)], capture_output=True, text=True)


def remove(name: str) -> None:
    """rmmod the named module."""
    run("rmmod", name)


def loaded_scope(*, prefix: str) -> AbstractContextManager[None]:
    """Track modules loaded under a caller-owned prefix."""
    return collection(
        members=partial(loaded, prefix),
        discard=remove,
    )
