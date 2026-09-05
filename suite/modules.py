# SPDX-License-Identifier: GPL-2.0-only

import ctypes
import subprocess
from contextlib import AbstractContextManager
from functools import partial
from pathlib import Path

from command import capture, run
from model import Observation
from scope import collection

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.init_module.argtypes = (ctypes.c_void_p, ctypes.c_ulong, ctypes.c_char_p)
_LIBC.init_module.restype = ctypes.c_int


def names() -> set[str]:
    """Return module names from the first column of lsmod output.

    For example::

        Module       Size  Used by
        ipe_test    12288  0

    ``[1:]`` skips the header and ``split()[0]`` returns ``ipe_test``.
    """
    return {line.split()[0] for line in capture("lsmod").splitlines()[1:]}


def loaded(prefix: str) -> set[str]:
    """Loaded module names beginning with a caller-owned prefix."""
    return {name for name in names() if name.startswith(prefix)}


def check_loaded(
    name: str,
    expected_loaded: bool,
    observation: Observation,
) -> str | None:
    """Check whether the named module has the expected loaded state."""
    actual_loaded = name in names()
    if actual_loaded != expected_loaded:
        return f"module {name} loaded={actual_loaded}, expected {expected_loaded}"
    return None


def insmod(binary: Path) -> subprocess.CompletedProcess:
    """Run insmod; return the result without raising on failure."""
    return subprocess.run(["insmod", str(binary)], capture_output=True, text=True)


def remove(name: str) -> None:
    """rmmod the named module."""
    run("rmmod", name)


def init_module_from_buffer(image: bytes) -> int:
    """Pass a complete module image to init_module and return its errno."""
    buffer = ctypes.create_string_buffer(image)
    ctypes.set_errno(0)
    result = _LIBC.init_module(buffer, len(image), b"")
    if result == 0:
        return 0
    error = ctypes.get_errno()
    if error == 0:
        raise RuntimeError("init_module failed without setting errno")
    return error


def loaded_scope(*, prefix: str) -> AbstractContextManager[None]:
    """Track modules loaded under a caller-owned prefix."""
    return collection(
        members=partial(loaded, prefix=prefix),
        discard=remove,
    )
