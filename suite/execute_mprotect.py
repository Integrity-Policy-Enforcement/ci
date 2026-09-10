# SPDX-License-Identifier: GPL-2.0-only

import ctypes
import mmap
import os
from pathlib import Path

from model import CaseState, Observation

MAP_FAILED = ctypes.c_void_p(-1).value

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.mmap.argtypes = (
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, ctypes.c_long,
)
_LIBC.mmap.restype = ctypes.c_void_p
_LIBC.mprotect.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int)
_LIBC.mprotect.restype = ctypes.c_int


def protect_file(
    binary: Path,
    initial_protection: int,
    protection: int,
    state: CaseState,
) -> Observation:
    """Test mprotect on a private original-file mapping; never execute its bytes.

    Initial mmap failure is a setup error, not a successful mprotect denial.
    The runner's per-case child releases the mapping when it exits.
    """
    with binary.open("rb") as source:
        length = os.fstat(source.fileno()).st_size
        if length <= 0:
            raise ValueError("mprotect input is empty")
        ctypes.set_errno(0)
        pointer = _LIBC.mmap(None, length, initial_protection, mmap.MAP_PRIVATE, source.fileno(), 0)
        error = ctypes.get_errno()
    if pointer == MAP_FAILED:
        if not error:
            raise RuntimeError("initial mmap failed without setting errno")
        raise OSError(error, "initial mmap failed before mprotect")
    ctypes.set_errno(0)
    result = _LIBC.mprotect(pointer, length, protection)
    error = ctypes.get_errno() if result != 0 else 0
    if result != 0 and not error:
        raise RuntimeError("mprotect failed without setting errno")
    return Observation(errno=error)
