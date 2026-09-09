# SPDX-License-Identifier: GPL-2.0-only

import ctypes
import mmap
import os
from contextlib import nullcontext
from pathlib import Path

from model import CaseState, Observation

PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
MAP_FAILED = ctypes.c_void_p(-1).value

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.mmap.argtypes = (
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, ctypes.c_long,
)
_LIBC.mmap.restype = ctypes.c_void_p


def map_memory(
    binary: Path | None,
    protection: int,
    shared: bool,
    state: CaseState,
) -> Observation:
    """Map the original file or one anonymous page and report success or errno.

    Input-open failures are preparation errors, not IPE denials. The per-case
    child exits after reporting and releases its mappings; never execute them.
    """
    flags = mmap.MAP_SHARED if shared else mmap.MAP_PRIVATE
    if binary is None:
        flags |= mmap.MAP_ANONYMOUS
    with (binary.open("rb") if binary is not None else nullcontext()) as source:
        descriptor = source.fileno() if source is not None else -1
        length = os.fstat(descriptor).st_size if source is not None else PAGE_SIZE
        if length <= 0:
            raise ValueError("mmap input is empty")
        ctypes.set_errno(0)
        pointer = _LIBC.mmap(None, length, protection, flags, descriptor, 0)
        error = ctypes.get_errno()
    if pointer == MAP_FAILED:
        if not error:
            raise RuntimeError("mmap failed without setting errno")
        return Observation(errno=error)
    return Observation(errno=0)
