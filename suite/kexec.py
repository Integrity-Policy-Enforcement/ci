# SPDX-License-Identifier: GPL-2.0-only

import ctypes
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from model import CaseState, Observation

LOADED_NODE = Path("/sys/kernel/kexec/loaded")
# These UAPI flag bits are architecture-independent; syscall numbers are not.
KEXEC_FILE_UNLOAD = 1 << 0
KEXEC_FILE_NO_INITRAMFS = 1 << 2

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.syscall.argtypes = (ctypes.c_long,)
_LIBC.syscall.restype = ctypes.c_long
_SECCOMP = ctypes.CDLL("libseccomp.so.2")
_SECCOMP.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,)
_SECCOMP.seccomp_syscall_resolve_name.restype = ctypes.c_int
_KEXEC_FILE_LOAD_NR = _SECCOMP.seccomp_syscall_resolve_name(b"kexec_file_load")
if _KEXEC_FILE_LOAD_NR < 0:
    raise RuntimeError("kexec_file_load is unavailable on this architecture")


def _file_load_syscall(
    kernel_fd: int,
    command_line: bytes | None,
    flags: int,
) -> int:
    """Call kexec_file_load with typed variadic arguments and return its errno."""
    ctypes.set_errno(0)
    result = _LIBC.syscall(
        _KEXEC_FILE_LOAD_NR,
        ctypes.c_int(kernel_fd),
        ctypes.c_int(-1),
        ctypes.c_ulong(len(command_line) if command_line is not None else 0),
        ctypes.c_char_p(command_line),
        ctypes.c_ulong(flags),
    )
    if result == 0:
        return 0
    error = ctypes.get_errno()
    if error == 0:
        raise RuntimeError("kexec_file_load failed without setting errno")
    return error


def loaded() -> bool:
    """Read the normal kexec slot, rejecting unexpected node contents."""
    value = LOADED_NODE.read_text().strip()
    if value not in ("0", "1"):
        raise RuntimeError(f"unexpected kexec loaded state: {value!r}")
    return value == "1"


def load_file(binary: Path, state: CaseState) -> Observation:
    """Load the original file through kexec_file_load and report its errno."""
    with binary.open("rb") as image:
        error = _file_load_syscall(
            kernel_fd=image.fileno(),
            command_line=b"\0",
            flags=KEXEC_FILE_NO_INITRAMFS,
        )
    return Observation(errno=error)


def check_loaded(expected_loaded: bool, observation: Observation) -> str | None:
    """Check whether the kernel has an image staged for a later kexec."""
    actual = loaded()
    if actual != expected_loaded:
        return f"kexec image loaded={actual}, expected {expected_loaded}"
    return None


@contextmanager
def image_scope() -> Generator[None, None, None]:
    """Reserve an empty normal kexec slot and unload any test-staged image."""
    if loaded():
        raise RuntimeError("refusing to replace a pre-existing kexec image")
    try:
        yield
    finally:
        if loaded():
            error = _file_load_syscall(
                kernel_fd=-1,
                command_line=None,
                flags=KEXEC_FILE_UNLOAD,
            )
            if error:
                raise OSError(error, "kexec_file_load unload failed")
        if loaded():
            raise RuntimeError("kexec image remained loaded after cleanup")
