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
KEXEC_ARCH_DEFAULT = 0

_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.syscall.argtypes = (ctypes.c_long,)
_LIBC.syscall.restype = ctypes.c_long
_SECCOMP = ctypes.CDLL("libseccomp.so.2")
_SECCOMP.seccomp_syscall_resolve_name.argtypes = (ctypes.c_char_p,)
_SECCOMP.seccomp_syscall_resolve_name.restype = ctypes.c_int
_KEXEC_FILE_LOAD_NR = _SECCOMP.seccomp_syscall_resolve_name(b"kexec_file_load")
if _KEXEC_FILE_LOAD_NR < 0:
    raise RuntimeError("kexec_file_load is unavailable on this architecture")
_KEXEC_LOAD_NR = _SECCOMP.seccomp_syscall_resolve_name(b"kexec_load")
if _KEXEC_LOAD_NR < 0:
    raise RuntimeError("kexec_load is unavailable on this architecture")


class _KexecSegment(ctypes.Structure):
    _fields_ = (
        ("buf", ctypes.c_void_p),
        ("bufsz", ctypes.c_size_t),
        ("mem", ctypes.c_ulong),
        ("memsz", ctypes.c_size_t),
    )


def _file_load_syscall(
    kernel_fd: int,
    initramfs_fd: int,
    command_line: bytes | None,
    flags: int,
) -> int:
    """Call kexec_file_load with typed variadic arguments and return its errno."""
    ctypes.set_errno(0)
    result = _LIBC.syscall(
        _KEXEC_FILE_LOAD_NR,
        ctypes.c_int(kernel_fd),
        ctypes.c_int(initramfs_fd),
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
            initramfs_fd=-1,
            command_line=b"\0",
            flags=KEXEC_FILE_NO_INITRAMFS,
        )
    return Observation(errno=error)


def load_initramfs(kernel: Path, binary: Path, state: CaseState) -> Observation:
    """Load an initramfs beside a fixed kernel, preserving both original fds."""
    with kernel.open("rb") as image, binary.open("rb") as initramfs:
        error = _file_load_syscall(
            kernel_fd=image.fileno(),
            initramfs_fd=initramfs.fileno(),
            command_line=b"\0",
            flags=0,
        )
    return Observation(errno=error)


def load_buffer(binary: Path, state: CaseState) -> Observation:
    """Try kexec_load on real kernel bytes; the rejection cases must stop at IPE."""
    image = binary.read_bytes()
    if not image:
        raise ValueError("kexec buffer input is empty")
    buffer = ctypes.create_string_buffer(image)
    # IPE runs before segment validation. A zero destination size ensures that
    # an unexpected ALLOW reaches EINVAL, not an installed image. EINVAL is not
    # an accepted result for the IPE-denial cases.
    segment = _KexecSegment(
        buf=ctypes.cast(buffer, ctypes.c_void_p),
        bufsz=len(image),
        mem=0,
        memsz=0,
    )
    ctypes.set_errno(0)
    result = _LIBC.syscall(
        _KEXEC_LOAD_NR,
        ctypes.c_ulong(0),
        ctypes.c_ulong(1),
        ctypes.byref(segment),
        ctypes.c_ulong(KEXEC_ARCH_DEFAULT),
    )
    if result == 0:
        return Observation(errno=0)
    error = ctypes.get_errno()
    if error == 0:
        raise RuntimeError("kexec_load failed without setting errno")
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
                initramfs_fd=-1,
                command_line=None,
                flags=KEXEC_FILE_UNLOAD,
            )
            if error:
                raise OSError(error, "kexec_file_load unload failed")
        if loaded():
            raise RuntimeError("kexec image remained loaded after cleanup")
