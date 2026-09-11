# SPDX-License-Identifier: GPL-2.0-only

import fcntl
import mmap
import os
import subprocess
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import nodeio
from model import CaseState, Observation
from triggers import error_observation

# Linux UAPI constants not yet exposed by Python's os/fcntl modules.
MFD_EXEC = 0x0010
F_SEAL_EXEC = 0x0020
FULL_SEALS = (
    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_FUTURE_WRITE | F_SEAL_EXEC
)
HUGE_PAGE_SIZE = 2 * 1024 * 1024
HUGE_POOL = Path("/sys/kernel/mm/hugepages/hugepages-2048kB")


@contextmanager
def hugepages_scope() -> Generator[None, None, None]:
    """Reserve four 2 MiB pages only for the current hugetlb memfd case.

    Ordinary mappings and kexec must not hold this pool. The case child exits
    before restoration, releasing its source and private exec mappings.
    Check both pool size and free-page count on restoration. A short allocation
    or retained hugepage is a setup/cleanup failure, never an IPE refusal.
    """
    count = HUGE_POOL / "nr_hugepages"
    free = HUGE_POOL / "free_hugepages"
    original_count = int(count.read_text())
    original_free = int(free.read_text())
    try:
        nodeio.write_path(count, str(original_count + 4))
        if int(count.read_text()) != original_count + 4:
            raise RuntimeError("could not reserve four hugepages for memfd tests")
        yield
    finally:
        nodeio.write_path(count, str(original_count))
        if int(count.read_text()) != original_count or int(free.read_text()) != original_free:
            raise RuntimeError("memfd hugepage pool did not return to its original state")


def execute(binary: Path, huge: bool, sealed: bool, state: CaseState) -> Observation:
    """Copy an ELF to a new executable memfd and try exec through its fd link.

    MFD_EXEC requests executable mode explicitly; MFD_NOEXEC_SEAL would cause a
    VFS denial even without IPE and is not used here. Hugetlbfs has no write()
    operation, so populate both kinds through a temporary shared RW mapping.
    Close the writable mapping before sealing; the per-case child closes the
    memfd itself on exit. Verify copied bytes and seals before exec. Only exec
    errors become observations: allocation/copy/seal failures remain preparation errors.
    """
    data = binary.read_bytes()
    if not data:
        raise ValueError("memfd executable input is empty")
    flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MFD_EXEC
    length = len(data)
    if huge:
        flags |= os.MFD_HUGETLB | os.MFD_HUGE_2MB
        length = (length + HUGE_PAGE_SIZE - 1) // HUGE_PAGE_SIZE * HUGE_PAGE_SIZE
    descriptor = os.memfd_create(binary.name, flags)
    os.ftruncate(descriptor, length)
    if huge and os.fstat(descriptor).st_blksize != HUGE_PAGE_SIZE:
        raise RuntimeError("memfd does not have 2 MiB hugetlb backing")
    with mmap.mmap(
        descriptor, length, flags=mmap.MAP_SHARED,
        prot=mmap.PROT_READ | mmap.PROT_WRITE,
    ) as contents:
        contents[:len(data)] = data
        if contents[:len(data)] != data:
            raise RuntimeError("memfd contents differ from the source ELF")
    if sealed:
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, FULL_SEALS)
    if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != (FULL_SEALS if sealed else 0):
        raise RuntimeError("memfd seals differ from the requested state")
    try:
        # /proc/self/fd resolves to this same memfd inode, not a disk copy.
        result = subprocess.run(
            [f"/proc/self/fd/{descriptor}"], pass_fds=(descriptor,),
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, env={}, check=False,
        )
    except OSError as failure:
        return error_observation(failure)
    return Observation(errno=0, returncode=result.returncode, message=result.stderr)
