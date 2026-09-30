# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Generator
from contextlib import contextmanager
import fcntl
import mmap
import os
import subprocess
from pathlib import Path

import nodeio
from model import CaseState, Observation
from triggers import error_observation

# Linux UAPI constants not yet exposed by Python's os/fcntl modules.
MFD_EXEC = 0x0010
F_SEAL_EXEC = 0x0020
# Content, size, executable mode and the seal set itself become immutable.
FULL_SEALS = (
    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW
    | fcntl.F_SEAL_WRITE | fcntl.F_SEAL_FUTURE_WRITE | F_SEAL_EXEC
)
HUGE_PAGE_SIZE = 2 * 1024 * 1024
HUGE_POOL = Path("/sys/kernel/mm/hugepages/hugepages-2048kB")


@contextmanager
def hugepages_scope() -> Generator[None, None, None]:
    """Give the current hugetlb memfd case two 2 MiB hugepages.

    Why two pages, although the program only calls exit(0):
    - The memfd holds the 2 MiB ELF: one page.
    - Exec maps the ELF's code with MAP_PRIVATE. When the kernel creates a
      private mapping of a hugetlbfs file, it reserves one page for a
      possible later copy-on-write, even for a read-only mapping (see
      hugetlb_reserve_pages() in mm/hugetlb.c). The program never writes, so
      that page is never used, but without a free page to reserve, exec
      fails and the process is killed by SIGSEGV.

    Steps:
    1. Record the pool size (nr_hugepages) and the free page count
       (free_hugepages).
    2. Grow the pool by two pages. Read the size back; if the kernel could
       not allocate both pages, fail.
    3. Run the case. Its child process copies the ELF into the memfd and
       execs it; when that child exits, the memfd and the exec mapping are
       freed.
    4. Shrink the pool back to the recorded size.
    5. Read both values again. If either differs from step 1, the pool was
       not restored; fail.

    Failures in steps 2 and 5 are setup/cleanup errors, never IPE refusals.
    Only hugetlb cases use this scope, so other cases, such as kexec, never
    lose this memory.
    """
    count = HUGE_POOL / "nr_hugepages"
    free = HUGE_POOL / "free_hugepages"
    original_count = int(count.read_text())
    original_free = int(free.read_text())
    target = original_count + 2
    try:
        nodeio.write_path(count, str(target))
        if int(count.read_text()) != target:
            raise RuntimeError("could not reserve two hugepages for memfd tests")
        yield
    finally:
        nodeio.write_path(count, str(original_count))
        if int(count.read_text()) != original_count or int(free.read_text()) != original_free:
            raise RuntimeError("memfd hugepage pool did not return to its original state")


def execute(
    binary: Path, state: CaseState, sealed: bool = False, huge: bool = False,
) -> Observation:
    """Copy an ELF into a new memfd and exec the memfd.

    The memfd gets the same bytes as the source file but none of its
    dm-verity or fs-verity properties.

    Steps:
    1. Read the ELF. For a hugetlb memfd it must be exactly one 2 MiB page.
    2. Create the memfd with MFD_EXEC, so it may be executed; MFD_NOEXEC_SEAL
       would make the VFS refuse exec even without IPE. Add
       MFD_ALLOW_SEALING if sealed, and MFD_HUGETLB | MFD_HUGE_2MB if huge.
    3. Copy the bytes and read them back. hugetlbfs has no write(), so a
       hugetlb memfd is filled through a shared mapping, which is unmapped
       again before steps 4 and 5.
    4. If sealed, add FULL_SEALS and read the seals back.
    5. Exec the memfd through /proc/self/fd/N in a child process. Return the
       exec errno, or errno 0 with the program's exit status.

    A failure in steps 1-4 is a preparation error, not an exec refusal. The
    memfd is closed when the per-case child exits.
    """
    data = binary.read_bytes()
    if not data:
        raise ValueError("memfd executable input is empty")
    if huge and len(data) != HUGE_PAGE_SIZE:
        raise ValueError("hugetlb memfd input is not exactly one 2 MiB page")
    flags = os.MFD_CLOEXEC | MFD_EXEC
    if sealed:
        flags |= os.MFD_ALLOW_SEALING
    if huge:
        flags |= os.MFD_HUGETLB | os.MFD_HUGE_2MB
    descriptor = os.memfd_create(binary.name, flags)
    if huge:
        os.ftruncate(descriptor, HUGE_PAGE_SIZE)
        if os.fstat(descriptor).st_blksize != HUGE_PAGE_SIZE:
            raise RuntimeError("memfd does not have 2 MiB hugetlb backing")
        with mmap.mmap(
            descriptor, HUGE_PAGE_SIZE, flags=mmap.MAP_SHARED,
            prot=mmap.PROT_READ | mmap.PROT_WRITE,
        ) as contents:
            contents[:] = data
            if contents[:] != data:
                raise RuntimeError("memfd contents differ from the source ELF")
    else:
        remaining = memoryview(data)
        while remaining:
            written = os.write(descriptor, remaining)
            if not written:
                raise RuntimeError("memfd write returned zero")
            remaining = remaining[written:]
        if os.pread(descriptor, len(data) + 1, 0) != data:
            raise RuntimeError("memfd contents differ from the source ELF")
    if sealed:
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, FULL_SEALS)
        if fcntl.fcntl(descriptor, fcntl.F_GET_SEALS) != FULL_SEALS:
            raise RuntimeError("memfd seals differ from the requested set")
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
