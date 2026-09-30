# SPDX-License-Identifier: GPL-2.0-only

import fcntl
import os
import subprocess
from pathlib import Path

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


def execute(binary: Path, state: CaseState, sealed: bool = False) -> Observation:
    """Copy an ELF into a new executable memfd and exec it through its fd link.

    The memfd holds the same bytes but none of the source file's dm-verity or
    fs-verity properties. MFD_EXEC requests an executable memfd explicitly;
    MFD_NOEXEC_SEAL would make the VFS refuse exec even without IPE. A sealed
    memfd allows sealing at creation and gets FULL_SEALS after the copy. Copy,
    verification and sealing failures are preparation errors, not exec
    refusals. The per-case child closes the memfd when it exits.
    """
    data = binary.read_bytes()
    if not data:
        raise ValueError("memfd executable input is empty")
    flags = os.MFD_CLOEXEC | MFD_EXEC
    if sealed:
        flags |= os.MFD_ALLOW_SEALING
    descriptor = os.memfd_create(binary.name, flags)
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
