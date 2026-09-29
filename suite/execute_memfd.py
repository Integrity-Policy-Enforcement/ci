# SPDX-License-Identifier: GPL-2.0-only

import os
import subprocess
from pathlib import Path

from model import CaseState, Observation
from triggers import error_observation

# Linux UAPI constant not yet exposed by Python's os module.
MFD_EXEC = 0x0010


def execute(binary: Path, state: CaseState) -> Observation:
    """Copy an ELF into a new executable memfd and exec it through its fd link.

    The memfd holds the same bytes but none of the source file's dm-verity or
    fs-verity properties. MFD_EXEC requests an executable memfd explicitly;
    MFD_NOEXEC_SEAL would make the VFS refuse exec even without IPE. Copy and
    verification failures are preparation errors, not exec refusals. The
    per-case child closes the memfd when it exits.
    """
    data = binary.read_bytes()
    if not data:
        raise ValueError("memfd executable input is empty")
    descriptor = os.memfd_create(binary.name, os.MFD_CLOEXEC | MFD_EXEC)
    remaining = memoryview(data)
    while remaining:
        written = os.write(descriptor, remaining)
        if not written:
            raise RuntimeError("memfd write returned zero")
        remaining = remaining[written:]
    if os.pread(descriptor, len(data) + 1, 0) != data:
        raise RuntimeError("memfd contents differ from the source ELF")
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
