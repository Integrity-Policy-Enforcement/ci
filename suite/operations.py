# SPDX-License-Identifier: GPL-2.0-only

import errno
from pathlib import Path

import firmware
import layout
import modules
from model import CaseState, Observation, Operation

# insmod reports a failed insertion with process return code 1, not an errno.
INSMOD_REFUSED_RETURN_CODE = 1
# Firmware search continues after IPE returns EACCES and ends with ENOENT.
FIRMWARE_REQUEST_REFUSED_ERRNO = errno.ENOENT
# This exact target name also reserves its prefix for case cleanup.
KMODULE_TEST_BINARY_NAME = layout.guest.KMODULE_TEST_BINARY.stem


def call_insmod(binary: Path, state: CaseState) -> Observation:
    """Try insmod and return what happened, without raising."""
    finished = modules.insmod(binary)
    return Observation(
        returncode=finished.returncode,
        message=finished.stderr.strip(),
    )


KMODULE_KERNEL_READ_INSMOD_OPERATION = Operation(
    id="kmodule_kernel_read_insmod",
    attempt=call_insmod,
    refused=INSMOD_REFUSED_RETURN_CODE,
)

FIRMWARE_KERNEL_READ_REQUEST_FIRMWARE_OPERATION = Operation(
    id="firmware_kernel_read_request_firmware",
    attempt=firmware.request_firmware,
    refused=FIRMWARE_REQUEST_REFUSED_ERRNO,
)
