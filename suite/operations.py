# SPDX-License-Identifier: GPL-2.0-only

import errno

import firmware
from model import Operation

# Firmware search continues after IPE returns EACCES and ends with ENOENT.
FIRMWARE_REQUEST_REFUSED_ERRNO = errno.ENOENT

FIRMWARE_KERNEL_READ_REQUEST_FIRMWARE_OPERATION = Operation(
    id="firmware_kernel_read_request_firmware",
    attempt=firmware.request_firmware,
)
