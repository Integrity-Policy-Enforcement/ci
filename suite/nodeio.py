# SPDX-License-Identifier: GPL-2.0-only

import os
from pathlib import Path


def write(descriptor: int, data: bytes) -> None:
    """Write one complete node transaction through an open descriptor."""
    written = os.write(descriptor, data)
    if written != len(data):
        raise RuntimeError(f"short node write: {written} of {len(data)} bytes")


def write_path(path: Path, data: bytes | str) -> None:
    """Open a node, write one complete transaction and close it."""
    payload = data.encode() if isinstance(data, str) else data
    descriptor = os.open(path, os.O_WRONLY)
    try:
        write(descriptor, payload)
    finally:
        os.close(descriptor)
