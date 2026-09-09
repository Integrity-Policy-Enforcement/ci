# SPDX-License-Identifier: GPL-2.0-only

from pathlib import Path

import nodeio
from model import CaseState, Observation
from triggers import error_observation

DEVICE = Path("/dev/ipe_test_x509")


def read_file(binary: Path, state: CaseState) -> Observation:
    """Pass the original fd to the test driver and report its read errno."""
    with binary.open("rb") as source, DEVICE.open("wb", buffering=0) as driver:
        try:
            nodeio.write(driver.fileno(), str(source.fileno()).encode())
            return Observation(errno=0)
        except OSError as failure:
            return error_observation(failure)


def check_contents(expected: Path | bytes, observation: Observation) -> str | None:
    """Compare retained certificate bytes with a file or exact expected bytes."""
    wanted = expected.read_bytes() if isinstance(expected, Path) else expected
    actual = DEVICE.read_bytes()
    if actual != wanted:
        return (
            f"X509_CERT read contents differ: got {len(actual)} bytes, "
            f"expected {len(wanted)} bytes"
        )
    return None
