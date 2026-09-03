# SPDX-License-Identifier: GPL-2.0-only

import errno
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

import layout
import nodeio
from model import CaseState, Observation
from scope import setting
from triggers import error_observation

FIRMWARE_SEARCH_PATH_NODE = Path("/sys/module/firmware_class/parameters/path")
FIRMWARE_REQUEST_NODE = Path(
    "/sys/devices/virtual/misc/test_firmware/trigger_request"
)
FIRMWARE_CONTENT_NODE = Path("/dev/test_firmware")
MISSING_FIRMWARE_NAME = "ipe_test_cleanup_missing.fw"


def search_path() -> str:
    """Read the firmware loader's custom search path."""
    return FIRMWARE_SEARCH_PATH_NODE.read_text()


def set_search_path(directory: str | Path) -> None:
    """Set the firmware loader's custom search path."""
    nodeio.write_path(FIRMWARE_SEARCH_PATH_NODE, str(directory))


def request_firmware(binary: Path, state: CaseState) -> Observation:
    """Request a firmware binary and report the resulting errno."""
    set_search_path(binary.parent)
    try:
        nodeio.write_path(FIRMWARE_REQUEST_NODE, binary.name)
        return Observation(errno=0)
    except OSError as failure:
        return error_observation(failure)


def requested_firmware_matches(expected: Path) -> bool:
    """Whether test_firmware retained the expected binary."""
    return FIRMWARE_CONTENT_NODE.read_bytes() == expected.read_bytes()


def clear_requested_firmware() -> None:
    """Request a missing name so test_firmware releases its retained binary."""
    set_search_path(layout.guest.FIRMWARE_DIR)
    try:
        nodeio.write_path(FIRMWARE_REQUEST_NODE, MISSING_FIRMWARE_NAME)
    except OSError as failure:
        if failure.errno != errno.ENOENT:
            raise
    if FIRMWARE_CONTENT_NODE.read_bytes():
        raise RuntimeError("test_firmware retained a binary after cleanup")


@contextmanager
def request_firmware_scope() -> Generator[None, None, None]:
    """Restore the search path and release the requested firmware binary."""
    with setting(read=search_path, write=set_search_path):
        try:
            yield
        finally:
            clear_requested_firmware()
