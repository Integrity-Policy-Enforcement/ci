# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path

import layout
import modules
from model import CaseState, Observation

# insmod reports a failed insertion with process return code 1, not an errno.
INSMOD_REFUSED = 1
# This exact target name also reserves its prefix for case cleanup.
KMODULE_TEST_BINARY_NAME = layout.guest.KMODULE_TEST_BINARY.stem


@dataclass(frozen=True)
class Operation:
    id: str
    attempt: Callable
    refused: int
    completed: Callable


def insert_module(path: Path, _state: CaseState) -> Observation:
    """Try insmod and return what happened, without raising."""
    finished = modules.insert(path)
    return Observation(
        returncode=finished.returncode,
        message=finished.stderr.strip(),
    )


def test_module_loaded(name: str) -> bool:
    """Whether the exact test module is currently loaded."""
    return modules.is_loaded(name)


KMODULE_INSERT_OPERATION = Operation(
    id="kmodule",
    attempt=insert_module,
    refused=INSMOD_REFUSED,
    completed=partial(test_module_loaded, KMODULE_TEST_BINARY_NAME),
)
