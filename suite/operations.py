# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import modules
from model import CaseState, Observation

INSMOD_REFUSED = 1


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


def test_module_loaded() -> bool:
    """Whether the test module is currently loaded."""
    return bool(modules.loaded())


KMODULE = Operation(
    id="kmodule",
    attempt=insert_module,
    refused=INSMOD_REFUSED,
    completed=test_module_loaded,
)
