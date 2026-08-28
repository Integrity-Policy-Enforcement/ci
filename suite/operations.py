# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import modules
from model import Observation

INSMOD_REFUSED = 1


@dataclass(frozen=True)
class Operation:
    id: str
    attempt: Callable
    refused: int
    completed: Callable


def insert_module(path: Path) -> Observation:
    finished = modules.insert(path)
    return Observation(finished.returncode, message=finished.stderr.strip())


def test_module_loaded() -> bool:
    return bool(modules.loaded())


KMODULE = Operation(
    id="kmodule",
    attempt=insert_module,
    refused=INSMOD_REFUSED,
    completed=test_module_loaded,
)
