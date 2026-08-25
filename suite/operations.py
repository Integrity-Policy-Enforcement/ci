# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Callable
from dataclasses import dataclass

import modules
from model import Observation

INSMOD_REFUSED = 1


@dataclass(frozen=True)
class Operation:
    id: str
    attempt: Callable
    refused: int
    completed: Callable


def insert_module(path):
    finished = modules.insert(path)
    return Observation(finished.returncode, finished.stderr.strip())


def test_module_loaded():
    return bool(modules.loaded())


KMODULE = Operation("kmodule", insert_module, INSMOD_REFUSED, test_module_loaded)
