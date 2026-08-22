# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class Observation:
    errno: int
    detail: str = ""


@dataclass(frozen=True)
class Case:
    id: str
    setup: tuple[Callable, ...]
    trigger: Callable
    expect: int
    check: Callable | None = None
