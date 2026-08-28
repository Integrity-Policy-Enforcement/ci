# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Callable
from dataclasses import dataclass

import runtime


@dataclass(frozen=True)
class Observation:
    errno: int
    detail: str | list[str] = ""


@dataclass(frozen=True)
class Case:
    id: str
    trigger: Callable | None = None
    expect: int | None = None
    collect: tuple[Callable, ...] = ()
    setup: tuple[Callable, ...] = ()
    check: Callable | None = None
    scope: Callable = runtime.case.scope


@dataclass(frozen=True)
class Batch:
    id: str
    cases: tuple[Case, ...]
    setup: tuple[Callable, ...] = ()
    scope: Callable = runtime.batch.scope
