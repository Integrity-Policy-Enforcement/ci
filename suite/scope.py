# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Callable, Generator, Set as AbstractSet
from contextlib import AbstractContextManager, contextmanager
from typing import Any

ContextFactory = Callable[[], AbstractContextManager[None]]


@contextmanager
def setting(
    *,
    read: Callable[[], Any],
    write: Callable[[Any], None],
) -> Generator[None, None, None]:
    """Restore one value when the context exits."""
    captured = read()
    try:
        yield
    finally:
        if read() != captured:
            write(captured)


@contextmanager
def collection(
    *,
    members: Callable[[], AbstractSet[Any]],
    discard: Callable[[Any], None],
) -> Generator[None, None, None]:
    """Discard every member that appears inside the context."""
    captured = members()
    try:
        yield
    finally:
        failures = []
        for member in members() - captured:
            try:
                discard(member)
            except BaseException as failure:
                failures.append(failure)
        if failures:
            raise BaseExceptionGroup("collection restoration failed", failures)
