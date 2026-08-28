# SPDX-License-Identifier: GPL-2.0-only

from collections.abc import Callable, Set
from typing import Any


class Setting:
    """One value that may change inside the scope and has to be put back."""

    def __init__(self, read: Callable[[], Any], write: Callable[[Any], None]) -> None:
        self.read = read
        self.write = write

    def capture(self) -> None:
        self.captured = self.read()

    def restore(self) -> None:
        if self.read() != self.captured:
            self.write(self.captured)


class Collection:
    """A set of members; whatever appears inside the scope has to go away."""

    def __init__(self, members: Callable[[], Set[Any]], discard: Callable[[Any], None]) -> None:
        self.members = members
        self.discard = discard

    def capture(self) -> None:
        self.captured = self.members()

    def restore(self) -> None:
        for member in self.members() - self.captured:
            self.discard(member)


class Scope:
    """A region of the run that leaves the tracked state as it found it."""

    def __init__(self, *tracked: Setting | Collection) -> None:
        self.tracked = tracked

    def __enter__(self) -> "Scope":
        for item in self.tracked:
            item.capture()
        return self

    def __exit__(self, *exception: object) -> bool:
        for item in self.tracked:
            item.restore()
        return False
