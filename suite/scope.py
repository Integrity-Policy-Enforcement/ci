# SPDX-License-Identifier: GPL-2.0-only


class Setting:
    """One value that may change inside the scope and has to be put back."""

    def __init__(self, read, write):
        self.read = read
        self.write = write

    def capture(self):
        self.captured = self.read()

    def restore(self):
        if self.read() != self.captured:
            self.write(self.captured)


class Collection:
    """A set of members; whatever appears inside the scope has to go away."""

    def __init__(self, members, discard):
        self.members = members
        self.discard = discard

    def capture(self):
        self.captured = self.members()

    def restore(self):
        for member in self.members() - self.captured:
            self.discard(member)


class Scope:
    """A region of the run that leaves the tracked state as it found it."""

    def __init__(self, *tracked):
        self.tracked = tracked

    def __enter__(self):
        for item in self.tracked:
            item.capture()
        return self

    def __exit__(self, *exception):
        for item in self.tracked:
            item.restore()
        return False
