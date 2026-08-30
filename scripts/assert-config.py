#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

import re
from pathlib import Path

import layout

SETTING = re.compile(r"^(CONFIG_[A-Z0-9_]+)=(.*)$")
UNSET = re.compile(r"^# (CONFIG_[A-Z0-9_]+) is not set$")


def read_config(path: Path) -> dict[str, str | None]:
    """Parse set and explicitly unset Kconfig values from a config file."""
    values = {}
    for line in path.read_text().splitlines():
        if match := SETTING.match(line):
            values[match.group(1)] = match.group(2)
        elif match := UNSET.match(line):
            values[match.group(1)] = None
    return values


def main() -> int:
    """Report any requested option the built kernel changed or dropped."""
    requested = read_config(layout.source.KERNEL_CONFIG)
    produced = read_config(layout.build.KERNEL_CONFIG)
    drifted = [
        f"{name}: requested {want or 'unset'}, produced {produced.get(name) or 'unset'}"
        for name, want in requested.items()
        if produced.get(name) != want
    ]
    if drifted:
        for line in drifted:
            print(f"    {line}")
        raise SystemExit(
            f"{len(drifted)} of {len(requested)} options did not survive the build"
        )
    print(f"    Verified {len(requested)} kernel options")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
