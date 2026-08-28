# SPDX-License-Identifier: GPL-2.0-only

import subprocess
from pathlib import Path

import layout
from command import capture, run
from scope import Collection


def loaded() -> set[str]:
    """Only the test module: the kernel loads its own without asking."""
    present = {line.split()[0] for line in capture("lsmod").splitlines()[1:]}
    return present & {layout.TEST_MODULE}


def insert(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["insmod", str(path)], capture_output=True, text=True)


def remove(name: str) -> None:
    run("rmmod", name)


LOADED = Collection(members=loaded, discard=remove)
