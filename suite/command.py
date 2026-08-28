# SPDX-License-Identifier: GPL-2.0-only

import subprocess


def run(*arguments: object) -> None:
    """Run a command, and report what it said when it refuses."""
    finished = subprocess.run(
        [str(argument) for argument in arguments], capture_output=True, text=True
    )
    if finished.returncode:
        raise RuntimeError(f"{arguments[0]} failed: {finished.stderr.strip()}")


def capture(*arguments: object) -> str:
    return subprocess.run(
        [str(argument) for argument in arguments], capture_output=True, text=True, check=True
    ).stdout
