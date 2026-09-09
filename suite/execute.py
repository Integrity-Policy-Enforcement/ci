# SPDX-License-Identifier: GPL-2.0-only

import subprocess
from pathlib import Path

from model import CaseState, Observation
from triggers import error_observation


def execve(binary: Path, state: CaseState) -> Observation:
    """Execute the original ELF, preserving exec errors separately from exit status."""
    try:
        result = subprocess.run(
            [str(binary)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, check=False,
        )
    except OSError as failure:
        return error_observation(failure)
    return Observation(errno=0, returncode=result.returncode, message=result.stderr)


def check_returncode(expected: int | None, observation: Observation) -> str | None:
    """An exec refusal has no program exit status; a started program does."""
    if observation.returncode != expected:
        return f"program return code {observation.returncode}, expected {expected}"
    return None
