# SPDX-License-Identifier: GPL-2.0-only
"""policy_op operation: case construction, execution and result checks."""

from functools import partial
from pathlib import Path

import checks
import ipe
import nodeio
import steps
from model import Case, CaseState, Observation
from triggers import error_observation

DEVICE = Path("/dev/ipe_test_policy_op")


def read_file(binary: Path, state: CaseState) -> Observation:
    """Pass the original fd to the test driver and report its read errno."""
    with binary.open("rb") as source, DEVICE.open("wb", buffering=0) as driver:
        try:
            nodeio.write(driver.fileno(), str(source.fileno()).encode())
            return Observation(errno=0)
        except OSError as failure:
            return error_observation(failure)


def check_contents(expected: Path | bytes, observation: Observation) -> str | None:
    """Compare retained bytes with a file, or with exact expected bytes."""
    wanted = expected.read_bytes() if isinstance(expected, Path) else expected
    actual = DEVICE.read_bytes()
    if actual != wanted:
        return (
            f"POLICY op read contents differ: got {len(actual)} bytes, "
            f"expected {len(wanted)} bytes"
        )
    return None


def read_case(
    id: str,
    policy: ipe.Policy,
    binary: Path,
    expected_errno: int,
    expected_content: Path | bytes,
) -> Case:
    """Read a file as POLICY and check the errno and actual retained bytes."""
    return Case(
        id=id,
        setup=(
            partial(steps.deploy_policy, policy=policy),
            partial(steps.activate_policy, name=policy.name),
            partial(steps.set_enforcement, enabled=True),
        ),
        trigger=partial(read_file, binary=binary),
        checks=(
            partial(checks.errno_is, expected=expected_errno),
            partial(check_contents, expected=expected_content),
        ),
    )
