# SPDX-License-Identifier: GPL-2.0-only

import json

import ipe
import layout
from model import Observation, Operation


def errno_is(expected: int, observation: Observation) -> str | None:
    """The trigger reported the expected syscall errno."""
    if observation.errno is None:
        return f"expected errno {expected}, trigger reported no errno"
    if observation.errno != expected:
        return f"expected errno {expected}, got {observation.errno}"
    return None


def returncode_is(expected: int, observation: Observation) -> str | None:
    """The trigger reported the expected command return code."""
    if observation.returncode is None:
        return f"expected return code {expected}, trigger reported no return code"
    if observation.returncode != expected:
        said = f": {observation.message}" if observation.message else ""
        return f"expected return code {expected}, got {observation.returncode}{said}"
    return None


def two_values_match(observation: Observation) -> str | None:
    """The two reads returned the same value."""
    if len(observation.observed) != 2:
        return f"expected two reads, got {len(observation.observed)}"
    first, second = observation.observed
    if first != second:
        return f"read values differ: {first!r} != {second!r}"
    return None


def two_values_differ(observation: Observation) -> str | None:
    """The two reads returned different values."""
    if len(observation.observed) != 2:
        return f"expected two reads, got {len(observation.observed)}"
    first, second = observation.observed
    if first == second:
        return f"read values did not change: {first!r}"
    return None


def policy_version_is(
    policy: ipe.Policy, expected: str, observation: Observation
) -> str | None:
    """The policy carries the expected version."""
    actual = ipe.policy_version(policy.name)
    if actual != expected:
        return f"policy {policy.name} version is {actual}, expected {expected}"
    return None


def policy_active_is(
    policy: ipe.Policy, expected: bool, observation: Observation
) -> str | None:
    """The policy is or is not the active one."""
    actual = ipe.policy_active(policy.name)
    if actual != expected:
        return f"policy {policy.name} active={actual}, expected {expected}"
    return None


def node_value_is(
    entry: str, expected: str, observation: Observation
) -> str | None:
    """A securityfs node holds the expected value."""
    actual = ipe.node_path(entry).read_text().strip()
    if actual != expected:
        return f"{entry} is {actual!r}, expected {expected!r}"
    return None


def policy_present_is(
    policy: ipe.Policy, expected: bool, observation: Observation
) -> str | None:
    """The policy is or is not loaded."""
    actual = ipe.policy_present(policy.name)
    if actual != expected:
        return f"policy {policy.name} present={actual}, expected {expected}"
    return None


def operation_completed_is(
    operation: Operation, expected: bool, observation: Observation
) -> str | None:
    """The operation left evidence of running, or did not."""
    actual = operation.completed()
    if actual != expected:
        return f"{operation.id} completed={actual}, expected {expected}"
    return None


def initramfs_case_passed(id: str, observation: Observation) -> str | None:
    """The saved outcome is None for a pass or [kind, message] for a problem."""
    outcome = json.loads(layout.initrd.BOOT_VERIFIED_RECORD.read_text())[id]
    if outcome is not None:
        kind, message = outcome
        return f"{kind} in the initramfs: {message}"
    return None
