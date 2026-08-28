# SPDX-License-Identifier: GPL-2.0-only

import json

import ipe
import layout
from operations import Operation


def two_values_match(observed: tuple[str, ...]) -> str | None:
    if len(observed) != 2:
        return f"expected two reads, got {len(observed)}"
    first, second = observed
    if first != second:
        return f"read values differ: {first!r} != {second!r}"


def two_values_differ(observed: tuple[str, ...]) -> str | None:
    if len(observed) != 2:
        return f"expected two reads, got {len(observed)}"
    first, second = observed
    if first == second:
        return f"read values did not change: {first!r}"


def policy_version_is(
    policy: ipe.Policy, expected: str, observed: tuple[str, ...]
) -> str | None:
    actual = ipe.policy_version(policy.name)
    if actual != expected:
        return f"policy {policy.name} version is {actual}, expected {expected}"


def policy_active_is(
    policy: ipe.Policy, expected: bool, observed: tuple[str, ...]
) -> str | None:
    actual = ipe.policy_active(policy.name)
    if actual != expected:
        return f"policy {policy.name} active={actual}, expected {expected}"


def node_value_is(
    entry: str, expected: str, observed: tuple[str, ...]
) -> str | None:
    actual = ipe.node_path(entry).read_text().strip()
    if actual != expected:
        return f"{entry} is {actual!r}, expected {expected!r}"


def policy_present_is(
    policy: ipe.Policy, expected: bool, observed: tuple[str, ...]
) -> str | None:
    actual = ipe.policy_present(policy.name)
    if actual != expected:
        return f"policy {policy.name} present={actual}, expected {expected}"


def operation_completed_is(
    operation: Operation, expected: bool, observed: tuple[str, ...]
) -> str | None:
    actual = operation.completed()
    if actual != expected:
        return f"{operation.id} completed={actual}, expected {expected}"


def initramfs_case_passed(
    id: str, observed: tuple[str, ...]
) -> str | None:
    outcome = json.loads(layout.initrd.BOOT_VERIFIED_RECORD.read_text())[id]
    if outcome is not None:
        kind, message = outcome
        return f"{kind} in the initramfs: {message}"
