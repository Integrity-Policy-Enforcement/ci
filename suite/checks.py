# SPDX-License-Identifier: GPL-2.0-only

import json

import ipe
import layout


def two_values_match(values):
    if len(values) != 2:
        return f"expected two reads, got {len(values)}"
    first, second = values
    if first != second:
        return f"read values differ: {first!r} != {second!r}"


def two_values_differ(values):
    if len(values) != 2:
        return f"expected two reads, got {len(values)}"
    first, second = values
    if first == second:
        return f"read values did not change: {first!r}"


def policy_version_is(policy, expected, detail):
    actual = ipe.policy_version(policy.name)
    if actual != expected:
        return f"policy {policy.name} version is {actual}, expected {expected}"


def policy_active_is(policy, expected, detail):
    actual = ipe.policy_active(policy.name)
    if actual != expected:
        return f"policy {policy.name} active={actual}, expected {expected}"


def node_value_is(node, expected, detail):
    actual = ipe.node_path(node).read_text().strip()
    if actual != expected:
        return f"{node} is {actual!r}, expected {expected!r}"


def policy_present_is(policy, expected, detail):
    actual = ipe.policy_present(policy.name)
    if actual != expected:
        return f"policy {policy.name} present={actual}, expected {expected}"


def operation_completed_is(operation, expected, detail):
    actual = operation.completed()
    if actual != expected:
        return f"{operation.id} completed={actual}, expected {expected}"


def initramfs_case_passed(id, detail):
    outcome = json.loads(layout.BOOT_VERIFIED_RECORD.read_text())[id]
    if outcome is not None:
        kind, message = outcome
        return f"{kind} in the initramfs: {message}"
