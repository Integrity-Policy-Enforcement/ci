# SPDX-License-Identifier: GPL-2.0-only

import ipe


def policy_version_is(policy, expected, detail):
    actual = ipe.policy_version(policy)
    if actual != expected:
        return f"policy {policy} version is {actual}, expected {expected}"


def policy_active_is(policy, expected, detail):
    actual = ipe.policy_active(policy)
    if actual != expected:
        return f"policy {policy} active={actual}, expected {expected}"


def node_value_is(node, expected, detail):
    actual = ipe.node_path(node).read_text().strip()
    if actual != expected:
        return f"{node} is {actual!r}, expected {expected!r}"
