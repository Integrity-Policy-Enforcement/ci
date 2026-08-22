# SPDX-License-Identifier: GPL-2.0-only

import ipe


def policy_version_is(policy, expected, detail):
    actual = ipe.policy_version(policy)
    if actual != expected:
        return f"policy {policy} version is {actual}, expected {expected}"
