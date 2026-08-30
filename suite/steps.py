# SPDX-License-Identifier: GPL-2.0-only

import os

import capabilities
import ipe


def deploy_policy(policy: ipe.Policy) -> None:
    """Write the signed policy into securityfs so the kernel loads it."""
    ipe.deploy_policy(policy.signed)


def open_node(entry: str, policy: ipe.Policy | None, descriptor: list[int]) -> None:
    """Open a securityfs node and stash the fd for a later write."""
    descriptor.append(os.open(ipe.node_path(entry, policy), os.O_WRONLY))


def read_node(entry: str, policy: ipe.Policy | None, observed: list[str]) -> None:
    """Read a securityfs node and append the value to the observed list."""
    observed.append(ipe.node_path(entry, policy).read_text().strip())


def read_binary_node(entry: str, policy: ipe.Policy | None, observed: list[str]) -> None:
    """Read a binary securityfs node and append its hex to the observed list."""
    observed.append(ipe.node_path(entry, policy).read_bytes().hex())


def unshare_user_namespace() -> None:
    """Enter a child user namespace where init_user_ns capabilities do not apply."""
    # IPE asks for CAP_MAC_ADMIN in init_user_ns.  A capability held in a
    # child user namespace does not apply to its parent; ID maps do not alter it.
    os.unshare(os.CLONE_NEWUSER)


def clear_mac_admin() -> None:
    """Remove CAP_MAC_ADMIN from the effective set, keeping it permitted."""
    capabilities.set_mac_admin_effective(False)


def raise_mac_admin() -> None:
    """Restore CAP_MAC_ADMIN to the effective set from the permitted set."""
    capabilities.set_mac_admin_effective(True)


def drop_mac_admin() -> None:
    """Remove CAP_MAC_ADMIN from both effective and permitted, irrecoverably."""
    capabilities.drop_mac_admin()


def activate_policy(policy: ipe.Policy) -> None:
    """Deploy a signed policy and make it the active one."""
    ipe.deploy_policy(policy.signed)
    ipe.activate_policy(policy.name)
