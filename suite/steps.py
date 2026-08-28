# SPDX-License-Identifier: GPL-2.0-only

import os

import capabilities
import ipe


def deploy_policy(policy: ipe.Policy) -> None:
    ipe.deploy_policy(policy.signed)


def open_node(entry: str, policy: ipe.Policy | None, descriptor: list[int]) -> None:
    descriptor[0] = os.open(ipe.node_path(entry, policy), os.O_WRONLY)


def read_node(entry: str, policy: ipe.Policy | None, observed: list[str]) -> None:
    observed.append(ipe.node_path(entry, policy).read_text().strip())


def read_binary_node(entry: str, policy: ipe.Policy | None, observed: list[str]) -> None:
    observed.append(ipe.node_path(entry, policy).read_bytes().hex())


def unshare_user_namespace() -> None:
    # IPE asks for CAP_MAC_ADMIN in init_user_ns.  A capability held in a
    # child user namespace does not apply to its parent; ID maps do not alter it.
    os.unshare(os.CLONE_NEWUSER)


def clear_mac_admin() -> None:
    capabilities.set_mac_admin_effective(False)


def raise_mac_admin() -> None:
    capabilities.set_mac_admin_effective(True)


def drop_mac_admin() -> None:
    capabilities.drop_mac_admin()


def activate_policy(policy: ipe.Policy) -> None:
    ipe.deploy_policy(policy.signed)
    ipe.activate_policy(policy.name)
