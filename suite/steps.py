# SPDX-License-Identifier: GPL-2.0-only

import os

import capabilities
import ipe
import keyring


def deploy_policy(asset):
    ipe.deploy_policy(ipe.policy_asset(asset, ".p7s"))


def open_node(node, policy, descriptor):
    descriptor[0] = os.open(ipe.node_path(node, policy), os.O_WRONLY)


def read_node(node, policy, values):
    values.append(ipe.node_path(node, policy).read_text().strip())


def read_binary_node(node, policy, values):
    values.append(ipe.node_path(node, policy).read_bytes().hex())


def unshare_user_namespace():
    # IPE asks for CAP_MAC_ADMIN in init_user_ns.  A capability held in a
    # child user namespace does not apply to its parent; ID maps do not alter it.
    os.unshare(os.CLONE_NEWUSER)


def clear_mac_admin():
    capabilities.set_mac_admin_effective(False)


def raise_mac_admin():
    capabilities.set_mac_admin_effective(True)


def drop_mac_admin():
    capabilities.drop_mac_admin()


def link_certificate(keyring_name, asset):
    keyring.add_certificate(keyring_name, ipe.policy_asset(asset, ".der"))


def activate_policy(policy):
    ipe.deploy_policy(policy.signed)
    ipe.activate_policy(policy.name)
