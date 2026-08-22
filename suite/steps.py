# SPDX-License-Identifier: GPL-2.0-only

import os

import capabilities
import ipe


def deploy_policy(asset):
    ipe.deploy_policy(asset)


def open_node(node, policy, descriptor):
    descriptor[0] = os.open(ipe.node_path(node, policy), os.O_WRONLY)


def drop_mac_admin():
    capabilities.drop_mac_admin()
