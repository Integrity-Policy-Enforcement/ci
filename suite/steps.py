# SPDX-License-Identifier: GPL-2.0-only

import capabilities
import ipe


def deploy_policy(asset):
    ipe.deploy_policy(asset)


def drop_mac_admin():
    capabilities.drop_mac_admin()
