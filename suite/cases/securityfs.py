# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import steps
import triggers
from assets import (
    CAPABILITY_POLICY_NAME,
    CAPABILITY_POLICY_V1,
    CAPABILITY_POLICY_V1_VERSION,
    CAPABILITY_POLICY_V2,
)
from model import Case


def build():
    return (
        Case(
            id="cap_update_nocap_eperm",
            setup=(
                partial(steps.deploy_policy, CAPABILITY_POLICY_V1),
                steps.drop_mac_admin,
            ),
            trigger=partial(
                triggers.write_node,
                "update",
                CAPABILITY_POLICY_NAME,
                ipe.signed_policy(CAPABILITY_POLICY_V2),
            ),
            expect=errno.EPERM,
            check=partial(checks.policy_version_is, CAPABILITY_POLICY_NAME, CAPABILITY_POLICY_V1_VERSION),
        ),
    )
