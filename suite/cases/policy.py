# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import checks
import ipe
import steps
import triggers
from assets import POLICY_FIXTURE_NAME, POLICY_FIXTURE_V1_ASSET, POLICY_FIXTURE_V1_VERSION
from model import Case


def build():
    return (
        Case(
            id="policy_load_ok",
            setup=(),
            trigger=partial(
                triggers.write_node,
                "new_policy",
                None,
                ipe.signed_policy(POLICY_FIXTURE_V1_ASSET),
            ),
            expect=0,
            check=partial(checks.policy_version_is, POLICY_FIXTURE_NAME, POLICY_FIXTURE_V1_VERSION),
        ),
        Case(
            id="policy_update_equal_estale",
            setup=(partial(steps.deploy_policy, POLICY_FIXTURE_V1_ASSET),),
            trigger=partial(
                triggers.write_node,
                "update",
                POLICY_FIXTURE_NAME,
                ipe.signed_policy(POLICY_FIXTURE_V1_ASSET),
            ),
            expect=errno.ESTALE,
            check=partial(checks.policy_version_is, POLICY_FIXTURE_NAME, POLICY_FIXTURE_V1_VERSION),
        ),
    )
