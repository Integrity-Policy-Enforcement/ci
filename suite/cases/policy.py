# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import checks
import ipe
import triggers
from assets import POLICY_NAME, POLICY_V1, POLICY_V1_VERSION
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
                ipe.signed_policy(POLICY_V1),
            ),
            expect=0,
            check=partial(checks.policy_version_is, POLICY_NAME, POLICY_V1_VERSION),
        ),
    )
