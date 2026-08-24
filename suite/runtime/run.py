# SPDX-License-Identifier: GPL-2.0-only

import ipe
from scope import Collection, Scope, Setting


def scope():
    """What the run itself adds: one policy, made active."""
    return Scope(
        Setting(ipe.active_policy, ipe.activate_policy),
        Collection(ipe.policy_names, ipe.delete_policy),
    )
