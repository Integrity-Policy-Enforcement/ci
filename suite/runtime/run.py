# SPDX-License-Identifier: GPL-2.0-only

import ipe
from scope import Collection, Scope, Setting


def scope() -> Scope:
    """What the run itself adds: one policy, made active."""
    return Scope(
        Setting(read=ipe.active_policy, write=ipe.activate_policy),
        Collection(members=ipe.policy_names, discard=ipe.delete_policy),
    )
