# SPDX-License-Identifier: GPL-2.0-only

import ipe
from scope import Collection, Scope, Setting


def scope(*also):
    """What any case may disturb, and what this one disturbs beyond that."""
    return Scope(
        Setting(ipe.enforcement, ipe.set_enforcement),
        Setting(ipe.success_audit, ipe.set_success_audit),
        Setting(ipe.active_policy, ipe.activate_policy),
        Collection(ipe.policy_names, ipe.delete_policy),
        *also,
    )
