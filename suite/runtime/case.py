# SPDX-License-Identifier: GPL-2.0-only

import ipe
from scope import Collection, Scope, Setting


def scope(*also: Collection | Setting) -> Scope:
    """What any case may disturb, and what this one disturbs beyond that."""
    return Scope(
        Setting(read=ipe.enforcement, write=ipe.set_enforcement),
        Setting(read=ipe.success_audit, write=ipe.set_success_audit),
        Setting(read=ipe.active_policy, write=ipe.activate_policy),
        Collection(members=ipe.policy_names, discard=ipe.delete_policy),
        *also,
    )
