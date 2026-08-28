# SPDX-License-Identifier: GPL-2.0-only

import ipe
from scope import Collection, Scope, Setting


def scope(*also: Collection | Setting) -> Scope:
    """What any batch may disturb, and what this one disturbs beyond that."""
    return Scope(
        Setting(read=ipe.enforcement, write=ipe.set_enforcement),
        *also,
    )
