# SPDX-License-Identifier: GPL-2.0-only

import ipe
from scope import Scope, Setting


def scope(*also):
    """What any batch may disturb, and what this one disturbs beyond that."""
    return Scope(
        Setting(ipe.enforcement, ipe.set_enforcement),
        *also,
    )
