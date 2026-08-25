# SPDX-License-Identifier: GPL-2.0-only

import ipe
import mounts
from scope import Collection, Scope, Setting


def scope():
    """Everything a batch prepares for its cases, undone in mount order."""
    return Scope(
        Setting(ipe.enforcement, ipe.set_enforcement),
        Collection(mounts.points, mounts.umount),
        Collection(mounts.devices, mounts.close),
    )
