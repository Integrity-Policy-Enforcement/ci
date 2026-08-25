# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import ipe
import keyring
import modules
from assets import SECONDARY_KEYRING
from scope import Collection, Scope, Setting


def scope():
    """Everything a single case may disturb."""
    return Scope(
        Setting(ipe.enforcement, ipe.set_enforcement),
        Setting(ipe.success_audit, ipe.set_success_audit),
        Setting(ipe.active_policy, ipe.activate_policy),
        Collection(ipe.policy_names, ipe.delete_policy),
        Collection(
            partial(keyring.linked_keys, SECONDARY_KEYRING),
            partial(keyring.unlink, keyring=SECONDARY_KEYRING),
        ),
        Collection(modules.loaded, modules.remove),
    )
