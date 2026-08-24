# SPDX-License-Identifier: GPL-2.0-only

import ipe
import keyring
from assets import BASELINE_POLICY_ASSET, BASELINE_POLICY_NAME, SECONDARY_KEYRING


class Session:
    def __init__(self):
        ipe.set_enforcement(False)
        ipe.set_success_audit(False)
        self.baseline_policy = ipe.load_baseline(BASELINE_POLICY_ASSET, BASELINE_POLICY_NAME)
        self.initial_policies = ipe.policy_names()
        self.initial_keys = keyring.linked_keys(SECONDARY_KEYRING)

    def reset(self):
        ipe.set_enforcement(False)
        ipe.set_success_audit(False)
        ipe.activate_policy(self.baseline_policy)
        for policy in ipe.policy_names() - self.initial_policies:
            ipe.delete_policy(policy)
        for key in keyring.linked_keys(SECONDARY_KEYRING) - self.initial_keys:
            keyring.unlink(key, SECONDARY_KEYRING)
