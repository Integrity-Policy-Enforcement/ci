# SPDX-License-Identifier: GPL-2.0-only

import ipe
from assets import BASELINE_POLICY, BASELINE_POLICY_NAME


class Session:
    def __init__(self):
        ipe.set_enforcement(False)
        ipe.set_success_audit(False)
        self.baseline_policy = ipe.load_baseline(BASELINE_POLICY, BASELINE_POLICY_NAME)
        self.initial_policies = ipe.policy_names()

    def reset(self):
        ipe.set_enforcement(False)
        ipe.set_success_audit(False)
        ipe.activate_policy(self.baseline_policy)
        for policy in ipe.policy_names() - self.initial_policies:
            ipe.delete_policy(policy)
