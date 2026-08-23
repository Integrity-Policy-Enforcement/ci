# SPDX-License-Identifier: GPL-2.0-only

# Session activates this policy before the run and restores it after every case.
BASELINE_POLICY_ASSET = "ipe_test_baseline-0.0.1"
BASELINE_POLICY_NAME = "ipe_test_baseline"

# securityfs capability cases update one policy name between these two versions.
CAPABILITY_POLICY_V1_ASSET = "capability/ipe_test_capability-0.0.1"
CAPABILITY_POLICY_V1_VERSION = "0.0.1"
CAPABILITY_POLICY_V2_ASSET = "capability/ipe_test_capability-0.0.2"
CAPABILITY_POLICY_V2_VERSION = "0.0.2"
CAPABILITY_POLICY_NAME = "ipe_test_capability"

# policy cases use an independent fixture so they do not alter capability cases.
POLICY_FIXTURE_V1_ASSET = "policy/ipe_test_policy-0.0.1"
POLICY_FIXTURE_V1_VERSION = "0.0.1"
POLICY_FIXTURE_NAME = "ipe_test_policy"
POLICY_FIXTURE_V0_ASSET = "policy/ipe_test_policy-0.0.0"
POLICY_FIXTURE_V2_ASSET = "policy/ipe_test_policy-0.0.2"
POLICY_FIXTURE_V2_VERSION = "0.0.2"
POLICY_FIXTURE_OTHER_NAME_ASSET = "policy/ipe_test_policy-other-name"
