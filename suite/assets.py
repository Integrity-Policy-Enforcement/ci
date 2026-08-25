# SPDX-License-Identifier: GPL-2.0-only

import ipe


def signed_policy(asset, name):
    return ipe.Policy(ipe.policy_asset(asset, ".p7s"), name)


# The run activates this permissive policy so a case starts from a known floor.
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
# Below the baseline version, so activating it must be rejected.
POLICY_FIXTURE_V0_ASSET = "policy/ipe_test_policy-0.0.0"
POLICY_FIXTURE_V2_ASSET = "policy/ipe_test_policy-0.0.2"
POLICY_FIXTURE_V2_VERSION = "0.0.2"
POLICY_FIXTURE_OTHER_NAME_ASSET = "policy/ipe_test_policy-other-name"
POLICY_FIXTURE_MALFORMED_ASSET = "policy/ipe_test_policy-malformed"

# policy signature cases sign this policy with a key the blacklist holds,
REVOKED_POLICY_ASSET = "policy_signature/revoked"
REVOKED_POLICY_NAME = "ipe_test_signature_revoked"

# this one with a key no keyring trusts,
UNTRUSTED_POLICY_ASSET = "policy_signature/untrusted"
UNTRUSTED_POLICY_NAME = "ipe_test_signature_untrusted"

# and replace this one's text after signing with a copy claiming a higher version.
TAMPERED_POLICY_ASSET = "policy_signature/tampered"
TAMPERED_POLICY_NAME = "ipe_test_signature_tampered"

# and this one with a leaf whose issuer must first be linked into a keyring.
SECONDARY_POLICY_ASSET = "policy_signature/secondary"
SECONDARY_POLICY_NAME = "ipe_test_signature_secondary"
SECONDARY_KEYRING = "%:.secondary_trusted_keys"

# and this one with the Secure Boot key the firmware already trusts.
PLATFORM_POLICY_ASSET = "policy_signature/platform"
PLATFORM_POLICY_NAME = "ipe_test_signature_platform"

# policy text corpus: one fixture per parser decision point.
TEXT_POLICY_NAME = "ipe_test_text"
TEXT_SPECIAL_POLICY_NAME = "ipe_test_text$-.+"

# dm-verity: a module on an image whose root hash carries a signature.
KMODULE_SIGNATURE_TRUE_POLICY = signed_policy(
    "dmverity/kmodule_signature_true_allow", "ipe_test_dmverity_kmodule_signature_true"
)
