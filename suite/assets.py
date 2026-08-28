# SPDX-License-Identifier: GPL-2.0-only

import ipe


def policy(asset, name):
    return ipe.Policy(ipe.POLICY_ROOT / asset, name)


# The run activates this permissive policy so a case starts from a known floor.
BASELINE_POLICY = policy("ipe_test_baseline-0.0.1", "ipe_test_baseline")

# securityfs capability cases update one policy name between these two versions.
CAPABILITY_POLICY_V1 = policy("capability/ipe_test_capability-0.0.1", "ipe_test_capability")
CAPABILITY_POLICY_V1_VERSION = "0.0.1"
CAPABILITY_POLICY_V2 = policy("capability/ipe_test_capability-0.0.2", "ipe_test_capability")
CAPABILITY_POLICY_V2_VERSION = "0.0.2"

# policy cases use an independent policy so they do not alter capability cases.
POLICY_V1 = policy("policy/ipe_test_policy-0.0.1", "ipe_test_policy")
POLICY_V1_VERSION = "0.0.1"
# Below the baseline version, so activating it must be rejected.
POLICY_V0 = policy("policy/ipe_test_policy-0.0.0", "ipe_test_policy")
POLICY_V2 = policy("policy/ipe_test_policy-0.0.2", "ipe_test_policy")
POLICY_V2_VERSION = "0.0.2"
POLICY_OTHER_NAME = policy("policy/ipe_test_policy-other-name", "ipe_test_policy_other")
POLICY_MALFORMED = policy("policy/ipe_test_policy-malformed", "ipe_test_policy")

# policy signature cases sign this policy with a key the blacklist holds,
REVOKED_POLICY = policy("policy_signature/revoked", "ipe_test_signature_revoked")

# this one with a key no keyring trusts,
UNTRUSTED_POLICY = policy("policy_signature/untrusted", "ipe_test_signature_untrusted")

# and replace this one's text after signing with a copy claiming a higher version.
TAMPERED_POLICY = policy("policy_signature/tampered", "ipe_test_signature_tampered")

# and this one with a leaf whose issuer must first be linked into a keyring.
SECONDARY_POLICY = policy("policy_signature/secondary", "ipe_test_signature_secondary")
SECONDARY_KEYRING = "%:.secondary_trusted_keys"

# and this one with the Secure Boot key the firmware already trusts.
PLATFORM_POLICY = policy("policy_signature/platform", "ipe_test_signature_platform")


# policy text corpus: one policy per parser decision point, all under one name
# except the one whose name exercises the characters a name may contain.
def text_policy(asset, name="ipe_test_text"):
    return policy(f"policy_text/{asset}", name)


TEXT_SPECIAL_NAME_POLICY = text_policy("special_name_ok", "ipe_test_text$-.+")

# dm-verity: a module on an image whose root hash carries a signature,
# against a rule written as TRUE allow and as FALSE deny.
KMODULE_SIGNATURE_TRUE_POLICY = policy(
    "dmverity/kmodule_signature_true_allow", "ipe_test_dmverity_kmodule_signature_true"
)
KMODULE_SIGNATURE_FALSE_POLICY = policy(
    "dmverity/kmodule_signature_false_deny", "ipe_test_dmverity_kmodule_signature_false"
)

# fs-verity: one module file with a built-in signature, one without.
FSVERITY_SIGNATURE_TRUE_POLICY = policy(
    "fsverity/kmodule_signature_true_allow", "ipe_test_fsverity_kmodule_signature_true"
)
FSVERITY_SIGNATURE_FALSE_POLICY = policy(
    "fsverity/kmodule_signature_false_deny", "ipe_test_fsverity_kmodule_signature_false"
)


def roothash_policy(algorithm, matching=True):
    kind = "" if matching else "mismatch_"
    return policy(
        f"dmverity/kmodule_roothash_{algorithm}_{kind}allow",
        f"ipe_test_dmverity_kmodule_roothash_{algorithm}" + ("" if matching else "_mismatch"),
    )


def digest_policy(algorithm, matching=True):
    kind = "" if matching else "mismatch_"
    return policy(
        f"fsverity/kmodule_digest_{algorithm}_{kind}allow",
        f"ipe_test_fsverity_kmodule_digest_{algorithm}" + ("" if matching else "_mismatch"),
    )
