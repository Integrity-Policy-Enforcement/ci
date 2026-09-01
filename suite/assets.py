# SPDX-License-Identifier: GPL-2.0-only

import ipe
import layout


def policy(asset: str, name: str) -> ipe.Policy:
    """Build a Policy from its relative path in the policies directory."""
    return ipe.Policy(signed=layout.guest.policy_signature(asset), name=name)


# The run activates this permissive policy so a case starts from a known floor.
BASELINE_POLICY = policy("ipe_test_baseline-0.0.1", "ipe_test_baseline")

# securityfs capability cases update one policy name between these two versions.
CAPABILITY_POLICY_V1 = policy("capability/ipe_test_capability-0.0.1", "ipe_test_capability")
CAPABILITY_POLICY_V1_VERSION = "0.0.1"
CAPABILITY_POLICY_V2 = policy("capability/ipe_test_capability-0.0.2", "ipe_test_capability")
CAPABILITY_POLICY_V2_VERSION = "0.0.2"

# Lifecycle cases use an independent policy so they do not alter capability cases.
LIFECYCLE_POLICY_V1 = policy(
    "policy/ipe_test_policy-0.0.1",
    "ipe_test_policy_lifecycle",
)
LIFECYCLE_POLICY_V1_VERSION = "0.0.1"
# Below the baseline version, so activating it must be rejected.
LIFECYCLE_POLICY_V0 = policy(
    "policy/ipe_test_policy-0.0.0",
    "ipe_test_policy_lifecycle",
)
LIFECYCLE_POLICY_V2 = policy(
    "policy/ipe_test_policy-0.0.2",
    "ipe_test_policy_lifecycle",
)
LIFECYCLE_POLICY_V2_VERSION = "0.0.2"
LIFECYCLE_POLICY_OTHER_NAME = policy(
    "policy/ipe_test_policy-other-name",
    "ipe_test_policy_lifecycle_other",
)
LIFECYCLE_POLICY_MALFORMED = policy(
    "policy/ipe_test_policy-malformed",
    "ipe_test_policy_lifecycle",
)

REVOKED_SIGNATURE_POLICY = ipe.Policy(
    signed=layout.guest.REVOKED_POLICY_SIGNATURE,
    name="ipe_test_signature_revoked",
)

UNTRUSTED_SIGNATURE_POLICY = ipe.Policy(
    signed=layout.guest.UNTRUSTED_POLICY_SIGNATURE,
    name="ipe_test_signature_untrusted",
)

TAMPERED_SIGNATURE_POLICY = ipe.Policy(
    signed=layout.guest.TAMPERED_POLICY_SIGNATURE,
    name="ipe_test_signature_tampered",
)

SECONDARY_KEYRING_SIGNATURE_POLICY = ipe.Policy(
    signed=layout.guest.SECONDARY_POLICY_SIGNATURE,
    name="ipe_test_signature_secondary",
)
PLATFORM_KEYRING_SIGNATURE_POLICY = ipe.Policy(
    signed=layout.guest.PLATFORM_POLICY_SIGNATURE,
    name="ipe_test_signature_platform",
)

# policy text corpus: one policy per parser decision point, all under one name
# except the one whose name exercises the characters a name may contain.
def text_policy(asset: str, name: str = "ipe_test_text") -> ipe.Policy:
    """A policy from the text corpus, sharing one name unless told otherwise."""
    return policy(f"policy_text/{asset}", name)


TEXT_SPECIAL_NAME_POLICY = text_policy("special_name_ok", "ipe_test_text$-.+")

# KMODULE policies for signed and unsigned dm-verity media.
KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    "dmverity/kmodule_signature_true_allow", "ipe_test_dmverity_kmodule_signature_true"
)
KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    "dmverity/kmodule_signature_false_deny", "ipe_test_dmverity_kmodule_signature_false"
)

# KMODULE policies for signed, unsigned, and plain fs-verity test binaries.
KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    "fsverity/kmodule_signature_true_allow", "ipe_test_fsverity_kmodule_signature_true"
)
KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    "fsverity/kmodule_signature_false_deny", "ipe_test_fsverity_kmodule_signature_false"
)


def kmodule_dmverity_roothash_policy(
    algorithm: str,
    matching: bool = True,
) -> ipe.Policy:
    """A policy that names a dm-verity root hash, or a value no device has."""
    kind = "" if matching else "mismatch_"
    return policy(
        f"dmverity/kmodule_roothash_{algorithm}_{kind}allow",
        f"ipe_test_dmverity_kmodule_roothash_{algorithm}" + ("" if matching else "_mismatch"),
    )


def kmodule_fsverity_digest_policy(
    algorithm: str,
    matching: bool = True,
) -> ipe.Policy:
    """A policy that names an fs-verity digest, or a value no file has."""
    kind = "" if matching else "mismatch_"
    return policy(
        f"fsverity/kmodule_digest_{algorithm}_{kind}allow",
        f"ipe_test_fsverity_kmodule_digest_{algorithm}" + ("" if matching else "_mismatch"),
    )
