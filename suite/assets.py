# SPDX-License-Identifier: GPL-2.0-only

import ipe
import layout


def policy(asset: str, name: str) -> ipe.Policy:
    """Build a Policy from its relative path in the policies directory."""
    return ipe.Policy(signed=layout.guest.policy_signature(asset=asset), name=name)


# The run activates this permissive policy so a case starts from a known floor.
BASELINE_POLICY = policy(asset="ipe_test_baseline-0.0.1", name="ipe_test_baseline")

# securityfs capability cases update one policy name between these two versions.
CAPABILITY_POLICY_V1 = policy(
    asset="capability/ipe_test_capability-0.0.1", name="ipe_test_capability"
)
CAPABILITY_POLICY_V1_VERSION = "0.0.1"
CAPABILITY_POLICY_V2 = policy(
    asset="capability/ipe_test_capability-0.0.2", name="ipe_test_capability"
)
CAPABILITY_POLICY_V2_VERSION = "0.0.2"

# Lifecycle cases use an independent policy so they do not alter capability cases.
LIFECYCLE_POLICY_V1 = policy(
    asset="policy/ipe_test_policy-0.0.1",
    name="ipe_test_policy_lifecycle",
)
LIFECYCLE_POLICY_V1_VERSION = "0.0.1"
# Below the baseline version, so activating it must be rejected.
LIFECYCLE_POLICY_V0 = policy(
    asset="policy/ipe_test_policy-0.0.0",
    name="ipe_test_policy_lifecycle",
)
LIFECYCLE_POLICY_V2 = policy(
    asset="policy/ipe_test_policy-0.0.2",
    name="ipe_test_policy_lifecycle",
)
LIFECYCLE_POLICY_V2_VERSION = "0.0.2"
LIFECYCLE_POLICY_OTHER_NAME = policy(
    asset="policy/ipe_test_policy-other-name",
    name="ipe_test_policy_lifecycle_other",
)
LIFECYCLE_POLICY_MALFORMED = policy(
    asset="policy/ipe_test_policy-malformed",
    name="ipe_test_policy_lifecycle",
)

REVOKED_SIGNATURE_POLICY = policy(
    asset="policy_signature/revoked",
    name="ipe_test_signature_revoked",
)
UNTRUSTED_SIGNATURE_POLICY = policy(
    asset="policy_signature/untrusted",
    name="ipe_test_signature_untrusted",
)
TAMPERED_SIGNATURE_POLICY = policy(
    asset="policy_signature/tampered",
    name="ipe_test_signature_tampered",
)
SECONDARY_KEYRING_SIGNATURE_POLICY = policy(
    asset="policy_signature/secondary",
    name="ipe_test_signature_secondary",
)
PLATFORM_KEYRING_SIGNATURE_POLICY = policy(
    asset="policy_signature/platform",
    name="ipe_test_signature_platform",
)


# policy text corpus: one policy per parser decision point, all under one name
# except the one whose name exercises the characters a name may contain.
def text_policy(asset: str, name: str = "ipe_test_text") -> ipe.Policy:
    """A policy from the text corpus, sharing one name unless told otherwise."""
    return policy(asset=f"policy_text/{asset}", name=name)


TEXT_SPECIAL_NAME_POLICY = text_policy(
    asset="special_name_ok", name="ipe_test_text$-.+"
)

EXECUTE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="dmverity/execute_signature_false_deny",
    name="ipe_test_dmverity_execute_signature_false",
)
EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="dmverity/execute_signature_true_allow",
    name="ipe_test_dmverity_execute_signature_true",
)

EXECUTE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="fsverity/execute_signature_false_deny",
    name="ipe_test_fsverity_execute_signature_false",
)
EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="fsverity/execute_signature_true_allow",
    name="ipe_test_fsverity_execute_signature_true",
)

INTERPRETER_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="dmverity/interpreter_signature_true_allow",
    name="ipe_test_dmverity_interpreter_signature_true",
)

INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="fsverity/interpreter_signature_true_allow",
    name="ipe_test_fsverity_interpreter_signature_true",
)

X509_CERT_DMVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="dmverity/x509_cert_signature_false_deny",
    name="ipe_test_dmverity_x509_cert_signature_false",
)
X509_CERT_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="dmverity/x509_cert_signature_true_allow",
    name="ipe_test_dmverity_x509_cert_signature_true",
)

X509_CERT_FSVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="fsverity/x509_cert_signature_false_deny",
    name="ipe_test_fsverity_x509_cert_signature_false",
)
X509_CERT_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="fsverity/x509_cert_signature_true_allow",
    name="ipe_test_fsverity_x509_cert_signature_true",
)

POLICY_OP_DMVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="dmverity/policy_op_signature_false_deny",
    name="ipe_test_dmverity_policy_op_signature_false",
)
POLICY_OP_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="dmverity/policy_op_signature_true_allow",
    name="ipe_test_dmverity_policy_op_signature_true",
)

POLICY_OP_FSVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="fsverity/policy_op_signature_false_deny",
    name="ipe_test_fsverity_policy_op_signature_false",
)
POLICY_OP_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="fsverity/policy_op_signature_true_allow",
    name="ipe_test_fsverity_policy_op_signature_true",
)

FIRMWARE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="dmverity/firmware_signature_false_deny",
    name="ipe_test_dmverity_firmware_signature_false",
)
FIRMWARE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="dmverity/firmware_signature_true_allow",
    name="ipe_test_dmverity_firmware_signature_true",
)

FIRMWARE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="fsverity/firmware_signature_false_deny",
    name="ipe_test_fsverity_firmware_signature_false",
)
FIRMWARE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="fsverity/firmware_signature_true_allow",
    name="ipe_test_fsverity_firmware_signature_true",
)

KEXEC_IMAGE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="dmverity/kexec_image_signature_false_deny",
    name="ipe_test_dmverity_kexec_image_signature_false",
)
KEXEC_IMAGE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="dmverity/kexec_image_signature_true_allow",
    name="ipe_test_dmverity_kexec_image_signature_true",
)

KEXEC_INITRAMFS_DMVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="dmverity/kexec_initramfs_signature_false_deny",
    name="ipe_test_dmverity_kexec_initramfs_signature_false",
)
KEXEC_INITRAMFS_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="dmverity/kexec_initramfs_signature_true_allow",
    name="ipe_test_dmverity_kexec_initramfs_signature_true",
)

KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="fsverity/kexec_image_signature_false_deny",
    name="ipe_test_fsverity_kexec_image_signature_false",
)
KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="fsverity/kexec_image_signature_true_allow",
    name="ipe_test_fsverity_kexec_image_signature_true",
)

KEXEC_INITRAMFS_FSVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="fsverity/kexec_initramfs_signature_false_deny",
    name="ipe_test_fsverity_kexec_initramfs_signature_false",
)
KEXEC_INITRAMFS_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="fsverity/kexec_initramfs_signature_true_allow",
    name="ipe_test_fsverity_kexec_initramfs_signature_true",
)

# KMODULE policies for signed and unsigned dm-verity media.
KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="dmverity/kmodule_signature_true_allow",
    name="ipe_test_dmverity_kmodule_signature_true",
)
KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="dmverity/kmodule_signature_false_deny",
    name="ipe_test_dmverity_kmodule_signature_false",
)

# KMODULE policies for signed, unsigned, and plain fs-verity test binaries.
KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY = policy(
    asset="fsverity/kmodule_signature_true_allow",
    name="ipe_test_fsverity_kmodule_signature_true",
)
KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY = policy(
    asset="fsverity/kmodule_signature_false_deny",
    name="ipe_test_fsverity_kmodule_signature_false",
)


def preload_dmverity_roothash_policy(algorithm: str) -> ipe.Policy:
    """Permit the signed-root runtime and an unsigned library mapping with this hash."""
    return policy(
        asset=f"dmverity/roothash/{algorithm}/preload_allow",
        name=f"ipe_test_dmverity_preload_roothash_{algorithm}",
    )


def interpreter_dmverity_roothash_policy(algorithm: str) -> ipe.Policy:
    """Permit the fixed interpreter and scripts from this dm-verity root hash."""
    return policy(
        asset=f"dmverity/roothash/{algorithm}/interpreter_allow",
        name=f"ipe_test_dmverity_interpreter_roothash_{algorithm}",
    )


def execute_dmverity_roothash_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """An EXECUTE rule naming a root hash, or a value no test device has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"dmverity/roothash/{algorithm}/execute_{kind}allow",
        name=f"ipe_test_dmverity_execute_roothash_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def x509_cert_dmverity_roothash_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """An X509_CERT rule naming a root hash, or a value no device has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"dmverity/roothash/{algorithm}/x509_cert_{kind}allow",
        name=f"ipe_test_dmverity_x509_cert_roothash_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def policy_op_dmverity_roothash_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """A POLICY rule naming a root hash, or a value no device has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"dmverity/roothash/{algorithm}/policy_op_{kind}allow",
        name=f"ipe_test_dmverity_policy_op_roothash_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def firmware_dmverity_roothash_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """A FIRMWARE policy naming a root hash, or a value no device has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"dmverity/roothash/{algorithm}/firmware_{kind}allow",
        name=f"ipe_test_dmverity_firmware_roothash_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def kexec_image_dmverity_roothash_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """A KEXEC_IMAGE policy naming a root hash, or a value no device has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"dmverity/roothash/{algorithm}/kexec_image_{kind}allow",
        name=f"ipe_test_dmverity_kexec_image_roothash_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def kexec_initramfs_dmverity_roothash_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """A KEXEC_INITRAMFS policy naming a root hash, or a value no device has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"dmverity/roothash/{algorithm}/kexec_initramfs_{kind}allow",
        name=f"ipe_test_dmverity_kexec_initramfs_roothash_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def kmodule_dmverity_roothash_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """A policy that names a dm-verity root hash, or a value no device has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"dmverity/roothash/{algorithm}/kmodule_{kind}allow",
        name=f"ipe_test_dmverity_kmodule_roothash_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def memfd_source_fsverity_digest_policy(algorithm: str) -> ipe.Policy:
    """An EXECUTE digest rule matching only the original file, not its memfd copy."""
    return policy(
        asset=f"fsverity/memfd_source_digest_{algorithm}_allow",
        name=f"ipe_test_fsverity_memfd_source_digest_{algorithm}",
    )


def shebang_fsverity_digest_policy(algorithm: str) -> ipe.Policy:
    """Permit the fixed interpreter and the digest of the complete shebang script."""
    return policy(
        asset=f"fsverity/shebang_digest_{algorithm}_allow",
        name=f"ipe_test_fsverity_shebang_digest_{algorithm}",
    )


def interpreter_fsverity_digest_policy(algorithm: str) -> ipe.Policy:
    """Permit the fixed interpreter and the matching script digest."""
    return policy(
        asset=f"fsverity/interpreter_digest_{algorithm}_allow",
        name=f"ipe_test_fsverity_interpreter_digest_{algorithm}",
    )


def execute_fsverity_digest_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """An EXECUTE rule naming the static ELF digest or a mismatching value."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"fsverity/execute_digest_{algorithm}_{kind}allow",
        name=f"ipe_test_fsverity_execute_digest_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def x509_cert_fsverity_digest_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """An X509_CERT rule naming its digest, or a value no test file has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"fsverity/x509_cert_digest_{algorithm}_{kind}allow",
        name=f"ipe_test_fsverity_x509_cert_digest_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def policy_op_fsverity_digest_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """A POLICY rule naming its digest, or a value no test file has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"fsverity/policy_op_digest_{algorithm}_{kind}allow",
        name=f"ipe_test_fsverity_policy_op_digest_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def firmware_fsverity_digest_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """A FIRMWARE policy naming its digest, or a value no test file has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"fsverity/firmware_digest_{algorithm}_{kind}allow",
        name=f"ipe_test_fsverity_firmware_digest_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def kexec_image_fsverity_digest_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """A KEXEC_IMAGE policy naming its digest, or a value no test file has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"fsverity/kexec_image_digest_{algorithm}_{kind}allow",
        name=f"ipe_test_fsverity_kexec_image_digest_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def kexec_initramfs_fsverity_digest_policy(
    algorithm: str,
    matching: bool,
) -> ipe.Policy:
    """A KEXEC_INITRAMFS policy naming its digest, or a value no test file has."""
    kind = "" if matching else "mismatch_"
    return policy(
        asset=f"fsverity/kexec_initramfs_digest_{algorithm}_{kind}allow",
        name=f"ipe_test_fsverity_kexec_initramfs_digest_{algorithm}"
        + ("" if matching else "_mismatch"),
    )


def kmodule_fsverity_digest_policy(
    algorithm: str,
    matching: bool,
    compressed: bool,
) -> ipe.Policy:
    """A policy naming the selected module's digest, or a value no file has."""
    kind = "" if matching else "mismatch_"
    variant = "compressed_" if compressed else ""
    return policy(
        asset=f"fsverity/kmodule_{variant}digest_{algorithm}_{kind}allow",
        name=f"ipe_test_fsverity_kmodule_{variant}digest_{algorithm}"
        + ("" if matching else "_mismatch"),
    )
