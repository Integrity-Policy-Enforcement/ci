# SPDX-License-Identifier: GPL-2.0-only

import errno
import mmap
from functools import partial

import files
import hashes
import ipe
import layout
import modules
from assets import (
    EXECUTE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    FIRMWARE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    FIRMWARE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    KEXEC_INITRAMFS_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KEXEC_INITRAMFS_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    POLICY_OP_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    POLICY_OP_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    PRELOAD_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    X509_CERT_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    X509_CERT_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    execute_fsverity_digest_policy,
    firmware_fsverity_digest_policy,
    interpreter_fsverity_digest_policy,
    kexec_image_fsverity_digest_policy,
    kexec_initramfs_fsverity_digest_policy,
    kmodule_fsverity_digest_policy,
    memfd_source_fsverity_digest_policy,
    policy_op_fsverity_digest_policy,
    preload_fsverity_digest_policy,
    shebang_fsverity_digest_policy,
    x509_cert_fsverity_digest_policy,
)
from command import run
from execute_memfd import hugepages_scope
from model import Batch, Case

from . import (
    execute,
    execute_interpreter,
    execute_memfd,
    execute_mmap,
    execute_mprotect,
    execute_preload,
    firmware,
    kexec,
    kmodule,
    policy_op,
    x509,
)

# Here "signed" means fs-verity's built-in signature, not module signing.
# For DER inputs it is not the certificate issuer signature.
# Signed and unsigned files both have fs-verity enabled; plain files do not.
# For .ko.gz, the signed fs-verity digest is computed from compressed bytes.


def signature_cases(*, algorithm: str) -> tuple[Case, ...]:
    """The signed and unsigned fs-verity signature cases for one algorithm."""
    signed_kmodule_binary = layout.guest.fsverity_signed_kmodule_test_binary(
        algorithm=algorithm, compressed=False
    )
    unsigned_kmodule_binary = layout.guest.fsverity_unsigned_kmodule_test_binary(
        algorithm=algorithm, compressed=False
    )
    return (
        # Policy: KMODULE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: .ko with fs-verity enabled and a verified built-in signature.
        # Match: the file's signature property is TRUE -> ALLOW.
        kmodule.insmod_case(
            id=(
                "kmodule_kernel_read_insmod_fsverity_signature_true_"
                f"{algorithm}_signed_ok"
            ),
            policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=signed_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        # Policy: KMODULE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: .ko with fs-verity enabled but no built-in signature.
        # Match: the signature property is FALSE -> no ALLOW match -> default DENY.
        kmodule.insmod_case(
            id=(
                "kmodule_kernel_read_insmod_fsverity_signature_true_"
                f"{algorithm}_unsigned_denied"
            ),
            policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=unsigned_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
        # Policy: KMODULE default ALLOW; DENY fsverity_signature=FALSE.
        # Input: .ko with fs-verity enabled and a verified built-in signature.
        # Match: FALSE does not match -> default ALLOW, not the DENY rule.
        kmodule.insmod_case(
            id=(
                "kmodule_kernel_read_insmod_fsverity_signature_false_"
                f"{algorithm}_signed_ok"
            ),
            policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=signed_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        # Policy: KMODULE default ALLOW; DENY fsverity_signature=FALSE.
        # Input: .ko with fs-verity enabled but no built-in signature.
        # Match: FALSE matches -> the explicit DENY rule applies.
        kmodule.insmod_case(
            id=(
                "kmodule_kernel_read_insmod_fsverity_signature_false_"
                f"{algorithm}_unsigned_denied"
            ),
            policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=unsigned_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
    )


def digest_cases(*, algorithm: str) -> tuple[Case, ...]:
    """The fs-verity digest cases for one algorithm."""
    matching_digest_policy = kmodule_fsverity_digest_policy(
        algorithm=algorithm, matching=True, compressed=False
    )
    mismatching_digest_policy = kmodule_fsverity_digest_policy(
        algorithm=algorithm, matching=False, compressed=False
    )
    signed_kmodule_binary = layout.guest.fsverity_signed_kmodule_test_binary(
        algorithm=algorithm, compressed=False
    )
    unsigned_kmodule_binary = layout.guest.fsverity_unsigned_kmodule_test_binary(
        algorithm=algorithm, compressed=False
    )
    plain_kmodule_binary = layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY
    return (
        # Policy: KMODULE default DENY; ALLOW matching fsverity_digest.
        # Input: signed fs-verity .ko; its measured digest matches the policy.
        # Match: digest rule -> ALLOW; this rule does not require a signature.
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_fsverity_digest_{algorithm}_signed_ok",
            policy=matching_digest_policy,
            binary=signed_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        # Policy: KMODULE default DENY; ALLOW matching fsverity_digest.
        # Input: unsigned fs-verity .ko; verity is enabled and its digest matches.
        # Match: digest rule -> ALLOW despite the missing built-in signature.
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_fsverity_digest_{algorithm}_unsigned_ok",
            policy=matching_digest_policy,
            binary=unsigned_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        # Policy: KMODULE default DENY; ALLOW matching fsverity_digest.
        # Input: the same .ko bytes, but fs-verity is not enabled.
        # Match: no fs-verity digest exists -> no ALLOW match -> default DENY.
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_fsverity_digest_{algorithm}_plain_denied",
            policy=matching_digest_policy,
            binary=plain_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
        # Policy: KMODULE default DENY; ALLOW a different fsverity_digest.
        # Input: signed fs-verity .ko; its digest differs from the policy value.
        # Match: digest mismatch -> default DENY, even with a valid signature.
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_fsverity_digest_{algorithm}_mismatch_denied",
            policy=mismatching_digest_policy,
            binary=signed_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
    )


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            id="fsverity",
            cases=(
                # Policy: X509_CERT default DENY; ALLOW fsverity_signature=TRUE.
                # Input: DER file with a verified built-in signature over its fs-verity digest.
                # Match: the file's TRUE signature -> ALLOW; retain bytes, import no key.
                *(
                    x509.read_case(
                        id=(
                            "x509_cert_kernel_read_ipe_test_x509_"
                            f"fsverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=X509_CERT_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: X509_CERT default DENY; ALLOW fsverity_signature=TRUE.
                # Input: DER file with fs-verity enabled but no built-in fs-verity signature.
                # Match: TRUE does not match -> default DENY; the issuer signature is irrelevant.
                *(
                    x509.read_case(
                        id=(
                            "x509_cert_kernel_read_ipe_test_x509_"
                            f"fsverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=X509_CERT_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_content=b"",
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: X509_CERT default DENY; ALLOW fsverity_signature=TRUE.
                # Input: the same DER bytes without fs-verity or a built-in file signature.
                # Match: TRUE does not match -> default DENY.
                x509.read_case(
                    id="x509_cert_kernel_read_ipe_test_x509_fsverity_signature_true_plain_denied",
                    policy=X509_CERT_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_X509_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_content=b"",
                ),
                # Policy: X509_CERT default ALLOW; DENY fsverity_signature=FALSE.
                # Input: DER file with a verified built-in signature over its fs-verity digest.
                # Match: FALSE does not match -> default ALLOW; retain the exact DER bytes.
                *(
                    x509.read_case(
                        id=(
                            "x509_cert_kernel_read_ipe_test_x509_"
                            f"fsverity_signature_false_{algorithm}_signed_ok"
                        ),
                        policy=X509_CERT_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: X509_CERT default ALLOW; DENY fsverity_signature=FALSE.
                # Input: DER file with fs-verity enabled but no built-in fs-verity signature.
                # Match: FALSE matches -> explicit DENY, not default ALLOW.
                *(
                    x509.read_case(
                        id=(
                            "x509_cert_kernel_read_ipe_test_x509_"
                            f"fsverity_signature_false_{algorithm}_unsigned_denied"
                        ),
                        policy=X509_CERT_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_content=b"",
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: X509_CERT default ALLOW; DENY fsverity_signature=FALSE.
                # Input: identical DER bytes with no fs-verity metadata or built-in signature.
                # Match: absence counts as FALSE -> explicit DENY.
                x509.read_case(
                    id="x509_cert_kernel_read_ipe_test_x509_fsverity_signature_false_plain_denied",
                    policy=X509_CERT_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_X509_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_content=b"",
                ),
                # Policy: X509_CERT default DENY; ALLOW matching fsverity_digest.
                # Input: a signed fs-verity DER file whose own digest matches the rule.
                # Match: digest rule -> ALLOW; a built-in file signature is not required.
                *(
                    x509.read_case(
                        id=(
                            "x509_cert_kernel_read_ipe_test_x509_"
                            f"fsverity_digest_{algorithm}_signed_ok"
                        ),
                        policy=x509_cert_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: X509_CERT default DENY; ALLOW matching fsverity_digest.
                # Input: DER file with fs-verity enabled, a matching digest, and no built-in signature.
                # Match: digest rule -> ALLOW without a built-in fs-verity signature.
                *(
                    x509.read_case(
                        id=(
                            "x509_cert_kernel_read_ipe_test_x509_"
                            f"fsverity_digest_{algorithm}_unsigned_ok"
                        ),
                        policy=x509_cert_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=0,
                        expected_content=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: X509_CERT default DENY; ALLOW matching fsverity_digest.
                # Input: identical DER bytes with fs-verity disabled.
                # Match: no inode digest property -> default DENY, not a digest mismatch.
                *(
                    x509.read_case(
                        id=(
                            "x509_cert_kernel_read_ipe_test_x509_"
                            f"fsverity_digest_{algorithm}_plain_denied"
                        ),
                        policy=x509_cert_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.FSVERITY_PLAIN_X509_TEST_BINARY,
                        expected_errno=errno.EACCES,
                        expected_content=b"",
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: X509_CERT default DENY; ALLOW a different fsverity_digest.
                # Input: signed fs-verity DER file whose digest differs from the rule.
                # Match: digest mismatch -> default DENY despite the built-in file signature.
                *(
                    x509.read_case(
                        id=(
                            "x509_cert_kernel_read_ipe_test_x509_"
                            f"fsverity_digest_{algorithm}_mismatch_denied"
                        ),
                        policy=x509_cert_fsverity_digest_policy(
                            algorithm=algorithm, matching=False
                        ),
                        binary=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=errno.EACCES,
                        expected_content=b"",
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: POLICY default DENY; ALLOW fsverity_signature=TRUE.
                # Input: policy text with fs-verity and a built-in signature over its digest.
                # Match: the file's verified signature is TRUE -> ALLOW; retain exact bytes.
                *(
                    policy_op.read_case(
                        id=(
                            "policy_op_kernel_read_ipe_test_policy_op_"
                            f"fsverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=POLICY_OP_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: POLICY default DENY; ALLOW fsverity_signature=TRUE.
                # Input: policy text with fs-verity enabled but no built-in digest signature.
                # Match: TRUE does not match -> default DENY; retained contents must be empty.
                *(
                    policy_op.read_case(
                        id=(
                            "policy_op_kernel_read_ipe_test_policy_op_"
                            f"fsverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=POLICY_OP_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_content=b"",
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: POLICY default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical policy text without fs-verity or a built-in signature.
                # Match: TRUE does not match -> default DENY.
                policy_op.read_case(
                    id="policy_op_kernel_read_ipe_test_policy_op_fsverity_signature_true_plain_denied",
                    policy=POLICY_OP_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_POLICY_OP_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_content=b"",
                ),
                # Policy: POLICY default ALLOW; DENY fsverity_signature=FALSE.
                # Input: policy text with a verified built-in fs-verity digest signature.
                # Match: FALSE does not match -> default ALLOW; retain the exact bytes.
                *(
                    policy_op.read_case(
                        id=(
                            "policy_op_kernel_read_ipe_test_policy_op_"
                            f"fsverity_signature_false_{algorithm}_signed_ok"
                        ),
                        policy=POLICY_OP_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: POLICY default ALLOW; DENY fsverity_signature=FALSE.
                # Input: policy text with fs-verity enabled but no built-in digest signature.
                # Match: FALSE matches -> explicit DENY, not default ALLOW.
                *(
                    policy_op.read_case(
                        id=(
                            "policy_op_kernel_read_ipe_test_policy_op_"
                            f"fsverity_signature_false_{algorithm}_unsigned_denied"
                        ),
                        policy=POLICY_OP_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_content=b"",
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: POLICY default ALLOW; DENY fsverity_signature=FALSE.
                # Input: the same policy text without fs-verity metadata or a signature.
                # Match: absence counts as FALSE -> explicit DENY.
                policy_op.read_case(
                    id="policy_op_kernel_read_ipe_test_policy_op_fsverity_signature_false_plain_denied",
                    policy=POLICY_OP_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_POLICY_OP_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_content=b"",
                ),
                # Policy: POLICY default DENY; ALLOW matching fsverity_digest.
                # Input: signed fs-verity policy text whose own digest matches the rule.
                # Match: digest rule -> ALLOW; a built-in signature is not required.
                *(
                    policy_op.read_case(
                        id=(
                            "policy_op_kernel_read_ipe_test_policy_op_"
                            f"fsverity_digest_{algorithm}_signed_ok"
                        ),
                        policy=policy_op_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: POLICY default DENY; ALLOW matching fsverity_digest.
                # Input: unsigned fs-verity policy text whose digest matches the rule.
                # Match: digest rule -> ALLOW without a built-in digest signature.
                *(
                    policy_op.read_case(
                        id=(
                            "policy_op_kernel_read_ipe_test_policy_op_"
                            f"fsverity_digest_{algorithm}_unsigned_ok"
                        ),
                        policy=policy_op_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=0,
                        expected_content=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: POLICY default DENY; ALLOW matching fsverity_digest.
                # Input: identical policy text with fs-verity disabled.
                # Match: no digest property -> default DENY, not a digest mismatch.
                *(
                    policy_op.read_case(
                        id=(
                            "policy_op_kernel_read_ipe_test_policy_op_"
                            f"fsverity_digest_{algorithm}_plain_denied"
                        ),
                        policy=policy_op_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.FSVERITY_PLAIN_POLICY_OP_TEST_BINARY,
                        expected_errno=errno.EACCES,
                        expected_content=b"",
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: POLICY default DENY; ALLOW a different fsverity_digest.
                # Input: signed fs-verity policy text whose digest differs from the rule.
                # Match: digest mismatch -> default DENY despite the built-in signature.
                *(
                    policy_op.read_case(
                        id=(
                            "policy_op_kernel_read_ipe_test_policy_op_"
                            f"fsverity_digest_{algorithm}_mismatch_denied"
                        ),
                        policy=policy_op_fsverity_digest_policy(
                            algorithm=algorithm, matching=False
                        ),
                        binary=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=errno.EACCES,
                        expected_content=b"",
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_INITRAMFS default DENY; ALLOW fsverity_signature=TRUE.
                # Input: CPIO with fs-verity enabled and a built-in signature over its digest;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: the CPIO's verified signature is TRUE -> ALLOW; stage then unload.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"fsverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_INITRAMFS default DENY; ALLOW fsverity_signature=TRUE.
                # Input: CPIO with fs-verity enabled but no built-in digest signature;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: TRUE does not match -> default DENY; nothing is staged.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"fsverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_INITRAMFS default DENY; ALLOW fsverity_signature=TRUE.
                # Input: the same CPIO bytes without fs-verity or a built-in signature;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: TRUE does not match -> default DENY.
                kexec.initramfs_load_case(
                    id="kexec_initramfs_kernel_read_kexec_file_load_fsverity_signature_true_plain_denied",
                    policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                    binary=layout.guest.FSVERITY_PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_INITRAMFS default ALLOW; DENY fsverity_signature=FALSE.
                # Input: CPIO with a verified built-in signature over its fs-verity digest;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: FALSE does not match -> default ALLOW; stage then unload.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"fsverity_signature_false_{algorithm}_signed_ok"
                        ),
                        policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_INITRAMFS default ALLOW; DENY fsverity_signature=FALSE.
                # Input: CPIO with fs-verity enabled but no built-in digest signature;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: FALSE matches -> explicit DENY, not the default ALLOW.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"fsverity_signature_false_{algorithm}_unsigned_denied"
                        ),
                        policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_INITRAMFS default ALLOW; DENY fsverity_signature=FALSE.
                # Input: the same CPIO without fs-verity metadata or a built-in signature;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: absence counts as FALSE -> explicit DENY.
                kexec.initramfs_load_case(
                    id="kexec_initramfs_kernel_read_kexec_file_load_fsverity_signature_false_plain_denied",
                    policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                    binary=layout.guest.FSVERITY_PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_INITRAMFS default DENY; ALLOW matching fsverity_digest.
                # Input: signed fs-verity CPIO whose own measured digest matches the rule;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: digest rule -> ALLOW; a built-in signature is not required.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"fsverity_digest_{algorithm}_signed_ok"
                        ),
                        policy=kexec_initramfs_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_INITRAMFS default DENY; ALLOW matching fsverity_digest.
                # Input: unsigned fs-verity CPIO whose own digest matches the rule;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: digest rule -> ALLOW without a built-in digest signature.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"fsverity_digest_{algorithm}_unsigned_ok"
                        ),
                        policy=kexec_initramfs_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_INITRAMFS default DENY; ALLOW matching fsverity_digest.
                # Input: identical CPIO bytes with fs-verity disabled;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: no digest property -> default DENY, not a digest mismatch.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"fsverity_digest_{algorithm}_plain_denied"
                        ),
                        policy=kexec_initramfs_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.FSVERITY_PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_INITRAMFS default DENY; ALLOW a different fsverity_digest.
                # Input: signed fs-verity CPIO whose digest differs from the rule;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: digest mismatch -> default DENY despite the built-in signature.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"fsverity_digest_{algorithm}_mismatch_denied"
                        ),
                        policy=kexec_initramfs_fsverity_digest_policy(
                            algorithm=algorithm, matching=False
                        ),
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: a real kernel image with a verified built-in fs-verity signature.
                # Match: TRUE matches -> ALLOW; check staging before unloading.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"fsverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: a real kernel image with fs-verity but no built-in signature.
                # Match: TRUE does not match -> EACCES; nothing is staged.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"fsverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical kernel bytes without any fs-verity metadata.
                # Match: TRUE does not match -> EACCES.
                kexec.file_load_case(
                    id="kexec_image_kernel_read_kexec_file_load_fsverity_signature_true_plain_denied",
                    policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_KEXEC_IMAGE_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: a kernel image with a verified built-in fs-verity signature.
                # Match: FALSE does not match -> default ALLOW; unload after checking.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"fsverity_signature_false_{algorithm}_signed_ok"
                        ),
                        policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: an unsigned fs-verity kernel image; verity remains enabled.
                # Match: FALSE matches -> explicit DENY; nothing is staged.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"fsverity_signature_false_{algorithm}_unsigned_denied"
                        ),
                        policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: the real kernel image without any fs-verity metadata.
                # Match: absence counts as FALSE -> explicit DENY.
                kexec.file_load_case(
                    id="kexec_image_kernel_read_kexec_file_load_fsverity_signature_false_plain_denied",
                    policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_KEXEC_IMAGE_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW matching fsverity_digest.
                # Input: a signed fs-verity kernel image; its own digest matches.
                # Match: digest rule -> ALLOW; verify staging and unload.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"fsverity_digest_{algorithm}_signed_ok"
                        ),
                        policy=kexec_image_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.fsverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW matching fsverity_digest.
                # Input: an unsigned fs-verity kernel image whose digest matches.
                # Match: digest rule -> ALLOW without a built-in signature.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"fsverity_digest_{algorithm}_unsigned_ok"
                        ),
                        policy=kexec_image_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.fsverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW matching fsverity_digest.
                # Input: identical kernel bytes with fs-verity disabled.
                # Match: no digest property -> default DENY, not a hash mismatch.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"fsverity_digest_{algorithm}_plain_denied"
                        ),
                        policy=kexec_image_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.FSVERITY_PLAIN_KEXEC_IMAGE_TEST_BINARY,
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW a different fsverity_digest.
                # Input: a signed fs-verity kernel image whose digest differs from the rule.
                # Match: digest mismatch -> EACCES despite the verified signature.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"fsverity_digest_{algorithm}_mismatch_denied"
                        ),
                        policy=kexec_image_fsverity_digest_policy(
                            algorithm=algorithm, matching=False
                        ),
                        binary=layout.guest.fsverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: a buffer read from a signed SHA-256 fs-verity kernel image.
                # Match: KERNEL_LOAD has no inode; TRUE cannot match -> EACCES.
                kexec.buffer_load_case(
                    id="kexec_image_kernel_load_kexec_load_fsverity_signature_true_signed_denied",
                    policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.fsverity_kexec_image_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: a buffer read from an unsigned SHA-256 fs-verity kernel image.
                # Match: KERNEL_LOAD has no inode/signature context -> EACCES.
                kexec.buffer_load_case(
                    id="kexec_image_kernel_load_kexec_load_fsverity_signature_true_unsigned_denied",
                    policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.fsverity_kexec_image_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: userspace bytes from a signed SHA-256 fs-verity kernel image.
                # Match: no inode makes the signature property FALSE -> explicit DENY.
                kexec.buffer_load_case(
                    id="kexec_image_kernel_load_kexec_load_fsverity_signature_false_signed_denied",
                    policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.fsverity_kexec_image_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: userspace bytes from an unsigned SHA-256 fs-verity kernel image.
                # Match: no inode context makes the property FALSE -> EACCES.
                kexec.buffer_load_case(
                    id="kexec_image_kernel_load_kexec_load_fsverity_signature_false_unsigned_denied",
                    policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.fsverity_kexec_image_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW the source file's fsverity_digest.
                # Input: a buffer from a signed kernel image with a matching SHA-256 digest.
                # Match: KERNEL_LOAD has no inode/digest property -> EACCES.
                kexec.buffer_load_case(
                    id="kexec_image_kernel_load_kexec_load_fsverity_digest_sha256_signed_denied",
                    policy=kexec_image_fsverity_digest_policy(
                        algorithm="sha256", matching=True
                    ),
                    binary=layout.guest.fsverity_kexec_image_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: FIRMWARE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: .fw with fs-verity enabled and a verified built-in signature.
                # Match: the file signature is TRUE -> ALLOW.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"fsverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=FIRMWARE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_firmware_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content_match=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: .fw with fs-verity enabled but no built-in signature.
                # Match: TRUE does not match -> default DENY; search ends in ENOENT.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"fsverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=FIRMWARE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_firmware_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.ENOENT,
                        expected_content_match=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical .fw bytes without fs-verity or its signature.
                # Match: TRUE does not match -> default DENY.
                firmware.request_firmware_case(
                    id=(
                        "firmware_kernel_read_request_firmware_"
                        "fsverity_signature_true_plain_denied"
                    ),
                    policy=FIRMWARE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_FIRMWARE_TEST_BINARY,
                    expected_errno=errno.ENOENT,
                    expected_content_match=False,
                ),
                # Policy: FIRMWARE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: .fw with fs-verity and a verified built-in signature.
                # Match: FALSE does not match -> default ALLOW.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"fsverity_signature_false_{algorithm}_signed_ok"
                        ),
                        policy=FIRMWARE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_firmware_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content_match=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: .fw with fs-verity enabled but no built-in signature.
                # Match: FALSE matches -> explicit DENY; search ends in ENOENT.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"fsverity_signature_false_{algorithm}_unsigned_denied"
                        ),
                        policy=FIRMWARE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_firmware_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.ENOENT,
                        expected_content_match=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: .fw without any fs-verity metadata.
                # Match: absence counts as FALSE -> the explicit DENY rule matches.
                firmware.request_firmware_case(
                    id=(
                        "firmware_kernel_read_request_firmware_"
                        "fsverity_signature_false_plain_denied"
                    ),
                    policy=FIRMWARE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_FIRMWARE_TEST_BINARY,
                    expected_errno=errno.ENOENT,
                    expected_content_match=False,
                ),
                # Policy: FIRMWARE default DENY; ALLOW matching fsverity_digest.
                # Input: signed fs-verity .fw; its own measured digest matches.
                # Match: digest rule -> ALLOW; this rule does not require a signature.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"fsverity_digest_{algorithm}_signed_ok"
                        ),
                        policy=firmware_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.fsverity_firmware_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content_match=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default DENY; ALLOW matching fsverity_digest.
                # Input: unsigned fs-verity .fw; verity is enabled and its digest matches.
                # Match: digest rule -> ALLOW despite the missing built-in signature.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"fsverity_digest_{algorithm}_unsigned_ok"
                        ),
                        policy=firmware_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.fsverity_firmware_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=0,
                        expected_content_match=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default DENY; ALLOW matching fsverity_digest.
                # Input: the same .fw bytes without fs-verity metadata.
                # Match: no digest property -> default DENY, not a value mismatch.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"fsverity_digest_{algorithm}_plain_denied"
                        ),
                        policy=firmware_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.FSVERITY_PLAIN_FIRMWARE_TEST_BINARY,
                        expected_errno=errno.ENOENT,
                        expected_content_match=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default DENY; ALLOW a different fsverity_digest.
                # Input: signed fs-verity .fw; its digest differs from the policy value.
                # Match: digest mismatch -> default DENY despite the verified signature.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"fsverity_digest_{algorithm}_mismatch_denied"
                        ),
                        policy=firmware_fsverity_digest_policy(
                            algorithm=algorithm, matching=False
                        ),
                        binary=layout.guest.fsverity_firmware_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=errno.ENOENT,
                        expected_content_match=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    test_case
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                    for test_case in signature_cases(algorithm=algorithm)
                ),
                # Policy: KMODULE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: .ko.gz with fs-verity and a verified built-in signature.
                # Match: the compressed file's signature is TRUE -> ALLOW before decompression.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_signed_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        expected_returncode=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: .ko.gz with fs-verity enabled but no built-in signature.
                # Match: TRUE does not match -> default DENY.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: the same .ko.gz bytes without fs-verity or its signature.
                # Match: the signature property is FALSE -> default DENY.
                kmodule.insmod_case(
                    id=(
                        "kmodule_kernel_read_insmod_compressed_"
                        "fsverity_signature_true_plain_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_COMPRESSED_KMODULE_TEST_BINARY,
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                # Policy: KMODULE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: .ko.gz with a verified signature for its compressed-file digest.
                # Match: FALSE does not match -> default ALLOW.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_signature_false_{algorithm}_signed_ok"
                        ),
                        policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_signed_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        expected_returncode=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: .ko.gz with fs-verity enabled but no built-in signature.
                # Match: FALSE matches -> the explicit DENY rule applies.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_signature_false_{algorithm}_unsigned_denied"
                        ),
                        policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: .ko.gz with no fs-verity metadata, not just a missing signature.
                # Match: absence counts as FALSE -> the explicit DENY rule matches.
                kmodule.insmod_case(
                    id=(
                        "kmodule_kernel_read_insmod_compressed_"
                        "fsverity_signature_false_plain_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_COMPRESSED_KMODULE_TEST_BINARY,
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                # Policy: KMODULE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: a buffer read from a signed fs-verity .ko.
                # Match: KERNEL_LOAD has no inode; TRUE cannot match -> default DENY.
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "fsverity_signature_true_signed_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha256", compressed=False
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KMODULE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: a buffer read from an unsigned fs-verity .ko.
                # Match: KERNEL_LOAD has no inode; TRUE cannot match -> default DENY.
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "fsverity_signature_true_unsigned_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                        algorithm="sha256", compressed=False
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KMODULE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: .ko without fs-verity or a built-in fs-verity signature.
                # Match: TRUE does not match -> default DENY.
                kmodule.insmod_case(
                    id="kmodule_kernel_read_insmod_fsverity_signature_true_plain_denied",
                    policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY,
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                # Policy: KMODULE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: a buffer read from a signed fs-verity .ko.
                # Match: no inode makes the signature property FALSE -> explicit DENY.
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "fsverity_signature_false_signed_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha256", compressed=False
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KMODULE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: a buffer read from an unsigned fs-verity .ko.
                # Match: no inode makes the signature property FALSE -> explicit DENY.
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "fsverity_signature_false_unsigned_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                        algorithm="sha256", compressed=False
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KMODULE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: .ko without any fs-verity metadata.
                # Match: absence counts as FALSE -> the explicit DENY rule matches.
                kmodule.insmod_case(
                    id="kmodule_kernel_read_insmod_fsverity_signature_false_plain_denied",
                    policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY,
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                *(
                    test_case
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                    for test_case in digest_cases(algorithm=algorithm)
                ),
                # Policy: KMODULE default DENY; ALLOW matching fsverity_digest.
                # Input: signed fs-verity .ko.gz; its compressed-file digest matches.
                # Match: digest rule -> ALLOW; the policy does not require a signature.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_digest_{algorithm}_signed_ok"
                        ),
                        policy=kmodule_fsverity_digest_policy(
                            algorithm=algorithm, matching=True, compressed=True
                        ),
                        binary=layout.guest.fsverity_signed_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        expected_returncode=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default DENY; ALLOW matching fsverity_digest.
                # Input: unsigned fs-verity .ko.gz; its compressed-file digest matches.
                # Match: digest rule -> ALLOW without a built-in signature.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_digest_{algorithm}_unsigned_ok"
                        ),
                        policy=kmodule_fsverity_digest_policy(
                            algorithm=algorithm, matching=True, compressed=True
                        ),
                        binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        expected_returncode=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default DENY; ALLOW matching fsverity_digest.
                # Input: identical .ko.gz bytes, but fs-verity is not enabled.
                # Match: no fs-verity digest property -> default DENY, not a value mismatch.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_digest_{algorithm}_plain_denied"
                        ),
                        policy=kmodule_fsverity_digest_policy(
                            algorithm=algorithm, matching=True, compressed=True
                        ),
                        binary=layout.guest.FSVERITY_PLAIN_COMPRESSED_KMODULE_TEST_BINARY,
                        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default DENY; ALLOW a different fsverity_digest.
                # Input: signed fs-verity .ko.gz; its actual compressed-file digest differs.
                # Match: digest mismatch -> default DENY despite the verified signature.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_digest_{algorithm}_mismatch_denied"
                        ),
                        policy=kmodule_fsverity_digest_policy(
                            algorithm=algorithm, matching=False, compressed=True
                        ),
                        binary=layout.guest.fsverity_signed_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default DENY; ALLOW the source file's fsverity_digest.
                # Input: a buffer read from a signed .ko with the matching SHA-256 digest.
                # Match: KERNEL_LOAD has no inode/digest property -> default DENY.
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "fsverity_digest_sha256_signed_denied"
                    ),
                    policy=kmodule_fsverity_digest_policy(
                        algorithm="sha256", matching=True, compressed=False
                    ),
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha256", compressed=False
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: a static ELF with a verified built-in fs-verity digest signature.
                # Match: TRUE matches -> ALLOW; the program exits zero.
                *(
                    execute.execve_case(
                        id=(
                            "execute_bprm_check_execve_"
                            f"fsverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_returncode=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: the static ELF with fs-verity enabled but no built-in signature.
                # Match: TRUE does not match -> default DENY; the program never starts.
                *(
                    execute.execve_case(
                        id=(
                            "execute_bprm_check_execve_"
                            f"fsverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical executable ELF bytes with no fs-verity metadata.
                # Match: no built-in signature -> no TRUE match -> default DENY.
                execute.execve_case(
                    id="execute_bprm_check_execve_fsverity_signature_true_plain_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_returncode=None,
                ),
                # Policy: EXECUTE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: a static ELF with a verified built-in fs-verity digest signature.
                # Match: FALSE does not match -> default ALLOW; the program exits zero.
                *(
                    execute.execve_case(
                        id=(
                            "execute_bprm_check_execve_"
                            f"fsverity_signature_false_{algorithm}_signed_ok"
                        ),
                        policy=EXECUTE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_returncode=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: the static ELF with fs-verity enabled but no built-in signature.
                # Match: FALSE matches -> explicit DENY, not default ALLOW.
                *(
                    execute.execve_case(
                        id=(
                            "execute_bprm_check_execve_"
                            f"fsverity_signature_false_{algorithm}_unsigned_denied"
                        ),
                        policy=EXECUTE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default ALLOW; DENY fsverity_signature=FALSE.
                # Input: identical executable ELF bytes without fs-verity or a signature.
                # Match: absence counts as FALSE -> explicit DENY.
                execute.execve_case(
                    id="execute_bprm_check_execve_fsverity_signature_false_plain_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_returncode=None,
                ),
                # Policy: EXECUTE default DENY; ALLOW matching fsverity_digest.
                # Input: a signed fs-verity static ELF whose own digest matches the rule.
                # Match: the digest rule -> ALLOW; no built-in signature is required by it.
                *(
                    execute.execve_case(
                        id=(
                            "execute_bprm_check_execve_"
                            f"fsverity_digest_{algorithm}_signed_ok"
                        ),
                        policy=execute_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.fsverity_execute_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_returncode=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW matching fsverity_digest.
                # Input: an unsigned fs-verity static ELF whose digest matches the rule.
                # Match: the digest rule -> ALLOW despite the missing built-in signature.
                *(
                    execute.execve_case(
                        id=(
                            "execute_bprm_check_execve_"
                            f"fsverity_digest_{algorithm}_unsigned_ok"
                        ),
                        policy=execute_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.fsverity_execute_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=0,
                        expected_returncode=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW matching fsverity_digest.
                # Input: identical executable ELF bytes with fs-verity disabled.
                # Match: no digest property -> default DENY, not a digest mismatch.
                *(
                    execute.execve_case(
                        id=(
                            "execute_bprm_check_execve_"
                            f"fsverity_digest_{algorithm}_plain_denied"
                        ),
                        policy=execute_fsverity_digest_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW a different fsverity_digest.
                # Input: a signed fs-verity static ELF whose digest differs from the rule.
                # Match: digest mismatch -> default DENY despite the built-in signature.
                *(
                    execute.execve_case(
                        id=(
                            "execute_bprm_check_execve_"
                            f"fsverity_digest_{algorithm}_mismatch_denied"
                        ),
                        policy=execute_fsverity_digest_policy(
                            algorithm=algorithm, matching=False
                        ),
                        binary=layout.guest.fsverity_execute_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: ELF with a verified built-in signature over its fs-verity digest; private R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_r_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_READ,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical ELF bytes without the required file property; private R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_file_private_r_fsverity_signature_true_plain_ok",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    protection=mmap.PROT_READ,
                    shared=False,
                    expected_errno=0,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: ELF with a verified built-in signature over its fs-verity digest; private W mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_w_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_WRITE,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical ELF bytes without the required file property; private W mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_file_private_w_fsverity_signature_true_plain_ok",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    protection=mmap.PROT_WRITE,
                    shared=False,
                    expected_errno=0,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: ELF with a verified built-in signature over its fs-verity digest; private RW mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_rw_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_READ | mmap.PROT_WRITE,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical ELF bytes without the required file property; private RW mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_file_private_rw_fsverity_signature_true_plain_ok",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    protection=mmap.PROT_READ | mmap.PROT_WRITE,
                    shared=False,
                    expected_errno=0,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: ELF with a verified built-in signature over its fs-verity digest; private X mapping.
                # Match: the file-property rule matches -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_x_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical ELF bytes without the required file property; private X mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_file_private_x_fsverity_signature_true_plain_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    protection=mmap.PROT_EXEC,
                    shared=False,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: ELF with a verified built-in signature over its fs-verity digest; private RX mapping.
                # Match: the file-property rule matches -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_rx_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_READ | mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical ELF bytes without the required file property; private RX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_file_private_rx_fsverity_signature_true_plain_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    protection=mmap.PROT_READ | mmap.PROT_EXEC,
                    shared=False,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: ELF with a verified built-in signature over its fs-verity digest; private WX mapping.
                # Match: the file-property rule matches -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_wx_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical ELF bytes without the required file property; private WX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_file_private_wx_fsverity_signature_true_plain_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                    shared=False,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: ELF with a verified built-in signature over its fs-verity digest; shared R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_shared_r_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_READ,
                        shared=True,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical ELF bytes without the required file property; shared R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_file_shared_r_fsverity_signature_true_plain_ok",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    protection=mmap.PROT_READ,
                    shared=True,
                    expected_errno=0,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: ELF with a verified built-in signature over its fs-verity digest; shared X mapping.
                # Match: the file-property rule matches -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_shared_x_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_EXEC,
                        shared=True,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical ELF bytes without the required file property; shared X mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_file_shared_x_fsverity_signature_true_plain_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    protection=mmap.PROT_EXEC,
                    shared=True,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: ELF with a verified built-in signature over its fs-verity digest; shared RX mapping.
                # Match: the file-property rule matches -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_shared_rx_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_READ | mmap.PROT_EXEC,
                        shared=True,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: identical ELF bytes without the required file property; shared RX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_file_shared_rx_fsverity_signature_true_plain_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    protection=mmap.PROT_READ | mmap.PROT_EXEC,
                    shared=True,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: anonymous memory with no trusted file provenance; private R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_anon_private_r_fsverity_signature_true_anonymous_ok",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=None,
                    protection=mmap.PROT_READ,
                    shared=False,
                    expected_errno=0,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: anonymous memory with no trusted file provenance; private W mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_anon_private_w_fsverity_signature_true_anonymous_ok",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=None,
                    protection=mmap.PROT_WRITE,
                    shared=False,
                    expected_errno=0,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: anonymous memory with no trusted file provenance; private RW mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_anon_private_rw_fsverity_signature_true_anonymous_ok",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=None,
                    protection=mmap.PROT_READ | mmap.PROT_WRITE,
                    shared=False,
                    expected_errno=0,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: anonymous memory with no trusted file provenance; private X mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_anon_private_x_fsverity_signature_true_anonymous_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=None,
                    protection=mmap.PROT_EXEC,
                    shared=False,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: anonymous memory with no trusted file provenance; private RX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_anon_private_rx_fsverity_signature_true_anonymous_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=None,
                    protection=mmap.PROT_READ | mmap.PROT_EXEC,
                    shared=False,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: anonymous memory with no trusted file provenance; private WX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_anon_private_wx_fsverity_signature_true_anonymous_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=None,
                    protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                    shared=False,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: anonymous memory with no trusted file provenance; shared R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_anon_shared_r_fsverity_signature_true_anonymous_ok",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=None,
                    protection=mmap.PROT_READ,
                    shared=True,
                    expected_errno=0,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: anonymous memory with no trusted file provenance; shared X mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_anon_shared_x_fsverity_signature_true_anonymous_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=None,
                    protection=mmap.PROT_EXEC,
                    shared=True,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: anonymous memory with no trusted file provenance; shared RX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                execute_mmap.mmap_case(
                    id="execute_mmap_mmap_anon_shared_rx_fsverity_signature_true_anonymous_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=None,
                    protection=mmap.PROT_READ | mmap.PROT_EXEC,
                    shared=True,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: signed fs-verity ELF whose digest matches the rule; private R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_r_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_READ,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: identical ELF bytes without the required file property; private R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_r_fsverity_digest_plain_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        protection=mmap.PROT_READ,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: signed fs-verity ELF whose digest matches the rule; private W mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_w_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_WRITE,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: identical ELF bytes without the required file property; private W mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_w_fsverity_digest_plain_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        protection=mmap.PROT_WRITE,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: signed fs-verity ELF whose digest matches the rule; private RW mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_rw_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_READ | mmap.PROT_WRITE,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: identical ELF bytes without the required file property; private RW mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_rw_fsverity_digest_plain_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        protection=mmap.PROT_READ | mmap.PROT_WRITE,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: signed fs-verity ELF whose digest matches the rule; private X mapping.
                # Match: the file-property rule matches -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_x_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: identical ELF bytes without the required file property; private X mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_x_fsverity_digest_plain_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        protection=mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: signed fs-verity ELF whose digest matches the rule; private RX mapping.
                # Match: the file-property rule matches -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_rx_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_READ | mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: identical ELF bytes without the required file property; private RX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_rx_fsverity_digest_plain_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        protection=mmap.PROT_READ | mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: signed fs-verity ELF whose digest matches the rule; private WX mapping.
                # Match: the file-property rule matches -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_wx_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: identical ELF bytes without the required file property; private WX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_private_wx_fsverity_digest_plain_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: signed fs-verity ELF whose digest matches the rule; shared R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_shared_r_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_READ,
                        shared=True,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: identical ELF bytes without the required file property; shared R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_shared_r_fsverity_digest_plain_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        protection=mmap.PROT_READ,
                        shared=True,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: signed fs-verity ELF whose digest matches the rule; shared X mapping.
                # Match: the file-property rule matches -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_shared_x_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_EXEC,
                        shared=True,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: identical ELF bytes without the required file property; shared X mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_shared_x_fsverity_digest_plain_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        protection=mmap.PROT_EXEC,
                        shared=True,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: signed fs-verity ELF whose digest matches the rule; shared RX mapping.
                # Match: the file-property rule matches -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_shared_rx_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        protection=mmap.PROT_READ | mmap.PROT_EXEC,
                        shared=True,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: identical ELF bytes without the required file property; shared RX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_file_shared_rx_fsverity_digest_plain_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        protection=mmap.PROT_READ | mmap.PROT_EXEC,
                        shared=True,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: anonymous memory with no trusted file provenance; private R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_anon_private_r_fsverity_digest_anonymous_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=None,
                        protection=mmap.PROT_READ,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: anonymous memory with no trusted file provenance; private W mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_anon_private_w_fsverity_digest_anonymous_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=None,
                        protection=mmap.PROT_WRITE,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: anonymous memory with no trusted file provenance; private RW mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_anon_private_rw_fsverity_digest_anonymous_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=None,
                        protection=mmap.PROT_READ | mmap.PROT_WRITE,
                        shared=False,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: anonymous memory with no trusted file provenance; private X mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_anon_private_x_fsverity_digest_anonymous_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=None,
                        protection=mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: anonymous memory with no trusted file provenance; private RX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_anon_private_rx_fsverity_digest_anonymous_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=None,
                        protection=mmap.PROT_READ | mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: anonymous memory with no trusted file provenance; private WX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_anon_private_wx_fsverity_digest_anonymous_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=None,
                        protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                        shared=False,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: anonymous memory with no trusted file provenance; shared R mapping.
                # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_anon_shared_r_fsverity_digest_anonymous_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=None,
                        protection=mmap.PROT_READ,
                        shared=True,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: anonymous memory with no trusted file provenance; shared X mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_anon_shared_x_fsverity_digest_anonymous_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=None,
                        protection=mmap.PROT_EXEC,
                        shared=True,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: anonymous memory with no trusted file provenance; shared RX mapping.
                # Match: the required file property is absent -> no ALLOW match -> default DENY.
                *(
                    execute_mmap.mmap_case(
                        id=f"execute_mmap_mmap_anon_shared_rx_fsverity_digest_anonymous_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=None,
                        protection=mmap.PROT_READ | mmap.PROT_EXEC,
                        shared=True,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; W -> X.
                # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_w_x_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_WRITE,
                        protection=mmap.PROT_EXEC,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of identical ELF bytes without the required file property; W -> X.
                # Match: no matching file property -> default DENY; mprotect fails with EACCES.
                execute_mprotect.mprotect_case(
                    id="execute_mprotect_mprotect_private_w_x_fsverity_signature_true_plain_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    initial_protection=mmap.PROT_WRITE,
                    protection=mmap.PROT_EXEC,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; W -> RX.
                # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_w_rx_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_WRITE,
                        protection=mmap.PROT_READ | mmap.PROT_EXEC,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of identical ELF bytes without the required file property; W -> RX.
                # Match: no matching file property -> default DENY; mprotect fails with EACCES.
                execute_mprotect.mprotect_case(
                    id="execute_mprotect_mprotect_private_w_rx_fsverity_signature_true_plain_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    initial_protection=mmap.PROT_WRITE,
                    protection=mmap.PROT_READ | mmap.PROT_EXEC,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; R -> X.
                # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_r_x_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_READ,
                        protection=mmap.PROT_EXEC,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of identical ELF bytes without the required file property; R -> X.
                # Match: no matching file property -> default DENY; mprotect fails with EACCES.
                execute_mprotect.mprotect_case(
                    id="execute_mprotect_mprotect_private_r_x_fsverity_signature_true_plain_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    initial_protection=mmap.PROT_READ,
                    protection=mmap.PROT_EXEC,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; R -> WX.
                # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_r_wx_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_READ,
                        protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of identical ELF bytes without the required file property; R -> WX.
                # Match: no matching file property -> default DENY; mprotect fails with EACCES.
                execute_mprotect.mprotect_case(
                    id="execute_mprotect_mprotect_private_r_wx_fsverity_signature_true_plain_denied",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    initial_protection=mmap.PROT_READ,
                    protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                    expected_errno=errno.EACCES,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; W -> R.
                # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_w_r_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_WRITE,
                        protection=mmap.PROT_READ,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of identical ELF bytes without the required file property; W -> R.
                # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
                execute_mprotect.mprotect_case(
                    id="execute_mprotect_mprotect_private_w_r_fsverity_signature_true_plain_ok",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    initial_protection=mmap.PROT_WRITE,
                    protection=mmap.PROT_READ,
                    expected_errno=0,
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; R -> W.
                # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_r_w_fsverity_signature_true_trusted_ok_{algorithm}",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_READ,
                        protection=mmap.PROT_WRITE,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: private mapping of identical ELF bytes without the required file property; R -> W.
                # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
                execute_mprotect.mprotect_case(
                    id="execute_mprotect_mprotect_private_r_w_fsverity_signature_true_plain_ok",
                    policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                    initial_protection=mmap.PROT_READ,
                    protection=mmap.PROT_WRITE,
                    expected_errno=0,
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of signed fs-verity ELF whose digest matches the rule; W -> X.
                # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_w_x_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_WRITE,
                        protection=mmap.PROT_EXEC,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of identical ELF bytes without the required file property; W -> X.
                # Match: no matching file property -> default DENY; mprotect fails with EACCES.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_w_x_fsverity_digest_plain_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        initial_protection=mmap.PROT_WRITE,
                        protection=mmap.PROT_EXEC,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of signed fs-verity ELF whose digest matches the rule; W -> RX.
                # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_w_rx_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_WRITE,
                        protection=mmap.PROT_READ | mmap.PROT_EXEC,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of identical ELF bytes without the required file property; W -> RX.
                # Match: no matching file property -> default DENY; mprotect fails with EACCES.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_w_rx_fsverity_digest_plain_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        initial_protection=mmap.PROT_WRITE,
                        protection=mmap.PROT_READ | mmap.PROT_EXEC,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of signed fs-verity ELF whose digest matches the rule; R -> X.
                # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_r_x_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_READ,
                        protection=mmap.PROT_EXEC,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of identical ELF bytes without the required file property; R -> X.
                # Match: no matching file property -> default DENY; mprotect fails with EACCES.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_r_x_fsverity_digest_plain_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        initial_protection=mmap.PROT_READ,
                        protection=mmap.PROT_EXEC,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of signed fs-verity ELF whose digest matches the rule; R -> WX.
                # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_r_wx_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_READ,
                        protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of identical ELF bytes without the required file property; R -> WX.
                # Match: no matching file property -> default DENY; mprotect fails with EACCES.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_r_wx_fsverity_digest_plain_denied_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        initial_protection=mmap.PROT_READ,
                        protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                        expected_errno=errno.EACCES,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of signed fs-verity ELF whose digest matches the rule; W -> R.
                # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_w_r_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_WRITE,
                        protection=mmap.PROT_READ,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of identical ELF bytes without the required file property; W -> R.
                # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_w_r_fsverity_digest_plain_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        initial_protection=mmap.PROT_WRITE,
                        protection=mmap.PROT_READ,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of signed fs-verity ELF whose digest matches the rule; R -> W.
                # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_r_w_fsverity_digest_trusted_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                        initial_protection=mmap.PROT_READ,
                        protection=mmap.PROT_WRITE,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: private mapping of identical ELF bytes without the required file property; R -> W.
                # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
                *(
                    execute_mprotect.mprotect_case(
                        id=f"execute_mprotect_mprotect_private_r_w_fsverity_digest_plain_ok_{algorithm}",
                        policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                        binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                        initial_protection=mmap.PROT_READ,
                        protection=mmap.PROT_WRITE,
                        expected_errno=0,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                #         Only the interpreter has a separate exact fs-verity digest allowance.
                # Input: '+' script with a verified built-in fs-verity signature over the script digest; open the script path in the interpreter.
                # Match: script property matches -> check errno 0 -> interpret and print 1.
                *(
                    execute_interpreter.interpreter_case(
                        id=f'execute_bprm_creds_for_exec_interpreter_file_fsverity_signature_true_{algorithm}_signed_ok',
                        policy=INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        script=layout.guest.fsverity_script_test_binary(algorithm=algorithm),
                        from_stdin=False,
                        expected_errno=0,
                        expected_returncode=0,
                        expected_output='1\n',
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                #         Only the interpreter has a separate exact fs-verity digest allowance.
                # Input: identical '+' script without the required file property; open the script path in the interpreter.
                # Match: no script property match -> EACCES -> no interpretation or stdout.
                execute_interpreter.interpreter_case(
                    id='execute_bprm_creds_for_exec_interpreter_file_fsverity_signature_true_plain_denied',
                    policy=INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    script=layout.guest.FSVERITY_PLAIN_SCRIPT_TEST_BINARY,
                    from_stdin=False,
                    expected_errno=errno.EACCES,
                    expected_returncode=1,
                    expected_output='',
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                #         Only the interpreter has a separate exact fs-verity digest allowance.
                # Input: '+' script with a verified built-in fs-verity signature over the script digest; pass its original fd as stdin.
                # Match: script property matches -> check errno 0 -> interpret and print 1.
                *(
                    execute_interpreter.interpreter_case(
                        id=f'execute_bprm_creds_for_exec_interpreter_stdin_fsverity_signature_true_{algorithm}_signed_ok',
                        policy=INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        script=layout.guest.fsverity_script_test_binary(algorithm=algorithm),
                        from_stdin=True,
                        expected_errno=0,
                        expected_returncode=0,
                        expected_output='1\n',
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                #         Only the interpreter has a separate exact fs-verity digest allowance.
                # Input: identical '+' script without the required file property; pass its original fd as stdin.
                # Match: no script property match -> EACCES -> no interpretation or stdout.
                execute_interpreter.interpreter_case(
                    id='execute_bprm_creds_for_exec_interpreter_stdin_fsverity_signature_true_plain_denied',
                    policy=INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    script=layout.guest.FSVERITY_PLAIN_SCRIPT_TEST_BINARY,
                    from_stdin=True,
                    expected_errno=errno.EACCES,
                    expected_returncode=1,
                    expected_output='',
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                #         Only the interpreter has a separate exact fs-verity digest allowance.
                # Input: '+' script with signed fs-verity and a matching script digest; open the script path in the interpreter.
                # Match: script property matches -> check errno 0 -> interpret and print 1.
                *(
                    execute_interpreter.interpreter_case(
                        id=f'execute_bprm_creds_for_exec_interpreter_file_fsverity_digest_{algorithm}_signed_ok',
                        policy=interpreter_fsverity_digest_policy(algorithm=algorithm),
                        script=layout.guest.fsverity_script_test_binary(algorithm=algorithm),
                        from_stdin=False,
                        expected_errno=0,
                        expected_returncode=0,
                        expected_output='1\n',
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                #         Only the interpreter has a separate exact fs-verity digest allowance.
                # Input: identical '+' script without the required file property; open the script path in the interpreter.
                # Match: no script property match -> EACCES -> no interpretation or stdout.
                *(
                    execute_interpreter.interpreter_case(
                        id=f'execute_bprm_creds_for_exec_interpreter_file_fsverity_digest_{algorithm}_plain_denied',
                        policy=interpreter_fsverity_digest_policy(algorithm=algorithm),
                        script=layout.guest.FSVERITY_PLAIN_SCRIPT_TEST_BINARY,
                        from_stdin=False,
                        expected_errno=errno.EACCES,
                        expected_returncode=1,
                        expected_output='',
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                #         Only the interpreter has a separate exact fs-verity digest allowance.
                # Input: '+' script with signed fs-verity and a matching script digest; pass its original fd as stdin.
                # Match: script property matches -> check errno 0 -> interpret and print 1.
                *(
                    execute_interpreter.interpreter_case(
                        id=f'execute_bprm_creds_for_exec_interpreter_stdin_fsverity_digest_{algorithm}_signed_ok',
                        policy=interpreter_fsverity_digest_policy(algorithm=algorithm),
                        script=layout.guest.fsverity_script_test_binary(algorithm=algorithm),
                        from_stdin=True,
                        expected_errno=0,
                        expected_returncode=0,
                        expected_output='1\n',
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                #         Only the interpreter has a separate exact fs-verity digest allowance.
                # Input: identical '+' script without the required file property; pass its original fd as stdin.
                # Match: no script property match -> EACCES -> no interpretation or stdout.
                *(
                    execute_interpreter.interpreter_case(
                        id=f'execute_bprm_creds_for_exec_interpreter_stdin_fsverity_digest_{algorithm}_plain_denied',
                        policy=interpreter_fsverity_digest_policy(algorithm=algorithm),
                        script=layout.guest.FSVERITY_PLAIN_SCRIPT_TEST_BINARY,
                        from_stdin=True,
                        expected_errno=errno.EACCES,
                        expected_returncode=1,
                        expected_output='',
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                #         A separate exact fs-verity digest permits only the interpreter.
                # Input: execve the shebang script itself; a verified built-in fs-verity signature over the shebang script.
                # Match: script rule matches -> exec and interpretation succeed.
                *(
                    execute_interpreter.shebang_case(
                        id=f'execute_bprm_check_execve_shebang_fsverity_signature_true_{algorithm}_signed_ok',
                        policy=INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        script=layout.guest.fsverity_shebang_test_script(algorithm=algorithm),
                        expected_errno=0,
                        expected_returncode=0,
                        expected_output='1\n',
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                #         A separate exact fs-verity digest permits only the interpreter.
                # Input: execve the shebang script itself; no required file property.
                # Match: no script match -> exec returns EACCES before the interpreter can run.
                execute_interpreter.shebang_case(
                    id='execute_bprm_check_execve_shebang_fsverity_signature_true_plain_denied',
                    policy=INTERPRETER_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    script=layout.guest.FSVERITY_PLAIN_SHEBANG_TEST_SCRIPT,
                    expected_errno=errno.EACCES,
                    expected_returncode=None,
                    expected_output=None,
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                #         A separate exact fs-verity digest permits only the interpreter.
                # Input: execve the shebang script itself; signed fs-verity and a matching shebang-script digest.
                # Match: script rule matches -> exec and interpretation succeed.
                *(
                    execute_interpreter.shebang_case(
                        id=f'execute_bprm_check_execve_shebang_fsverity_digest_{algorithm}_signed_ok',
                        policy=shebang_fsverity_digest_policy(algorithm=algorithm),
                        script=layout.guest.fsverity_shebang_test_script(algorithm=algorithm),
                        expected_errno=0,
                        expected_returncode=0,
                        expected_output='1\n',
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                #         A separate exact fs-verity digest permits only the interpreter.
                # Input: execve the shebang script itself; no required file property.
                # Match: no script match -> exec returns EACCES before the interpreter can run.
                *(
                    execute_interpreter.shebang_case(
                        id=f'execute_bprm_check_execve_shebang_fsverity_digest_{algorithm}_plain_denied',
                        policy=shebang_fsverity_digest_policy(algorithm=algorithm),
                        script=layout.guest.FSVERITY_PLAIN_SHEBANG_TEST_SCRIPT,
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                        expected_output=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: unsealed ordinary memfd copied from a source with a verified built-in fs-verity digest signature.
                # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
                *(
                    execute_memfd.memfd_case(
                        id=f"execute_bprm_check_execve_memfd_unsealed_fsverity_signature_true_{algorithm}_denied",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                        huge=False,
                        sealed=False,
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: fully sealed ordinary memfd copied from a source with a verified built-in fs-verity digest signature.
                # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
                *(
                    execute_memfd.memfd_case(
                        id=f"execute_bprm_check_execve_memfd_sealed_fsverity_signature_true_{algorithm}_denied",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                        huge=False,
                        sealed=True,
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: unsealed 2 MiB hugetlb memfd copied from a source with a verified built-in fs-verity digest signature.
                # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
                *(
                    execute_memfd.memfd_case(
                        id=f"execute_bprm_check_execve_memfd_hugetlb_fsverity_signature_true_{algorithm}_denied",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                        huge=True,
                        sealed=False,
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
                # Input: fully sealed 2 MiB hugetlb memfd copied from a source with a verified built-in fs-verity digest signature.
                # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
                *(
                    execute_memfd.memfd_case(
                        id=f"execute_bprm_check_execve_memfd_hugetlb_sealed_fsverity_signature_true_{algorithm}_denied",
                        policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                        huge=True,
                        sealed=True,
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: unsealed ordinary memfd copied from a signed fs-verity source with a matching ELF digest.
                # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
                *(
                    execute_memfd.memfd_case(
                        id=f"execute_bprm_check_execve_memfd_unsealed_fsverity_digest_{algorithm}_denied",
                        policy=memfd_source_fsverity_digest_policy(algorithm=algorithm),
                        binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                        huge=False,
                        sealed=False,
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: fully sealed ordinary memfd copied from a signed fs-verity source with a matching ELF digest.
                # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
                *(
                    execute_memfd.memfd_case(
                        id=f"execute_bprm_check_execve_memfd_sealed_fsverity_digest_{algorithm}_denied",
                        policy=memfd_source_fsverity_digest_policy(algorithm=algorithm),
                        binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                        huge=False,
                        sealed=True,
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: unsealed 2 MiB hugetlb memfd copied from a signed fs-verity source with a matching ELF digest.
                # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
                *(
                    execute_memfd.memfd_case(
                        id=f"execute_bprm_check_execve_memfd_hugetlb_fsverity_digest_{algorithm}_denied",
                        policy=memfd_source_fsverity_digest_policy(algorithm=algorithm),
                        binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                        huge=True,
                        sealed=False,
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
                # Input: fully sealed 2 MiB hugetlb memfd copied from a signed fs-verity source with a matching ELF digest.
                # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
                *(
                    execute_memfd.memfd_case(
                        id=f"execute_bprm_check_execve_memfd_hugetlb_sealed_fsverity_digest_{algorithm}_denied",
                        policy=memfd_source_fsverity_digest_policy(algorithm=algorithm),
                        binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                        huge=True,
                        sealed=True,
                        expected_errno=errno.EACCES,
                        expected_returncode=None,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; fsverity_signature=TRUE permits the library; signed root permits the runtime.
                # Input: library on the unsigned payload with a verified built-in fs-verity digest signature.
                # Match: library ALLOW -> constructor prints preload; the client exits zero.
                *(
                    execute_preload.preload_case(
                        id=f'execute_mmap_ld_preload_fsverity_signature_true_{algorithm}_signed_ok',
                        policy=PRELOAD_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        library=layout.guest.fsverity_preload_library(algorithm=algorithm),
                        expected_returncode=0,
                        expected_preloaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; fsverity_signature=TRUE permits the library; signed root permits the runtime.
                # Input: identical library bytes without either permitted property.
                # Match: library default DENY -> no constructor output; loader refuses its segment mapping.
                execute_preload.preload_case(
                    id='execute_mmap_ld_preload_fsverity_signature_true_plain_denied',
                    policy=PRELOAD_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    library=layout.guest.FSVERITY_PLAIN_PRELOAD_LIBRARY,
                    expected_returncode=0,
                    expected_preloaded=False,
                ),
                # Policy: EXECUTE default DENY; matching fsverity_digest permits the library; signed root permits the runtime.
                # Input: library on the unsigned payload with signed fs-verity and a matching digest.
                # Match: library ALLOW -> constructor prints preload; the client exits zero.
                *(
                    execute_preload.preload_case(
                        id=f'execute_mmap_ld_preload_fsverity_digest_{algorithm}_signed_ok',
                        policy=preload_fsverity_digest_policy(algorithm=algorithm),
                        library=layout.guest.fsverity_preload_library(algorithm=algorithm),
                        expected_returncode=0,
                        expected_preloaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Policy: EXECUTE default DENY; matching fsverity_digest permits the library; signed root permits the runtime.
                # Input: identical library bytes without either permitted property.
                # Match: library default DENY -> no constructor output; loader refuses its segment mapping.
                *(
                    execute_preload.preload_case(
                        id=f'execute_mmap_ld_preload_fsverity_digest_{algorithm}_plain_denied',
                        policy=preload_fsverity_digest_policy(algorithm=algorithm),
                        library=layout.guest.FSVERITY_PLAIN_PRELOAD_LIBRARY,
                        expected_returncode=0,
                        expected_preloaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
            ),
            # Prepare fixtures with enforcement off; each case then activates
            # its selected policy and enables enforcement for its operation.
            setup=(
                partial(ipe.set_enforcement, enabled=False),
                partial(
                    files.prepare_fsverity_test_binary,
                    source=layout.guest.INTERPRETER_TEST_BINARY,
                    target=layout.guest.FSVERITY_INTERPRETER_TEST_BINARY,
                    algorithm=layout.INTERPRETER_HASH,
                ),
                partial(run, "insmod", layout.guest.POLICY_OP_TEST_MODULE),
                partial(run, "insmod", layout.guest.X509_TEST_MODULE),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=(
                            layout.guest.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY
                            if compressed
                            else layout.guest.KMODULE_TEST_BINARY
                        ),
                        target=layout.guest.fsverity_signed_kmodule_test_binary(
                            algorithm=algorithm, compressed=compressed
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_signature(
                            algorithm=algorithm, compressed=compressed
                        ),
                    )
                    for compressed in (False, True)
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                # Unsigned still runs fsverity enable; signature=None omits --signature.
                # The plain copies below skip fsverity enable entirely.
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=(
                            layout.guest.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY
                            if compressed
                            else layout.guest.KMODULE_TEST_BINARY
                        ),
                        target=layout.guest.fsverity_unsigned_kmodule_test_binary(
                            algorithm=algorithm, compressed=compressed
                        ),
                        algorithm=algorithm,
                    )
                    for compressed in (False, True)
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_COMPRESSED_KMODULE_TEST_BINARY,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.KMODULE_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.FIRMWARE_TEST_BINARY,
                        target=layout.guest.fsverity_firmware_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_firmware_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.FIRMWARE_TEST_BINARY,
                        target=layout.guest.fsverity_firmware_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.FIRMWARE_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_FIRMWARE_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        target=layout.guest.fsverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_kexec_image_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        target=layout.guest.fsverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_KEXEC_IMAGE_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.KEXEC_INITRAMFS_TEST_BINARY,
                        target=layout.guest.fsverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_kexec_initramfs_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.KEXEC_INITRAMFS_TEST_BINARY,
                        target=layout.guest.fsverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.KEXEC_INITRAMFS_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.POLICY_OP_TEST_BINARY,
                        target=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_policy_op_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.POLICY_OP_TEST_BINARY,
                        target=layout.guest.fsverity_policy_op_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.POLICY_OP_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_POLICY_OP_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.X509_TEST_BINARY,
                        target=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_x509_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.X509_TEST_BINARY,
                        target=layout.guest.fsverity_x509_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.X509_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_X509_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.EXECUTE_TEST_BINARY,
                        target=layout.guest.fsverity_execute_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_execute_signature(
                            algorithm=algorithm
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.EXECUTE_TEST_BINARY,
                        target=layout.guest.fsverity_execute_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.EXECUTE_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.SCRIPT_TEST_BINARY,
                        target=layout.guest.fsverity_script_test_binary(algorithm=algorithm),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_script_signature(algorithm=algorithm),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.SCRIPT_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_SCRIPT_TEST_BINARY,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.SHEBANG_TEST_SCRIPT,
                        target=layout.guest.fsverity_shebang_test_script(algorithm=algorithm),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_shebang_signature(algorithm=algorithm),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.SHEBANG_TEST_SCRIPT,
                    target=layout.guest.FSVERITY_PLAIN_SHEBANG_TEST_SCRIPT,
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.MEMFD_TEST_BINARY,
                        target=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_memfd_signature(algorithm=algorithm),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_test_binary,
                        source=layout.guest.PRELOAD_LIBRARY,
                        target=layout.guest.fsverity_preload_library(algorithm=algorithm),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_preload_signature(algorithm=algorithm),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.PRELOAD_LIBRARY,
                    target=layout.guest.FSVERITY_PLAIN_PRELOAD_LIBRARY,
                ),
            ),
            extra_scopes=(
                hugepages_scope,
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_EXECUTE_DIR,
                ),
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_MODULES_DIR,
                ),
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_FIRMWARE_DIR,
                ),
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_KEXEC_IMAGES_DIR,
                ),
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_POLICY_OP_DIR,
                ),
                partial(
                    modules.loaded_scope,
                    prefix=layout.guest.POLICY_OP_TEST_MODULE.stem,
                ),
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_X509_DIR,
                ),
                partial(
                    modules.loaded_scope,
                    prefix=layout.guest.X509_TEST_MODULE.stem,
                ),
            ),
        ),
    )
