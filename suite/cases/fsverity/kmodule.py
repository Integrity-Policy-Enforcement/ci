# SPDX-License-Identifier: GPL-2.0-only
"""Kernel module file and buffer cases using fs-verity properties."""

import errno

import hashes
import layout
from assets import (
    KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    kmodule_fsverity_digest_policy,
)
from model import Case
from operations import kmodule


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


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
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
    )
