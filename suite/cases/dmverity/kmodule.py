# SPDX-License-Identifier: GPL-2.0-only
"""Kernel module file and buffer cases using dm-verity properties."""

import errno

import hashes
import layout
from assets import (
    KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    kmodule_dmverity_roothash_policy,
)
from model import Case
from operations import kmodule


def roothash_cases(*, algorithm: str) -> tuple[Case, ...]:
    """The root-hash cases for one algorithm."""
    matching_root_hash_policy = kmodule_dmverity_roothash_policy(
        algorithm=algorithm, matching=True
    )
    mismatching_root_hash_policy = kmodule_dmverity_roothash_policy(
        algorithm=algorithm, matching=False
    )
    signed_kmodule_binary = layout.guest.dmverity_kmodule_test_binary(
        algorithm=algorithm, signed=True
    )
    unsigned_kmodule_binary = layout.guest.dmverity_kmodule_test_binary(
        algorithm=algorithm, signed=False
    )
    plain_kmodule_binary = layout.guest.PLAIN_KMODULE_TEST_BINARY
    return (
        # Policy: KMODULE default DENY; ALLOW matching dmverity_roothash.
        # Input: .ko on signed dm-verity; the mapping's root hash matches.
        # Match: root-hash rule -> ALLOW; this rule does not require a signature.
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_dmverity_roothash_{algorithm}_signed_ok",
            policy=matching_root_hash_policy,
            binary=signed_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        # Policy: KMODULE default DENY; ALLOW matching dmverity_roothash.
        # Input: .ko on dm-verity without a root-hash signature; the hash matches.
        # Match: root-hash rule -> ALLOW despite the missing signature.
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_dmverity_roothash_{algorithm}_unsigned_ok",
            policy=matching_root_hash_policy,
            binary=unsigned_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        # Policy: KMODULE default DENY; ALLOW matching dmverity_roothash.
        # Input: the same .ko on plain tmpfs, with no dm-verity hash or signature.
        # Match: no root-hash property -> no ALLOW match -> default DENY.
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_dmverity_roothash_{algorithm}_plain_denied",
            policy=matching_root_hash_policy,
            binary=plain_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
        # Policy: KMODULE default DENY; ALLOW a different dmverity_roothash.
        # Input: .ko on signed dm-verity; its root hash differs from the policy.
        # Match: hash mismatch -> default DENY, even with a valid signature.
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_dmverity_roothash_{algorithm}_mismatch_denied",
            policy=mismatching_root_hash_policy,
            binary=signed_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
    )


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: .ko on dm-verity with a verified root-hash signature.
        # Match: the mapping signature is TRUE -> ALLOW.
        *(
            kmodule.insmod_case(
                id=(
                    "kmodule_kernel_read_insmod_dmverity_signature_true_"
                    f"{algorithm}_signed_ok"
                ),
                policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_kmodule_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_returncode=0,
                expected_loaded=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: .ko.gz on signed dm-verity, passed for kernel decompression.
        # Match: the original file's mapping signature is TRUE -> ALLOW.
        # A userspace-decompressed buffer has no mapping and cannot pass.
        *(
            kmodule.insmod_case(
                id=(
                    "kmodule_kernel_read_insmod_compressed_"
                    f"dmverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_compressed_kmodule_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_returncode=0,
                expected_loaded=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: .ko.gz on dm-verity without a root-hash signature.
        # Match: TRUE does not match -> default DENY; compression adds no trust.
        *(
            kmodule.insmod_case(
                id=(
                    "kmodule_kernel_read_insmod_compressed_"
                    f"dmverity_signature_true_{algorithm}_unsigned_denied"
                ),
                policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_compressed_kmodule_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                expected_loaded=False,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: a buffer read from the .ko on signed SHA-256 dm-verity.
        # Match: KERNEL_LOAD has no file/device context -> default DENY.
        kmodule.init_module_case(
            id=(
                "kmodule_kernel_load_init_module_"
                "dmverity_signature_true_signed_denied"
            ),
            policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.dmverity_kmodule_test_binary(
                algorithm="sha256", signed=True
            ),
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: .ko on dm-verity without a root-hash signature.
        # Match: the signature is FALSE -> no ALLOW match -> default DENY.
        *(
            kmodule.insmod_case(
                id=(
                    "kmodule_kernel_read_insmod_dmverity_signature_true_"
                    f"{algorithm}_unsigned_denied"
                ),
                policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_kmodule_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                expected_loaded=False,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: a buffer read from the .ko on unsigned SHA-256 dm-verity.
        # Match: KERNEL_LOAD has no file/device context -> default DENY.
        kmodule.init_module_case(
            id=(
                "kmodule_kernel_load_init_module_"
                "dmverity_signature_true_unsigned_denied"
            ),
            policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.dmverity_kmodule_test_binary(
                algorithm="sha256", signed=False
            ),
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: .ko on plain tmpfs; neither dm-verity nor its signature exists.
        # Match: TRUE does not match -> default DENY.
        kmodule.insmod_case(
            id="kmodule_kernel_read_insmod_dmverity_signature_true_plain_denied",
            policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_KMODULE_TEST_BINARY,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
        # Policy: KMODULE default ALLOW; DENY dmverity_signature=FALSE.
        # Input: .ko on dm-verity with a verified root-hash signature.
        # Match: FALSE does not match -> default ALLOW, not the DENY rule.
        *(
            kmodule.insmod_case(
                id=(
                    "kmodule_kernel_read_insmod_dmverity_signature_false_"
                    f"{algorithm}_signed_ok"
                ),
                policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.dmverity_kmodule_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_returncode=0,
                expected_loaded=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: KMODULE default ALLOW; DENY dmverity_signature=FALSE.
        # Input: a buffer read from the .ko on signed SHA-256 dm-verity.
        # Match: no file/device context makes the property FALSE -> DENY.
        kmodule.init_module_case(
            id=(
                "kmodule_kernel_load_init_module_"
                "dmverity_signature_false_signed_denied"
            ),
            policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=layout.guest.dmverity_kmodule_test_binary(
                algorithm="sha256", signed=True
            ),
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KMODULE default ALLOW; DENY dmverity_signature=FALSE.
        # Input: .ko on dm-verity without a root-hash signature.
        # Match: FALSE matches -> the explicit DENY rule applies.
        *(
            kmodule.insmod_case(
                id=(
                    "kmodule_kernel_read_insmod_dmverity_signature_false_"
                    f"{algorithm}_unsigned_denied"
                ),
                policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.dmverity_kmodule_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                expected_loaded=False,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: KMODULE default ALLOW; DENY dmverity_signature=FALSE.
        # Input: a buffer read from the .ko on unsigned SHA-256 dm-verity.
        # Match: no file/device context makes the property FALSE -> DENY.
        kmodule.init_module_case(
            id=(
                "kmodule_kernel_load_init_module_"
                "dmverity_signature_false_unsigned_denied"
            ),
            policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=layout.guest.dmverity_kmodule_test_binary(
                algorithm="sha256", signed=False
            ),
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KMODULE default ALLOW; DENY dmverity_signature=FALSE.
        # Input: .ko on plain tmpfs, without any dm-verity metadata.
        # Match: absence counts as FALSE -> the explicit DENY rule matches.
        kmodule.insmod_case(
            id="kmodule_kernel_read_insmod_dmverity_signature_false_plain_denied",
            policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=layout.guest.PLAIN_KMODULE_TEST_BINARY,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
        *(
            test_case
            for algorithm in hashes.DMVERITY_ALGORITHMS
            for test_case in roothash_cases(algorithm=algorithm)
        ),
        # Policy: KMODULE default DENY; ALLOW the source mapping's root hash.
        # Input: a buffer read from the .ko on matching, signed SHA-256 dm-verity.
        # Match: KERNEL_LOAD has no root-hash context -> default DENY.
        kmodule.init_module_case(
            id=(
                "kmodule_kernel_load_init_module_"
                "dmverity_roothash_sha256_signed_denied"
            ),
            policy=kmodule_dmverity_roothash_policy(
                algorithm="sha256", matching=True
            ),
            binary=layout.guest.dmverity_kmodule_test_binary(
                algorithm="sha256", signed=True
            ),
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
    )
