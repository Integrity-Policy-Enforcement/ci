# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import files
import hashes
import ipe
import layout
from assets import (
    FIRMWARE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    FIRMWARE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    firmware_fsverity_digest_policy,
    kmodule_fsverity_digest_policy,
)
from model import Batch, Case

from . import firmware, kexec, kmodule

# Here "signed" means fs-verity's built-in signature, not module signing.
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
            ),
            # Prepare fixtures with enforcement off; each case then activates
            # its selected policy and enables enforcement for the module load.
            setup=(
                partial(ipe.set_enforcement, enabled=False),
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
            ),
            extra_scopes=(
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
            ),
        ),
    )
