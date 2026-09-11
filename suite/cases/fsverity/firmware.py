# SPDX-License-Identifier: GPL-2.0-only
"""Firmware file-read cases using fs-verity properties."""

import errno

import hashes
import layout
from assets import (
    FIRMWARE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    FIRMWARE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    firmware_fsverity_digest_policy,
)
from model import Case
from operations import firmware


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
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
    )
