# SPDX-License-Identifier: GPL-2.0-only
"""Firmware file-read cases using dm-verity properties."""

import errno

import hashes
import layout
from assets import (
    FIRMWARE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    FIRMWARE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    firmware_dmverity_roothash_policy,
)
from model import Case

from .. import firmware


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: FIRMWARE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: .fw on a mapping opened with a trusted root-hash signature.
        # Match: the mapping signature is TRUE -> the ALLOW rule matches.
        *(
            firmware.request_firmware_case(
                id=(
                    "firmware_kernel_read_request_firmware_"
                    f"dmverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=FIRMWARE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_firmware_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_content_match=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: FIRMWARE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: .fw on dm-verity without a root-hash signature.
        # Match: TRUE does not match -> default DENY; search ends in ENOENT.
        *(
            firmware.request_firmware_case(
                id=(
                    "firmware_kernel_read_request_firmware_"
                    f"dmverity_signature_true_{algorithm}_unsigned_denied"
                ),
                policy=FIRMWARE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_firmware_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.ENOENT,
                expected_content_match=False,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: FIRMWARE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: the same .fw bytes on plain tmpfs, without dm-verity.
        # Match: no mapping signature -> default DENY; search ends in ENOENT.
        firmware.request_firmware_case(
            id=(
                "firmware_kernel_read_request_firmware_"
                "dmverity_signature_true_plain_denied"
            ),
            policy=FIRMWARE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_FIRMWARE_TEST_BINARY,
            expected_errno=errno.ENOENT,
            expected_content_match=False,
        ),
        # Policy: FIRMWARE default ALLOW; DENY dmverity_signature=FALSE.
        # Input: .fw on dm-verity with a verified root-hash signature.
        # Match: FALSE does not match -> default ALLOW.
        *(
            firmware.request_firmware_case(
                id=(
                    "firmware_kernel_read_request_firmware_"
                    f"dmverity_signature_false_{algorithm}_signed_ok"
                ),
                policy=FIRMWARE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.dmverity_firmware_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_content_match=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: FIRMWARE default ALLOW; DENY dmverity_signature=FALSE.
        # Input: .fw on dm-verity without a root-hash signature.
        # Match: FALSE matches -> explicit DENY; search ends in ENOENT.
        *(
            firmware.request_firmware_case(
                id=(
                    "firmware_kernel_read_request_firmware_"
                    f"dmverity_signature_false_{algorithm}_unsigned_denied"
                ),
                policy=FIRMWARE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.dmverity_firmware_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.ENOENT,
                expected_content_match=False,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: FIRMWARE default ALLOW; DENY dmverity_signature=FALSE.
        # Input: .fw on plain tmpfs, with no dm-verity metadata.
        # Match: absence counts as FALSE -> explicit DENY, not default denial.
        firmware.request_firmware_case(
            id=(
                "firmware_kernel_read_request_firmware_"
                "dmverity_signature_false_plain_denied"
            ),
            policy=FIRMWARE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=layout.guest.PLAIN_FIRMWARE_TEST_BINARY,
            expected_errno=errno.ENOENT,
            expected_content_match=False,
        ),
        # Policy: FIRMWARE default DENY; ALLOW matching dmverity_roothash.
        # Input: .fw on signed dm-verity; the mapping's root hash matches.
        # Match: root-hash rule -> ALLOW; this rule does not require a signature.
        *(
            firmware.request_firmware_case(
                id=(
                    "firmware_kernel_read_request_firmware_"
                    f"dmverity_roothash_{algorithm}_signed_ok"
                ),
                policy=firmware_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.dmverity_firmware_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_content_match=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: FIRMWARE default DENY; ALLOW matching dmverity_roothash.
        # Input: .fw on unsigned dm-verity; the root hash still matches.
        # Match: root-hash rule -> ALLOW without a root-hash signature.
        *(
            firmware.request_firmware_case(
                id=(
                    "firmware_kernel_read_request_firmware_"
                    f"dmverity_roothash_{algorithm}_unsigned_ok"
                ),
                policy=firmware_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.dmverity_firmware_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=0,
                expected_content_match=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: FIRMWARE default DENY; ALLOW matching dmverity_roothash.
        # Input: .fw on plain tmpfs; no dm-verity root-hash property exists.
        # Match: no ALLOW match -> default DENY; search ends in ENOENT.
        *(
            firmware.request_firmware_case(
                id=(
                    "firmware_kernel_read_request_firmware_"
                    f"dmverity_roothash_{algorithm}_plain_denied"
                ),
                policy=firmware_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.PLAIN_FIRMWARE_TEST_BINARY,
                expected_errno=errno.ENOENT,
                expected_content_match=False,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: FIRMWARE default DENY; ALLOW a different dmverity_roothash.
        # Input: .fw on signed dm-verity; its root hash differs from the rule.
        # Match: hash mismatch -> default DENY despite the valid signature.
        *(
            firmware.request_firmware_case(
                id=(
                    "firmware_kernel_read_request_firmware_"
                    f"dmverity_roothash_{algorithm}_mismatch_denied"
                ),
                policy=firmware_dmverity_roothash_policy(
                    algorithm=algorithm, matching=False
                ),
                binary=layout.guest.dmverity_firmware_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.ENOENT,
                expected_content_match=False,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
