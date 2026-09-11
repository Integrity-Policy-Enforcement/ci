# SPDX-License-Identifier: GPL-2.0-only
"""POLICY file-read cases using fs-verity properties."""

import errno

import hashes
import layout
from assets import (
    POLICY_OP_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    POLICY_OP_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    policy_op_fsverity_digest_policy,
)
from model import Case
from operations import policy_op


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
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
    )
