# SPDX-License-Identifier: GPL-2.0-only
"""POLICY file-read cases using dm-verity properties."""

import errno

import hashes
import layout
from assets import (
    POLICY_OP_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    POLICY_OP_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    policy_op_dmverity_roothash_policy,
)
from model import Case

from .. import policy_op


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: POLICY default DENY; ALLOW dmverity_signature=TRUE.
        # Input: policy text on dm-verity with a trusted root-hash signature;
        #        the test module reads the original fd without applying the text.
        # Match: the mapping's signature is TRUE -> ALLOW; retain the exact bytes.
        *(
            policy_op.read_case(
                id=(
                    "policy_op_kernel_read_ipe_test_policy_op_"
                    f"dmverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=POLICY_OP_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_policy_op_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_content=layout.guest.dmverity_policy_op_test_binary(
                    algorithm=algorithm, signed=True
                ),
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: POLICY default DENY; ALLOW dmverity_signature=TRUE.
        # Input: the same policy text on dm-verity without a root-hash signature;
        #        the test module reads the original fd without applying the text.
        # Match: TRUE does not match -> default DENY; no old contents may remain.
        *(
            policy_op.read_case(
                id=(
                    "policy_op_kernel_read_ipe_test_policy_op_"
                    f"dmverity_signature_true_{algorithm}_unsigned_denied"
                ),
                policy=POLICY_OP_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_policy_op_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_content=b"",
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: POLICY default DENY; ALLOW dmverity_signature=TRUE.
        # Input: the same policy text on plain tmpfs, without dm-verity.
        # Match: no mapping signature -> no TRUE match -> default DENY.
        policy_op.read_case(
            id="policy_op_kernel_read_ipe_test_policy_op_dmverity_signature_true_plain_denied",
            policy=POLICY_OP_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_POLICY_OP_TEST_BINARY,
            expected_errno=errno.EACCES,
            expected_content=b"",
        ),
        # Policy: POLICY default ALLOW; DENY dmverity_signature=FALSE.
        # Input: policy text on dm-verity with a verified root-hash signature.
        # Match: FALSE does not match -> default ALLOW; retain the exact bytes.
        *(
            policy_op.read_case(
                id=(
                    "policy_op_kernel_read_ipe_test_policy_op_"
                    f"dmverity_signature_false_{algorithm}_signed_ok"
                ),
                policy=POLICY_OP_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.dmverity_policy_op_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_content=layout.guest.dmverity_policy_op_test_binary(
                    algorithm=algorithm, signed=True
                ),
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: POLICY default ALLOW; DENY dmverity_signature=FALSE.
        # Input: policy text on dm-verity without a root-hash signature.
        # Match: FALSE matches -> explicit DENY, not the default ALLOW.
        *(
            policy_op.read_case(
                id=(
                    "policy_op_kernel_read_ipe_test_policy_op_"
                    f"dmverity_signature_false_{algorithm}_unsigned_denied"
                ),
                policy=POLICY_OP_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.dmverity_policy_op_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_content=b"",
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: POLICY default ALLOW; DENY dmverity_signature=FALSE.
        # Input: identical policy text on plain tmpfs with no dm-verity metadata.
        # Match: absence counts as FALSE -> explicit DENY.
        policy_op.read_case(
            id="policy_op_kernel_read_ipe_test_policy_op_dmverity_signature_false_plain_denied",
            policy=POLICY_OP_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=layout.guest.PLAIN_POLICY_OP_TEST_BINARY,
            expected_errno=errno.EACCES,
            expected_content=b"",
        ),
        # Policy: POLICY default DENY; ALLOW matching dmverity_roothash.
        # Input: policy text on signed dm-verity whose root hash matches the rule.
        # Match: root-hash rule -> ALLOW; this rule does not require a signature.
        *(
            policy_op.read_case(
                id=(
                    "policy_op_kernel_read_ipe_test_policy_op_"
                    f"dmverity_roothash_{algorithm}_signed_ok"
                ),
                policy=policy_op_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.dmverity_policy_op_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_content=layout.guest.dmverity_policy_op_test_binary(
                    algorithm=algorithm, signed=True
                ),
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: POLICY default DENY; ALLOW matching dmverity_roothash.
        # Input: policy text on dm-verity with a matching but unsigned root hash.
        # Match: root-hash rule -> ALLOW without a root-hash signature.
        *(
            policy_op.read_case(
                id=(
                    "policy_op_kernel_read_ipe_test_policy_op_"
                    f"dmverity_roothash_{algorithm}_unsigned_ok"
                ),
                policy=policy_op_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.dmverity_policy_op_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=0,
                expected_content=layout.guest.dmverity_policy_op_test_binary(
                    algorithm=algorithm, signed=False
                ),
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: POLICY default DENY; ALLOW matching dmverity_roothash.
        # Input: identical policy text on plain tmpfs, with no device root hash.
        # Match: no property -> no root-hash match -> default DENY.
        *(
            policy_op.read_case(
                id=(
                    "policy_op_kernel_read_ipe_test_policy_op_"
                    f"dmverity_roothash_{algorithm}_plain_denied"
                ),
                policy=policy_op_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.PLAIN_POLICY_OP_TEST_BINARY,
                expected_errno=errno.EACCES,
                expected_content=b"",
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: POLICY default DENY; ALLOW a different dmverity_roothash.
        # Input: policy text on signed dm-verity whose root hash differs.
        # Match: root-hash mismatch -> default DENY despite the valid signature.
        *(
            policy_op.read_case(
                id=(
                    "policy_op_kernel_read_ipe_test_policy_op_"
                    f"dmverity_roothash_{algorithm}_mismatch_denied"
                ),
                policy=policy_op_dmverity_roothash_policy(
                    algorithm=algorithm, matching=False
                ),
                binary=layout.guest.dmverity_policy_op_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_content=b"",
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
