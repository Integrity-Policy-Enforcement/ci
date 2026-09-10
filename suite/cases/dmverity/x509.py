# SPDX-License-Identifier: GPL-2.0-only
"""X509_CERT file-read cases using dm-verity properties."""

import errno

import hashes
import layout
from assets import (
    X509_CERT_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    X509_CERT_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    x509_cert_dmverity_roothash_policy,
)
from model import Case

from .. import x509


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: X509_CERT default DENY; ALLOW dmverity_signature=TRUE.
        # Input: DER file on dm-verity with a trusted root-hash signature.
        # Match: the mapping's TRUE signature -> ALLOW; retain bytes, import no key.
        *(
            x509.read_case(
                id=(
                    "x509_cert_kernel_read_ipe_test_x509_"
                    f"dmverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=X509_CERT_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_x509_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_content=layout.guest.dmverity_x509_test_binary(
                    algorithm=algorithm, signed=True
                ),
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: X509_CERT default DENY; ALLOW dmverity_signature=TRUE.
        # Input: the same DER file on dm-verity without a root-hash signature.
        # Match: TRUE does not match -> default DENY; no prior bytes may remain.
        *(
            x509.read_case(
                id=(
                    "x509_cert_kernel_read_ipe_test_x509_"
                    f"dmverity_signature_true_{algorithm}_unsigned_denied"
                ),
                policy=X509_CERT_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_x509_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_content=b"",
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: X509_CERT default DENY; ALLOW dmverity_signature=TRUE.
        # Input: identical DER bytes on plain tmpfs, with no dm-verity mapping.
        # Match: no mapping signature -> no TRUE match -> default DENY.
        x509.read_case(
            id="x509_cert_kernel_read_ipe_test_x509_dmverity_signature_true_plain_denied",
            policy=X509_CERT_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_X509_TEST_BINARY,
            expected_errno=errno.EACCES,
            expected_content=b"",
        ),
        # Policy: X509_CERT default ALLOW; DENY dmverity_signature=FALSE.
        # Input: DER file on dm-verity with a verified root-hash signature.
        # Match: FALSE does not match -> default ALLOW; retain the exact DER bytes.
        *(
            x509.read_case(
                id=(
                    "x509_cert_kernel_read_ipe_test_x509_"
                    f"dmverity_signature_false_{algorithm}_signed_ok"
                ),
                policy=X509_CERT_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.dmverity_x509_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_content=layout.guest.dmverity_x509_test_binary(
                    algorithm=algorithm, signed=True
                ),
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: X509_CERT default ALLOW; DENY dmverity_signature=FALSE.
        # Input: DER file on dm-verity without a root-hash signature.
        # Match: FALSE matches -> explicit DENY, not default ALLOW.
        *(
            x509.read_case(
                id=(
                    "x509_cert_kernel_read_ipe_test_x509_"
                    f"dmverity_signature_false_{algorithm}_unsigned_denied"
                ),
                policy=X509_CERT_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.dmverity_x509_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_content=b"",
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: X509_CERT default ALLOW; DENY dmverity_signature=FALSE.
        # Input: the same DER bytes on plain tmpfs, without dm-verity metadata.
        # Match: absence counts as FALSE -> explicit DENY.
        x509.read_case(
            id="x509_cert_kernel_read_ipe_test_x509_dmverity_signature_false_plain_denied",
            policy=X509_CERT_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=layout.guest.PLAIN_X509_TEST_BINARY,
            expected_errno=errno.EACCES,
            expected_content=b"",
        ),
        # Policy: X509_CERT default DENY; ALLOW matching dmverity_roothash.
        # Input: DER file on signed dm-verity whose root hash matches the rule.
        # Match: root-hash rule -> ALLOW; no mapping signature is required by it.
        *(
            x509.read_case(
                id=(
                    "x509_cert_kernel_read_ipe_test_x509_"
                    f"dmverity_roothash_{algorithm}_signed_ok"
                ),
                policy=x509_cert_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.dmverity_x509_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_content=layout.guest.dmverity_x509_test_binary(
                    algorithm=algorithm, signed=True
                ),
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: X509_CERT default DENY; ALLOW matching dmverity_roothash.
        # Input: DER file on dm-verity with a matching but unsigned root hash.
        # Match: root-hash rule -> ALLOW without a mapping signature.
        *(
            x509.read_case(
                id=(
                    "x509_cert_kernel_read_ipe_test_x509_"
                    f"dmverity_roothash_{algorithm}_unsigned_ok"
                ),
                policy=x509_cert_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.dmverity_x509_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=0,
                expected_content=layout.guest.dmverity_x509_test_binary(
                    algorithm=algorithm, signed=False
                ),
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: X509_CERT default DENY; ALLOW matching dmverity_roothash.
        # Input: identical DER bytes on plain tmpfs, with no device root hash.
        # Match: no root-hash property -> default DENY.
        *(
            x509.read_case(
                id=(
                    "x509_cert_kernel_read_ipe_test_x509_"
                    f"dmverity_roothash_{algorithm}_plain_denied"
                ),
                policy=x509_cert_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.PLAIN_X509_TEST_BINARY,
                expected_errno=errno.EACCES,
                expected_content=b"",
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: X509_CERT default DENY; ALLOW a different dmverity_roothash.
        # Input: DER file on signed dm-verity whose root hash differs from the rule.
        # Match: root-hash mismatch -> default DENY despite the mapping signature.
        *(
            x509.read_case(
                id=(
                    "x509_cert_kernel_read_ipe_test_x509_"
                    f"dmverity_roothash_{algorithm}_mismatch_denied"
                ),
                policy=x509_cert_dmverity_roothash_policy(
                    algorithm=algorithm, matching=False
                ),
                binary=layout.guest.dmverity_x509_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_content=b"",
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
