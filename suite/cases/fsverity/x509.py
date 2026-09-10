# SPDX-License-Identifier: GPL-2.0-only
"""X509_CERT file-read cases using fs-verity properties."""

import errno

import hashes
import layout
from assets import (
    X509_CERT_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    X509_CERT_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    x509_cert_fsverity_digest_policy,
)
from model import Case

from .. import x509


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
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
    )
