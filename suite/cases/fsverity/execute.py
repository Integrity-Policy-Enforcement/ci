# SPDX-License-Identifier: GPL-2.0-only
"""Static ELF execution cases using fs-verity properties."""

import errno

import hashes
import layout
from assets import (
    EXECUTE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    execute_fsverity_digest_policy,
)
from model import Case
from operations import execve as execute


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
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
    )
