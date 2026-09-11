# SPDX-License-Identifier: GPL-2.0-only
"""Static ELF execution cases using dm-verity properties."""

import errno

import hashes
import layout
from assets import (
    EXECUTE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    execute_dmverity_roothash_policy,
)
from model import Case
from operations import execve as execute


def signature_true_cases() -> tuple[Case, ...]:
    """Return the signature-TRUE execution cases in their existing order."""
    return (
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: a static ELF on dm-verity with a verified root-hash signature.
        # Match: TRUE matches -> ALLOW; exec succeeds and the program exits zero.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_"
                    f"dmverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_returncode=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: the same static ELF on dm-verity without a root-hash signature.
        # Match: TRUE does not match -> default DENY; the program never starts.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_"
                    f"dmverity_signature_true_{algorithm}_unsigned_denied"
                ),
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: identical executable ELF bytes copied to a separate plain tmpfs.
        # Match: no dm-verity signature -> no TRUE match -> default DENY.
        execute.execve_case(
            id="execute_bprm_check_execve_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            expected_errno=errno.EACCES,
            expected_returncode=None,
        ),
    )


def signature_false_cases() -> tuple[Case, ...]:
    """Return the signature-FALSE execution cases in their existing order."""
    return (
        # Policy: EXECUTE default ALLOW; DENY dmverity_signature=FALSE.
        # Input: a static ELF on dm-verity with a verified root-hash signature.
        # Match: FALSE does not match -> default ALLOW; the program exits zero.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_"
                    f"dmverity_signature_false_{algorithm}_signed_ok"
                ),
                policy=EXECUTE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_returncode=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default ALLOW; DENY dmverity_signature=FALSE.
        # Input: the same static ELF on dm-verity without a root-hash signature.
        # Match: FALSE matches -> explicit DENY; no program exit status exists.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_"
                    f"dmverity_signature_false_{algorithm}_unsigned_denied"
                ),
                policy=EXECUTE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default ALLOW; DENY dmverity_signature=FALSE.
        # Input: identical executable ELF bytes on plain tmpfs, without dm-verity.
        # Match: absence counts as FALSE -> explicit DENY.
        execute.execve_case(
            id="execute_bprm_check_execve_dmverity_signature_false_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            expected_errno=errno.EACCES,
            expected_returncode=None,
        ),
    )


def roothash_cases() -> tuple[Case, ...]:
    """Return the root-hash execution cases in their existing order."""
    return (
        # Policy: EXECUTE default DENY; ALLOW matching dmverity_roothash.
        # Input: a static ELF on signed dm-verity whose root hash matches.
        # Match: the root-hash rule -> ALLOW; this rule does not require a signature.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_"
                    f"dmverity_roothash_{algorithm}_signed_ok"
                ),
                policy=execute_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.dmverity_execute_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_returncode=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW matching dmverity_roothash.
        # Input: the static ELF on dm-verity with a matching but unsigned root hash.
        # Match: the root-hash rule -> ALLOW without a mapping signature.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_"
                    f"dmverity_roothash_{algorithm}_unsigned_ok"
                ),
                policy=execute_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.dmverity_execute_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=0,
                expected_returncode=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW matching dmverity_roothash.
        # Input: identical executable ELF bytes on tmpfs, with no root-hash property.
        # Match: the property is absent -> no ALLOW match -> default DENY.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_"
                    f"dmverity_roothash_{algorithm}_plain_denied"
                ),
                policy=execute_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW a different dmverity_roothash.
        # Input: a static ELF on signed dm-verity whose root hash differs.
        # Match: hash mismatch -> default DENY despite the valid mapping signature.
        *(
            execute.execve_case(
                id=(
                    "execute_bprm_check_execve_"
                    f"dmverity_roothash_{algorithm}_mismatch_denied"
                ),
                policy=execute_dmverity_roothash_policy(
                    algorithm=algorithm, matching=False
                ),
                binary=layout.guest.dmverity_execute_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
