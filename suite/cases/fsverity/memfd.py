# SPDX-License-Identifier: GPL-2.0-only
"""Memfd execution cases using fs-verity properties."""

import errno

import hashes
import layout
from assets import (
    EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    memfd_source_fsverity_digest_policy,
)
from model import Case
from operations import memfd as execute_memfd


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: unsealed ordinary memfd copied from a source with a verified built-in fs-verity digest signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_unsealed_fsverity_signature_true_{algorithm}_denied",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                huge=False,
                sealed=False,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: fully sealed ordinary memfd copied from a source with a verified built-in fs-verity digest signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_sealed_fsverity_signature_true_{algorithm}_denied",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                huge=False,
                sealed=True,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: unsealed 2 MiB hugetlb memfd copied from a source with a verified built-in fs-verity digest signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_hugetlb_fsverity_signature_true_{algorithm}_denied",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                huge=True,
                sealed=False,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: fully sealed 2 MiB hugetlb memfd copied from a source with a verified built-in fs-verity digest signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_hugetlb_sealed_fsverity_signature_true_{algorithm}_denied",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                huge=True,
                sealed=True,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: unsealed ordinary memfd copied from a signed fs-verity source with a matching ELF digest.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_unsealed_fsverity_digest_{algorithm}_denied",
                policy=memfd_source_fsverity_digest_policy(algorithm=algorithm),
                binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                huge=False,
                sealed=False,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: fully sealed ordinary memfd copied from a signed fs-verity source with a matching ELF digest.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_sealed_fsverity_digest_{algorithm}_denied",
                policy=memfd_source_fsverity_digest_policy(algorithm=algorithm),
                binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                huge=False,
                sealed=True,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: unsealed 2 MiB hugetlb memfd copied from a signed fs-verity source with a matching ELF digest.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_hugetlb_fsverity_digest_{algorithm}_denied",
                policy=memfd_source_fsverity_digest_policy(algorithm=algorithm),
                binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                huge=True,
                sealed=False,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: fully sealed 2 MiB hugetlb memfd copied from a signed fs-verity source with a matching ELF digest.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_hugetlb_sealed_fsverity_digest_{algorithm}_denied",
                policy=memfd_source_fsverity_digest_policy(algorithm=algorithm),
                binary=layout.guest.fsverity_memfd_test_binary(algorithm=algorithm),
                huge=True,
                sealed=True,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
    )
