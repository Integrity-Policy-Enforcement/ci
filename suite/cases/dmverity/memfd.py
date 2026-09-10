# SPDX-License-Identifier: GPL-2.0-only
"""Memfd execution cases using dm-verity properties."""

import errno

import hashes
import layout
from assets import (
    EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    execute_dmverity_roothash_policy,
)
from model import Case

from .. import execute_memfd


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: unsealed ordinary memfd copied from a dm-verity source with a verified root-hash signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_unsealed_dmverity_signature_true_{algorithm}_denied",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_memfd_test_binary(algorithm=algorithm, signed=True),
                huge=False,
                sealed=False,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: fully sealed ordinary memfd copied from a dm-verity source with a verified root-hash signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_sealed_dmverity_signature_true_{algorithm}_denied",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_memfd_test_binary(algorithm=algorithm, signed=True),
                huge=False,
                sealed=True,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: unsealed 2 MiB hugetlb memfd copied from a dm-verity source with a verified root-hash signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_hugetlb_dmverity_signature_true_{algorithm}_denied",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_memfd_test_binary(algorithm=algorithm, signed=True),
                huge=True,
                sealed=False,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: fully sealed 2 MiB hugetlb memfd copied from a dm-verity source with a verified root-hash signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_hugetlb_sealed_dmverity_signature_true_{algorithm}_denied",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_memfd_test_binary(algorithm=algorithm, signed=True),
                huge=True,
                sealed=True,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: unsealed ordinary memfd copied from a matching dm-verity source without a mapping signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_unsealed_dmverity_roothash_{algorithm}_denied",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_memfd_test_binary(algorithm=algorithm, signed=False),
                huge=False,
                sealed=False,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: fully sealed ordinary memfd copied from a matching dm-verity source without a mapping signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_sealed_dmverity_roothash_{algorithm}_denied",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_memfd_test_binary(algorithm=algorithm, signed=False),
                huge=False,
                sealed=True,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: unsealed 2 MiB hugetlb memfd copied from a matching dm-verity source without a mapping signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_hugetlb_dmverity_roothash_{algorithm}_denied",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_memfd_test_binary(algorithm=algorithm, signed=False),
                huge=True,
                sealed=False,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: fully sealed 2 MiB hugetlb memfd copied from a matching dm-verity source without a mapping signature.
        # Match: a new memfd has no source-file provenance -> default DENY (EACCES).
        *(
            execute_memfd.memfd_case(
                id=f"execute_bprm_check_execve_memfd_hugetlb_sealed_dmverity_roothash_{algorithm}_denied",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_memfd_test_binary(algorithm=algorithm, signed=False),
                huge=True,
                sealed=True,
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
