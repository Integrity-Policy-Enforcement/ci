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
    """Return this operation's cases."""
    return (
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE. The same
        #         policy allows the original static ELF on each signed mapping.
        # Input: that ELF's bytes copied into a new unsealed memfd.
        # Match: the memfd has no dm-verity signature -> default DENY -> EACCES.
        *(
            execute_memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_unsealed_"
                    f"dmverity_signature_true_{algorithm}_denied"
                ),
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash. The
        #         same policy allows the original static ELF on each unsigned mapping.
        # Input: that ELF's bytes copied into a new unsealed memfd.
        # Match: the memfd has no dm-verity root hash -> default DENY -> EACCES.
        *(
            execute_memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_unsealed_"
                    f"dmverity_roothash_{algorithm}_denied"
                ),
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE. The same
        #         policy allows the original static ELF on each signed mapping.
        # Input: that ELF's bytes copied into a new memfd, then fully sealed.
        # Match: sealing makes the copy immutable, not trusted: it has no dm-verity
        #        signature -> default DENY -> EACCES.
        *(
            execute_memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_sealed_"
                    f"dmverity_signature_true_{algorithm}_denied"
                ),
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                sealed=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash. The
        #         same policy allows the original static ELF on each unsigned mapping.
        # Input: that ELF's bytes copied into a new memfd, then fully sealed.
        # Match: sealing makes the copy immutable, not trusted: it has no dm-verity
        #        root hash -> default DENY -> EACCES.
        *(
            execute_memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_sealed_"
                    f"dmverity_roothash_{algorithm}_denied"
                ),
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                sealed=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE, which matches
        #         the hugetlb ELF on each signed mapping.
        # Input: that ELF's bytes copied into a new unsealed hugetlb memfd.
        # Match: the memfd has no dm-verity signature -> default DENY -> EACCES.
        *(
            execute_memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_hugetlb_"
                    f"dmverity_signature_true_{algorithm}_denied"
                ),
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_hugetlb_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                huge=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash, which
        #         matches the hugetlb ELF on each unsigned mapping.
        # Input: that ELF's bytes copied into a new unsealed hugetlb memfd.
        # Match: the memfd has no dm-verity root hash -> default DENY -> EACCES.
        *(
            execute_memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_hugetlb_"
                    f"dmverity_roothash_{algorithm}_denied"
                ),
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_hugetlb_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                huge=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE, which matches
        #         the hugetlb ELF on each signed mapping.
        # Input: that ELF's bytes copied into a new hugetlb memfd, then fully sealed.
        # Match: sealing makes the copy immutable, not trusted: it has no dm-verity
        #        signature -> default DENY -> EACCES.
        *(
            execute_memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_hugetlb_sealed_"
                    f"dmverity_signature_true_{algorithm}_denied"
                ),
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_hugetlb_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                sealed=True,
                huge=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash, which
        #         matches the hugetlb ELF on each unsigned mapping.
        # Input: that ELF's bytes copied into a new hugetlb memfd, then fully sealed.
        # Match: sealing makes the copy immutable, not trusted: it has no dm-verity
        #        root hash -> default DENY -> EACCES.
        *(
            execute_memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_hugetlb_sealed_"
                    f"dmverity_roothash_{algorithm}_denied"
                ),
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_hugetlb_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                sealed=True,
                huge=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
