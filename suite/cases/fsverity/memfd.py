# SPDX-License-Identifier: GPL-2.0-only
"""Memfd execution cases using fs-verity properties."""

import errno

import hashes
import layout
from assets import (
    EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    execute_fsverity_digest_policy,
    hugetlb_fsverity_digest_policy,
)
from model import Case
from operations import memfd


def cases() -> tuple[Case, ...]:
    """Return this operation's cases."""
    return (
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE. The same
        #         policy allows the original signed fs-verity static ELF.
        # Input: that ELF's bytes copied into a new unsealed memfd.
        # Match: the memfd has no fs-verity signature -> default DENY -> EACCES.
        *(
            memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_unsealed_"
                    f"fsverity_signature_true_{algorithm}_denied"
                ),
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the static ELF's exact fsverity_digest.
        #         The same policy allows the original fs-verity ELF without a
        #         built-in signature.
        # Input: that ELF's bytes copied into a new unsealed memfd.
        # Match: the memfd has no fs-verity digest -> default DENY -> EACCES.
        *(
            memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_unsealed_"
                    f"fsverity_digest_{algorithm}_denied"
                ),
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE. The same
        #         policy allows the original signed fs-verity static ELF.
        # Input: that ELF's bytes copied into a new memfd, then fully sealed.
        # Match: sealing makes the copy immutable, not trusted: it has no fs-verity
        #        signature -> default DENY -> EACCES.
        *(
            memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_sealed_"
                    f"fsverity_signature_true_{algorithm}_denied"
                ),
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                sealed=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the static ELF's exact fsverity_digest.
        #         The same policy allows the original fs-verity ELF without a
        #         built-in signature.
        # Input: that ELF's bytes copied into a new memfd, then fully sealed.
        # Match: sealing makes the copy immutable, not trusted: it has no fs-verity
        #        digest -> default DENY -> EACCES.
        *(
            memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_sealed_"
                    f"fsverity_digest_{algorithm}_denied"
                ),
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                sealed=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE, which matches
        #         the signed fs-verity copy of the hugetlb ELF.
        # Input: that copy's bytes in a new unsealed hugetlb memfd.
        # Match: the memfd has no fs-verity signature -> default DENY -> EACCES.
        *(
            memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_hugetlb_"
                    f"fsverity_signature_true_{algorithm}_denied"
                ),
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_hugetlb_test_binary(algorithm=algorithm),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                huge=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the hugetlb ELF's exact fsverity_digest.
        #         No fsverity_signature rule exists, so only the digest matches the
        #         signed fs-verity copy.
        # Input: that copy's bytes in a new unsealed hugetlb memfd.
        # Match: the memfd has no fs-verity digest -> default DENY -> EACCES.
        *(
            memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_hugetlb_"
                    f"fsverity_digest_{algorithm}_denied"
                ),
                policy=hugetlb_fsverity_digest_policy(algorithm=algorithm),
                binary=layout.guest.fsverity_hugetlb_test_binary(algorithm=algorithm),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                huge=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE, which matches
        #         the signed fs-verity copy of the hugetlb ELF.
        # Input: that copy's bytes in a new hugetlb memfd, then fully sealed.
        # Match: sealing makes the copy immutable, not trusted: it has no fs-verity
        #        signature -> default DENY -> EACCES.
        *(
            memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_hugetlb_sealed_"
                    f"fsverity_signature_true_{algorithm}_denied"
                ),
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_hugetlb_test_binary(algorithm=algorithm),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                sealed=True,
                huge=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the hugetlb ELF's exact fsverity_digest.
        #         No fsverity_signature rule exists, so only the digest matches the
        #         signed fs-verity copy.
        # Input: that copy's bytes in a new hugetlb memfd, then fully sealed.
        # Match: sealing makes the copy immutable, not trusted: it has no fs-verity
        #        digest -> default DENY -> EACCES.
        *(
            memfd.memfd_case(
                id=(
                    "execute_bprm_check_execve_memfd_hugetlb_sealed_"
                    f"fsverity_digest_{algorithm}_denied"
                ),
                policy=hugetlb_fsverity_digest_policy(algorithm=algorithm),
                binary=layout.guest.fsverity_hugetlb_test_binary(algorithm=algorithm),
                expected_errno=errno.EACCES,
                expected_returncode=None,
                sealed=True,
                huge=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
    )
