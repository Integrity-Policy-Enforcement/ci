# SPDX-License-Identifier: GPL-2.0-only
"""Private file mprotect cases using dm-verity properties."""

import errno
import mmap

import hashes
import layout
from assets import (
    EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    execute_dmverity_roothash_policy,
)
from model import Case

from .. import execute_mprotect


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of ELF on dm-verity with a verified root-hash signature; W -> X.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_x_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; W -> X.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_w_x_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_WRITE,
            protection=mmap.PROT_EXEC,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of ELF on dm-verity with a verified root-hash signature; W -> RX.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_rx_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; W -> RX.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_w_rx_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_WRITE,
            protection=mmap.PROT_READ | mmap.PROT_EXEC,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of ELF on dm-verity with a verified root-hash signature; R -> X.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_x_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; R -> X.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_r_x_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_READ,
            protection=mmap.PROT_EXEC,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of ELF on dm-verity with a verified root-hash signature; R -> WX.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_wx_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; R -> WX.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_r_wx_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_READ,
            protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of ELF on dm-verity with a verified root-hash signature; W -> R.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_r_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; W -> R.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_w_r_dmverity_signature_true_plain_ok",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_WRITE,
            protection=mmap.PROT_READ,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of ELF on dm-verity with a verified root-hash signature; R -> W.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_w_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; R -> W.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_r_w_dmverity_signature_true_plain_ok",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_READ,
            protection=mmap.PROT_WRITE,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of ELF on matching dm-verity without a root-hash signature; W -> X.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_x_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of identical ELF bytes without the required file property; W -> X.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_x_dmverity_roothash_plain_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_EXEC,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of ELF on matching dm-verity without a root-hash signature; W -> RX.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_rx_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of identical ELF bytes without the required file property; W -> RX.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_rx_dmverity_roothash_plain_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of ELF on matching dm-verity without a root-hash signature; R -> X.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_x_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of identical ELF bytes without the required file property; R -> X.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_x_dmverity_roothash_plain_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_EXEC,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of ELF on matching dm-verity without a root-hash signature; R -> WX.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_wx_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of identical ELF bytes without the required file property; R -> WX.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_wx_dmverity_roothash_plain_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of ELF on matching dm-verity without a root-hash signature; W -> R.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_r_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of identical ELF bytes without the required file property; W -> R.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_r_dmverity_roothash_plain_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of ELF on matching dm-verity without a root-hash signature; R -> W.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_w_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: private mapping of identical ELF bytes without the required file property; R -> W.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_w_dmverity_roothash_plain_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
