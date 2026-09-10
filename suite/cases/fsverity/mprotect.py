# SPDX-License-Identifier: GPL-2.0-only
"""Private file mprotect cases using fs-verity properties."""

import errno
import mmap

import hashes
import layout
from assets import (
    EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    execute_fsverity_digest_policy,
)
from model import Case

from .. import execute_mprotect


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; W -> X.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_x_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; W -> X.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_w_x_fsverity_signature_true_plain_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_WRITE,
            protection=mmap.PROT_EXEC,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; W -> RX.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_rx_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; W -> RX.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_w_rx_fsverity_signature_true_plain_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_WRITE,
            protection=mmap.PROT_READ | mmap.PROT_EXEC,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; R -> X.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_x_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; R -> X.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_r_x_fsverity_signature_true_plain_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_READ,
            protection=mmap.PROT_EXEC,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; R -> WX.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_wx_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; R -> WX.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_r_wx_fsverity_signature_true_plain_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_READ,
            protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; W -> R.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_r_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; W -> R.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_w_r_fsverity_signature_true_plain_ok",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_WRITE,
            protection=mmap.PROT_READ,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of ELF with a verified built-in signature over its fs-verity digest; R -> W.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_w_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: private mapping of identical ELF bytes without the required file property; R -> W.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        execute_mprotect.mprotect_case(
            id="execute_mprotect_mprotect_private_r_w_fsverity_signature_true_plain_ok",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            initial_protection=mmap.PROT_READ,
            protection=mmap.PROT_WRITE,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of signed fs-verity ELF whose digest matches the rule; W -> X.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_x_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of identical ELF bytes without the required file property; W -> X.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_x_fsverity_digest_plain_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_EXEC,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of signed fs-verity ELF whose digest matches the rule; W -> RX.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_rx_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of identical ELF bytes without the required file property; W -> RX.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_rx_fsverity_digest_plain_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of signed fs-verity ELF whose digest matches the rule; R -> X.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_x_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of identical ELF bytes without the required file property; R -> X.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_x_fsverity_digest_plain_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_EXEC,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of signed fs-verity ELF whose digest matches the rule; R -> WX.
        # Match: the file-property rule matches -> ALLOW; mprotect succeeds.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_wx_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of identical ELF bytes without the required file property; R -> WX.
        # Match: no matching file property -> default DENY; mprotect fails with EACCES.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_wx_fsverity_digest_plain_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of signed fs-verity ELF whose digest matches the rule; W -> R.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_r_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of identical ELF bytes without the required file property; W -> R.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_w_r_fsverity_digest_plain_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_WRITE,
                protection=mmap.PROT_READ,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of signed fs-verity ELF whose digest matches the rule; R -> W.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_w_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: private mapping of identical ELF bytes without the required file property; R -> W.
        # Match: no requested PROT_EXEC -> skip EXECUTE evaluation -> ALLOW.
        *(
            execute_mprotect.mprotect_case(
                id=f"execute_mprotect_mprotect_private_r_w_fsverity_digest_plain_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                initial_protection=mmap.PROT_READ,
                protection=mmap.PROT_WRITE,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
    )
