# SPDX-License-Identifier: GPL-2.0-only
"""File and anonymous mmap cases using fs-verity properties."""

import errno
import mmap

import hashes
import layout
from assets import (
    EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    execute_fsverity_digest_policy,
)
from model import Case

from .. import execute_mmap


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: ELF with a verified built-in signature over its fs-verity digest; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_r_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_r_fsverity_signature_true_plain_ok",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_READ,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: ELF with a verified built-in signature over its fs-verity digest; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_w_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_w_fsverity_signature_true_plain_ok",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_WRITE,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: ELF with a verified built-in signature over its fs-verity digest; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rw_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ | mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_rw_fsverity_signature_true_plain_ok",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_READ | mmap.PROT_WRITE,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: ELF with a verified built-in signature over its fs-verity digest; private X mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_x_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_x_fsverity_signature_true_plain_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: ELF with a verified built-in signature over its fs-verity digest; private RX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rx_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_rx_fsverity_signature_true_plain_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_READ | mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: ELF with a verified built-in signature over its fs-verity digest; private WX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_wx_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private WX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_wx_fsverity_signature_true_plain_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: ELF with a verified built-in signature over its fs-verity digest; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_r_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_shared_r_fsverity_signature_true_plain_ok",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_READ,
            shared=True,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: ELF with a verified built-in signature over its fs-verity digest; shared X mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_x_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_EXEC,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; shared X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_shared_x_fsverity_signature_true_plain_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_EXEC,
            shared=True,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: ELF with a verified built-in signature over its fs-verity digest; shared RX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_rx_fsverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; shared RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_shared_rx_fsverity_signature_true_plain_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_READ | mmap.PROT_EXEC,
            shared=True,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_r_fsverity_signature_true_anonymous_ok",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_READ,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_w_fsverity_signature_true_anonymous_ok",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_WRITE,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_rw_fsverity_signature_true_anonymous_ok",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_READ | mmap.PROT_WRITE,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_x_fsverity_signature_true_anonymous_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_rx_fsverity_signature_true_anonymous_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_READ | mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private WX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_wx_fsverity_signature_true_anonymous_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_shared_r_fsverity_signature_true_anonymous_ok",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_READ,
            shared=True,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; shared X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_shared_x_fsverity_signature_true_anonymous_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_EXEC,
            shared=True,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; shared RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_shared_rx_fsverity_signature_true_anonymous_denied",
            policy=EXECUTE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_READ | mmap.PROT_EXEC,
            shared=True,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: signed fs-verity ELF whose digest matches the rule; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_r_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: identical ELF bytes without the required file property; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_r_fsverity_digest_plain_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_READ,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: signed fs-verity ELF whose digest matches the rule; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_w_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: identical ELF bytes without the required file property; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_w_fsverity_digest_plain_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: signed fs-verity ELF whose digest matches the rule; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rw_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ | mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: identical ELF bytes without the required file property; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rw_fsverity_digest_plain_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_READ | mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: signed fs-verity ELF whose digest matches the rule; private X mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_x_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: identical ELF bytes without the required file property; private X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_x_fsverity_digest_plain_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: signed fs-verity ELF whose digest matches the rule; private RX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rx_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: identical ELF bytes without the required file property; private RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rx_fsverity_digest_plain_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: signed fs-verity ELF whose digest matches the rule; private WX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_wx_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: identical ELF bytes without the required file property; private WX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_wx_fsverity_digest_plain_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: signed fs-verity ELF whose digest matches the rule; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_r_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: identical ELF bytes without the required file property; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_r_fsverity_digest_plain_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_READ,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: signed fs-verity ELF whose digest matches the rule; shared X mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_x_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_EXEC,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: identical ELF bytes without the required file property; shared X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_x_fsverity_digest_plain_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_EXEC,
                shared=True,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: signed fs-verity ELF whose digest matches the rule; shared RX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_rx_fsverity_digest_trusted_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.fsverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: identical ELF bytes without the required file property; shared RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_rx_fsverity_digest_plain_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.FSVERITY_PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=True,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: anonymous memory with no trusted file provenance; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_r_fsverity_digest_anonymous_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_READ,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: anonymous memory with no trusted file provenance; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_w_fsverity_digest_anonymous_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: anonymous memory with no trusted file provenance; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_rw_fsverity_digest_anonymous_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_READ | mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: anonymous memory with no trusted file provenance; private X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_x_fsverity_digest_anonymous_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: anonymous memory with no trusted file provenance; private RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_rx_fsverity_digest_anonymous_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: anonymous memory with no trusted file provenance; private WX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_wx_fsverity_digest_anonymous_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: anonymous memory with no trusted file provenance; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_shared_r_fsverity_digest_anonymous_ok_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_READ,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: anonymous memory with no trusted file provenance; shared X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_shared_x_fsverity_digest_anonymous_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_EXEC,
                shared=True,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching fsverity_digest.
        # Input: anonymous memory with no trusted file provenance; shared RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_shared_rx_fsverity_digest_anonymous_denied_{algorithm}",
                policy=execute_fsverity_digest_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=True,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
    )
