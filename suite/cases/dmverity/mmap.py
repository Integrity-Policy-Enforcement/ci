# SPDX-License-Identifier: GPL-2.0-only
"""File and anonymous mmap cases using dm-verity properties."""

import errno
import mmap

import hashes
import layout
from assets import (
    EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    execute_dmverity_roothash_policy,
)
from model import Case

from .. import execute_mmap


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: ELF on dm-verity with a verified root-hash signature; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_r_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_r_dmverity_signature_true_plain_ok",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_READ,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: ELF on dm-verity with a verified root-hash signature; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_w_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_w_dmverity_signature_true_plain_ok",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_WRITE,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: ELF on dm-verity with a verified root-hash signature; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rw_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ | mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_rw_dmverity_signature_true_plain_ok",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_READ | mmap.PROT_WRITE,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: ELF on dm-verity with a verified root-hash signature; private X mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_x_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_x_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: ELF on dm-verity with a verified root-hash signature; private RX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rx_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_rx_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_READ | mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: ELF on dm-verity with a verified root-hash signature; private WX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_wx_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; private WX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_private_wx_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: ELF on dm-verity with a verified root-hash signature; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_r_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_shared_r_dmverity_signature_true_plain_ok",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_READ,
            shared=True,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: ELF on dm-verity with a verified root-hash signature; shared X mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_x_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_EXEC,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; shared X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_shared_x_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_EXEC,
            shared=True,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: ELF on dm-verity with a verified root-hash signature; shared RX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_rx_dmverity_signature_true_trusted_ok_{algorithm}",
                policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=True),
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: identical ELF bytes without the required file property; shared RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_file_shared_rx_dmverity_signature_true_plain_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
            protection=mmap.PROT_READ | mmap.PROT_EXEC,
            shared=True,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_r_dmverity_signature_true_anonymous_ok",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_READ,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_w_dmverity_signature_true_anonymous_ok",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_WRITE,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_rw_dmverity_signature_true_anonymous_ok",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_READ | mmap.PROT_WRITE,
            shared=False,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_x_dmverity_signature_true_anonymous_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_rx_dmverity_signature_true_anonymous_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_READ | mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; private WX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_private_wx_dmverity_signature_true_anonymous_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
            shared=False,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_shared_r_dmverity_signature_true_anonymous_ok",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_READ,
            shared=True,
            expected_errno=0,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; shared X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_shared_x_dmverity_signature_true_anonymous_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_EXEC,
            shared=True,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW dmverity_signature=TRUE.
        # Input: anonymous memory with no trusted file provenance; shared RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        execute_mmap.mmap_case(
            id="execute_mmap_mmap_anon_shared_rx_dmverity_signature_true_anonymous_denied",
            policy=EXECUTE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=None,
            protection=mmap.PROT_READ | mmap.PROT_EXEC,
            shared=True,
            expected_errno=errno.EACCES,
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: ELF on matching dm-verity without a root-hash signature; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_r_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                protection=mmap.PROT_READ,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: identical ELF bytes without the required file property; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_r_dmverity_roothash_plain_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_READ,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: ELF on matching dm-verity without a root-hash signature; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_w_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                protection=mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: identical ELF bytes without the required file property; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_w_dmverity_roothash_plain_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: ELF on matching dm-verity without a root-hash signature; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rw_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                protection=mmap.PROT_READ | mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: identical ELF bytes without the required file property; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rw_dmverity_roothash_plain_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_READ | mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: ELF on matching dm-verity without a root-hash signature; private X mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_x_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                protection=mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: identical ELF bytes without the required file property; private X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_x_dmverity_roothash_plain_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: ELF on matching dm-verity without a root-hash signature; private RX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rx_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: identical ELF bytes without the required file property; private RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_rx_dmverity_roothash_plain_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: ELF on matching dm-verity without a root-hash signature; private WX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_wx_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: identical ELF bytes without the required file property; private WX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_private_wx_dmverity_roothash_plain_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: ELF on matching dm-verity without a root-hash signature; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_r_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                protection=mmap.PROT_READ,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: identical ELF bytes without the required file property; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_r_dmverity_roothash_plain_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_READ,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: ELF on matching dm-verity without a root-hash signature; shared X mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_x_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                protection=mmap.PROT_EXEC,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: identical ELF bytes without the required file property; shared X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_x_dmverity_roothash_plain_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_EXEC,
                shared=True,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: ELF on matching dm-verity without a root-hash signature; shared RX mapping.
        # Match: the file-property rule matches -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_rx_dmverity_roothash_trusted_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.dmverity_execute_test_binary(algorithm=algorithm, signed=False),
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: identical ELF bytes without the required file property; shared RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_file_shared_rx_dmverity_roothash_plain_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=layout.guest.PLAIN_EXECUTE_TEST_BINARY,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=True,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: anonymous memory with no trusted file provenance; private R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_r_dmverity_roothash_anonymous_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_READ,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: anonymous memory with no trusted file provenance; private W mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_w_dmverity_roothash_anonymous_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: anonymous memory with no trusted file provenance; private RW mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_rw_dmverity_roothash_anonymous_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_READ | mmap.PROT_WRITE,
                shared=False,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: anonymous memory with no trusted file provenance; private X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_x_dmverity_roothash_anonymous_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: anonymous memory with no trusted file provenance; private RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_rx_dmverity_roothash_anonymous_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: anonymous memory with no trusted file provenance; private WX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_private_wx_dmverity_roothash_anonymous_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_WRITE | mmap.PROT_EXEC,
                shared=False,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: anonymous memory with no trusted file provenance; shared R mapping.
        # Match: PROT_EXEC is absent -> the hook skips EXECUTE evaluation -> ALLOW.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_shared_r_dmverity_roothash_anonymous_ok_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_READ,
                shared=True,
                expected_errno=0,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: anonymous memory with no trusted file provenance; shared X mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_shared_x_dmverity_roothash_anonymous_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_EXEC,
                shared=True,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: EXECUTE default DENY; ALLOW the matching dmverity_roothash.
        # Input: anonymous memory with no trusted file provenance; shared RX mapping.
        # Match: the required file property is absent -> no ALLOW match -> default DENY.
        *(
            execute_mmap.mmap_case(
                id=f"execute_mmap_mmap_anon_shared_rx_dmverity_roothash_anonymous_denied_{algorithm}",
                policy=execute_dmverity_roothash_policy(algorithm=algorithm, matching=True),
                binary=None,
                protection=mmap.PROT_READ | mmap.PROT_EXEC,
                shared=True,
                expected_errno=errno.EACCES,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
