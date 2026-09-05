# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import files
import hashes
import ipe
import layout
from assets import (
    KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    kmodule_fsverity_digest_policy,
)
from model import Batch, Case

from . import kmodule


def signature_cases(*, algorithm: str) -> tuple[Case, ...]:
    """The signed and unsigned fs-verity signature cases for one algorithm."""
    signed_kmodule_binary = layout.guest.fsverity_signed_kmodule_test_binary(
        algorithm=algorithm
    )
    unsigned_kmodule_binary = layout.guest.fsverity_unsigned_kmodule_test_binary(
        algorithm=algorithm
    )
    return (
        kmodule.insmod_case(
            id=(
                "kmodule_kernel_read_insmod_fsverity_signature_true_"
                f"{algorithm}_signed_ok"
            ),
            policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=signed_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        kmodule.insmod_case(
            id=(
                "kmodule_kernel_read_insmod_fsverity_signature_true_"
                f"{algorithm}_unsigned_denied"
            ),
            policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=unsigned_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
        kmodule.insmod_case(
            id=(
                "kmodule_kernel_read_insmod_fsverity_signature_false_"
                f"{algorithm}_signed_ok"
            ),
            policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=signed_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        kmodule.insmod_case(
            id=(
                "kmodule_kernel_read_insmod_fsverity_signature_false_"
                f"{algorithm}_unsigned_denied"
            ),
            policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=unsigned_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
    )


def digest_cases(*, algorithm: str) -> tuple[Case, ...]:
    """The fs-verity digest cases for one algorithm."""
    matching_digest_policy = kmodule_fsverity_digest_policy(
        algorithm=algorithm, matching=True
    )
    mismatching_digest_policy = kmodule_fsverity_digest_policy(
        algorithm=algorithm, matching=False
    )
    signed_kmodule_binary = layout.guest.fsverity_signed_kmodule_test_binary(
        algorithm=algorithm
    )
    unsigned_kmodule_binary = layout.guest.fsverity_unsigned_kmodule_test_binary(
        algorithm=algorithm
    )
    plain_kmodule_binary = layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY
    return (
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_fsverity_digest_{algorithm}_signed_ok",
            policy=matching_digest_policy,
            binary=signed_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_fsverity_digest_{algorithm}_unsigned_ok",
            policy=matching_digest_policy,
            binary=unsigned_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_fsverity_digest_{algorithm}_plain_denied",
            policy=matching_digest_policy,
            binary=plain_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_fsverity_digest_{algorithm}_mismatch_denied",
            policy=mismatching_digest_policy,
            binary=signed_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
    )


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            id="fsverity",
            cases=(
                *(
                    test_case
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                    for test_case in signature_cases(algorithm=algorithm)
                ),
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_signed_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        expected_returncode=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                kmodule.insmod_case(
                    id=(
                        "kmodule_kernel_read_insmod_compressed_"
                        "fsverity_signature_true_plain_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_COMPRESSED_KMODULE_TEST_BINARY,
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_signature_false_{algorithm}_signed_ok"
                        ),
                        policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_signed_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        expected_returncode=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"fsverity_signature_false_{algorithm}_unsigned_denied"
                        ),
                        policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                kmodule.insmod_case(
                    id=(
                        "kmodule_kernel_read_insmod_compressed_"
                        "fsverity_signature_false_plain_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_COMPRESSED_KMODULE_TEST_BINARY,
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "fsverity_signature_true_signed_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "fsverity_signature_true_unsigned_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                kmodule.insmod_case(
                    id="kmodule_kernel_read_insmod_fsverity_signature_true_plain_denied",
                    policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY,
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "fsverity_signature_false_signed_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "fsverity_signature_false_unsigned_denied"
                    ),
                    policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                kmodule.insmod_case(
                    id="kmodule_kernel_read_insmod_fsverity_signature_false_plain_denied",
                    policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY,
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                *(
                    test_case
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                    for test_case in digest_cases(algorithm=algorithm)
                ),
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "fsverity_digest_sha256_signed_denied"
                    ),
                    policy=kmodule_fsverity_digest_policy(
                        algorithm="sha256", matching=True
                    ),
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
            ),
            setup=(
                partial(ipe.set_enforcement, enabled=False),
                *(
                    partial(
                        files.prepare_fsverity_kmodule_test_binary,
                        target=layout.guest.fsverity_signed_kmodule_test_binary(
                            algorithm=algorithm
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_signature(algorithm=algorithm),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_kmodule_test_binary,
                        target=layout.guest.fsverity_unsigned_kmodule_test_binary(
                            algorithm=algorithm
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_kmodule_test_binary,
                        source=layout.guest.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY,
                        target=layout.guest.fsverity_signed_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        algorithm=algorithm,
                        signature=layout.guest.fsverity_signature(
                            algorithm=algorithm, compressed=True
                        ),
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_kmodule_test_binary,
                        source=layout.guest.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY,
                        target=layout.guest.fsverity_unsigned_kmodule_test_binary(
                            algorithm=algorithm, compressed=True
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.FSVERITY_ALGORITHMS
                ),
                partial(
                    files.copy_kmodule_test_binary,
                    source=layout.guest.FSVERITY_COMPRESSED_KMODULE_TEST_BINARY,
                    target=layout.guest.FSVERITY_PLAIN_COMPRESSED_KMODULE_TEST_BINARY,
                ),
                partial(
                    files.copy_kmodule_test_binary,
                    target=layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY,
                ),
            ),
            extra_scopes=(
                partial(
                    files.directory_scope,
                    directory=layout.guest.FSVERITY_MODULES_DIR,
                ),
            ),
        ),
    )
