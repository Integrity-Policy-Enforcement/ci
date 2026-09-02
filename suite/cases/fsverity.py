# SPDX-License-Identifier: GPL-2.0-only

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
from model import Batch

from . import kmodule


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            id="fsverity",
            cases=(
                kmodule.case(
                    id="kmodule_fsverity_signature_true_signed_ok",
                    policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_fsverity_signature_true_unsigned_denied",
                    policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_fsverity_signature_true_plain_denied",
                    policy=KMODULE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_fsverity_signature_false_signed_ok",
                    policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_fsverity_signature_false_unsigned_denied",
                    policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_fsverity_signature_false_plain_denied",
                    policy=KMODULE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_fsverity_digest_sha256_signed_ok",
                    policy=kmodule_fsverity_digest_policy(algorithm="sha256"),
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_fsverity_digest_sha256_unsigned_ok",
                    policy=kmodule_fsverity_digest_policy(algorithm="sha256"),
                    binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_fsverity_digest_sha256_plain_denied",
                    policy=kmodule_fsverity_digest_policy(algorithm="sha256"),
                    binary=layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_fsverity_digest_sha512_signed_ok",
                    policy=kmodule_fsverity_digest_policy(algorithm="sha512"),
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha512"
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_fsverity_digest_sha512_unsigned_ok",
                    policy=kmodule_fsverity_digest_policy(algorithm="sha512"),
                    binary=layout.guest.fsverity_unsigned_kmodule_test_binary(
                        algorithm="sha512"
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_fsverity_digest_sha512_plain_denied",
                    policy=kmodule_fsverity_digest_policy(algorithm="sha512"),
                    binary=layout.guest.FSVERITY_PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_fsverity_digest_sha256_mismatch_denied",
                    policy=kmodule_fsverity_digest_policy(
                        algorithm="sha256", matching=False
                    ),
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha256"
                    ),
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_fsverity_digest_sha512_mismatch_denied",
                    policy=kmodule_fsverity_digest_policy(
                        algorithm="sha512", matching=False
                    ),
                    binary=layout.guest.fsverity_signed_kmodule_test_binary(
                        algorithm="sha512"
                    ),
                    allowed=False,
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
                    for algorithm in hashes.ALGORITHMS
                ),
                *(
                    partial(
                        files.prepare_fsverity_kmodule_test_binary,
                        target=layout.guest.fsverity_unsigned_kmodule_test_binary(
                            algorithm=algorithm
                        ),
                        algorithm=algorithm,
                    )
                    for algorithm in hashes.ALGORITHMS
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
