# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import files
import hashes
import ipe
import layout
import mounts
from assets import (
    KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    kmodule_dmverity_roothash_policy,
)
from model import Batch

from . import kmodule

# dm-verity mappings under this prefix are reserved for batch cleanup.
DMVERITY_DEVICE_PREFIX = "ipe-dmverity-"


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            id="dmverity",
            cases=(
                kmodule.case(
                    id="kmodule_dmverity_signature_true_signed_ok",
                    policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_dmverity_signature_true_unsigned_denied",
                    policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_dmverity_signature_true_plain_denied",
                    policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_dmverity_signature_false_signed_ok",
                    policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_dmverity_signature_false_unsigned_denied",
                    policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_dmverity_signature_false_plain_denied",
                    policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_dmverity_roothash_sha256_signed_ok",
                    policy=kmodule_dmverity_roothash_policy(algorithm="sha256"),
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_dmverity_roothash_sha256_unsigned_ok",
                    policy=kmodule_dmverity_roothash_policy(algorithm="sha256"),
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_dmverity_roothash_sha256_plain_denied",
                    policy=kmodule_dmverity_roothash_policy(algorithm="sha256"),
                    binary=layout.guest.PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_dmverity_roothash_sha512_signed_ok",
                    policy=kmodule_dmverity_roothash_policy(algorithm="sha512"),
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha512", signed=True
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_dmverity_roothash_sha512_unsigned_ok",
                    policy=kmodule_dmverity_roothash_policy(algorithm="sha512"),
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha512", signed=False
                    ),
                    allowed=True,
                ),
                kmodule.case(
                    id="kmodule_dmverity_roothash_sha512_plain_denied",
                    policy=kmodule_dmverity_roothash_policy(algorithm="sha512"),
                    binary=layout.guest.PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_dmverity_roothash_sha256_mismatch_denied",
                    policy=kmodule_dmverity_roothash_policy(
                        algorithm="sha256", matching=False
                    ),
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    allowed=False,
                ),
                kmodule.case(
                    id="kmodule_dmverity_roothash_sha512_mismatch_denied",
                    policy=kmodule_dmverity_roothash_policy(
                        algorithm="sha512", matching=False
                    ),
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha512", signed=True
                    ),
                    allowed=False,
                ),
            ),
            setup=(
                partial(ipe.set_enforcement, enabled=False),
                *(
                    partial(
                        mounts.dmverity,
                        prefix=DMVERITY_DEVICE_PREFIX,
                        algorithm=algorithm,
                        signed=signed,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                    for signed in (True, False)
                ),
                partial(mounts.tmpfs, point=layout.guest.PLAIN_MOUNT_DIR),
                partial(
                    files.copy_kmodule_test_binary,
                    target=layout.guest.PLAIN_KMODULE_TEST_BINARY,
                ),
            ),
            extra_scopes=(
                partial(
                    mounts.dmverity_scope,
                    prefix=DMVERITY_DEVICE_PREFIX,
                ),
                partial(
                    mounts.mounted_scope,
                    directory=layout.guest.MEDIA_DIR,
                ),
            ),
        ),
    )
