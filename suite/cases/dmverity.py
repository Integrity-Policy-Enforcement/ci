# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import files
import hashes
import ipe
import layout
import mounts
import runtime
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
            "dmverity",
            (
                kmodule.case(
                    "kmodule_dmverity_signature_true_signed_ok",
                    KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    layout.guest.dmverity_kmodule_test_binary("sha256", signed=True),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_dmverity_signature_true_unsigned_denied",
                    KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    layout.guest.dmverity_kmodule_test_binary("sha256", signed=False),
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_dmverity_signature_true_plain_denied",
                    KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    layout.guest.PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_dmverity_signature_false_signed_ok",
                    KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    layout.guest.dmverity_kmodule_test_binary("sha256", signed=True),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_dmverity_signature_false_unsigned_denied",
                    KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    layout.guest.dmverity_kmodule_test_binary("sha256", signed=False),
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_dmverity_signature_false_plain_denied",
                    KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    layout.guest.PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_dmverity_roothash_sha256_signed_ok",
                    kmodule_dmverity_roothash_policy("sha256"),
                    layout.guest.dmverity_kmodule_test_binary("sha256", signed=True),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_dmverity_roothash_sha256_unsigned_ok",
                    kmodule_dmverity_roothash_policy("sha256"),
                    layout.guest.dmverity_kmodule_test_binary("sha256", signed=False),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_dmverity_roothash_sha256_plain_denied",
                    kmodule_dmverity_roothash_policy("sha256"),
                    layout.guest.PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_dmverity_roothash_sha512_signed_ok",
                    kmodule_dmverity_roothash_policy("sha512"),
                    layout.guest.dmverity_kmodule_test_binary("sha512", signed=True),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_dmverity_roothash_sha512_unsigned_ok",
                    kmodule_dmverity_roothash_policy("sha512"),
                    layout.guest.dmverity_kmodule_test_binary("sha512", signed=False),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_dmverity_roothash_sha512_plain_denied",
                    kmodule_dmverity_roothash_policy("sha512"),
                    layout.guest.PLAIN_KMODULE_TEST_BINARY,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_dmverity_roothash_sha256_mismatch_denied",
                    kmodule_dmverity_roothash_policy("sha256", matching=False),
                    layout.guest.dmverity_kmodule_test_binary("sha256", signed=True),
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_dmverity_roothash_sha512_mismatch_denied",
                    kmodule_dmverity_roothash_policy("sha512", matching=False),
                    layout.guest.dmverity_kmodule_test_binary("sha512", signed=True),
                    allowed=False,
                ),
            ),
            (
                partial(ipe.set_enforcement, False),
                *(
                    partial(
                        mounts.dmverity,
                        prefix=DMVERITY_DEVICE_PREFIX,
                        algorithm=algorithm,
                        signed=signed,
                    )
                    for algorithm in hashes.ALGORITHMS
                    for signed in (True, False)
                ),
                partial(mounts.tmpfs, layout.guest.PLAIN_MOUNT_DIR),
                partial(
                    files.copy_kmodule_test_binary,
                    layout.guest.PLAIN_KMODULE_TEST_BINARY,
                ),
            ),
            scope=partial(
                runtime.batch_scope,
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
