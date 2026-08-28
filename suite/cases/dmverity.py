# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import ipe
import layout
import mounts
from assets import (
    KMODULE_SIGNATURE_FALSE_POLICY,
    KMODULE_SIGNATURE_TRUE_POLICY,
    roothash_policy,
)
from model import Batch

from . import kmodule

PLAIN = layout.guest.PLAIN_MOUNT
MODULE = layout.TEST_MODULE_FILE


def build():
    return (
        Batch(
            "dmverity",
            (
                kmodule.case(
                    "kmodule_signature_true_signed_ok",
                    KMODULE_SIGNATURE_TRUE_POLICY,
                    layout.guest.dmverity_mount("sha256", signed=True) / MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_signature_true_unsigned_denied",
                    KMODULE_SIGNATURE_TRUE_POLICY,
                    layout.guest.dmverity_mount("sha256", signed=False) / MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_signature_true_plain_denied",
                    KMODULE_SIGNATURE_TRUE_POLICY,
                    PLAIN / MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_signature_false_signed_ok",
                    KMODULE_SIGNATURE_FALSE_POLICY,
                    layout.guest.dmverity_mount("sha256", signed=True) / MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_signature_false_unsigned_denied",
                    KMODULE_SIGNATURE_FALSE_POLICY,
                    layout.guest.dmverity_mount("sha256", signed=False) / MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_signature_false_plain_denied",
                    KMODULE_SIGNATURE_FALSE_POLICY,
                    PLAIN / MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_roothash_sha256_signed_ok",
                    roothash_policy("sha256"),
                    layout.guest.dmverity_mount("sha256", signed=True) / MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_roothash_sha256_unsigned_ok",
                    roothash_policy("sha256"),
                    layout.guest.dmverity_mount("sha256", signed=False) / MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_roothash_sha256_plain_denied",
                    roothash_policy("sha256"),
                    PLAIN / MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_roothash_sha512_signed_ok",
                    roothash_policy("sha512"),
                    layout.guest.dmverity_mount("sha512", signed=True) / MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_roothash_sha512_unsigned_ok",
                    roothash_policy("sha512"),
                    layout.guest.dmverity_mount("sha512", signed=False) / MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_roothash_sha512_plain_denied",
                    roothash_policy("sha512"),
                    PLAIN / MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_roothash_sha256_mismatch_denied",
                    roothash_policy("sha256", matching=False),
                    layout.guest.dmverity_mount("sha256", signed=True) / MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_roothash_sha512_mismatch_denied",
                    roothash_policy("sha512", matching=False),
                    layout.guest.dmverity_mount("sha512", signed=True) / MODULE,
                    allowed=False,
                ),
            ),
            (
                partial(ipe.set_enforcement, False),
                *(
                    partial(mounts.dmverity, algorithm, signed)
                    for algorithm in layout.HASH_ALGORITHMS
                    for signed in (True, False)
                ),
                partial(mounts.tmpfs, PLAIN, layout.guest.PAYLOAD / MODULE),
            ),
        ),
    )
