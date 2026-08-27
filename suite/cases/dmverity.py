# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import ipe
import layout
import mounts
from assets import (
    KMODULE_ROOTHASH_MISMATCH_POLICY,
    KMODULE_ROOTHASH_POLICY,
    KMODULE_SIGNATURE_FALSE_POLICY,
    KMODULE_SIGNATURE_TRUE_POLICY,
)
from model import Batch

from . import kmodule

SIGNED = layout.dmverity_mount(layout.HASH_ALGORITHM, signed=True)
UNSIGNED = layout.dmverity_mount(layout.HASH_ALGORITHM, signed=False)
PLAIN = layout.PLAIN_MOUNT
MODULE = layout.TEST_MODULE_FILE


def build():
    return (
        Batch(
            "dmverity",
            (
                kmodule.case(
                    "kmodule_signature_true_signed_ok",
                    KMODULE_SIGNATURE_TRUE_POLICY,
                    SIGNED / MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_signature_true_unsigned_denied",
                    KMODULE_SIGNATURE_TRUE_POLICY,
                    UNSIGNED / MODULE,
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
                    SIGNED / MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_signature_false_unsigned_denied",
                    KMODULE_SIGNATURE_FALSE_POLICY,
                    UNSIGNED / MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_signature_false_plain_denied",
                    KMODULE_SIGNATURE_FALSE_POLICY,
                    PLAIN / MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_roothash_signed_ok",
                    KMODULE_ROOTHASH_POLICY,
                    SIGNED / MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_roothash_unsigned_ok",
                    KMODULE_ROOTHASH_POLICY,
                    UNSIGNED / MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_roothash_plain_denied",
                    KMODULE_ROOTHASH_POLICY,
                    PLAIN / MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_roothash_mismatch_denied",
                    KMODULE_ROOTHASH_MISMATCH_POLICY,
                    SIGNED / MODULE,
                    allowed=False,
                ),
            ),
            (
                partial(ipe.set_enforcement, False),
                partial(mounts.dmverity, layout.HASH_ALGORITHM, True),
                partial(mounts.dmverity, layout.HASH_ALGORITHM, False),
                partial(mounts.tmpfs, PLAIN, layout.PAYLOAD / MODULE),
            ),
        ),
    )
