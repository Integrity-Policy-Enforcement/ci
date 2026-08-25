# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import files
import ipe
import layout
from assets import (
    FSVERITY_DIGEST_POLICY,
    FSVERITY_SIGNATURE_FALSE_POLICY,
    FSVERITY_SIGNATURE_TRUE_POLICY,
)
from model import Batch

from . import kmodule


def build():
    return (
        Batch(
            "fsverity",
            (
                kmodule.case(
                    "kmodule_fsverity_signature_true_signed_ok",
                    FSVERITY_SIGNATURE_TRUE_POLICY,
                    layout.FSVERITY_SIGNED_MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_fsverity_signature_true_unsigned_denied",
                    FSVERITY_SIGNATURE_TRUE_POLICY,
                    layout.FSVERITY_UNSIGNED_MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_fsverity_signature_true_plain_denied",
                    FSVERITY_SIGNATURE_TRUE_POLICY,
                    layout.FSVERITY_PLAIN_MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_fsverity_signature_false_signed_ok",
                    FSVERITY_SIGNATURE_FALSE_POLICY,
                    layout.FSVERITY_SIGNED_MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_fsverity_signature_false_unsigned_denied",
                    FSVERITY_SIGNATURE_FALSE_POLICY,
                    layout.FSVERITY_UNSIGNED_MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_fsverity_signature_false_plain_denied",
                    FSVERITY_SIGNATURE_FALSE_POLICY,
                    layout.FSVERITY_PLAIN_MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_fsverity_digest_signed_ok",
                    FSVERITY_DIGEST_POLICY,
                    layout.FSVERITY_SIGNED_MODULE,
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_fsverity_digest_unsigned_ok",
                    FSVERITY_DIGEST_POLICY,
                    layout.FSVERITY_UNSIGNED_MODULE,
                    allowed=True,
                ),
            ),
            (
                partial(ipe.set_enforcement, False),
                partial(
                    files.verity_module,
                    layout.FSVERITY_SIGNED_MODULE,
                    layout.FSVERITY_ASSETS / layout.FSVERITY_SIGNATURE,
                ),
                partial(files.verity_module, layout.FSVERITY_UNSIGNED_MODULE),
                partial(files.copy_module, layout.FSVERITY_PLAIN_MODULE),
            ),
        ),
    )
