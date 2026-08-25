# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import files
import ipe
import layout
from assets import FSVERITY_SIGNATURE_TRUE_POLICY
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
            ),
            (
                partial(ipe.set_enforcement, False),
                partial(
                    files.verity_module,
                    layout.FSVERITY_SIGNED_MODULE,
                    layout.FSVERITY_ASSETS / layout.FSVERITY_SIGNATURE,
                ),
            ),
        ),
    )
