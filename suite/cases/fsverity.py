# SPDX-License-Identifier: GPL-2.0-only

from functools import partial

import files
import ipe
import layout
from assets import (
    FSVERITY_SIGNATURE_FALSE_POLICY,
    FSVERITY_SIGNATURE_TRUE_POLICY,
    digest_policy,
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
                    layout.fsverity_signed_module("sha256"),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_fsverity_signature_true_unsigned_denied",
                    FSVERITY_SIGNATURE_TRUE_POLICY,
                    layout.fsverity_unsigned_module("sha256"),
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
                    layout.fsverity_signed_module("sha256"),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_fsverity_signature_false_unsigned_denied",
                    FSVERITY_SIGNATURE_FALSE_POLICY,
                    layout.fsverity_unsigned_module("sha256"),
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_fsverity_signature_false_plain_denied",
                    FSVERITY_SIGNATURE_FALSE_POLICY,
                    layout.FSVERITY_PLAIN_MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_fsverity_digest_sha256_signed_ok",
                    digest_policy("sha256"),
                    layout.fsverity_signed_module("sha256"),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_fsverity_digest_sha256_unsigned_ok",
                    digest_policy("sha256"),
                    layout.fsverity_unsigned_module("sha256"),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_fsverity_digest_sha256_plain_denied",
                    digest_policy("sha256"),
                    layout.FSVERITY_PLAIN_MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_fsverity_digest_sha512_signed_ok",
                    digest_policy("sha512"),
                    layout.fsverity_signed_module("sha512"),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_fsverity_digest_sha512_unsigned_ok",
                    digest_policy("sha512"),
                    layout.fsverity_unsigned_module("sha512"),
                    allowed=True,
                ),
                kmodule.case(
                    "kmodule_fsverity_digest_sha512_plain_denied",
                    digest_policy("sha512"),
                    layout.FSVERITY_PLAIN_MODULE,
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_fsverity_digest_sha256_mismatch_denied",
                    digest_policy("sha256", matching=False),
                    layout.fsverity_signed_module("sha256"),
                    allowed=False,
                ),
                kmodule.case(
                    "kmodule_fsverity_digest_sha512_mismatch_denied",
                    digest_policy("sha512", matching=False),
                    layout.fsverity_signed_module("sha512"),
                    allowed=False,
                ),
            ),
            (
                partial(ipe.set_enforcement, False),
                *(
                    partial(
                        files.verity_module,
                        layout.fsverity_signed_module(algorithm),
                        algorithm,
                        layout.FSVERITY_ASSETS / layout.fsverity_signature(algorithm),
                    )
                    for algorithm in layout.HASH_ALGORITHMS
                ),
                *(
                    partial(
                        files.verity_module,
                        layout.fsverity_unsigned_module(algorithm),
                        algorithm,
                    )
                    for algorithm in layout.HASH_ALGORITHMS
                ),
                partial(files.copy_module, layout.FSVERITY_PLAIN_MODULE),
            ),
        ),
    )
