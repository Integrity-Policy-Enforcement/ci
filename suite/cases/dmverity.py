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
from model import Batch, Case

from . import kmodule

# dm-verity mappings under this prefix are reserved for batch cleanup.
DMVERITY_DEVICE_PREFIX = "ipe-dmverity-"


def roothash_cases(*, algorithm: str) -> tuple[Case, ...]:
    """The root-hash cases for one algorithm."""
    matching_root_hash_policy = kmodule_dmverity_roothash_policy(
        algorithm=algorithm, matching=True
    )
    mismatching_root_hash_policy = kmodule_dmverity_roothash_policy(
        algorithm=algorithm, matching=False
    )
    signed_kmodule_binary = layout.guest.dmverity_kmodule_test_binary(
        algorithm=algorithm, signed=True
    )
    unsigned_kmodule_binary = layout.guest.dmverity_kmodule_test_binary(
        algorithm=algorithm, signed=False
    )
    plain_kmodule_binary = layout.guest.PLAIN_KMODULE_TEST_BINARY
    return (
        kmodule.case(
            id=f"kmodule_dmverity_roothash_{algorithm}_signed_ok",
            policy=matching_root_hash_policy,
            binary=signed_kmodule_binary,
            allowed=True,
        ),
        kmodule.case(
            id=f"kmodule_dmverity_roothash_{algorithm}_unsigned_ok",
            policy=matching_root_hash_policy,
            binary=unsigned_kmodule_binary,
            allowed=True,
        ),
        kmodule.case(
            id=f"kmodule_dmverity_roothash_{algorithm}_plain_denied",
            policy=matching_root_hash_policy,
            binary=plain_kmodule_binary,
            allowed=False,
        ),
        kmodule.case(
            id=f"kmodule_dmverity_roothash_{algorithm}_mismatch_denied",
            policy=mismatching_root_hash_policy,
            binary=signed_kmodule_binary,
            allowed=False,
        ),
    )


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
                *(
                    test_case
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                    for test_case in roothash_cases(algorithm=algorithm)
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
