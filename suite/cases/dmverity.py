# SPDX-License-Identifier: GPL-2.0-only

import errno
from functools import partial

import files
import hashes
import ipe
import layout
import mounts
from assets import (
    FIRMWARE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    kmodule_dmverity_roothash_policy,
)
from model import Batch, Case

from . import firmware, kmodule

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
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_dmverity_roothash_{algorithm}_signed_ok",
            policy=matching_root_hash_policy,
            binary=signed_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_dmverity_roothash_{algorithm}_unsigned_ok",
            policy=matching_root_hash_policy,
            binary=unsigned_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_dmverity_roothash_{algorithm}_plain_denied",
            policy=matching_root_hash_policy,
            binary=plain_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_dmverity_roothash_{algorithm}_mismatch_denied",
            policy=mismatching_root_hash_policy,
            binary=signed_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
    )


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            id="dmverity",
            cases=(
                firmware.request_firmware_case(
                    id=(
                        "firmware_kernel_read_request_firmware_"
                        "dmverity_signature_true_sha256_signed_ok"
                    ),
                    policy=FIRMWARE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.dmverity_firmware_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_errno=0,
                    expected_content_match=True,
                ),
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_dmverity_signature_true_"
                            f"{algorithm}_signed_ok"
                        ),
                        policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.dmverity_kmodule_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_returncode=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # A userspace-decompressed buffer cannot pass this policy.
                # Success requires finit_module's in-kernel compressed-file path.
                kmodule.insmod_case(
                    id=(
                        "kmodule_kernel_read_insmod_compressed_"
                        "dmverity_signature_true_sha256_signed_ok"
                    ),
                    policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.dmverity_compressed_kmodule_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_returncode=0,
                    expected_loaded=True,
                ),
                kmodule.insmod_case(
                    id=(
                        "kmodule_kernel_read_insmod_compressed_"
                        "dmverity_signature_true_sha256_unsigned_denied"
                    ),
                    policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.dmverity_compressed_kmodule_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "dmverity_signature_true_signed_denied"
                    ),
                    policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                kmodule.insmod_case(
                    id="kmodule_kernel_read_insmod_dmverity_signature_true_unsigned_denied",
                    policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "dmverity_signature_true_unsigned_denied"
                    ),
                    policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                kmodule.insmod_case(
                    id="kmodule_kernel_read_insmod_dmverity_signature_true_plain_denied",
                    policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.PLAIN_KMODULE_TEST_BINARY,
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                kmodule.insmod_case(
                    id="kmodule_kernel_read_insmod_dmverity_signature_false_signed_ok",
                    policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_returncode=0,
                    expected_loaded=True,
                ),
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "dmverity_signature_false_signed_denied"
                    ),
                    policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                kmodule.insmod_case(
                    id="kmodule_kernel_read_insmod_dmverity_signature_false_unsigned_denied",
                    policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "dmverity_signature_false_unsigned_denied"
                    ),
                    policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                kmodule.insmod_case(
                    id="kmodule_kernel_read_insmod_dmverity_signature_false_plain_denied",
                    policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.PLAIN_KMODULE_TEST_BINARY,
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                *(
                    test_case
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                    for test_case in roothash_cases(algorithm=algorithm)
                ),
                kmodule.init_module_case(
                    id=(
                        "kmodule_kernel_load_init_module_"
                        "dmverity_roothash_sha256_signed_denied"
                    ),
                    policy=kmodule_dmverity_roothash_policy(
                        algorithm="sha256", matching=True
                    ),
                    binary=layout.guest.dmverity_kmodule_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
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
