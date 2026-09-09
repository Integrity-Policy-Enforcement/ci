# SPDX-License-Identifier: GPL-2.0-only

import errno
import shutil
from functools import partial

import files
import hashes
import ipe
import layout
import mounts
from assets import (
    FIRMWARE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    FIRMWARE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    KEXEC_IMAGE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KEXEC_IMAGE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    KEXEC_INITRAMFS_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KEXEC_INITRAMFS_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    firmware_dmverity_roothash_policy,
    kexec_image_dmverity_roothash_policy,
    kmodule_dmverity_roothash_policy,
)
from model import Batch, Case

from . import firmware, kexec, kmodule

# Signed/unsigned refers to the mapping's root-hash signature, not an
# embedded module signature or a signature attached to an input file.

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
        # Policy: KMODULE default DENY; ALLOW matching dmverity_roothash.
        # Input: .ko on signed dm-verity; the mapping's root hash matches.
        # Match: root-hash rule -> ALLOW; this rule does not require a signature.
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_dmverity_roothash_{algorithm}_signed_ok",
            policy=matching_root_hash_policy,
            binary=signed_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        # Policy: KMODULE default DENY; ALLOW matching dmverity_roothash.
        # Input: .ko on dm-verity without a root-hash signature; the hash matches.
        # Match: root-hash rule -> ALLOW despite the missing signature.
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_dmverity_roothash_{algorithm}_unsigned_ok",
            policy=matching_root_hash_policy,
            binary=unsigned_kmodule_binary,
            expected_returncode=0,
            expected_loaded=True,
        ),
        # Policy: KMODULE default DENY; ALLOW matching dmverity_roothash.
        # Input: the same .ko on plain tmpfs, with no dm-verity hash or signature.
        # Match: no root-hash property -> no ALLOW match -> default DENY.
        kmodule.insmod_case(
            id=f"kmodule_kernel_read_insmod_dmverity_roothash_{algorithm}_plain_denied",
            policy=matching_root_hash_policy,
            binary=plain_kmodule_binary,
            expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
            expected_loaded=False,
        ),
        # Policy: KMODULE default DENY; ALLOW a different dmverity_roothash.
        # Input: .ko on signed dm-verity; its root hash differs from the policy.
        # Match: hash mismatch -> default DENY, even with a valid signature.
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
                # Policy: KEXEC_INITRAMFS default DENY; ALLOW dmverity_signature=TRUE.
                # Input: CPIO on dm-verity with a trusted root-hash signature, by original fd;
                #        the fixed kernel is on the payload and KEXEC_IMAGE is allowed.
                # Match: the initramfs mapping's TRUE signature -> ALLOW; stage then unload.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"dmverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=KEXEC_INITRAMFS_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.dmverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_INITRAMFS default DENY; ALLOW dmverity_signature=TRUE.
                # Input: the same CPIO on dm-verity without a root-hash signature;
                #        the fixed kernel and its KEXEC_IMAGE permission are unchanged.
                # Match: TRUE does not match -> default DENY (EACCES); nothing is staged.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"dmverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=KEXEC_INITRAMFS_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.dmverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_INITRAMFS default DENY; ALLOW dmverity_signature=TRUE.
                # Input: the same CPIO on plain tmpfs, with no dm-verity mapping;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: no mapping signature -> no TRUE match -> default DENY.
                kexec.initramfs_load_case(
                    id="kexec_initramfs_kernel_read_kexec_file_load_dmverity_signature_true_plain_denied",
                    policy=KEXEC_INITRAMFS_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                    binary=layout.guest.PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_INITRAMFS default ALLOW; DENY dmverity_signature=FALSE.
                # Input: CPIO on dm-verity with a verified root-hash signature;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: FALSE does not match -> default ALLOW; stage then unload.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"dmverity_signature_false_{algorithm}_signed_ok"
                        ),
                        policy=KEXEC_INITRAMFS_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.dmverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_INITRAMFS default ALLOW; DENY dmverity_signature=FALSE.
                # Input: CPIO on dm-verity without a root-hash signature;
                #        the fixed kernel remains permitted under KEXEC_IMAGE.
                # Match: FALSE matches -> explicit DENY, not the default ALLOW.
                *(
                    kexec.initramfs_load_case(
                        id=(
                            "kexec_initramfs_kernel_read_kexec_file_load_"
                            f"dmverity_signature_false_{algorithm}_unsigned_denied"
                        ),
                        policy=KEXEC_INITRAMFS_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                        binary=layout.guest.dmverity_kexec_initramfs_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: the real kernel image on signed dm-verity, passed by original fd.
                # Match: TRUE matches -> ALLOW; stage the image, then unload without executing.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"dmverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=KEXEC_IMAGE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.dmverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: the same real kernel image on unsigned dm-verity, using its original fd.
                # Match: TRUE does not match -> EACCES; no image may remain staged.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"dmverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=KEXEC_IMAGE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.dmverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: the real kernel image on plain tmpfs, without dm-verity.
                # Match: TRUE does not match -> EACCES; nothing is staged.
                kexec.file_load_case(
                    id="kexec_image_kernel_read_kexec_file_load_dmverity_signature_true_plain_denied",
                    policy=KEXEC_IMAGE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.PLAIN_KEXEC_IMAGE_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: the real kernel image on signed dm-verity.
                # Match: FALSE does not match -> default ALLOW; unload after checking.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"dmverity_signature_false_{algorithm}_signed_ok"
                        ),
                        policy=KEXEC_IMAGE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.dmverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: the same kernel image on dm-verity without a root-hash signature.
                # Match: FALSE matches -> explicit DENY; nothing is staged.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"dmverity_signature_false_{algorithm}_unsigned_denied"
                        ),
                        policy=KEXEC_IMAGE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.dmverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: the kernel image on plain tmpfs, without dm-verity metadata.
                # Match: absence counts as FALSE -> explicit DENY.
                kexec.file_load_case(
                    id="kexec_image_kernel_read_kexec_file_load_dmverity_signature_false_plain_denied",
                    policy=KEXEC_IMAGE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.PLAIN_KEXEC_IMAGE_TEST_BINARY,
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW matching dmverity_roothash.
                # Input: a real kernel image on signed dm-verity; the root hash matches.
                # Match: root-hash rule -> ALLOW; verify staging, then unload.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"dmverity_roothash_{algorithm}_signed_ok"
                        ),
                        policy=kexec_image_dmverity_roothash_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.dmverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW matching dmverity_roothash.
                # Input: the same kernel image on unsigned dm-verity; the hash matches.
                # Match: root-hash rule -> ALLOW without a root-hash signature.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"dmverity_roothash_{algorithm}_unsigned_ok"
                        ),
                        policy=kexec_image_dmverity_roothash_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.dmverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW matching dmverity_roothash.
                # Input: identical kernel bytes on plain tmpfs; no root hash exists.
                # Match: no property -> no ALLOW match -> EACCES.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"dmverity_roothash_{algorithm}_plain_denied"
                        ),
                        policy=kexec_image_dmverity_roothash_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.PLAIN_KEXEC_IMAGE_TEST_BINARY,
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW a different dmverity_roothash.
                # Input: a signed dm-verity kernel image whose root hash differs.
                # Match: hash mismatch -> EACCES despite the valid signature.
                *(
                    kexec.file_load_case(
                        id=(
                            "kexec_image_kernel_read_kexec_file_load_"
                            f"dmverity_roothash_{algorithm}_mismatch_denied"
                        ),
                        policy=kexec_image_dmverity_roothash_policy(
                            algorithm=algorithm, matching=False
                        ),
                        binary=layout.guest.dmverity_kexec_image_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=errno.EACCES,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: a userspace buffer read from a signed SHA-256 dm-verity image.
                # Match: KERNEL_LOAD has no file/device context -> EACCES before segment checks.
                kexec.buffer_load_case(
                    id="kexec_image_kernel_load_kexec_load_dmverity_signature_true_signed_denied",
                    policy=KEXEC_IMAGE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.dmverity_kexec_image_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: a userspace buffer from an unsigned SHA-256 dm-verity image.
                # Match: no file/device context -> EACCES before segment validation.
                kexec.buffer_load_case(
                    id="kexec_image_kernel_load_kexec_load_dmverity_signature_true_unsigned_denied",
                    policy=KEXEC_IMAGE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.dmverity_kexec_image_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: userspace bytes read from a signed SHA-256 dm-verity image.
                # Match: KERNEL_LOAD has no device context; FALSE matches -> EACCES.
                kexec.buffer_load_case(
                    id="kexec_image_kernel_load_kexec_load_dmverity_signature_false_signed_denied",
                    policy=KEXEC_IMAGE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.dmverity_kexec_image_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: userspace bytes read from an unsigned SHA-256 dm-verity image.
                # Match: no device context makes the property FALSE -> explicit DENY.
                kexec.buffer_load_case(
                    id="kexec_image_kernel_load_kexec_load_dmverity_signature_false_unsigned_denied",
                    policy=KEXEC_IMAGE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.dmverity_kexec_image_test_binary(
                        algorithm="sha256", signed=False
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: KEXEC_IMAGE default DENY; ALLOW the source mapping's root hash.
                # Input: userspace bytes from the matching signed SHA-256 mapping.
                # Match: KERNEL_LOAD has no root-hash context -> EACCES.
                kexec.buffer_load_case(
                    id="kexec_image_kernel_load_kexec_load_dmverity_roothash_sha256_signed_denied",
                    policy=kexec_image_dmverity_roothash_policy(
                        algorithm="sha256", matching=True
                    ),
                    binary=layout.guest.dmverity_kexec_image_test_binary(
                        algorithm="sha256", signed=True
                    ),
                    expected_errno=errno.EACCES,
                    expected_loaded=False,
                ),
                # Policy: FIRMWARE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: .fw on a mapping opened with a trusted root-hash signature.
                # Match: the mapping signature is TRUE -> the ALLOW rule matches.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"dmverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=FIRMWARE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.dmverity_firmware_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content_match=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: .fw on dm-verity without a root-hash signature.
                # Match: TRUE does not match -> default DENY; search ends in ENOENT.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"dmverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=FIRMWARE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.dmverity_firmware_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.ENOENT,
                        expected_content_match=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: the same .fw bytes on plain tmpfs, without dm-verity.
                # Match: no mapping signature -> default DENY; search ends in ENOENT.
                firmware.request_firmware_case(
                    id=(
                        "firmware_kernel_read_request_firmware_"
                        "dmverity_signature_true_plain_denied"
                    ),
                    policy=FIRMWARE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.PLAIN_FIRMWARE_TEST_BINARY,
                    expected_errno=errno.ENOENT,
                    expected_content_match=False,
                ),
                # Policy: FIRMWARE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: .fw on dm-verity with a verified root-hash signature.
                # Match: FALSE does not match -> default ALLOW.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"dmverity_signature_false_{algorithm}_signed_ok"
                        ),
                        policy=FIRMWARE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.dmverity_firmware_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content_match=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: .fw on dm-verity without a root-hash signature.
                # Match: FALSE matches -> explicit DENY; search ends in ENOENT.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"dmverity_signature_false_{algorithm}_unsigned_denied"
                        ),
                        policy=FIRMWARE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.dmverity_firmware_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=errno.ENOENT,
                        expected_content_match=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: .fw on plain tmpfs, with no dm-verity metadata.
                # Match: absence counts as FALSE -> explicit DENY, not default denial.
                firmware.request_firmware_case(
                    id=(
                        "firmware_kernel_read_request_firmware_"
                        "dmverity_signature_false_plain_denied"
                    ),
                    policy=FIRMWARE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                    binary=layout.guest.PLAIN_FIRMWARE_TEST_BINARY,
                    expected_errno=errno.ENOENT,
                    expected_content_match=False,
                ),
                # Policy: FIRMWARE default DENY; ALLOW matching dmverity_roothash.
                # Input: .fw on signed dm-verity; the mapping's root hash matches.
                # Match: root-hash rule -> ALLOW; this rule does not require a signature.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"dmverity_roothash_{algorithm}_signed_ok"
                        ),
                        policy=firmware_dmverity_roothash_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.dmverity_firmware_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=0,
                        expected_content_match=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default DENY; ALLOW matching dmverity_roothash.
                # Input: .fw on unsigned dm-verity; the root hash still matches.
                # Match: root-hash rule -> ALLOW without a root-hash signature.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"dmverity_roothash_{algorithm}_unsigned_ok"
                        ),
                        policy=firmware_dmverity_roothash_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.dmverity_firmware_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_errno=0,
                        expected_content_match=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default DENY; ALLOW matching dmverity_roothash.
                # Input: .fw on plain tmpfs; no dm-verity root-hash property exists.
                # Match: no ALLOW match -> default DENY; search ends in ENOENT.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"dmverity_roothash_{algorithm}_plain_denied"
                        ),
                        policy=firmware_dmverity_roothash_policy(
                            algorithm=algorithm, matching=True
                        ),
                        binary=layout.guest.PLAIN_FIRMWARE_TEST_BINARY,
                        expected_errno=errno.ENOENT,
                        expected_content_match=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: FIRMWARE default DENY; ALLOW a different dmverity_roothash.
                # Input: .fw on signed dm-verity; its root hash differs from the rule.
                # Match: hash mismatch -> default DENY despite the valid signature.
                *(
                    firmware.request_firmware_case(
                        id=(
                            "firmware_kernel_read_request_firmware_"
                            f"dmverity_roothash_{algorithm}_mismatch_denied"
                        ),
                        policy=firmware_dmverity_roothash_policy(
                            algorithm=algorithm, matching=False
                        ),
                        binary=layout.guest.dmverity_firmware_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_errno=errno.ENOENT,
                        expected_content_match=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: .ko on dm-verity with a verified root-hash signature.
                # Match: the mapping signature is TRUE -> ALLOW.
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
                # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: .ko.gz on signed dm-verity, passed for kernel decompression.
                # Match: the original file's mapping signature is TRUE -> ALLOW.
                # A userspace-decompressed buffer has no mapping and cannot pass.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"dmverity_signature_true_{algorithm}_signed_ok"
                        ),
                        policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.dmverity_compressed_kmodule_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_returncode=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: .ko.gz on dm-verity without a root-hash signature.
                # Match: TRUE does not match -> default DENY; compression adds no trust.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_compressed_"
                            f"dmverity_signature_true_{algorithm}_unsigned_denied"
                        ),
                        policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.dmverity_compressed_kmodule_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: a buffer read from the .ko on signed SHA-256 dm-verity.
                # Match: KERNEL_LOAD has no file/device context -> default DENY.
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
                # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: .ko on dm-verity without a root-hash signature.
                # Match: the signature is FALSE -> no ALLOW match -> default DENY.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_dmverity_signature_true_"
                            f"{algorithm}_unsigned_denied"
                        ),
                        policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                        binary=layout.guest.dmverity_kmodule_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: a buffer read from the .ko on unsigned SHA-256 dm-verity.
                # Match: KERNEL_LOAD has no file/device context -> default DENY.
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
                # Policy: KMODULE default DENY; ALLOW dmverity_signature=TRUE.
                # Input: .ko on plain tmpfs; neither dm-verity nor its signature exists.
                # Match: TRUE does not match -> default DENY.
                kmodule.insmod_case(
                    id="kmodule_kernel_read_insmod_dmverity_signature_true_plain_denied",
                    policy=KMODULE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                    binary=layout.guest.PLAIN_KMODULE_TEST_BINARY,
                    expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                    expected_loaded=False,
                ),
                # Policy: KMODULE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: .ko on dm-verity with a verified root-hash signature.
                # Match: FALSE does not match -> default ALLOW, not the DENY rule.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_dmverity_signature_false_"
                            f"{algorithm}_signed_ok"
                        ),
                        policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.dmverity_kmodule_test_binary(
                            algorithm=algorithm, signed=True
                        ),
                        expected_returncode=0,
                        expected_loaded=True,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: a buffer read from the .ko on signed SHA-256 dm-verity.
                # Match: no file/device context makes the property FALSE -> DENY.
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
                # Policy: KMODULE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: .ko on dm-verity without a root-hash signature.
                # Match: FALSE matches -> the explicit DENY rule applies.
                *(
                    kmodule.insmod_case(
                        id=(
                            "kmodule_kernel_read_insmod_dmverity_signature_false_"
                            f"{algorithm}_unsigned_denied"
                        ),
                        policy=KMODULE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
                        binary=layout.guest.dmverity_kmodule_test_binary(
                            algorithm=algorithm, signed=False
                        ),
                        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
                        expected_loaded=False,
                    )
                    for algorithm in hashes.DMVERITY_ALGORITHMS
                ),
                # Policy: KMODULE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: a buffer read from the .ko on unsigned SHA-256 dm-verity.
                # Match: no file/device context makes the property FALSE -> DENY.
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
                # Policy: KMODULE default ALLOW; DENY dmverity_signature=FALSE.
                # Input: .ko on plain tmpfs, without any dm-verity metadata.
                # Match: absence counts as FALSE -> the explicit DENY rule matches.
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
                # Policy: KMODULE default DENY; ALLOW the source mapping's root hash.
                # Input: a buffer read from the .ko on matching, signed SHA-256 dm-verity.
                # Match: KERNEL_LOAD has no root-hash context -> default DENY.
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
                    files.copy_test_binary,
                    source=layout.guest.KMODULE_TEST_BINARY,
                    target=layout.guest.PLAIN_KMODULE_TEST_BINARY,
                ),
                partial(
                    layout.guest.PLAIN_FIRMWARE_TEST_BINARY.parent.mkdir,
                    parents=True,
                    exist_ok=True,
                ),
                partial(
                    shutil.copy,
                    src=layout.guest.FIRMWARE_TEST_BINARY,
                    dst=layout.guest.PLAIN_FIRMWARE_TEST_BINARY,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                    target=layout.guest.PLAIN_KEXEC_IMAGE_TEST_BINARY,
                ),
                partial(
                    files.copy_test_binary,
                    source=layout.guest.KEXEC_INITRAMFS_TEST_BINARY,
                    target=layout.guest.PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
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
