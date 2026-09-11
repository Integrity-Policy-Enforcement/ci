# SPDX-License-Identifier: GPL-2.0-only
"""KEXEC_IMAGE file and buffer cases using dm-verity properties."""

import errno

import hashes
import layout
from assets import (
    KEXEC_IMAGE_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KEXEC_IMAGE_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    kexec_image_dmverity_roothash_policy,
)
from model import Case
from operations import kexec


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
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
    )
