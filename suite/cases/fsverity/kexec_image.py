# SPDX-License-Identifier: GPL-2.0-only
"""KEXEC_IMAGE file and buffer cases using fs-verity properties."""

import errno

import hashes
import layout
from assets import (
    KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    kexec_image_fsverity_digest_policy,
)
from model import Case

from .. import kexec


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: KEXEC_IMAGE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: a real kernel image with a verified built-in fs-verity signature.
        # Match: TRUE matches -> ALLOW; check staging before unloading.
        *(
            kexec.file_load_case(
                id=(
                    "kexec_image_kernel_read_kexec_file_load_"
                    f"fsverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_kexec_image_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_loaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_IMAGE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: a real kernel image with fs-verity but no built-in signature.
        # Match: TRUE does not match -> EACCES; nothing is staged.
        *(
            kexec.file_load_case(
                id=(
                    "kexec_image_kernel_read_kexec_file_load_"
                    f"fsverity_signature_true_{algorithm}_unsigned_denied"
                ),
                policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                binary=layout.guest.fsverity_kexec_image_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_loaded=False,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_IMAGE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: identical kernel bytes without any fs-verity metadata.
        # Match: TRUE does not match -> EACCES.
        kexec.file_load_case(
            id="kexec_image_kernel_read_kexec_file_load_fsverity_signature_true_plain_denied",
            policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_KEXEC_IMAGE_TEST_BINARY,
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KEXEC_IMAGE default ALLOW; DENY fsverity_signature=FALSE.
        # Input: a kernel image with a verified built-in fs-verity signature.
        # Match: FALSE does not match -> default ALLOW; unload after checking.
        *(
            kexec.file_load_case(
                id=(
                    "kexec_image_kernel_read_kexec_file_load_"
                    f"fsverity_signature_false_{algorithm}_signed_ok"
                ),
                policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.fsverity_kexec_image_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_loaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_IMAGE default ALLOW; DENY fsverity_signature=FALSE.
        # Input: an unsigned fs-verity kernel image; verity remains enabled.
        # Match: FALSE matches -> explicit DENY; nothing is staged.
        *(
            kexec.file_load_case(
                id=(
                    "kexec_image_kernel_read_kexec_file_load_"
                    f"fsverity_signature_false_{algorithm}_unsigned_denied"
                ),
                policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                binary=layout.guest.fsverity_kexec_image_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_loaded=False,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_IMAGE default ALLOW; DENY fsverity_signature=FALSE.
        # Input: the real kernel image without any fs-verity metadata.
        # Match: absence counts as FALSE -> explicit DENY.
        kexec.file_load_case(
            id="kexec_image_kernel_read_kexec_file_load_fsverity_signature_false_plain_denied",
            policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=layout.guest.FSVERITY_PLAIN_KEXEC_IMAGE_TEST_BINARY,
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KEXEC_IMAGE default DENY; ALLOW matching fsverity_digest.
        # Input: a signed fs-verity kernel image; its own digest matches.
        # Match: digest rule -> ALLOW; verify staging and unload.
        *(
            kexec.file_load_case(
                id=(
                    "kexec_image_kernel_read_kexec_file_load_"
                    f"fsverity_digest_{algorithm}_signed_ok"
                ),
                policy=kexec_image_fsverity_digest_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.fsverity_kexec_image_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_loaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_IMAGE default DENY; ALLOW matching fsverity_digest.
        # Input: an unsigned fs-verity kernel image whose digest matches.
        # Match: digest rule -> ALLOW without a built-in signature.
        *(
            kexec.file_load_case(
                id=(
                    "kexec_image_kernel_read_kexec_file_load_"
                    f"fsverity_digest_{algorithm}_unsigned_ok"
                ),
                policy=kexec_image_fsverity_digest_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.fsverity_kexec_image_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=0,
                expected_loaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_IMAGE default DENY; ALLOW matching fsverity_digest.
        # Input: identical kernel bytes with fs-verity disabled.
        # Match: no digest property -> default DENY, not a hash mismatch.
        *(
            kexec.file_load_case(
                id=(
                    "kexec_image_kernel_read_kexec_file_load_"
                    f"fsverity_digest_{algorithm}_plain_denied"
                ),
                policy=kexec_image_fsverity_digest_policy(
                    algorithm=algorithm, matching=True
                ),
                binary=layout.guest.FSVERITY_PLAIN_KEXEC_IMAGE_TEST_BINARY,
                expected_errno=errno.EACCES,
                expected_loaded=False,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_IMAGE default DENY; ALLOW a different fsverity_digest.
        # Input: a signed fs-verity kernel image whose digest differs from the rule.
        # Match: digest mismatch -> EACCES despite the verified signature.
        *(
            kexec.file_load_case(
                id=(
                    "kexec_image_kernel_read_kexec_file_load_"
                    f"fsverity_digest_{algorithm}_mismatch_denied"
                ),
                policy=kexec_image_fsverity_digest_policy(
                    algorithm=algorithm, matching=False
                ),
                binary=layout.guest.fsverity_kexec_image_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_loaded=False,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_IMAGE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: a buffer read from a signed SHA-256 fs-verity kernel image.
        # Match: KERNEL_LOAD has no inode; TRUE cannot match -> EACCES.
        kexec.buffer_load_case(
            id="kexec_image_kernel_load_kexec_load_fsverity_signature_true_signed_denied",
            policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.fsverity_kexec_image_test_binary(
                algorithm="sha256", signed=True
            ),
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KEXEC_IMAGE default DENY; ALLOW fsverity_signature=TRUE.
        # Input: a buffer read from an unsigned SHA-256 fs-verity kernel image.
        # Match: KERNEL_LOAD has no inode/signature context -> EACCES.
        kexec.buffer_load_case(
            id="kexec_image_kernel_load_kexec_load_fsverity_signature_true_unsigned_denied",
            policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            binary=layout.guest.fsverity_kexec_image_test_binary(
                algorithm="sha256", signed=False
            ),
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KEXEC_IMAGE default ALLOW; DENY fsverity_signature=FALSE.
        # Input: userspace bytes from a signed SHA-256 fs-verity kernel image.
        # Match: no inode makes the signature property FALSE -> explicit DENY.
        kexec.buffer_load_case(
            id="kexec_image_kernel_load_kexec_load_fsverity_signature_false_signed_denied",
            policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=layout.guest.fsverity_kexec_image_test_binary(
                algorithm="sha256", signed=True
            ),
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KEXEC_IMAGE default ALLOW; DENY fsverity_signature=FALSE.
        # Input: userspace bytes from an unsigned SHA-256 fs-verity kernel image.
        # Match: no inode context makes the property FALSE -> EACCES.
        kexec.buffer_load_case(
            id="kexec_image_kernel_load_kexec_load_fsverity_signature_false_unsigned_denied",
            policy=KEXEC_IMAGE_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
            binary=layout.guest.fsverity_kexec_image_test_binary(
                algorithm="sha256", signed=False
            ),
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KEXEC_IMAGE default DENY; ALLOW the source file's fsverity_digest.
        # Input: a buffer from a signed kernel image with a matching SHA-256 digest.
        # Match: KERNEL_LOAD has no inode/digest property -> EACCES.
        kexec.buffer_load_case(
            id="kexec_image_kernel_load_kexec_load_fsverity_digest_sha256_signed_denied",
            policy=kexec_image_fsverity_digest_policy(
                algorithm="sha256", matching=True
            ),
            binary=layout.guest.fsverity_kexec_image_test_binary(
                algorithm="sha256", signed=True
            ),
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
    )
