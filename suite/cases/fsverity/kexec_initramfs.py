# SPDX-License-Identifier: GPL-2.0-only
"""KEXEC_INITRAMFS file-read cases using fs-verity properties."""

import errno

import hashes
import layout
from assets import (
    KEXEC_INITRAMFS_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KEXEC_INITRAMFS_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    kexec_initramfs_fsverity_digest_policy,
)
from model import Case
from operations import kexec


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
        # Policy: KEXEC_INITRAMFS default DENY; ALLOW fsverity_signature=TRUE.
        # Input: CPIO with fs-verity enabled and a built-in signature over its digest;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: the CPIO's verified signature is TRUE -> ALLOW; stage then unload.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"fsverity_signature_true_{algorithm}_signed_ok"
                ),
                policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_loaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_INITRAMFS default DENY; ALLOW fsverity_signature=TRUE.
        # Input: CPIO with fs-verity enabled but no built-in digest signature;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: TRUE does not match -> default DENY; nothing is staged.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"fsverity_signature_true_{algorithm}_unsigned_denied"
                ),
                policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_loaded=False,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_INITRAMFS default DENY; ALLOW fsverity_signature=TRUE.
        # Input: the same CPIO bytes without fs-verity or a built-in signature;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: TRUE does not match -> default DENY.
        kexec.initramfs_load_case(
            id="kexec_initramfs_kernel_read_kexec_file_load_fsverity_signature_true_plain_denied",
            policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
            kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
            binary=layout.guest.FSVERITY_PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KEXEC_INITRAMFS default ALLOW; DENY fsverity_signature=FALSE.
        # Input: CPIO with a verified built-in signature over its fs-verity digest;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: FALSE does not match -> default ALLOW; stage then unload.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"fsverity_signature_false_{algorithm}_signed_ok"
                ),
                policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_loaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_INITRAMFS default ALLOW; DENY fsverity_signature=FALSE.
        # Input: CPIO with fs-verity enabled but no built-in digest signature;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: FALSE matches -> explicit DENY, not the default ALLOW.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"fsverity_signature_false_{algorithm}_unsigned_denied"
                ),
                policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=errno.EACCES,
                expected_loaded=False,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_INITRAMFS default ALLOW; DENY fsverity_signature=FALSE.
        # Input: the same CPIO without fs-verity metadata or a built-in signature;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: absence counts as FALSE -> explicit DENY.
        kexec.initramfs_load_case(
            id="kexec_initramfs_kernel_read_kexec_file_load_fsverity_signature_false_plain_denied",
            policy=KEXEC_INITRAMFS_FSVERITY_SIGNATURE_FALSE_DENY_POLICY,
            kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
            binary=layout.guest.FSVERITY_PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KEXEC_INITRAMFS default DENY; ALLOW matching fsverity_digest.
        # Input: signed fs-verity CPIO whose own measured digest matches the rule;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: digest rule -> ALLOW; a built-in signature is not required.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"fsverity_digest_{algorithm}_signed_ok"
                ),
                policy=kexec_initramfs_fsverity_digest_policy(
                    algorithm=algorithm, matching=True
                ),
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_loaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_INITRAMFS default DENY; ALLOW matching fsverity_digest.
        # Input: unsigned fs-verity CPIO whose own digest matches the rule;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: digest rule -> ALLOW without a built-in digest signature.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"fsverity_digest_{algorithm}_unsigned_ok"
                ),
                policy=kexec_initramfs_fsverity_digest_policy(
                    algorithm=algorithm, matching=True
                ),
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=0,
                expected_loaded=True,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_INITRAMFS default DENY; ALLOW matching fsverity_digest.
        # Input: identical CPIO bytes with fs-verity disabled;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: no digest property -> default DENY, not a digest mismatch.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"fsverity_digest_{algorithm}_plain_denied"
                ),
                policy=kexec_initramfs_fsverity_digest_policy(
                    algorithm=algorithm, matching=True
                ),
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.FSVERITY_PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
                expected_errno=errno.EACCES,
                expected_loaded=False,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_INITRAMFS default DENY; ALLOW a different fsverity_digest.
        # Input: signed fs-verity CPIO whose digest differs from the rule;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: digest mismatch -> default DENY despite the built-in signature.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"fsverity_digest_{algorithm}_mismatch_denied"
                ),
                policy=kexec_initramfs_fsverity_digest_policy(
                    algorithm=algorithm, matching=False
                ),
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.fsverity_kexec_initramfs_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_loaded=False,
            )
            for algorithm in hashes.FSVERITY_ALGORITHMS
        ),
    )
