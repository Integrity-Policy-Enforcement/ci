# SPDX-License-Identifier: GPL-2.0-only
"""KEXEC_INITRAMFS file-read cases using dm-verity properties."""

import errno

import hashes
import layout
from assets import (
    KEXEC_INITRAMFS_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
    KEXEC_INITRAMFS_DMVERITY_SIGNATURE_TRUE_ALLOW_POLICY,
    kexec_initramfs_dmverity_roothash_policy,
)
from model import Case
from operations import kexec


def cases() -> tuple[Case, ...]:
    """Return this operation's cases in their existing order."""
    return (
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
        # Policy: KEXEC_INITRAMFS default ALLOW; DENY dmverity_signature=FALSE.
        # Input: identical CPIO bytes on plain tmpfs, without dm-verity;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: absence counts as FALSE -> explicit DENY.
        kexec.initramfs_load_case(
            id="kexec_initramfs_kernel_read_kexec_file_load_dmverity_signature_false_plain_denied",
            policy=KEXEC_INITRAMFS_DMVERITY_SIGNATURE_FALSE_DENY_POLICY,
            kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
            binary=layout.guest.PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
            expected_errno=errno.EACCES,
            expected_loaded=False,
        ),
        # Policy: KEXEC_INITRAMFS default DENY; ALLOW matching dmverity_roothash.
        # Input: CPIO on dm-verity with a signed, matching root hash;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: root-hash rule -> ALLOW; the rule does not require a signature.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"dmverity_roothash_{algorithm}_signed_ok"
                ),
                policy=kexec_initramfs_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.dmverity_kexec_initramfs_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=0,
                expected_loaded=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_INITRAMFS default DENY; ALLOW matching dmverity_roothash.
        # Input: CPIO on dm-verity with a matching but unsigned root hash;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: root-hash rule -> ALLOW without a root-hash signature.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"dmverity_roothash_{algorithm}_unsigned_ok"
                ),
                policy=kexec_initramfs_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.dmverity_kexec_initramfs_test_binary(
                    algorithm=algorithm, signed=False
                ),
                expected_errno=0,
                expected_loaded=True,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_INITRAMFS default DENY; ALLOW matching dmverity_roothash.
        # Input: identical CPIO bytes on plain tmpfs, with no root hash;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: no property -> no root-hash match -> default DENY.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"dmverity_roothash_{algorithm}_plain_denied"
                ),
                policy=kexec_initramfs_dmverity_roothash_policy(
                    algorithm=algorithm, matching=True
                ),
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.PLAIN_KEXEC_INITRAMFS_TEST_BINARY,
                expected_errno=errno.EACCES,
                expected_loaded=False,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
        # Policy: KEXEC_INITRAMFS default DENY; ALLOW a different dmverity_roothash.
        # Input: CPIO on signed dm-verity whose root hash differs from the rule;
        #        the fixed kernel remains permitted under KEXEC_IMAGE.
        # Match: root-hash mismatch -> default DENY despite the valid signature.
        *(
            kexec.initramfs_load_case(
                id=(
                    "kexec_initramfs_kernel_read_kexec_file_load_"
                    f"dmverity_roothash_{algorithm}_mismatch_denied"
                ),
                policy=kexec_initramfs_dmverity_roothash_policy(
                    algorithm=algorithm, matching=False
                ),
                kernel=layout.guest.KEXEC_IMAGE_TEST_BINARY,
                binary=layout.guest.dmverity_kexec_initramfs_test_binary(
                    algorithm=algorithm, signed=True
                ),
                expected_errno=errno.EACCES,
                expected_loaded=False,
            )
            for algorithm in hashes.DMVERITY_ALGORITHMS
        ),
    )
