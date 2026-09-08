# SPDX-License-Identifier: GPL-2.0-only
"""Define the boot_verified cases and expose their saved outcomes to TAP.

IPE evaluates boot_verified for the file being authorized: a file from the
initramfs matches TRUE, while the same file copied to a separate tmpfs matches
FALSE. The initrd program image/initrd/boot-verified.py runs INITRAMFS_CASES
before switch_root and stores their outcomes in /run/ipe-boot-verified.

After switch_root, build() creates reporting-only cases. Each reads one saved
outcome instead of trying to access the removed initramfs files again.
"""

import errno
from functools import partial

import checks
import ipe
import layout
from model import Batch, Case

from . import firmware, kexec, kmodule

KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY = ipe.Policy(
    signed=layout.initrd.KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY_SIGNATURE,
    name="ipe_test_kmodule_boot_verified_true",
)
KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY = ipe.Policy(
    signed=layout.initrd.KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY_SIGNATURE,
    name="ipe_test_kmodule_boot_verified_false",
)
FIRMWARE_BOOT_VERIFIED_FALSE_DENY_POLICY = ipe.Policy(
    signed=layout.initrd.FIRMWARE_BOOT_VERIFIED_FALSE_DENY_POLICY_SIGNATURE,
    name="ipe_test_firmware_boot_verified_false",
)
FIRMWARE_BOOT_VERIFIED_TRUE_ALLOW_POLICY = ipe.Policy(
    signed=layout.initrd.FIRMWARE_BOOT_VERIFIED_TRUE_ALLOW_POLICY_SIGNATURE,
    name="ipe_test_firmware_boot_verified_true",
)
KEXEC_IMAGE_BOOT_VERIFIED_FALSE_DENY_POLICY = ipe.Policy(
    signed=layout.initrd.KEXEC_IMAGE_BOOT_VERIFIED_FALSE_DENY_POLICY_SIGNATURE,
    name="ipe_test_kexec_image_boot_verified_false",
)
KEXEC_IMAGE_BOOT_VERIFIED_TRUE_ALLOW_POLICY = ipe.Policy(
    signed=layout.initrd.KEXEC_IMAGE_BOOT_VERIFIED_TRUE_ALLOW_POLICY_SIGNATURE,
    name="ipe_test_kexec_image_boot_verified_true",
)
INITRAMFS_KMODULE_TEST_BINARY = layout.initrd.KMODULE_TEST_BINARY
TMPFS_KMODULE_TEST_BINARY = layout.initrd.BOOT_TMPFS_KMODULE_TEST_BINARY


# These rules test initramfs provenance, not dm/fs-verity or module signatures.
# Tmpfs cases use byte-for-byte copies of their initramfs inputs.
INITRAMFS_CASES = (
    # Policy: KMODULE default DENY; ALLOW boot_verified=TRUE.
    # Input: the original initramfs .ko, whose file context has boot_verified=TRUE.
    # Match: TRUE matches -> the ALLOW rule applies.
    kmodule.insmod_case(
        id="kmodule_kernel_read_insmod_boot_verified_true_initramfs_ok",
        policy=KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY,
        binary=INITRAMFS_KMODULE_TEST_BINARY,
        expected_returncode=0,
        expected_loaded=True,
    ),
    # Policy: KMODULE default DENY; ALLOW boot_verified=TRUE.
    # Input: a buffer read from the same verified initramfs .ko.
    # Match: no file context means boot_verified=FALSE -> default DENY.
    kmodule.init_module_case(
        id="kmodule_kernel_load_init_module_boot_verified_true_initramfs_denied",
        policy=KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY,
        binary=INITRAMFS_KMODULE_TEST_BINARY,
        expected_errno=errno.EACCES,
        expected_loaded=False,
    ),
    # Policy: KMODULE default DENY; ALLOW boot_verified=TRUE.
    # Input: identical .ko bytes copied to a separate tmpfs; boot_verified=FALSE.
    # Match: TRUE does not match -> default DENY despite the identical bytes.
    kmodule.insmod_case(
        id="kmodule_kernel_read_insmod_boot_verified_true_tmpfs_denied",
        policy=KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY,
        binary=TMPFS_KMODULE_TEST_BINARY,
        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
        expected_loaded=False,
    ),
    # Policy: KMODULE default ALLOW; DENY boot_verified=FALSE.
    # Input: the original initramfs .ko, whose file context has boot_verified=TRUE.
    # Match: FALSE does not match -> default ALLOW, not the DENY rule.
    kmodule.insmod_case(
        id="kmodule_kernel_read_insmod_boot_verified_false_initramfs_ok",
        policy=KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY,
        binary=INITRAMFS_KMODULE_TEST_BINARY,
        expected_returncode=0,
        expected_loaded=True,
    ),
    # Policy: KMODULE default ALLOW; DENY boot_verified=FALSE.
    # Input: a buffer read from the verified initramfs .ko, without its file context.
    # Match: KERNEL_LOAD has boot_verified=FALSE -> the explicit DENY rule matches.
    kmodule.init_module_case(
        id="kmodule_kernel_load_init_module_boot_verified_false_initramfs_denied",
        policy=KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY,
        binary=INITRAMFS_KMODULE_TEST_BINARY,
        expected_errno=errno.EACCES,
        expected_loaded=False,
    ),
    # Policy: KMODULE default ALLOW; DENY boot_verified=FALSE.
    # Input: the .ko copy on a separate tmpfs, whose boot_verified property is FALSE.
    # Match: FALSE matches -> the explicit DENY rule applies.
    kmodule.insmod_case(
        id="kmodule_kernel_read_insmod_boot_verified_false_tmpfs_denied",
        policy=KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY,
        binary=TMPFS_KMODULE_TEST_BINARY,
        expected_returncode=kmodule.INSMOD_REFUSED_RETURN_CODE,
        expected_loaded=False,
    ),
    # Policy: FIRMWARE default DENY; ALLOW boot_verified=TRUE.
    # Input: the original initramfs .fw, whose file context has boot_verified=TRUE.
    # Match: TRUE matches -> ALLOW; the retained bytes must match the input.
    firmware.request_firmware_case(
        id="firmware_kernel_read_request_firmware_boot_verified_true_initramfs_ok",
        policy=FIRMWARE_BOOT_VERIFIED_TRUE_ALLOW_POLICY,
        binary=layout.initrd.FIRMWARE_TEST_BINARY,
        expected_errno=0,
        expected_content_match=True,
    ),
    # Policy: FIRMWARE default DENY; ALLOW boot_verified=TRUE.
    # Input: identical .fw bytes on a separate tmpfs; boot_verified=FALSE.
    # Match: TRUE does not match -> default DENY; search ends in ENOENT.
    firmware.request_firmware_case(
        id="firmware_kernel_read_request_firmware_boot_verified_true_tmpfs_denied",
        policy=FIRMWARE_BOOT_VERIFIED_TRUE_ALLOW_POLICY,
        binary=layout.initrd.BOOT_TMPFS_FIRMWARE_TEST_BINARY,
        expected_errno=errno.ENOENT,
        expected_content_match=False,
    ),
    # Policy: FIRMWARE default ALLOW; DENY boot_verified=FALSE.
    # Input: the original initramfs .fw, whose boot_verified property is TRUE.
    # Match: FALSE does not match -> default ALLOW.
    firmware.request_firmware_case(
        id="firmware_kernel_read_request_firmware_boot_verified_false_initramfs_ok",
        policy=FIRMWARE_BOOT_VERIFIED_FALSE_DENY_POLICY,
        binary=layout.initrd.FIRMWARE_TEST_BINARY,
        expected_errno=0,
        expected_content_match=True,
    ),
    # Policy: FIRMWARE default ALLOW; DENY boot_verified=FALSE.
    # Input: the .fw copy on a separate tmpfs, whose boot_verified property is FALSE.
    # Match: FALSE matches -> explicit DENY; search ends in ENOENT.
    firmware.request_firmware_case(
        id="firmware_kernel_read_request_firmware_boot_verified_false_tmpfs_denied",
        policy=FIRMWARE_BOOT_VERIFIED_FALSE_DENY_POLICY,
        binary=layout.initrd.BOOT_TMPFS_FIRMWARE_TEST_BINARY,
        expected_errno=errno.ENOENT,
        expected_content_match=False,
    ),
    # Policy: KEXEC_IMAGE default DENY; ALLOW boot_verified=TRUE.
    # Input: the real kernel image from the verified boot filesystem.
    # Match: TRUE matches -> ALLOW; check staging and unload without executing.
    kexec.file_load_case(
        id="kexec_image_kernel_read_kexec_file_load_boot_verified_true_initramfs_ok",
        policy=KEXEC_IMAGE_BOOT_VERIFIED_TRUE_ALLOW_POLICY,
        binary=layout.initrd.KEXEC_IMAGE_TEST_BINARY,
        expected_errno=0,
        expected_loaded=True,
    ),
    # Policy: KEXEC_IMAGE default DENY; ALLOW boot_verified=TRUE.
    # Input: the same kernel image copied to a separate tmpfs.
    # Match: boot_verified is FALSE -> EACCES; nothing is staged.
    kexec.file_load_case(
        id="kexec_image_kernel_read_kexec_file_load_boot_verified_true_tmpfs_denied",
        policy=KEXEC_IMAGE_BOOT_VERIFIED_TRUE_ALLOW_POLICY,
        binary=layout.initrd.BOOT_TMPFS_KEXEC_IMAGE_TEST_BINARY,
        expected_errno=errno.EACCES,
        expected_loaded=False,
    ),
    # Policy: KEXEC_IMAGE default ALLOW; DENY boot_verified=FALSE.
    # Input: the original kernel image from the verified boot filesystem.
    # Match: FALSE does not match -> default ALLOW; check staging and unload.
    kexec.file_load_case(
        id="kexec_image_kernel_read_kexec_file_load_boot_verified_false_initramfs_ok",
        policy=KEXEC_IMAGE_BOOT_VERIFIED_FALSE_DENY_POLICY,
        binary=layout.initrd.KEXEC_IMAGE_TEST_BINARY,
        expected_errno=0,
        expected_loaded=True,
    ),
    # Policy: KEXEC_IMAGE default ALLOW; DENY boot_verified=FALSE.
    # Input: the real kernel image copied onto a separate tmpfs.
    # Match: FALSE matches -> explicit DENY; nothing is staged.
    kexec.file_load_case(
        id="kexec_image_kernel_read_kexec_file_load_boot_verified_false_tmpfs_denied",
        policy=KEXEC_IMAGE_BOOT_VERIFIED_FALSE_DENY_POLICY,
        binary=layout.initrd.BOOT_TMPFS_KEXEC_IMAGE_TEST_BINARY,
        expected_errno=errno.EACCES,
        expected_loaded=False,
    ),
    # Policy: KEXEC_IMAGE default DENY; ALLOW boot_verified=TRUE.
    # Input: a userspace buffer read from the verified boot kernel image.
    # Match: KERNEL_LOAD has no file context; boot_verified is FALSE -> EACCES.
    kexec.buffer_load_case(
        id="kexec_image_kernel_load_kexec_load_boot_verified_true_initramfs_denied",
        policy=KEXEC_IMAGE_BOOT_VERIFIED_TRUE_ALLOW_POLICY,
        binary=layout.initrd.KEXEC_IMAGE_TEST_BINARY,
        expected_errno=errno.EACCES,
        expected_loaded=False,
    ),
)


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            id="boot",
            # Operations already ran in initramfs; report their saved outcomes.
            cases=tuple(
                Case(
                    id=case.id,
                    checks=(partial(checks.initramfs_case_passed, id=case.id),),
                )
                for case in INITRAMFS_CASES
            ),
        ),
    )
