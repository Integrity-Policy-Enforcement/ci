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

from . import kmodule

KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY = ipe.Policy(
    signed=layout.initrd.KMODULE_BOOT_VERIFIED_TRUE_ALLOW_POLICY_SIGNATURE,
    name="ipe_test_kmodule_boot_verified_true",
)
KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY = ipe.Policy(
    signed=layout.initrd.KMODULE_BOOT_VERIFIED_FALSE_DENY_POLICY_SIGNATURE,
    name="ipe_test_kmodule_boot_verified_false",
)
INITRAMFS_KMODULE_TEST_BINARY = layout.initrd.KMODULE_TEST_BINARY
TMPFS_KMODULE_TEST_BINARY = layout.initrd.BOOT_TMPFS_KMODULE_TEST_BINARY


# These rules test initramfs provenance, not dm/fs-verity or module signatures.
# The tmpfs input is a byte-for-byte copy of the initramfs module.
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
)


def build() -> tuple[Batch, ...]:
    """The batches this group contributes."""
    return (
        Batch(
            id="boot",
            # Module loading already ran in initramfs; report its saved outcome.
            cases=tuple(
                Case(
                    id=case.id,
                    checks=(partial(checks.initramfs_case_passed, id=case.id),),
                )
                for case in INITRAMFS_CASES
            ),
        ),
    )
